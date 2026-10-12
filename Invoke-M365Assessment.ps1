<#
.SYNOPSIS
    Read-only Microsoft 365 / Microsoft Entra ID security assessment, with HTML client report.

.DESCRIPTION
    Connects to Microsoft Graph with READ-ONLY scopes and runs six checks:
      1. Global Administrators      (privileged-role sprawl)
      2. MFA registration coverage  (users with no MFA registered)
      3. License waste              (disabled-but-licensed accounts)
      4. Baseline protection        (Security Defaults + Conditional Access states)
      5. Legacy authentication      (is it blocked?)
      6. External sharing posture   (SharePoint/OneDrive org setting)

    Prints a console summary AND writes a self-contained HTML report a non-technical
    owner can read, print, or email. Makes NO changes: requests only *.Read.All scopes
    and refuses to run if any write scope is present.

.NOTES
    Author : Magic Ben Ventures
    Safety : read-only by design. Tenant-agnostic (assesses whichever tenant you sign in to).
    Output : ./output/M365-Assessment-<timestamp>.html  (the output/ folder is git-ignored)
#>

# ---------------------------------------------------------------------------
# Read-only scopes this tool needs. NOTHING here contains ReadWrite.
# ---------------------------------------------------------------------------
$ReadOnlyScopes = @(
    'User.Read.All',
    'Directory.Read.All',
    'AuditLog.Read.All',
    'Policy.Read.All',
    'SharePointTenantSettings.Read.All'
)

# ---------------------------------------------------------------------------
# Connect read-only, verify the session is real, and prove it's read-only.
# ---------------------------------------------------------------------------
function Connect-Assessment {
    Connect-MgGraph -UseDeviceCode -Scopes $ReadOnlyScopes -NoWelcome
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.Account) {
        throw "Authentication failed - no active Microsoft Graph session. Aborting."
    }
    $writeScopes = $ctx.Scopes | Where-Object { $_ -like '*ReadWrite*' -or $_ -like '*Write*' }
    if ($writeScopes) {
        throw "REFUSING TO RUN: write scope(s) detected: $($writeScopes -join ', '). This tool is read-only."
    }
    Write-Host "Connected as $($ctx.Account)  [read-only verified]" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Helper: build one structured finding.
#   Items          = affected users / facts (one per line in output)
#   Impact         = plain-English "why it matters" (client-facing)
#   Recommendation = plain-English "what to do"     (client-facing)
# ---------------------------------------------------------------------------
function New-Finding {
    param(
        [string]   $Check,
        [string]   $Severity,
        [string]   $Finding,
        [string[]] $Items = @(),
        [string]   $Impact = '',
        [string]   $Recommendation = ''
    )
    [PSCustomObject]@{
        Check          = $Check
        Severity       = $Severity
        Finding        = $Finding
        Items          = $Items
        Impact         = $Impact
        Recommendation = $Recommendation
    }
}

# ---------------------------------------------------------------------------
# Check 1 - Global Administrators
# ---------------------------------------------------------------------------
function Get-GlobalAdminFindings {
    $ga      = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $ga.Id
    $names   = @($members | ForEach-Object { $_.AdditionalProperties.userPrincipalName })
    $sev     = if ($names.Count -gt 2) { 'High' } else { 'Info' }
    New-Finding -Check 'Global Admins' -Severity $sev -Finding "$($names.Count) Global Administrator(s)" -Items $names `
        -Impact 'Global Administrators can change anything in Microsoft 365, including security settings and other people''s access. Every extra admin account is another target: if one is phished, the whole organization is exposed.' `
        -Recommendation 'Keep Global Administrators to a minimum (typically 2-4, including one emergency "break-glass" account). Remove admin rights from anyone who does not need them, and use standard (non-admin) accounts for day-to-day work.'
}

# ---------------------------------------------------------------------------
# Check 2 - MFA registration coverage
# ---------------------------------------------------------------------------
function Get-MfaFindings {
    $reg   = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
    $noMfa = @($reg | Where-Object { -not $_.IsMfaRegistered } | ForEach-Object { $_.UserPrincipalName })
    $sev   = if ($noMfa.Count -gt 0) { 'Medium' } else { 'Info' }
    New-Finding -Check 'MFA coverage' -Severity $sev -Finding "$($noMfa.Count) user(s) with no MFA registered" -Items $noMfa `
        -Impact 'Accounts without multi-factor authentication (MFA) rely on a password alone. A stolen or guessed password gives an attacker full access to that person''s email and files.' `
        -Recommendation 'Require and register MFA for every user, favouring app-based or phishing-resistant methods. Enroll users proactively rather than waiting for them to opt in.'
}

# ---------------------------------------------------------------------------
# Check 3 - License waste (disabled but still licensed)
# ---------------------------------------------------------------------------
function Get-LicenseWasteFindings {
    $users = Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses
    $waste = @($users | Where-Object { -not $_.AccountEnabled -and $_.AssignedLicenses.Count -gt 0 } | ForEach-Object { $_.UserPrincipalName })
    $sev   = if ($waste.Count -gt 0) { 'Medium' } else { 'Info' }
    New-Finding -Check 'License waste' -Severity $sev -Finding "$($waste.Count) disabled-but-licensed account(s)" -Items $waste `
        -Impact 'Disabled accounts that still hold paid licenses waste money every month. Accounts left active for people who have departed are also unmonitored entry points.' `
        -Recommendation 'Remove licenses from disabled accounts to reclaim cost, and disable or delete accounts for departed staff. Adopt a simple offboarding checklist (disable, remove licenses, review, delete).'
}

# ---------------------------------------------------------------------------
# Check 4 - Baseline protection (Security Defaults + Conditional Access)
# ---------------------------------------------------------------------------
function Get-BaselineFindings {
    $sd         = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    $ca         = @(Get-MgIdentityConditionalAccessPolicy)
    $enabled    = @($ca | Where-Object { $_.State -eq 'enabled' }).Count
    $reportOnly = @($ca | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
    $items = @(
        "Security Defaults enabled: $($sd.IsEnabled)",
        "Conditional Access policies: $($ca.Count) total ($enabled enabled, $reportOnly report-only)"
    )
    $sev = if (-not $sd.IsEnabled -and $ca.Count -eq 0) { 'High' }
           elseif ($reportOnly -gt 0)                   { 'Low'  }
           else                                         { 'Info' }
    New-Finding -Check 'Baseline' -Severity $sev -Finding 'Baseline protection posture' -Items $items `
        -Impact 'Baseline protections (such as requiring MFA organization-wide and blocking risky sign-ins) stop the most common attacks. A policy that exists but is left in "report-only" is not enforced and gives a false sense of security.' `
        -Recommendation 'Ensure organization-wide security policies are turned on and enforced (not report-only). Review them periodically for drift, and retire redundant or overlapping policies.'
}

# ---------------------------------------------------------------------------
# Check 5 - Legacy authentication blocked?
# ---------------------------------------------------------------------------
function Get-LegacyAuthFindings {
    $leg = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq 'Block legacy authentication' }
    if ($leg -and $leg.State -eq 'enabled') {
        New-Finding -Check 'Legacy auth' -Severity 'Info' -Finding 'Legacy authentication is blocked' -Items @("Policy '$($leg.DisplayName)' = enabled") `
            -Impact 'Legacy (older) sign-in protocols cannot use MFA, so attackers use them to bypass it. This control is correctly closing that back door.' `
            -Recommendation 'Keep legacy authentication blocked for all users. Grant narrow, time-limited exceptions only if a specific legacy application genuinely requires it.'
    } else {
        New-Finding -Check 'Legacy auth' -Severity 'High' -Finding 'Legacy authentication NOT blocked' -Items @('No enabled policy blocking legacy auth found') `
            -Impact 'Legacy (older) sign-in protocols cannot use MFA. While they are allowed, an attacker can use one to bypass MFA entirely with just a password.' `
            -Recommendation 'Block legacy authentication for all users via Conditional Access. Identify any legacy-dependent apps first and migrate or scope a temporary exception.'
    }
}

# ---------------------------------------------------------------------------
# Check 6 - External sharing posture (org-level)
# ---------------------------------------------------------------------------
function Get-SharingFindings {
    $s   = Get-MgAdminSharepointSetting
    $cap = $s.SharingCapability
    $sev = switch ($cap) {
        'externalUserAndGuestSharing' { 'High' }
        'externalUserSharingOnly'     { 'Low'  }
        default                       { 'Info' }
    }
    $items = @(
        "Org sharing capability: $cap",
        "Resharing by external users: $($s.IsResharingByExternalUsersEnabled)",
        "(Org-level only; per-file anonymous-link inventory needs SharePoint Advanced Management.)"
    )
    New-Finding -Check 'External sharing' -Severity $sev -Finding "Sharing set to '$cap'" -Items $items `
        -Impact 'When files can be shared with "anyone" via anonymous links, a single forwarded or leaked link can expose company data to the public, and AI tools can surface it too. Anonymous links also leave no record of who accessed the file.' `
        -Recommendation 'Restrict external sharing to signed-in guests at most. Disable anonymous "anyone" links, or require expiration and a password if they are truly needed. Review existing shared links.'
}

# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
}

function Export-HtmlReport {
    param($Findings, $TenantId, [string]$Path)

    $sevColors = @{ High='#c0392b'; Medium='#e67e22'; Low='#2980b9'; Info='#7f8c8d'; ERROR='#7b241c' }
    $order = 'High','Medium','Low','Info','ERROR'

    $tiles = foreach ($s in $order) {
        $n = @($Findings | Where-Object { $_.Severity -eq $s }).Count
        if ($n -gt 0) {
            "<div class='tile' style='background:$($sevColors[$s])'><div class='tile-n'>$n</div><div class='tile-s'>$s</div></div>"
        }
    }

    $cards = foreach ($f in $Findings) {
        $color = $sevColors[$f.Severity]
        $itemsHtml = ''
        if ($f.Items -and @($f.Items).Count -gt 0) {
            $lis = ($f.Items | ForEach-Object { '<li>' + (ConvertTo-HtmlSafe $_) + '</li>' }) -join ''
            $itemsHtml = "<ul>$lis</ul>"
        }
        $impactHtml = if ($f.Impact)         { "<div class='label'>Why it matters</div><div class='text'>$(ConvertTo-HtmlSafe $f.Impact)</div>" } else { '' }
        $recHtml    = if ($f.Recommendation) { "<div class='label'>What to do</div><div class='text'>$(ConvertTo-HtmlSafe $f.Recommendation)</div>" } else { '' }
@"
<div class="card">
  <div class="card-head">
    <span class="badge" style="background:$color">$($f.Severity)</span>
    <span class="check">$(ConvertTo-HtmlSafe $f.Check)</span>
  </div>
  <div class="finding">$(ConvertTo-HtmlSafe $f.Finding)</div>
  $itemsHtml
  $impactHtml
  $recHtml
</div>
"@
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Microsoft 365 Security Assessment</title>
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;color:#222;max-width:900px;margin:24px auto;padding:0 16px;line-height:1.55}
 h1{margin-bottom:0}
 .sub{color:#666;margin-top:4px;font-size:14px}
 .tiles{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
 .tile{color:#fff;border-radius:8px;padding:12px 18px;min-width:88px;text-align:center}
 .tile-n{font-size:28px;font-weight:700}
 .tile-s{font-size:11px;text-transform:uppercase;letter-spacing:.6px}
 .intro{background:#f6f8fa;border:1px solid #eaecef;border-radius:8px;padding:12px 16px}
 .card{border:1px solid #e3e3e3;border-radius:10px;padding:16px 18px;margin:16px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
 .card-head{display:flex;align-items:center;gap:10px;margin-bottom:6px}
 .badge{color:#fff;font-size:11px;font-weight:700;padding:3px 10px;border-radius:12px;text-transform:uppercase}
 .check{font-size:18px;font-weight:600}
 .finding{font-weight:600;margin:6px 0}
 ul{margin:6px 0 10px 22px}
 li{font-family:Consolas,monospace;font-size:13px;color:#444}
 .label{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#8a8a8a;margin-top:12px}
 .text{margin-top:2px}
 footer{color:#888;font-size:12px;margin-top:28px;border-top:1px solid #eee;padding-top:12px}
 @media print{body{margin:0}.card{break-inside:avoid}.tile{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style>
</head>
<body>
<h1>Microsoft 365 Security Assessment</h1>
<div class="sub">Prepared by Magic Ben Ventures &middot; Tenant: $(ConvertTo-HtmlSafe $TenantId) &middot; $(Get-Date -Format 'yyyy-MM-dd')</div>

<div class="tiles">
$($tiles -join "`n")
</div>

<div class="intro">
This report summarizes a <strong>read-only</strong> security assessment of your Microsoft 365 environment across six high-impact areas. Each finding below shows what was observed, why it matters to your business, and a recommended action. <strong>No changes were made to your tenant</strong> during this assessment.
</div>

$($cards -join "`n")

<footer>
Read-only assessment performed with least-privilege access. Scope: Microsoft Entra ID identities, Conditional Access, licensing, and organization-level SharePoint/OneDrive sharing. Per-file sharing inventory and endpoint posture are out of scope for this assessment. Severity levels: High (address promptly) &middot; Medium (plan to fix) &middot; Low (hygiene) &middot; Info (no action).
</footer>
</body>
</html>
"@

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $html | Out-File -FilePath $Path -Encoding utf8
    Write-Host "HTML report written to: $Path" -ForegroundColor Green
}

# ===========================================================================
# MAIN
# ===========================================================================
Connect-Assessment

$checks = @(
    'Get-GlobalAdminFindings',
    'Get-MfaFindings',
    'Get-LicenseWasteFindings',
    'Get-BaselineFindings',
    'Get-LegacyAuthFindings',
    'Get-SharingFindings'
)

$findings = foreach ($c in $checks) {
    try   { & $c }
    catch { New-Finding -Check $c -Severity 'ERROR' -Finding 'Check failed to run' -Items @($_.Exception.Message) }
}

# ----- Console summary -----
Write-Host ""
Write-Host "===== M365 / Entra Security Assessment =====" -ForegroundColor Cyan
Write-Host ("Tenant: {0}   Run: {1}" -f (Get-MgContext).TenantId, (Get-Date))
Write-Host ""
$findings | Format-Table Check, Severity, Finding -AutoSize

Write-Host "----- Details -----" -ForegroundColor Cyan
foreach ($f in $findings) {
    Write-Host ""
    Write-Host ("[{0}] {1} - {2}" -f $f.Severity, $f.Check, $f.Finding) -ForegroundColor Yellow
    foreach ($item in $f.Items) { Write-Host "    - $item" }
}
Write-Host ""

# ----- HTML client report -----
$reportPath = Join-Path (Get-Location) ("output/M365-Assessment-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Export-HtmlReport -Findings $findings -TenantId (Get-MgContext).TenantId -Path $reportPath
Write-Host ""
