<#
.SYNOPSIS
    Read-only Microsoft 365 / Entra ID security assessment.
 
.DESCRIPTION
    Connects to Microsoft Graph with READ-ONLY scopes and runs six checks:
      1. Global Administrators      (privileged-role sprawl)
      2. MFA registration coverage  (users with no MFA registered)
      3. License waste              (disabled-but-licensed accounts)
      4. Baseline protection        (Security Defaults + Conditional Access states)
      5. Legacy authentication      (is it blocked?)
      6. External sharing posture   (SharePoint/OneDrive org setting)
 
    Outputs structured findings to the console. Makes NO changes: it requests only
    *.Read.All scopes and refuses to run if any write scope is present. It also
    re-verifies the Graph connection on every run, so a stale/expired session can
    never cause a misleading "all clear".
 
.NOTES
    Author : Magic Ben Ventures
    Safety : read-only by design. Tenant-agnostic (assesses whichever tenant you sign in to).
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
# Connect read-only, PROVE it's read-only, and PROVE we're actually signed in.
# Always calls Connect-MgGraph: it reuses a valid cached token silently, or
# prompts via device code if the token is missing/expired. This is what stops
# a stale session from fooling the tool into running unauthenticated.
# ---------------------------------------------------------------------------
function Connect-Assessment {
    Connect-MgGraph -UseDeviceCode -Scopes $ReadOnlyScopes -NoWelcome | Out-Null
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
# Helper: build one structured finding. Items[] holds the affected users/facts.
# ---------------------------------------------------------------------------
function New-Finding {
    param(
        [string]   $Check,
        [string]   $Severity,
        [string]   $Finding,
        [string[]] $Items = @()
    )
    [PSCustomObject]@{
        Check    = $Check
        Severity = $Severity
        Finding  = $Finding
        Items    = $Items
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
    New-Finding -Check 'Global Admins' -Severity $sev -Finding "$($names.Count) Global Administrator(s)" -Items $names
}
 
# ---------------------------------------------------------------------------
# Check 2 - MFA registration coverage
# ---------------------------------------------------------------------------
function Get-MfaFindings {
    $reg   = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
    $noMfa = @($reg | Where-Object { -not $_.IsMfaRegistered } | ForEach-Object { $_.UserPrincipalName })
    $sev   = if ($noMfa.Count -gt 0) { 'Medium' } else { 'Info' }
    New-Finding -Check 'MFA coverage' -Severity $sev -Finding "$($noMfa.Count) user(s) with no MFA registered" -Items $noMfa
}
 
# ---------------------------------------------------------------------------
# Check 3 - License waste (disabled but still licensed)
# ---------------------------------------------------------------------------
function Get-LicenseWasteFindings {
    $users = Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled,AssignedLicenses
    $waste = @($users | Where-Object { -not $_.AccountEnabled -and $_.AssignedLicenses.Count -gt 0 } | ForEach-Object { $_.UserPrincipalName })
    $sev   = if ($waste.Count -gt 0) { 'Medium' } else { 'Info' }
    New-Finding -Check 'License waste' -Severity $sev -Finding "$($waste.Count) disabled-but-licensed account(s)" -Items $waste
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
    New-Finding -Check 'Baseline' -Severity $sev -Finding 'Baseline protection posture' -Items $items
}
 
# ---------------------------------------------------------------------------
# Check 5 - Legacy authentication blocked?
# ---------------------------------------------------------------------------
function Get-LegacyAuthFindings {
    $leg = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq 'Block legacy authentication' }
    if ($leg -and $leg.State -eq 'enabled') {
        New-Finding -Check 'Legacy auth' -Severity 'Info' -Finding 'Legacy authentication is blocked' -Items @("Policy '$($leg.DisplayName)' = enabled")
    } else {
        New-Finding -Check 'Legacy auth' -Severity 'High' -Finding 'Legacy authentication NOT blocked' -Items @('No enabled policy blocking legacy auth found')
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
    New-Finding -Check 'External sharing' -Severity $sev -Finding "Sharing set to '$cap'" -Items $items
}
 
# ===========================================================================
# MAIN
# ===========================================================================
Connect-Assessment
 
# Data-driven list of checks: add a new check by adding its function name here.
$checks = @(
    'Get-GlobalAdminFindings',
    'Get-MfaFindings',
    'Get-LicenseWasteFindings',
    'Get-BaselineFindings',
    'Get-LegacyAuthFindings',
    'Get-SharingFindings'
)
 
# Run each check; if one errors, record it and keep going.
$findings = foreach ($c in $checks) {
    try   { & $c }
    catch { New-Finding -Check $c -Severity 'ERROR' -Finding 'Check failed to run' -Items @($_.Exception.Message) }
}
 
# ----- Summary table -----
Write-Host ""
Write-Host "===== M365 / Entra Security Assessment =====" -ForegroundColor Cyan
Write-Host ("Tenant: {0}   Run: {1}" -f (Get-MgContext).TenantId, (Get-Date))
Write-Host ""
$findings | Format-Table Check, Severity, Finding -AutoSize
 
# ----- Details (one item per line, grouped under each finding) -----
Write-Host "----- Details -----" -ForegroundColor Cyan
foreach ($f in $findings) {
    Write-Host ""
    Write-Host ("[{0}] {1} - {2}" -f $f.Severity, $f.Check, $f.Finding) -ForegroundColor Yellow
    foreach ($item in $f.Items) {
        Write-Host "    - $item"
    }
}
Write-Host ""