# M365 Security Assessment

A **read-only** Microsoft 365 / Microsoft Entra ID security assessment tool, written in PowerShell on the Microsoft Graph SDK. It runs six high-value checks that small businesses most often fail, and produces both a console summary **and a clean, client-ready HTML report** — without making any changes to the tenant.

Built as the automation layer behind a manual methodology: every check was first performed by hand in the admin portals, then reproduced here in read-only code.

## What it checks

| # | Check | Why it matters |
|---|---|---|
| 1 | Global Administrators | Excess admins = large blast radius (least privilege) |
| 2 | MFA registration coverage | Accounts with no MFA registered are one stolen password from takeover |
| 3 | License waste | Disabled accounts still consuming paid licenses |
| 4 | Baseline protection | Are Security Defaults / Conditional Access actually enforced? |
| 5 | Legacy authentication | Old protocols that bypass MFA entirely (detected by policy *behavior*, not by name) |
| 6 | External sharing posture | Org-level SharePoint/OneDrive sharing set to "Anyone" (anonymous) |

## The client report

Running the tool writes a self-contained HTML report to `output/` (next to the script). It is designed for a **non-technical business owner**:

- **Severity tiles** at the top (High / Medium / Low / Info counts).
- **One card per finding** with three plain-English sections: **What we found** (incl. affected users) → **Why it matters** → **What to do**.
- Print-to-PDF ready (open in a browser and *Print → Save as PDF*).

The findings are generated as structured objects (`Check` / `Severity` / `Finding` / `Items` / `Impact` / `Recommendation`), so the same data can feed a report, a dashboard, or an automated workflow — not just the console.

## Design principles

- **Read-only by design.** Requests only `*.Read.All` scopes. Every run verifies the active session and **refuses to run if any write scope is present** — the tool cannot change the tenant even if misconfigured.
- **Least privilege.** Exactly five read scopes, each required by a specific check.
- **Name-independent detection.** Checks look at policy *behavior* and settings, not hardcoded display names, so they work on tenants with custom-named policies.
- **Fail loud, not silent.** The connection is re-verified each run, so a stale/expired token can never produce a misleading "all clear."
- **Resilient.** Each check runs in isolation; one failure is recorded and the rest continue.
- **Tenant-agnostic & portable.** Assesses whichever tenant you sign in to; the report is always written next to the script (`$PSScriptRoot`), independent of the current folder. Developed against a lab tenant with synthetic data only.

## Setup

**Requirements**

- PowerShell 7+ (`pwsh`)
- Microsoft Graph PowerShell SDK sub-modules (v2.41.1+, matching versions): `Authentication`, `Users`, `Identity.DirectoryManagement`, `Identity.SignIns`, `Reports`, `Sites`
- An account with read access to directory, policy, reports, and SharePoint tenant settings (Global Reader or equivalent)

**Install PowerShell 7**

- Windows: `winget install Microsoft.PowerShell`
- Ubuntu (snap): `sudo snap install powershell --classic`

**Install the required Graph modules** (only what the tool needs, kept to one version):

```powershell
Install-Module Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement, `
               Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Reports, Microsoft.Graph.Sites `
               -RequiredVersion 2.41.1 -Scope CurrentUser -Repository PSGallery
```

> Tip: the full `Microsoft.Graph` meta-module is large; installing only these sub-modules is faster and lighter. If a temp-space error appears on Linux, point temp at a roomier disk first: `$env:TMPDIR = "$HOME/pstmp"` (and `New-Item -ItemType Directory -Force -Path $env:TMPDIR`).

## Usage

```
pwsh ./Invoke-M365Assessment.ps1
```

On first run it signs in with the **device-code flow** (headless-friendly: open the shown URL, enter the code) and requests read-only consent. Later runs reuse the cached token. The tool prints a summary to the console and writes the HTML report to `output/`.

### Scopes requested (all read-only)

```
User.Read.All
Directory.Read.All
AuditLog.Read.All
Policy.Read.All
SharePointTenantSettings.Read.All
```

## Sample console output (sanitized)

```
Connected as admin@contoso.onmicrosoft.com  [read-only verified]

===== M365 / Entra Security Assessment =====
Tenant: <tenant-guid>   Run: 2026-01-01 12:00:00

Check              Severity Finding
-----              -------- -------
Global Admins      High     3 Global Administrator(s)
MFA coverage       Medium   9 user(s) with no MFA registered
License waste      Medium   1 disabled-but-licensed account(s)
Baseline           Info     Baseline protection posture
Legacy auth        Info     Legacy authentication is blocked
External sharing   High     Sharing set to 'externalUserAndGuestSharing'
```

## Limitations / roadmap

- **Global Admins:** counts *active* role holders; admins who are only *eligible* via Privileged Identity Management (PIM) are not yet counted.
- **External sharing:** reports the **org-level** posture. Enumerating per-file anonymous links across all sites requires SharePoint Advanced Management (licensed) and is out of scope for v1.
- **Ghost accounts:** detection keys on *disabled + licensed*. Adding `SignInActivity` (inactivity) is the production upgrade for catching enabled-but-dormant accounts.
- **Roadmap:** benchmark against Microsoft Identity Secure Score; app-only (certificate) authentication for unattended runs; an approval-gated agent wrapper with per-tenant scoped identity and full action logging.

## Skills applied

Microsoft Entra ID / Microsoft 365 administration · Microsoft Graph API & PowerShell SDK · Conditional Access · identity & access management · least privilege · PowerShell scripting (functions, structured objects, error handling, HTML generation) · security assessment methodology (Observation / Evidence / Conclusion / Action) · Git/GitHub PR workflow with protected branches.

Maps to **CompTIA Security+** (IAM, least privilege, hardening, logging) and **Microsoft AZ-800** (Entra identity, Conditional Access, Graph administration).

## License

All rights reserved (portfolio demonstration).
