# M365 Security Assessment

A **read-only** Microsoft 365 / Microsoft Entra ID security assessment tool, written in PowerShell on the Microsoft Graph SDK. It runs six high-value checks that small businesses most often fail, and reports findings with severity ratings — **without making any changes to the tenant**.

Built as the automation layer behind a manual methodology: every check was first performed by hand in the admin portals, then reproduced here in read-only code.

## What it checks

| # | Check | Why it matters |
|---|---|---|
| 1 | Global Administrators | Excess admins = large blast radius (least privilege) |
| 2 | MFA registration coverage | Accounts with no MFA registered are one stolen password from takeover |
| 3 | License waste | Disabled accounts still consuming paid licenses |
| 4 | Baseline protection | Are Security Defaults / Conditional Access actually enforced? |
| 5 | Legacy authentication | Old protocols that bypass MFA entirely |
| 6 | External sharing posture | Org-level SharePoint/OneDrive sharing set to "Anyone" (anonymous) |

## Design principles

- **Read-only by design.** Requests only `*.Read.All` scopes. Every run verifies the active session and **refuses to run if any write scope is present** — the tool cannot change the tenant even if misconfigured.
- **Least privilege.** Exactly five read scopes, each required by a specific check.
- **Structured findings.** Each finding is an object (`Check` / `Severity` / `Finding` / `Items`), so results can feed a client report or an automated workflow — not just the console.
- **Fail loud, not silent.** The connection is re-verified each run, so a stale/expired token can never produce a misleading "all clear".
- **Resilient.** Each check runs in isolation; one failure is recorded and the rest continue.
- **Tenant-agnostic.** Assesses whichever tenant you authenticate to (developed against a lab tenant with synthetic data only).

## Requirements

- PowerShell 7+
- Microsoft Graph PowerShell SDK (`Microsoft.Graph.*`, v2.41.1+): `Authentication`, `Users`, `Identity.DirectoryManagement`, `Identity.SignIns`, `Reports`, `Sites`
- An account with read access to directory, policy, reports, and SharePoint tenant settings (Global Reader or equivalent)

## Usage

```
pwsh ./Invoke-M365Assessment.ps1
```

On first run it signs in with the device-code flow (headless-friendly) and requests read-only consent. Later runs reuse the cached token.

## Scopes requested (all read-only)

```
User.Read.All
Directory.Read.All
AuditLog.Read.All
Policy.Read.All
SharePointTenantSettings.Read.All
```

## Sample output (sanitized)

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

----- Details -----

[High] Global Admins - 3 Global Administrator(s)
    - admin@contoso.onmicrosoft.com
    - breakglass@contoso.onmicrosoft.com
    - user1@contoso.onmicrosoft.com
...
```

## Limitations / roadmap

- Check 6 reports the **org-level** sharing posture. Enumerating per-file anonymous links across all sites requires SharePoint Advanced Management (licensed) and is out of scope for v1.
- Ghost-account detection currently keys on *disabled + licensed*. Adding `SignInActivity` (inactivity) is the production upgrade for catching enabled-but-dormant accounts.
- Roadmap: client-report output, then an approval-gated agent wrapper with per-tenant scoped identity and full action logging.

## Skills applied

Microsoft Entra ID / Microsoft 365 administration · Microsoft Graph API & PowerShell SDK · Conditional Access · identity & access management · least privilege · PowerShell scripting (functions, structured objects, error handling) · security assessment methodology (Observation / Evidence / Conclusion / Action).

Maps to **CompTIA Security+** (IAM, least privilege, hardening, logging) and **Microsoft AZ-800** (Entra identity, Conditional Access, Graph administration).

## License

All rights reserved (portfolio demonstration).
