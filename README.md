![banner](et-banner.png)

# EntraTrace

![Focus](https://img.shields.io/badge/FOCUS-ENTRA%20%2B%20AZURE%20IDENTITY%20DRIFT-374151?style=for-the-badge)
![Use](https://img.shields.io/badge/USE-DEFENSIVE%20PRIVILEGE--PATH%20ANALYSIS-7F1D1D?style=for-the-badge)
![Language](https://img.shields.io/badge/LANGUAGE-PYTHON-1D4ED8?style=for-the-badge&logo=python&logoColor=white)
![Output](https://img.shields.io/badge/OUTPUT-CLI%20%7C%20JSON%20%7C%20HTML-0F766E?style=for-the-badge)

## Example Usage

```powershell
python .\entratrace.py analyze .\public_snapshots\official_demo_current --previous .\public_snapshots\official_demo_previous --summary-only
```

`EntraTrace` is a defender-first Microsoft Entra ID and Azure privilege-path analyzer that focuses on `what changed`, `who can reach crown-jewel access`, and `how to break the path`, not just graph exploration.

It is designed to be different from generic cloud graph tooling by prioritizing:
- named abuse scenarios defenders can act on
- path drift between snapshots
- workload identity risk
- guest and ownership exposure
- directory audit and sign-in behavior tied to identity abuse patterns
- MITRE ATT&CK mapping on each finding for SOC context
- baseline and ignore workflows for noise suppression
- remediation-first findings

This repo ships with a `public reference snapshot pack` built from official Microsoft role identifiers and documented role behavior, so you can test it immediately without needing a lab tenant or VM.

## Why It Matters

Most identity graph tools answer:
- what objects exist?
- what edges connect them?
- can I find a path?

EntraTrace is meant to answer:
- which new dangerous paths appeared since the previous snapshot?
- which identities can reach high-value apps, directory control, or Azure subscriptions?
- which app owners and workload identities matter most?
- what is the smallest fix that breaks the path?

## Current Detection Coverage

- Application Administrator or Cloud Application Administrator to privileged app impersonation
- User Administrator, Helpdesk Administrator, or Authentication Administrator pivoting through app owners
- Guest ownership of privileged apps or service principals
- Privileged workload identities with dangerous Microsoft Graph permissions
- Workload identities with risky Azure RBAC on high-value scopes
- Direct Global Administrator exposure
- New service principal credential added from directory audit telemetry
- Admin consent followed by service principal credential creation (chain detection)
- User added to privileged Entra role groups from audit telemetry
- Suspicious OAuth consent with `offline_access` and sensitive scopes
- PwnAuth-like OAuth consent scope pattern detection
- Risky sign-in burst on privileged workload identities
- MITRE ATT&CK technique mapping embedded in JSON, CLI, and HTML output
- Snapshot drift marking for newly introduced paths

## Project Layout

```text
<repo-root>
  entratrace.py
  entratrace.ignore.example
  README.md
  entratrace/
    collector_graph.py
    cli.py
    loader.py
    analysis.py
    suppressions.py
    reporting.py
  public_snapshots/
    SOURCES.md
    official_demo_previous/
    official_demo_current/
  reports/
```

## Safe Public Demo Data

The snapshot pack under [public_snapshots](public_snapshots) is intentionally safe:
- role IDs and role semantics come from official Microsoft documentation
- the tenant objects themselves are synthetic
- no live tenant export, secret, or customer data is included

That means you get realistic Entra and Azure modeling without pulling data from a real environment.

## Quick Start

Run the console-only demo first:

```powershell
cd C:\projects\entratrace
python .\entratrace.py analyze .\public_snapshots\official_demo_current --previous .\public_snapshots\official_demo_previous --summary-only
```

Collect a real snapshot from Microsoft Graph (read-only):

```powershell
cd C:\projects\entratrace
az login
python .\entratrace.py collect .\snapshots\tenant-2026-04-08 --audit-days 14 --signin-days 14
```

Analyze the collected snapshot:

```powershell
cd C:\projects\entratrace
python .\entratrace.py analyze .\snapshots\tenant-2026-04-08 --summary-only
```

Generate JSON and HTML reports:

```powershell
cd C:\projects\entratrace
python .\entratrace.py analyze .\public_snapshots\official_demo_current --previous .\public_snapshots\official_demo_previous --json .\reports\official-demo.json --html .\reports\official-demo.html
```

Run the new attack-informed scenario packs:

```powershell
cd C:\projects\entratrace
python .\entratrace.py analyze .\public_snapshots\incident_oauth_chain_current --previous .\public_snapshots\incident_oauth_chain_previous --summary-only
python .\entratrace.py analyze .\public_snapshots\incident_role_escalation_current --previous .\public_snapshots\incident_role_escalation_previous --summary-only
```

Baseline and ignore mode (suppress known findings):

```powershell
cd C:\projects\entratrace
python .\entratrace.py analyze .\public_snapshots\official_demo_current --previous .\public_snapshots\official_demo_previous --json .\reports\baseline.json --html .\reports\baseline.html
python .\entratrace.py analyze .\public_snapshots\official_demo_current --previous .\public_snapshots\official_demo_previous --baseline .\reports\baseline.json --ignore-file .\entratrace.ignore.example --summary-only --width 78
```

Open the HTML report:

```powershell
Start-Process '.\reports\official-demo.html'
```

## What The Demo Should Show

The bundled public diff is designed to surface:
- a standing `Application Administrator -> privileged app/service principal` path
- a newly introduced `User Administrator -> app owner -> privileged app` path
- guest ownership of a privileged app and service principal
- privileged workload identities with tenant-wide or Azure control-plane reach
- a crown-jewel `Production Subscription`
- a consent-to-credential attack chain on the same service principal
- suspicious delegated OAuth consent patterns seen in phishing-style abuse
- privileged role-group additions and workload sign-in anomaly bursts

## Example Use Cases

- validate whether a newly exported tenant snapshot introduced dangerous identity paths
- identify workload identities that can reach tenant-wide or subscription-wide control
- spot guest or external ownership of high-value applications
- prioritize cloud identity cleanup based on blast radius, not raw edge count

## Notes

- This MVP is intentionally local and file-driven.
- It does not require Microsoft Graph access to test the demo pack.
- Live tenant collection is available with the `collect` command (read-only Graph + optional Azure CLI RBAC).
- Public scenarios are synthetic but attack-informed from real Microsoft Sentinel detection logic.

## References

- [Microsoft Learn: New name for Azure Active Directory](https://learn.microsoft.com/en-us/entra/fundamentals/new-name)
- [Microsoft Learn: What is Microsoft Entra?](https://learn.microsoft.com/en-us/entra/fundamentals/what-is-entra)
- [Microsoft Learn: Microsoft Entra built-in roles permissions reference](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Microsoft Learn: Azure built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
- [Azure Sentinel Entra ID analytics rules](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules)
- [AzureHound](https://github.com/SpecterOps/AzureHound)
- [Stormspotter](https://github.com/Azure/Stormspotter)
- [ROADrecon](https://github.com/dirkjanm/ROADtools/wiki/Getting-started-with-ROADrecon)
