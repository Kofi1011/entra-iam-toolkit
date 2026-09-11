# Architecture & Design

This document explains how the **Entra ID Identity Governance & Access Automation Toolkit**
works, the design decisions behind it, and how each capability maps to real IAM
job responsibilities and security controls. It's written so you can talk through
the project confidently in an interview.

---

## 1. Problem statement

Identity is the #1 attack vector in modern breaches. IAM teams are judged on how
well they run four repeatable, auditable processes:

1. **Provision** access when someone joins (least privilege from day one)
2. **Adjust** access when someone changes roles
3. **Remove** access the moment someone leaves
4. **Prove** — via reviews and logs — that only the right people have the right access

This toolkit automates all four and adds identity **threat detection** on top.

---

## 2. Components

| Component | Language | Talks to | Responsibility |
|---|---|---|---|
| `New-JmlUser.ps1` | PowerShell | Microsoft Graph | Joiner: create users, least-privilege groups |
| `Remove-JmlUser.ps1` | PowerShell | Microsoft Graph | Leaver: disable, revoke, strip, audit |
| `Get-AccessReview.ps1` | PowerShell | Microsoft Graph | Certify stale / privileged / guest accounts |
| `Invoke-MfaComplianceCheck.ps1` | PowerShell | Microsoft Graph | Audit MFA + Conditional Access coverage |
| `signin_log_analyzer.py` | Python | Log exports | Detect spray, impossible travel, risky sign-ins |

### Why this split?

- **PowerShell + Microsoft Graph** is the native admin language of Entra ID.
  Every IAM team automates lifecycle tasks this way, so the code looks like the
  real job.
- **Python** is the analyst/DFIR language for log analysis. Keeping detection in
  Python shows breadth and makes the analyzer portable (it runs on any exported
  log, offline, with no tenant access needed for a demo).

---

## 3. Data flow

```
        JOINER                         LEAVER
   HR CSV ──▶ New-JmlUser         UPN ──▶ Remove-JmlUser
        │  (Graph: New-MgUser,          │ (disable → revoke sessions
        │   New-MgGroupMember)          │  → remove groups → reset pwd)
        ▼                               ▼
   ┌──────────────────── Entra ID tenant ────────────────────┐
   │  Users • Groups • Roles • Sign-in logs • CA policies     │
   └──────────────────────────────────────────────────────────┘
        ▲                               │
        │ (Graph reads)                 │ (log export)
   Get-AccessReview                Sign-in logs CSV/JSON
   Invoke-MfaComplianceCheck            │
        │                               ▼
        ▼                        signin_log_analyzer.py
   Governance reports (CSV)      Risk report (CSV + console)
```

---

## 4. Key design decisions

### Least privilege by mapping, not by hand
`New-JmlUser.ps1` uses a central `$RoleGroupMap`. Access is a function of role,
so onboarding is consistent and auditable, and there's a single place to govern
"what does a Finance hire get?" — exactly what an access-governance model looks
like.

### `-WhatIf` everywhere it matters
Provisioning and offboarding scripts implement `SupportsShouldProcess`. You can
dry-run against production and show the intended changes before committing —
the operational-safety habit reviewers look for.

### Everything is auditable
The leaver script writes a CSV audit record for every action (who did what, when,
result). That's the compliance evidence auditors ask for (SOX/PCI/ISO).

### Detection tuned to reduce noise
The Python analyzer:
- uses a **rolling time window** for spray detection (not a naive daily count),
- ignores impossible-travel pairs under 500 km (avoids false positives from
  nearby cities / VPN egress),
- escalates new-country sign-ins to HIGH only when **MFA wasn't satisfied**.

This "tune for signal, not noise" thinking is what separates a script from a
usable detection.

---

## 5. Control mapping

| Capability | NIST 800-53 | NIST CSF | SC-300 domain |
|---|---|---|---|
| Joiner provisioning | AC-2 | PR.AC-1 | Manage user identities |
| Least-privilege groups | AC-6 | PR.AC-4 | Manage access to apps |
| Leaver deprovisioning | AC-2(3) | PR.AC-1 | Manage identity lifecycle |
| Session revocation | AC-12 | PR.AC-7 | Implement authentication |
| Access reviews | AC-2(3), AU-6 | ID.GV, DE.CM | Plan identity governance |
| MFA / CA audit | IA-2, AC-7 | PR.AC-7 | Implement CA & auth |
| Sign-in risk detection | AU-6, SI-4 | DE.CM-1 | Monitor identity |

---

## 6. How to extend it (roadmap ideas)

- Schedule the access review as an **Azure Automation runbook** and email results.
- Push analyzer findings to **Microsoft Sentinel** via the Log Analytics API.
- Add a **Mover** script that recalculates group membership on department change.
- Replace CSV audit with a **Log Analytics workspace** for tamper-evident logging.
- Wrap the Python analyzer in a small **Streamlit dashboard** for non-technical reviewers.

Each of these is a natural "what would you do next?" answer in an interview.

---

## 7. Security notes

- Scripts request **only the Graph scopes they need** (least privilege applies to
  the tooling too).
- No secrets are stored in the repo; auth is interactive `Connect-MgGraph` (swap
  for a certificate-based app registration in production).
- All sample data is synthetic. `.gitignore` blocks generated reports and any
  `*secret*` / `*.env` files from being committed.
