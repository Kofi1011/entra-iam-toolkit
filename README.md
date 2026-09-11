# 🔐 Entra ID Identity Governance & Access Automation Toolkit

> A hands-on **Identity & Access Management (IAM)** automation toolkit for **Microsoft Entra ID (Azure AD)** that automates the **Joiner–Mover–Leaver (JML)** lifecycle, runs **access reviews**, audits **MFA / Conditional Access** compliance, and analyzes **sign-in logs** for risky activity.

Built to demonstrate real-world IAM analyst workflows — **provisioning, deprovisioning, RBAC, least-privilege access reviews, and identity threat detection** — all mapped to **SC-300** and **NIST 800-53** access-control controls.

![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?logo=microsoft&logoColor=white)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🎯 Why this project exists

Identity is the new security perimeter. IAM teams spend their day on a few repeatable jobs — this toolkit automates all of them:

| IAM workflow | What it solves | Script |
|---|---|---|
| **Joiner** | Onboard new hires with the right groups & least-privilege roles | `New-JmlUser.ps1` |
| **Leaver** | Offboard cleanly — disable, revoke sessions, strip access, audit | `Remove-JmlUser.ps1` |
| **Access Review** | Find stale, guest, and over-privileged accounts | `Get-AccessReview.ps1` |
| **MFA / CA Audit** | Flag users without strong MFA or CA coverage | `Invoke-MfaComplianceCheck.ps1` |
| **Threat Detection** | Detect password spray, impossible travel & risky sign-ins | `signin_log_analyzer.py` |

---

## 🧱 Architecture

```
                 ┌──────────────────────────────┐
   HR / CSV ───▶ │  JML Automation (PowerShell) │──▶ Microsoft Graph API ──▶ Entra ID Tenant
                 └──────────────────────────────┘
                                │
   Entra logs ─▶  signin_log_analyzer.py  ──▶  Prioritized risk report (CSV + console)
                                │
   Access reviews + MFA audit  ──▶  Governance reports for auditors
```

Full design + control mapping: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**

---

## ⚙️ Prerequisites

- **PowerShell 7+** with the Microsoft Graph module:
  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- **Python 3.10+** (the analyzer core uses only the standard library):
  ```bash
  pip install -r requirements.txt   # only needed for the test suite
  ```
- A **Microsoft Entra ID tenant** — a free
  [Microsoft 365 Developer tenant](https://developer.microsoft.com/microsoft-365/dev-program)
  is perfect for the labs.

---

## 🚀 Quick start

### 1. Connect to Graph
```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","AuditLog.Read.All","Directory.Read.All"
```

### 2. Onboard new hires (Joiner)
```powershell
./scripts/New-JmlUser.ps1 -CsvPath ./samples/new_hires.csv -WhatIf   # dry run
./scripts/New-JmlUser.ps1 -CsvPath ./samples/new_hires.csv           # execute
```

### 3. Offboard a leaver
```powershell
./scripts/Remove-JmlUser.ps1 -UserPrincipalName "jdoe@contoso.com" -WhatIf
./scripts/Remove-JmlUser.ps1 -UserPrincipalName "jdoe@contoso.com"
```

### 4. Run an access review
```powershell
./scripts/Get-AccessReview.ps1 -StaleDays 45 -OutFile ./access_review.csv
```

### 5. Audit MFA / Conditional Access coverage
```powershell
./scripts/Invoke-MfaComplianceCheck.ps1 -OutFile ./mfa_gaps.csv
```

### 6. Analyze sign-in logs for risk *(works offline on the sample data)*
```bash
python src/signin_log_analyzer.py --input samples/signin_logs_sample.csv --out risk_report.csv
```

---

## 📊 Sample output — Sign-in Log Analyzer

```
==================================================================
        ENTRA ID SIGN-IN RISK REPORT
==================================================================
Events analyzed : 18
Unique users    : 7
Findings        : 10  (HIGH: 3  MEDIUM: 3  LOW: 4)
------------------------------------------------------------------
[HIGH  ] asmith@contoso.com   Impossible travel
          Toronto -> Lagos: 8926 km in 42 min (~12792 km/h)
          ATT&CK: T1078 (Valid Accounts) / anomalous access
[HIGH  ] jdoe@contoso.com     Brute force / password spray
          5 failed sign-ins within 10 min (from 45.83.12.7)
          ATT&CK: T1110.001 (Brute Force)
...
```

---

## 🧪 Tests

```bash
python -m pytest tests/ -v      # 8 unit tests covering every detection
```
CI runs the Python tests **and** lints the PowerShell scripts on every push
(see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

---

## 🗺️ Control mapping (great for interviews)

| Toolkit feature | NIST 800-53 | SC-300 domain |
|---|---|---|
| JML provisioning / deprovisioning | AC-2 | Manage the identity lifecycle |
| Least-privilege group assignment | AC-6 | Manage access to apps |
| Access reviews / stale accounts | AC-2(3), AU-6 | Plan & implement identity governance |
| MFA / Conditional Access audit | IA-2, AC-7 | Implement authentication & CA |
| Sign-in log risk detection | AU-6, SI-4 | Monitor identity with reporting |

---

## 📁 Repository structure

```
entra-iam-toolkit/
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── scripts/                       # PowerShell IAM automation (Microsoft Graph)
│   ├── New-JmlUser.ps1
│   ├── Remove-JmlUser.ps1
│   ├── Get-AccessReview.ps1
│   └── Invoke-MfaComplianceCheck.ps1
├── src/
│   └── signin_log_analyzer.py     # Python identity threat detection
├── samples/                       # Safe, synthetic data to demo the tools
│   ├── new_hires.csv
│   └── signin_logs_sample.csv
├── tests/
│   └── test_signin_log_analyzer.py
├── docs/
│   ├── ARCHITECTURE.md
│   └── RESUME_AND_INTERVIEW.md
└── .github/workflows/ci.yml
```

---

## 🔒 Security & disclaimer

- All sample data is **synthetic** — no real credentials, tokens, or PII.
- Scripts request **only the Microsoft Graph scopes they need** (least privilege).
- Always test in a **dev / lab tenant** with `-WhatIf` before running against production.

---

## 👤 Author

**Kofi Williams** — Identity & Access Management • Security Operations
Microsoft SC-300 Certified · Toronto, ON
[LinkedIn](https://www.linkedin.com/in/kofi-williams-9b17a9319)

*If this project helped you, ⭐ the repo!*
