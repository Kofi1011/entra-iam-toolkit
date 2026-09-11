# How to use this project to land the job

This file turns the repo into **interview ammunition**. It gives you resume
bullets, a 60-second "walk me through your project" script, and answers to the
tough questions a reviewer will ask to test whether you actually built it.

---

## 1. Resume bullets (paste under PROJECTS)

**Entra ID Identity Governance & Access Automation Toolkit** — *PowerShell, Python, Microsoft Graph*

- Built an IAM automation toolkit that provisions and deprovisions **Entra ID**
  accounts via **Microsoft Graph**, enforcing **least-privilege** group
  assignment through a role-to-group mapping model (NIST AC-2, AC-6).
- Automated the secure **leaver** playbook — account disable, **session/token
  revocation**, group removal, and password reset — with a full CSV **audit
  trail** for compliance evidence.
- Developed access-review automation that flags **stale, guest, and
  over-privileged** accounts and rates each by risk for manager certification
  (NIST AC-2(3), AU-6).
- Wrote a **Python sign-in log analyzer** that detects **password spray,
  impossible travel, new-country logins, legacy auth, and MFA gaps**, mapping
  each finding to **MITRE ATT&CK**; covered by 8 unit tests and CI.
- Audited **MFA / Conditional Access** coverage across all users and reported
  gaps against **IA-2** authentication controls.

> Tip: pick the 3 bullets closest to each job description — don't paste all five.

---

## 2. The 60-second walkthrough (memorize the shape, not the words)

> "In my Technical Specialist role I kept running into access and account
> issues, so I built a toolkit that automates how an IAM team handles them.
> It has two halves. The PowerShell half uses Microsoft Graph to run the
> joiner-mover-leaver lifecycle — onboarding new hires into least-privilege
> groups, and offboarding leavers by disabling the account, revoking their
> sessions, stripping group access, and writing an audit log. The Python half
> analyzes Entra sign-in logs to catch things like password spraying and
> impossible travel, and rates each finding by severity with a MITRE ATT&CK
> reference. Everything's tuned to reduce false positives, it's got unit tests,
> and CI runs on every push. I mapped each feature back to NIST 800-53 and the
> SC-300 objectives so I could tie it to the controls teams actually report on."

---

## 3. Tough questions & strong answers

**Q: You're a Technical Specialist, not a security analyst — why should we trust you with IAM?**
> "Fair — my title is support, but the work overlaps a lot: I already handle
> password resets, lockouts, group membership, and access validation daily. I
> built this toolkit to formalize that into the governance side — lifecycle,
> reviews, and detection — and to prove I can automate it with Graph, not just
> click through a portal. I've also got the SC-300 cert backing the concepts."

**Q: Walk me through what your leaver script does and why the order matters.**
> "Disable first so sign-in is blocked immediately, then revoke refresh tokens
> so any existing session dies, then remove group memberships to strip standing
> access, then randomize the password. Order matters because if you removed
> groups first but left the account enabled with a live token, they could still
> be active during the cleanup."

**Q: How does your impossible-travel detection avoid false positives?**
> "I ignore any pair of sign-ins under 500 km apart, because nearby cities or
> VPN egress points shouldn't trigger it. I only flag when the required speed
> between two locations exceeds ~900 km/h. I also only compare successful
> sign-ins with real geo-coordinates."

**Q: What's the difference between authentication and authorization here?**
> "Authentication is proving who you are — that's the MFA and Conditional Access
> audit side. Authorization is what you're allowed to do — that's the group and
> role mapping in provisioning and the access review. My toolkit touches both."

**Q: What would you build next?**
> "Push the analyzer findings into Microsoft Sentinel, run the access review as
> a scheduled Azure Automation runbook, and add a Mover script that recalculates
> group membership when someone changes departments." (see ARCHITECTURE.md §6)

---

## 4. Make the GitHub repo itself sell you

- [ ] Repo name: `entra-iam-toolkit` (clean, professional)
- [ ] Add topics/tags: `iam`, `entra-id`, `azure-ad`, `microsoft-graph`,
      `powershell`, `security`, `sc-300`
- [ ] Pin it on your GitHub profile
- [ ] Make sure the green **CI passing** badge shows (push to `main`)
- [ ] Record a 2-min screen capture of the analyzer + a `-WhatIf` run; link it in the README
- [ ] Put the repo URL on your resume header and LinkedIn "Featured" section

---

## 5. Roles this project targets (and why it fits)

| Role (typical $75–95K CAD) | Why this project fits |
|---|---|
| IAM Analyst I / Identity Analyst | Directly demonstrates JML, access reviews, RBAC |
| Access Management Analyst | Provisioning + least-privilege group governance |
| Junior IAM / Entra Administrator | PowerShell + Graph administration of Entra ID |
| Security Operations Analyst (identity focus) | Sign-in threat detection + MITRE mapping |
| IT Security Analyst | MFA/CA audit, NIST control mapping, log analysis |

> Honesty note: keep it truthful. This is a **personal lab project** — say so.
> "I built this in a dev tenant to learn" is a strength, not a weakness. Never
> imply it ran in production at an employer.
