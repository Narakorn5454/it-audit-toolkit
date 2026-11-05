# 🧰 IT Audit Toolkit

**13 audit analytics tools for IT auditors, covering ITGC, IAM & cybersecurity, cloud, data analytics, third-party risk, privacy and AI governance.**
Test the full population instead of a sample, and get audit-ready Excel workpapers in seconds.

**ชุดเครื่องมือ 13 ตัวสำหรับผู้ตรวจสอบด้านเทคโนโลยีสารสนเทศ** ทดสอบข้อมูลทั้งประชากร 100% และออกรายงาน Excel พร้อมใช้เป็นกระดาษทำการ

🌐 **Live demo:** [it-audit-toolkit-narakorn.streamlit.app](https://it-audit-toolkit-narakorn.streamlit.app) &nbsp;·&nbsp; ✅ 19 automated tests

---

## Why this exists

IT audit is moving from sample-based testing to **continuous, data-driven assurance**, and the scope keeps widening beyond ITGC into IAM, cloud, third-party and AI risk. Most audit teams still do this work with VLOOKUPs and manual checklists. This toolkit turns the most common IT audit procedures into repeatable, documented tests that any auditor can run.
[![Home](docs/screenshot_home.png)](https://it-audit-toolkit-narakorn.streamlit.app)
## The tools

| # | Tool | What it tests | Standards |
|---|---|---|---|
| 1 | 🔍 **User Access Review** | Leavers with active accounts, orphan, dormant, shared and duplicate accounts, SoD, login after termination | ITGC, ISO 27001 A.5.18 |
| 2 | ⚖️ **SoD Analysis** | Toxic combinations **across systems** (ERP + banking + HR), roles that conflict by design, mitigating controls | COBIT DSS05, ISO 27001 A.5.3 |
| 3 | 🔄 **Change Management** | Deployments without a ticket or approval, approved after deploy, developer self-deploy, no UAT, emergency ratio | ITGC, ISO 27001 A.8.32 |
| 4 | 🕵️ **Login Anomaly Detection** | Brute force, password spraying, success after failures, impossible travel, disabled-account logins | ISO 27001 A.8.15–16, NIST CSF DE.CM |
| 5 | 🔑 **Password Policy Review** | Parses secedit, `net accounts`, AD policy, login.defs / PAM; compares against a configurable baseline | ISO 27001 A.5.17, CIS |
| 6 | 🛡️ **System Hardening** | Windows (secedit, auditpol) and Linux (sshd, passwd, sudoers) against CIS-style rules | CIS Benchmarks, ISO 27001 A.8.9 |
| 7 | ☁️ **AWS Cloud Review** | Root MFA and keys, IAM MFA, key rotation, unused credentials, open security groups, public S3, CloudTrail | CIS AWS Foundations |
| 8 | 📒 **Journal Entry Testing** | 14 risk-scored tests + **Benford's Law** + sequence gaps; SAP-ready | ISA 240 / TSA 240 |
| 9 | 🇹🇭 **PDPA Readiness** | 29 questions across 10 domains of Thailand's PDPA | PDPA s.19–42 |
| 10 | 🤝 **Vendor Risk** | Inherent → residual risk, review frequency, questionnaire round-trip | ISO 27001 A.5.19–5.23 |
| 11 | 🤖 **AI Governance** | AI policy, inventory, impact assessment, bias testing, human oversight, GenAI controls | ISO/IEC 42001, NIST AI RMF |
| 12 | 📌 **Finding Tracker** | Aging, overdue, extensions, repeat findings, follow-up emails, Audit Committee report | IIA Standards |
| 13 | 📑 **AI Policy Review** | Gap review of policy documents, with offline keyword mode or **Claude API** mode | ISO 27001 Annex A |

## Design principles

- **Full-population testing.** Every record is tested; results are ranked by risk so follow-up starts with what matters.
- **Read-only evidence collection.** `scripts/` holds collection scripts for Windows (PowerShell), Linux (shell) and AWS (CLI) that only read configuration. The auditor never needs admin access to client systems.
- **Real-world input formats.** SAP exports (BELNR, BUDAT, SHKZG…), Windows Event IDs 4624/4625, Microsoft Entra sign-in logs, AWS credential reports, Thai column headers and Buddhist-era dates (พ.ศ.).
- **Transparent scope.** Every report states which checks were performed and which were **skipped and why** (missing data), so scope limitations are visible.
- **Workpaper-ready output.** Summary, findings with risk rating and recommendation, blank columns for management response / owner / due date, plus a methodology sheet listing all parameters.
- **Configurable criteria.** Thresholds, baselines, SoD rulesets and keyword lists can all be adjusted to the organisation's own policy.

## Quick start

```bash
pip install -r requirements.txt
python -m streamlit run Home.py        # web app at http://localhost:8501
python -m pytest -q                    # run the test suite
```

Every page has a **"try with sample data"** switch, using sample data with planted anomalies so you can see results immediately.

Command line (for the first two tools):
```bash
python -m audit_tools.access_review --demo
python -m audit_tools.journal_entry --demo
```

## Project structure

```
├── Home.py                    # Landing page
├── pages/                     # One Streamlit page per tool (01–13)
├── audit_tools/               # Core logic, independent of the UI and unit-tested
│   ├── common.py              #   shared reading, parsing, Excel reporting
│   ├── access_review.py  sod.py  change_mgmt.py  login_anomaly.py
│   ├── password_policy.py  hardening.py  cloud_aws.py  journal_entry.py
│   ├── assessment.py  assessment_banks.py   # questionnaire engine + PDPA/Vendor/AI banks
│   ├── finding_tracker.py  policy_review.py
│   └── config.py              #   author details shown in the app
├── scripts/                   # Read-only collection scripts (Windows / Linux / AWS)
├── sample_data/               # Sample inputs for every tool
└── tests/                     # pytest suite (19 tests)
```

The audit logic in `audit_tools/` has no dependency on Streamlit, so it can be reused in notebooks, scheduled jobs or another UI.

## Data handling

Uploaded files are processed in memory and not stored. The public demo is meant for **sample data only**; for real client data, run the toolkit locally. AI Policy Review sends document text to the Claude API **only** when AI mode is selected and an API key is provided.

## Limitations

Results are indicators that support, but do not replace, professional judgment. Baselines are "CIS-style" selections and should be aligned with the benchmark version and organisational policy in use. The sample 2026 holiday calendar lists fixed-date holidays only. Keyword mode in policy review is a screening aid.

## About the author

Built by **[Your Name]**, IT Auditor with experience in ITGC, IT risk and compliance.
💼 [LinkedIn](www.linkedin.com/in/narakorn-poomsuwan-4261052b2) · ✉️ [narakornpoomsuwan@gmail.com]

---
© 2026 Narakorn Poomsuwan. Source available for evaluation; commercial use requires permission (see LICENSE).
