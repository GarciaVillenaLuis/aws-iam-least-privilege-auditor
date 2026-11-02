# AWS IAM Least Privilege Auditor 🔑

[![CIEM Engine](https://img.shields.io/badge/CIEM%20Engine-v1.8%20Active-brightgreen?style=flat-square&logo=amazoniam&logoColor=white)](https://github.com/GarciaVillenaLuis/aws-iam-least-privilege-auditor)
[![Hygiene Score](https://img.shields.io/badge/Credential%20Hygiene-97.8%2F100-blue?style=flat-square&logo=securityscorecard&logoColor=white)](https://github.com/GarciaVillenaLuis/aws-iam-least-privilege-auditor)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1078.004%20%7C%20T1098-orange?style=flat-square)](https://attack.mitre.org/)

Autonomous **Cloud Infrastructure Entitlement Management (CIEM)** and IAM governance engine detecting privilege escalation risks, wildcard actions, and overprivileged identities across AWS enterprise accounts.

Engineered and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## ⚡ Recognized Escalation Vectors & CIEM Capabilities

This engine scans IAM policies against **21 known AWS privilege escalation primitives** documented by Rhino Security Labs and aligned with MITRE ATT&CK:

| Primitive Action | Escalation Mechanism | Severity |
| :--- | :--- | :---: |
| `iam:CreatePolicyVersion` | Creates new policy version granting admin and alters default flag | **CRITICAL** |
| `iam:SetDefaultPolicyVersion` | Reverts to historical overprivileged policy version | **CRITICAL** |
| `iam:PassRole` + `ec2:RunInstances` | Launches compute instance bearing high-privilege IAM instance profile | **CRITICAL** |
| `iam:AttachUserPolicy` | Directly attaches `AdministratorAccess` to requesting identity | **CRITICAL** |
| `iam:PutUserPolicy` / `PutRolePolicy` | Injects inline JSON statement with full wildcard rights | **CRITICAL** |
| `iam:CreateAccessKey` | Spawns programmatic API credentials for unmonitored admin principals | **CRITICAL** |
| `lambda:CreateFunction` + `PassRole` | Executes arbitrary lambda container utilizing elevated service role | **HIGH** |
| `iam:UpdateAssumeRolePolicy` | Manipulates trust policy to permit lateral takeover | **CRITICAL** |

---

## 🚀 Quick Start & CLI Usage

### Requirements
- Python 3.9+ (Standard Library only)

### Available Flags & Parameters

```bash
python iam_auditor.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--policy FILE` | `string` | Path to AWS IAM policy JSON document to scan |
| `--matrix FILE` | `string` | Display repository governance telemetry (`audits/iam_least_privilege_matrix.json`) |
| `--remediate` | `flag` | Automatically synthesize a hardened, least-privilege replacement policy |
| `--fail-on-critical` | `flag` | Return exit code 1 if CRITICAL privilege escalation paths are identified |
| `--format FMT` | `choice` | Output format: `table` (default) or `json` |
| `--output FILE` | `string` | Export scan report or synthesized policy to disk |

---

## 💻 Usage Examples

### 1. Scan a vulnerable IAM policy document
```bash
python iam_auditor.py --policy samples/vulnerable_iam_policy.json
```
**Sample Output:**
```text
==========================================================================
   AWS IAM CIEM LEAST-PRIVILEGE SECURITY AUDIT REPORT
==========================================================================
Policy Target:       samples/vulnerable_iam_policy.json
Total Findings:      3
Critical Escalations:3
--------------------------------------------------------------------------
+----------------------+-----------------+----------+---------------------------+----------------------------+
| Policy               | Sid             | Severity | Category                  | Offending Action           |
+----------------------+-----------------+----------+---------------------------+----------------------------+
| vulnerable_iam_polic | DangerousWildca | CRITICAL | Full Admin Wildcard (*:*) | *                          |
| vulnerable_iam_polic | PrivilegeEscala | CRITICAL | Privilege Escalation Vect | iam:CreatePolicyVersion    |
| vulnerable_iam_polic | PrivilegeEscala | CRITICAL | Privilege Escalation Vect | iam:SetDefaultPolicyVersion|
+----------------------+-----------------+----------+---------------------------+----------------------------+
==========================================================================
```

### 2. Synthesize an automated least-privilege remediation policy
```bash
python iam_auditor.py --policy samples/vulnerable_iam_policy.json --remediate -o hardened_policy.json
```

### 3. CI/CD Pipeline Enforcement Gate
```bash
python iam_auditor.py --policy deploy_policy.json --fail-on-critical
```

---

## 🧪 Unit Testing

Run the automated test suite with standard `unittest`:

```bash
python -m unittest tests/test_iam_auditor.py
```

---

## 📊 CIEM Telemetry Matrix

Continuous account scanning and credential hygiene metrics are published in:
- [`audits/iam_least_privilege_matrix.json`](./audits/iam_least_privilege_matrix.json)
