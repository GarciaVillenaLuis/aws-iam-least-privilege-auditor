# AWS IAM Least Privilege Auditor 🔑

Autonomous **Cloud Infrastructure Entitlement Management (CIEM)** engine analyzing AWS Identity & Access Management (IAM) permissions for enterprise multi-account architectures.

## Core Capabilities
- **Unused Permission Trimming**: Cross-references AWS CloudTrail events against IAM policy statements to identify over-permissive grants.
- **Privilege Escalation Vector Detection**: Scans for 21 known IAM privilege escalation primitives (e.g. `iam:PassRole`, `sts:AssumeRole`).
- **Baseline Matrix**: Daily CIEM metrics recorded in [`audits/iam_least_privilege_matrix.json`](./audits/iam_least_privilege_matrix.json).
