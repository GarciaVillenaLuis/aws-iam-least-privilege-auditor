#!/usr/bin/env python3
"""
AWS IAM Least Privilege Auditor & CIEM Privilege Escalation Detector.

Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
License: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set

# Recognized IAM Privilege Escalation Primitives (Rhino Security / Bishop Fox / MITRE ATT&CK T1078.004 & T1098)
PRIVILEGE_ESCALATION_VECTORS: Dict[str, Dict[str, Any]] = {
    "iam:CreatePolicyVersion": {
        "name": "Create Policy Version & Alter Defaults",
        "severity": "CRITICAL",
        "description": "Allows creating a new policy version with admin permissions and setting it as default."
    },
    "iam:SetDefaultPolicyVersion": {
        "name": "Set Default Policy Version",
        "severity": "CRITICAL",
        "description": "Allows switching to an older, dormant, over-permissive policy version."
    },
    "iam:PassRole": {
        "name": "PassRole to Compute Services",
        "severity": "HIGH",
        "description": "Allows passing high-privilege roles to EC2/Lambda to execute arbitrary code with elevated credentials."
    },
    "iam:AttachUserPolicy": {
        "name": "Attach Policy to Current User",
        "severity": "CRITICAL",
        "description": "Enables attaching AdministratorAccess or any existing policy directly to user."
    },
    "iam:AttachRolePolicy": {
        "name": "Attach Policy to Accessible Role",
        "severity": "CRITICAL",
        "description": "Allows escalating permissions on any assumable IAM role."
    },
    "iam:AttachGroupPolicy": {
        "name": "Attach Policy to User Group",
        "severity": "HIGH",
        "description": "Attaches high-privilege policies to a group the user belongs to."
    },
    "iam:PutUserPolicy": {
        "name": "Put Inline User Policy",
        "severity": "CRITICAL",
        "description": "Allows injecting custom inline policy granting AdministratorAccess."
    },
    "iam:PutRolePolicy": {
        "name": "Put Inline Role Policy",
        "severity": "CRITICAL",
        "description": "Allows injecting custom inline policy into target role."
    },
    "iam:CreateAccessKey": {
        "name": "Create Access Key for Another User",
        "severity": "CRITICAL",
        "description": "Enables generating secret access keys for administrative users without active credentials."
    },
    "iam:CreateLoginProfile": {
        "name": "Create Console Login Profile",
        "severity": "HIGH",
        "description": "Allows creating AWS Management Console passwords for users lacking console access."
    },
    "iam:UpdateLoginProfile": {
        "name": "Reset Console Login Profile",
        "severity": "HIGH",
        "description": "Allows resetting passwords of existing administrator accounts."
    },
    "iam:UpdateAssumeRolePolicy": {
        "name": "Alter Trust Relationship Policy",
        "severity": "CRITICAL",
        "description": "Allows modifying role trust relationship to allow current user to assume it."
    },
    "lambda:CreateFunction": {
        "name": "Create Lambda with Elevated Role",
        "severity": "HIGH",
        "description": "Enables creating Lambda function attached to admin role to run arbitrary escalation code."
    },
    "glue:CreateDevEndpoint": {
        "name": "Create Glue Dev Endpoint with Role",
        "severity": "HIGH",
        "description": "Allows creating AWS Glue development endpoint attached to high-privilege role."
    },
    "cloudformation:CreateStack": {
        "name": "Create CloudFormation Stack with Role",
        "severity": "HIGH",
        "description": "Deploys CloudFormation stack utilizing an existing role to create admin resources."
    }
}


@dataclass
class Finding:
    category: str
    severity: str
    policy_name: str
    statement_sid: str
    action: str
    resource: str
    description: str
    remediation: str


class IAMAuditor:
    """CIEM engine inspecting AWS IAM policy documents for least-privilege violations."""

    def __init__(self):
        self.findings: List[Finding] = []

    def audit_policy_document(self, doc: Dict[str, Any], policy_name: str = "InlinePolicy") -> List[Finding]:
        """Audits a parsed IAM policy statement array."""
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        findings: List[Finding] = []

        for stmt in statements:
            effect = stmt.get("Effect", "")
            if effect != "Allow":
                continue

            sid = stmt.get("Sid", "UnnamedStatement")
            raw_actions = stmt.get("Action", [])
            if isinstance(raw_actions, str):
                actions = [raw_actions]
            else:
                actions = list(raw_actions)

            raw_resources = stmt.get("Resource", [])
            if isinstance(raw_resources, str):
                resources = [raw_resources]
            else:
                resources = list(raw_resources)

            has_star_resource = "*" in resources

            # 1. Detect Wildcard Permissions
            for act in actions:
                act_lower = act.lower()
                if act == "*" and has_star_resource:
                    findings.append(Finding(
                        category="Full Admin Wildcard (*:*)",
                        severity="CRITICAL",
                        policy_name=policy_name,
                        statement_sid=sid,
                        action=act,
                        resource="*",
                        description="Statement grants unrestricted Action=* on Resource=*, equivalent to full AdministratorAccess.",
                        remediation="Decompose statement into specific least-privilege actions scoped to exact ARN resources."
                    ))
                elif act_lower.endswith(":*") and has_star_resource:
                    findings.append(Finding(
                        category="Service-Level Wildcard",
                        severity="HIGH",
                        policy_name=policy_name,
                        statement_sid=sid,
                        action=act,
                        resource="*",
                        description=f"Statement grants complete control over service ({act}) on all resources.",
                        remediation=f"Specify explicit APIs (e.g., '{act.split(':')[0]}:GetObject') rather than wildcards."
                    ))

            # 2. Detect Privilege Escalation Primitives
            for act in actions:
                for prim, meta in PRIVILEGE_ESCALATION_VECTORS.items():
                    if act == "*" or act.lower() == prim.lower():
                        # Check conditions
                        conditions = stmt.get("Condition", {})
                        has_mfa = "aws:MultiFactorAuthPresent" in str(conditions)
                        if not has_mfa:
                            findings.append(Finding(
                                category="Privilege Escalation Vector",
                                severity=meta["severity"],
                                policy_name=policy_name,
                                statement_sid=sid,
                                action=prim,
                                resource=", ".join(resources),
                                description=f"{meta['name']}: {meta['description']}",
                                remediation="Remove action or restrict to specific bounded ARN with mandatory MFA condition."
                            ))

        self.findings.extend(findings)
        return findings

    def generate_remediation_policy(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a trimmed, least-privilege version of the policy document."""
        new_doc = json.loads(json.dumps(doc))
        statements = new_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        trimmed_stmts = []
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                trimmed_stmts.append(stmt)
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # Replace full wildcard with read-only/audit safe actions
            refined_actions = []
            for a in actions:
                if a == "*":
                    refined_actions.extend(["ec2:Describe*", "s3:ListBucket", "s3:GetObject"])
                elif a == "iam:*":
                    refined_actions.extend(["iam:Get*", "iam:List*"])
                elif a in PRIVILEGE_ESCALATION_VECTORS:
                    # Omit high-risk escalation actions unless condition present
                    continue
                else:
                    refined_actions.append(a)

            stmt["Action"] = refined_actions if refined_actions else ["s3:GetObject"]
            if stmt.get("Resource") == "*":
                stmt["Resource"] = "arn:aws:s3:::example-restricted-bucket/*"

            # Add MFA condition
            stmt.setdefault("Condition", {})["Bool"] = {"aws:MultiFactorAuthPresent": "true"}
            trimmed_stmts.append(stmt)

        new_doc["Statement"] = trimmed_stmts
        return new_doc


def format_iam_table(findings: List[Finding]) -> str:
    """Format ASCII report table."""
    if not findings:
        return "No least-privilege or privilege escalation findings detected. Policy is well hardened."

    headers = ["Policy", "Sid", "Severity", "Category", "Offending Action"]
    rows = []
    for f in findings:
        rows.append([f.policy_name[:20], f.statement_sid[:15], f.severity, f.category[:25], f.action])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(val)))

    line_sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_str = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"

    output = [line_sep, header_str, line_sep]
    for row in rows:
        row_str = "| " + " | ".join(str(val).ljust(col_widths[i]) for i, val in enumerate(row)) + " |"
        output.append(row_str)
    output.append(line_sep)
    return "\n".join(output)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AWS IAM Least Privilege Auditor & CIEM Privilege Escalation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python iam_auditor.py --policy samples/vulnerable_iam_policy.json
  python iam_auditor.py --matrix audits/iam_least_privilege_matrix.json
  python iam_auditor.py --policy samples/vulnerable_iam_policy.json --remediate
  python iam_auditor.py --policy samples/vulnerable_iam_policy.json --fail-on-critical
        """
    )
    parser.add_argument("--policy", "-p", type=str, help="Path to AWS IAM policy JSON file to scan")
    parser.add_argument("--matrix", "-m", type=str, help="Path to repository iam_least_privilege_matrix.json")
    parser.add_argument("--remediate", action="store_true", help="Generate least-privilege remediation JSON policy")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit code 1 if CRITICAL findings exist")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--output", "-o", type=str, help="Write output to file")

    args = parser.parse_args()
    auditor = IAMAuditor()

    if args.matrix:
        if not os.path.exists(args.matrix):
            sys.stderr.write(f"[ERROR] Matrix file '{args.matrix}' not found.\n")
            sys.exit(1)
        with open(args.matrix, "r", encoding="utf-8") as f:
            matrix_data = json.load(f)
        print("==========================================================================")
        print("   AWS IAM CIEM LEAST PRIVILEGE TELEMETRY MATRIX")
        print("==========================================================================")
        print(f"Engine:                    {matrix_data.get('engine')}")
        print(f"Accounts Scanned:          {matrix_data.get('accounts_scanned')}")
        print(f"Identities Analyzed:       {matrix_data.get('identities_analyzed')}")
        metrics = matrix_data.get("metrics", {})
        print(f"Overprivileged Roles:      {metrics.get('overprivileged_roles_detected')}")
        print(f"Wildcard Grants (*:*):     {metrics.get('wildcard_action_grants')}")
        print(f"MFA Enforcement Ratio:     {metrics.get('mfa_enforcement_ratio')}")
        print(f"Credential Hygiene Score:  {metrics.get('credential_hygiene_score')}/100")
        print("==========================================================================")
        sys.exit(0)

    policy_file = args.policy or "samples/vulnerable_iam_policy.json"
    if not os.path.exists(policy_file):
        sys.stderr.write(f"[ERROR] Policy file '{policy_file}' not found.\n")
        sys.exit(1)

    with open(policy_file, "r", encoding="utf-8") as f:
        policy_json = json.load(f)

    if args.remediate:
        remediated = auditor.generate_remediation_policy(policy_json)
        out_str = json.dumps(remediated, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_str + "\n")
            print(f"[SUCCESS] Remediated policy written to {args.output}")
        else:
            print(out_str)
        sys.exit(0)

    findings = auditor.audit_policy_document(policy_json, policy_name=os.path.basename(policy_file))
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")

    if args.format == "json":
        out_str = json.dumps([asdict(f) for f in findings], indent=2)
    else:
        table_str = format_iam_table(findings)
        lines = [
            "==========================================================================",
            "   AWS IAM CIEM LEAST-PRIVILEGE SECURITY AUDIT REPORT",
            "==========================================================================",
            f"Policy Target:       {policy_file}",
            f"Total Findings:      {len(findings)}",
            f"Critical Escalations:{critical_count}",
            "--------------------------------------------------------------------------",
            table_str,
            "=========================================================================="
        ]
        out_str = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_str + "\n")
        print(f"[SUCCESS] Report saved to {args.output}")
    else:
        print(out_str)

    if args.fail_on_critical and critical_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
