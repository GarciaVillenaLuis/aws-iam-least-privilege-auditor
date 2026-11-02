#!/usr/bin/env python3
"""
Unit tests for AWS IAM Least Privilege Auditor.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from iam_auditor import IAMAuditor, format_iam_table


class TestIAMAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = IAMAuditor()

    def test_detect_full_wildcard_admin(self):
        doc = {
            "Statement": [
                {
                    "Sid": "AllowAll",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        findings = self.auditor.audit_policy_document(doc)
        criticals = [f for f in findings if f.severity == "CRITICAL"]
        self.assertGreaterEqual(len(criticals), 1)
        self.assertTrue(any("Full Admin Wildcard" in f.category for f in criticals))

    def test_detect_privilege_escalation_primitive(self):
        doc = {
            "Statement": [
                {
                    "Sid": "CreateVersion",
                    "Effect": "Allow",
                    "Action": "iam:CreatePolicyVersion",
                    "Resource": "*"
                }
            ]
        }
        findings = self.auditor.audit_policy_document(doc)
        esc = [f for f in findings if f.action == "iam:CreatePolicyVersion"]
        self.assertEqual(len(esc), 1)
        self.assertEqual(esc[0].severity, "CRITICAL")

    def test_hardened_policy_has_zero_findings(self):
        doc = {
            "Statement": [
                {
                    "Sid": "ReadOnly",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::mybucket/*"],
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
                }
            ]
        }
        findings = self.auditor.audit_policy_document(doc)
        self.assertEqual(len(findings), 0)

    def test_remediation_policy_generation(self):
        doc = {
            "Statement": [
                {
                    "Sid": "Unsafe",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        remediated = self.auditor.generate_remediation_policy(doc)
        remediated_stmts = remediated["Statement"]
        self.assertNotIn("*", remediated_stmts[0]["Action"])
        self.assertIn("aws:MultiFactorAuthPresent", str(remediated_stmts[0].get("Condition")))

    def test_catalog_has_21_vectors(self):
        from iam_auditor import PRIVILEGE_ESCALATION_VECTORS
        self.assertEqual(len(PRIVILEGE_ESCALATION_VECTORS), 21)

    def test_detect_false_mfa_condition(self):
        doc = {
            "Statement": [
                {
                    "Sid": "BypassMFAAttempt",
                    "Effect": "Allow",
                    "Action": "iam:AttachUserPolicy",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
                }
            ]
        }
        findings = self.auditor.audit_policy_document(doc)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].action, "iam:AttachUserPolicy")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_detect_wildcard_service_escalation(self):
        doc = {
            "Statement": [
                {
                    "Sid": "WildcardIAM",
                    "Effect": "Allow",
                    "Action": "iam:*",
                    "Resource": "*"
                }
            ]
        }
        findings = self.auditor.audit_policy_document(doc)
        escalation_findings = [f for f in findings if f.category == "Privilege Escalation Vector"]
        # iam:* must trigger all iam:* escalation primitives (e.g., CreatePolicyVersion, AttachUserPolicy, etc.)
        self.assertGreaterEqual(len(escalation_findings), 10)

    def test_detect_notaction_grant(self):
        doc = {
            "Statement": [
                {
                    "Sid": "AllowNotAction",
                    "Effect": "Allow",
                    "NotAction": ["iam:*"],
                    "Resource": "*"
                }
            ]
        }
        findings = self.auditor.audit_policy_document(doc)
        notaction_findings = [f for f in findings if f.category == "Overpermissive NotAction Grant"]
        self.assertEqual(len(notaction_findings), 1)


if __name__ == "__main__":
    unittest.main()
