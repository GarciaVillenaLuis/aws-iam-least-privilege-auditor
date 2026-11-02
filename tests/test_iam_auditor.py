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


if __name__ == "__main__":
    unittest.main()
