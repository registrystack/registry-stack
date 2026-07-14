# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_advisory_baselines.py"
    spec = importlib.util.spec_from_file_location("check_advisory_baselines", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AdvisoryBaselineCheckTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "security").mkdir()
        self.baseline_path = self.root / "security" / "advisory-baseline.json"

    def tearDown(self):
        self.tmp.cleanup()

    def write_baseline(self, reviewed=None):
        self.baseline_path.write_text(json.dumps({
            "version": 1,
            "service": "test-service",
            "policies": [
                {
                    "tool": "zizmor",
                    "minimum_severity": "high",
                    "action": "block_unreviewed",
                },
                {
                    "tool": "grype",
                    "minimum_severity": "critical",
                    "action": "block_unreviewed",
                },
            ],
            "reviewed_findings": reviewed or [],
        }))

    def zizmor_report(self, severity="High"):
        return [{
            "ident": "unpinned-uses",
            "desc": "action is not pinned",
            "determinations": {"severity": severity, "confidence": "High"},
            "locations": [{
                "symbolic": {
                    "key": {"Local": {"given_path": "./.github/workflows/ci.yml"}},
                    "annotation": "action is not pinned",
                    "route": {
                        "route": [
                            {"Key": "jobs"},
                            {"Key": "test"},
                            {"Key": "steps"},
                            {"Index": 0},
                            {"Key": "uses"},
                        ]
                    },
                },
                "concrete": {"feature": "actions/checkout@v6"},
            }],
            "ignored": False,
        }]

    def review(self, finding, **overrides):
        base = {
            "tool": finding.tool,
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "status": "accepted_risk",
            "owner": "@PublicSchema/maintainers",
            "reason": "Reviewed existing advisory signal for ratchet baseline.",
            "reviewed_at": "2026-06-02",
            "expires_at": "2026-09-01",
        }
        base.update(overrides)
        return base

    def test_unreviewed_zizmor_high_fails(self):
        self.write_baseline()
        baseline = self.module.load_baseline(self.baseline_path)
        findings = self.module.normalize_zizmor(self.zizmor_report())
        self.assertEqual(
            self.module.check_findings(
                "zizmor",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            1,
        )

    def test_reviewed_zizmor_high_passes_until_expiration(self):
        finding = self.module.normalize_zizmor(self.zizmor_report())[0]
        self.write_baseline([self.review(finding)])
        baseline = self.module.load_baseline(self.baseline_path)
        self.assertEqual(
            self.module.check_findings(
                "zizmor",
                [finding],
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            0,
        )

    def test_expired_review_fails_even_when_fingerprint_matches(self):
        finding = self.module.normalize_zizmor(self.zizmor_report())[0]
        self.write_baseline([self.review(finding, expires_at="2026-06-01")])
        baseline = self.module.load_baseline(self.baseline_path)
        self.assertEqual(
            self.module.check_findings(
                "zizmor",
                [finding],
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            1,
        )

    def test_expired_stale_review_does_not_block(self):
        stale_finding = self.module.normalize_zizmor(self.zizmor_report())[0]
        active_finding = self.module.normalize_zizmor(self.zizmor_report(severity="Medium"))[0]
        self.write_baseline([self.review(stale_finding, expires_at="2026-06-01")])
        baseline = self.module.load_baseline(self.baseline_path)
        self.assertEqual(
            self.module.check_findings(
                "zizmor",
                [active_finding],
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            0,
        )

    def test_zizmor_medium_is_below_initial_threshold(self):
        self.write_baseline()
        baseline = self.module.load_baseline(self.baseline_path)
        findings = self.module.normalize_zizmor(self.zizmor_report(severity="Medium"))
        self.assertEqual(
            self.module.check_findings(
                "zizmor",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            0,
        )

    def test_zizmor_uses_primary_location_for_fingerprint(self):
        def report_for_step(index):
            return {
                "ident": "cache-poisoning",
                "desc": "runtime artifacts potentially vulnerable to cache poisoning",
                "determinations": {"severity": "High", "confidence": "Low"},
                "locations": [
                    {
                        "symbolic": {
                            "key": {"Local": {"given_path": "./.github/workflows/ci.yml"}},
                            "annotation": "shared related trigger",
                            "route": {"route": [{"Key": "on"}]},
                            "kind": "Related",
                        },
                        "concrete": {"feature": "on: pull_request"},
                    },
                    {
                        "symbolic": {
                            "key": {"Local": {"given_path": "./.github/workflows/ci.yml"}},
                            "annotation": "enables caching by default",
                            "route": {
                                "route": [
                                    {"Key": "jobs"},
                                    {"Key": "test"},
                                    {"Key": "steps"},
                                    {"Index": index},
                                    {"Key": "uses"},
                                ]
                            },
                            "kind": "Primary",
                        },
                        "concrete": {"feature": f"cache step {index}"},
                    },
                ],
                "ignored": False,
            }

        findings = self.module.normalize_zizmor([report_for_step(1), report_for_step(2)])
        self.assertNotEqual(findings[0].fingerprint, findings[1].fingerprint)
        self.assertIn("i:1", findings[0].fingerprint)
        self.assertIn("i:2", findings[1].fingerprint)

    def test_zizmor_null_determinations_defaults_to_informational(self):
        self.write_baseline()
        baseline = self.module.load_baseline(self.baseline_path)
        report = self.zizmor_report()
        report[0]["determinations"] = None
        findings = self.module.normalize_zizmor(report)
        self.assertEqual(findings[0].severity, "informational")
        self.assertEqual(
            self.module.check_findings(
                "zizmor",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            0,
        )

    def test_zizmor_null_route_does_not_crash(self):
        report = self.zizmor_report()
        report[0]["locations"][0]["symbolic"]["route"] = {"route": None}
        finding = self.module.normalize_zizmor(report)[0]
        self.assertIn("zizmor|unpinned-uses|.github/workflows/ci.yml||", finding.fingerprint)

    def test_grype_critical_requires_review(self):
        self.write_baseline()
        baseline = self.module.load_baseline(self.baseline_path)
        report = {
            "matches": [{
                "vulnerability": {"id": "CVE-2026-0001", "severity": "Critical"},
                "artifact": {
                    "name": "openssl",
                    "version": "3.0.0",
                    "type": "deb",
                },
            }]
        }
        findings = self.module.normalize_grype(report, "registry-notary-image")
        self.assertEqual(
            self.module.check_findings(
                "grype",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            1,
        )

    def test_grype_unknown_severity_is_below_initial_threshold(self):
        self.write_baseline()
        baseline = self.module.load_baseline(self.baseline_path)
        report = {
            "matches": [{
                "vulnerability": {"id": "CVE-2026-0002", "severity": "Unknown"},
                "artifact": {
                    "name": "openssl",
                    "version": "3.0.0",
                    "type": "deb",
                },
            }]
        }
        findings = self.module.normalize_grype(report, "registry-notary-image")
        self.assertEqual(
            self.module.check_findings(
                "grype",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            0,
        )

    def test_grype_undefined_severity_is_below_initial_threshold(self):
        self.write_baseline()
        baseline = self.module.load_baseline(self.baseline_path)
        report = {
            "matches": [{
                "vulnerability": {"id": "CVE-2026-0003", "severity": "Undefined"},
                "artifact": {
                    "name": "openssl",
                    "version": "3.0.0",
                    "type": "deb",
                },
            }]
        }
        findings = self.module.normalize_grype(report, "registry-notary-image")
        self.assertEqual(
            self.module.check_findings(
                "grype",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            0,
        )

    def test_grype_review_scope_ignores_other_image_subjects(self):
        other_image_finding = self.module.Finding(
            tool="grype",
            fingerprint="grype|unrelated-image|CVE-2026-0004|zlib1g|1.0|deb",
            rule_id="CVE-2026-0004",
            severity="critical",
            location="unrelated-image",
            summary="CVE-2026-0004 in zlib1g 1.0",
        )
        self.write_baseline([self.review(other_image_finding)])
        baseline = self.module.load_baseline(self.baseline_path)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = self.module.check_findings(
                "grype",
                [],
                baseline,
                self.module.parse_date("2026-06-02", "today"),
                "registry-notary-image",
            )
        self.assertEqual(result, 0)
        self.assertIn("reviewed=0", stdout.getvalue())
        self.assertIn("stale=0", stdout.getvalue())

    def test_malformed_review_entry_fails_baseline_load(self):
        self.baseline_path.write_text(json.dumps({
            "version": 1,
            "policies": [
                {
                    "tool": "zizmor",
                    "minimum_severity": "high",
                    "action": "block_unreviewed",
                }
            ],
            "reviewed_findings": [{"tool": "zizmor"}],
        }))
        with self.assertRaises(SystemExit):
            self.module.load_baseline(self.baseline_path)

    def test_duplicate_review_fingerprint_fails_baseline_load(self):
        finding = self.module.normalize_zizmor(self.zizmor_report())[0]
        review = self.review(finding)
        self.write_baseline([review, dict(review)])
        with self.assertRaises(SystemExit):
            self.module.load_baseline(self.baseline_path)

    def test_review_string_fields_must_be_non_blank_strings(self):
        finding = self.module.normalize_zizmor(self.zizmor_report())[0]
        for field, value in (
            ("fingerprint", None),
            ("owner", ""),
            ("reason", "   "),
        ):
            with self.subTest(field=field):
                self.write_baseline([self.review(finding, **{field: value})])
                with self.assertRaises(SystemExit):
                    self.module.load_baseline(self.baseline_path)


if __name__ == "__main__":
    unittest.main()
