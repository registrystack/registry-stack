# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = (
        Path(__file__).resolve().parents[1] / "scripts" / "check_advisory_baselines.py"
    )
    spec = importlib.util.spec_from_file_location("check_advisory_baselines", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AdvisoryBaselineCheckTest(unittest.TestCase):
    DIGEST = "sha256:" + "a" * 64
    SUBJECT = "test-image"

    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.baseline_path = Path(self.tmp.name) / "advisory-baseline.json"

    def tearDown(self):
        self.tmp.cleanup()

    def target(self, digest=None):
        digest = digest or self.DIGEST
        image = f"registry.example/test@{digest}"
        return {
            "userInput": image,
            "repoDigests": [image],
            "architecture": "amd64",
            "os": "linux",
        }

    def reports(
        self,
        *,
        vulnerability_id="CVE-2026-0001",
        package="openssl",
        installed_version="3.0.0",
        severity="High",
        fix=None,
    ):
        artifact = {
            "id": "artifact-1",
            "name": package,
            "version": installed_version,
            "type": "deb",
        }
        grype = {
            "descriptor": {"name": "grype", "version": "0.114.0"},
            "schema": {"version": "6.0.2"},
            "source": {"type": "image", "target": self.target()},
            "matches": [
                {
                    "vulnerability": {
                        "id": vulnerability_id,
                        "severity": severity,
                        "fix": fix
                        or {"versions": [], "state": "not-fixed"},
                    },
                    "artifact": copy.deepcopy(artifact),
                }
            ],
        }
        syft = {
            "descriptor": {"name": "syft", "version": "1.45.1"},
            "schema": {"version": "16.1.4"},
            "source": {"type": "image", "metadata": self.target()},
            "artifacts": [copy.deepcopy(artifact)],
        }
        return grype, syft

    def finding(self, **overrides):
        grype, syft = self.reports(**overrides)
        return self.module.normalize_grype(grype, self.SUBJECT, syft)[0]

    def exception(self, finding=None, **overrides):
        finding = finding or self.finding()
        value = {
            "vulnerability_id": finding.rule_id,
            "package": finding.package,
            "installed_version": finding.installed_version,
            "severity": finding.severity,
            "status": "accepted_risk",
            "owner": "@maintainers",
            "rationale": (
                "The affected behavior is not reachable in the reviewed deployment."
            ),
            "reviewed_at": "2026-06-02",
            "expires_at": "2026-09-01",
            "invalidation_triggers": sorted(
                self.module.REQUIRED_INVALIDATION_TRIGGERS
            ),
        }
        value.update(overrides)
        return value

    def baseline(self, exceptions=None):
        return {
            "version": 3,
            "service": "test-service",
            "policies": [
                {
                    "tool": "zizmor",
                    "minimum_severity": "high",
                    "action": "block_unreviewed",
                },
                {
                    "tool": "grype",
                    "minimum_severity": "high",
                    "action": "block_unreviewed",
                    "block_fixable": True,
                },
            ],
            "exceptions": exceptions or [],
        }

    def write_baseline(self, value):
        self.baseline_path.write_text(json.dumps(value), encoding="utf-8")
        return self.module.load_baseline(self.baseline_path)

    def check(self, findings, baseline, today="2026-06-02"):
        return self.module.check_findings(
            "grype",
            findings,
            baseline,
            self.module.parse_date(today, "today"),
        )

    def test_v3_exception_uses_only_stable_identity_and_review_fields(self):
        finding = self.finding()
        baseline = self.write_baseline(self.baseline([self.exception(finding)]))
        self.assertEqual(3, baseline["version"])
        self.assertNotIn("fingerprint", baseline["exceptions"][0])
        self.assertNotIn("runtime_base", baseline["exceptions"][0])
        self.assertNotIn("evidence_revision", baseline["exceptions"][0])
        self.assertNotIn("exposure_assertion", baseline["exceptions"][0])
        self.assertEqual(0, self.check([finding], baseline))

    def test_v3_schema_rejects_missing_or_transient_fields(self):
        exception = self.exception()
        del exception["owner"]
        with self.assertRaises(SystemExit):
            self.write_baseline(self.baseline([exception]))
        exception = self.exception()
        exception["component_layer_id"] = "sha256:" + "1" * 64
        with self.assertRaises(SystemExit):
            self.write_baseline(self.baseline([exception]))

    def test_invalidation_triggers_are_exact_and_complete(self):
        exception = self.exception()
        exception["invalidation_triggers"].remove("fix_available")
        with self.assertRaises(SystemExit):
            self.write_baseline(self.baseline([exception]))

    def test_high_or_critical_requires_review(self):
        for severity in ("High", "Critical"):
            with self.subTest(severity=severity):
                finding = self.finding(severity=severity)
                self.assertEqual(
                    1, self.check([finding], self.write_baseline(self.baseline()))
                )

    def test_below_threshold_without_fix_passes(self):
        finding = self.finding(severity="Medium")
        self.assertEqual(
            0, self.check([finding], self.write_baseline(self.baseline()))
        )

    def test_fixable_finding_cannot_be_excepted(self):
        low = self.finding(
            severity="Low",
            fix={"versions": ["3.0.1"], "state": "fixed"},
        )
        self.assertEqual(1, self.check([low], self.write_baseline(self.baseline())))
        finding = self.finding(
            severity="High",
            fix={"versions": ["3.0.1"], "state": "fixed"},
        )
        baseline = self.write_baseline(self.baseline([self.exception(finding)]))
        self.assertEqual(1, self.check([finding], baseline))

    def test_expired_and_future_dated_exceptions_fail(self):
        finding = self.finding()
        expired = self.write_baseline(
            self.baseline(
                [
                    self.exception(
                        finding,
                        reviewed_at="2026-05-01",
                        expires_at="2026-06-01",
                    )
                ]
            )
        )
        self.assertEqual(1, self.check([finding], expired))
        future = self.write_baseline(
            self.baseline([self.exception(finding, reviewed_at="2026-06-03")])
        )
        self.assertEqual(1, self.check([finding], future))

    def test_package_version_change_invalidates_exception(self):
        reviewed = self.finding()
        baseline = self.write_baseline(self.baseline([self.exception(reviewed)]))
        changed = self.finding(installed_version="3.0.1")
        self.assertEqual(1, self.check([changed], baseline))

    def test_second_installed_version_is_not_hidden_by_matching_exception(self):
        reviewed = self.finding()
        baseline = self.write_baseline(self.baseline([self.exception(reviewed)]))
        additional = self.finding(installed_version="3.0.1")
        self.assertEqual(1, self.check([reviewed, additional], baseline))

    def test_severity_change_is_a_material_change(self):
        reviewed = self.finding()
        baseline = self.write_baseline(self.baseline([self.exception(reviewed)]))
        changed = self.finding(severity="Critical")
        self.assertEqual(1, self.check([changed], baseline))

    def test_exception_for_absent_or_fixed_finding_fails(self):
        finding = self.finding()
        baseline = self.write_baseline(self.baseline([self.exception(finding)]))
        self.assertEqual(1, self.check([], baseline))

    def test_grype_and_syft_are_bound_to_same_exact_digest(self):
        grype, syft = self.reports()
        syft["source"]["metadata"] = self.target("sha256:" + "b" * 64)
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)

    def test_unpinned_image_or_wrong_platform_fails_closed(self):
        grype, syft = self.reports()
        grype["source"]["target"]["userInput"] = "registry.example/test:latest"
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)
        grype, syft = self.reports()
        syft["source"]["metadata"]["architecture"] = "arm64"
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)

    def test_incomplete_or_unsupported_scanner_reports_fail_closed(self):
        grype, syft = self.reports()
        del grype["descriptor"]
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)
        grype, syft = self.reports()
        syft["descriptor"]["name"] = "not-syft"
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)
        grype, syft = self.reports()
        syft["schema"]["version"] = "17.0.0"
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)
        grype, syft = self.reports()
        grype["matches"][0]["vulnerability"]["fix"]["state"] = "unknown"
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)

    def test_grype_package_must_match_syft_package_model(self):
        grype, syft = self.reports()
        syft["artifacts"][0]["version"] = "3.0.1"
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(grype, self.SUBJECT, syft)

    def test_historical_v2_baseline_is_still_parsed(self):
        finding = self.finding()
        legacy = self.baseline()
        legacy["version"] = 2
        legacy.pop("exceptions")
        legacy["field_semantics"] = {"historical": "ignored"}
        legacy["reviewed_findings"] = [
            {
                "tool": "grype",
                "fingerprint": finding.fingerprint,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "status": "accepted_risk",
                "owner": "@maintainers",
                "reason": "Historical reviewed finding.",
                "reviewed_at": "2026-06-02",
                "expires_at": "2026-09-01",
            }
        ]
        baseline = self.write_baseline(legacy)
        self.assertEqual(0, self.check([finding], baseline))

    def test_zizmor_high_remains_blocking(self):
        baseline = self.write_baseline(self.baseline())
        findings = self.module.normalize_zizmor(
            [
                {
                    "ident": "unpinned-uses",
                    "desc": "action is not pinned",
                    "determinations": {"severity": "High"},
                    "locations": [],
                    "ignored": False,
                }
            ]
        )
        self.assertEqual(
            1,
            self.module.check_findings(
                "zizmor",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
        )


if __name__ == "__main__":
    unittest.main()
