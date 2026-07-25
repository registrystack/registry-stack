# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
import struct
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
    TEST_IMAGE_DIGEST = "sha256:" + "a" * 64
    TEST_REVISION = "b" * 40
    BASE_LAYER_1 = "sha256:" + "1" * 64
    BASE_LAYER_2 = "sha256:" + "2" * 64
    APP_LAYER = "sha256:" + "3" * 64
    SUBJECT = "test-image"

    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.baseline_path = self.root / "advisory-baseline.json"
        self.rootfs = self.root / "rootfs"
        self.rootfs.mkdir()
        self.write_elf("/app/service")

    def tearDown(self):
        self.tmp.cleanup()

    def write_elf(self, image_path, undefined=(), needed=(), runpaths=()):
        path = self.rootfs / image_path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        strings = bytearray(b"\0")

        def add_string(value):
            offset = len(strings)
            strings.extend(value.encode() + b"\0")
            return offset

        symbol_offsets = [add_string(symbol) for symbol in undefined]
        needed_offsets = [add_string(library) for library in needed]
        runpath_offset = add_string(":".join(runpaths)) if runpaths else None
        symbols = bytearray(b"\0" * 24)
        for offset in symbol_offsets:
            symbols.extend(struct.pack("<IBBHQQ", offset, 0x12, 0, 0, 0, 0))
        dynamic = bytearray()
        for offset in needed_offsets:
            dynamic.extend(struct.pack("<qQ", 1, offset))
        if runpath_offset is not None:
            dynamic.extend(struct.pack("<qQ", 29, runpath_offset))
        dynamic.extend(struct.pack("<qQ", 0, 0))

        header_size = 64
        string_offset = header_size
        symbol_offset = (string_offset + len(strings) + 7) & ~7
        dynamic_offset = (symbol_offset + len(symbols) + 7) & ~7
        section_offset = (dynamic_offset + len(dynamic) + 7) & ~7
        section_count = 4
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
        header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident,
            3,
            62,
            1,
            0,
            0,
            section_offset,
            0,
            header_size,
            0,
            0,
            64,
            section_count,
            0,
        )
        data = bytearray(header)
        data.extend(strings)
        data.extend(b"\0" * (symbol_offset - len(data)))
        data.extend(symbols)
        data.extend(b"\0" * (dynamic_offset - len(data)))
        data.extend(dynamic)
        data.extend(b"\0" * (section_offset - len(data)))
        section_header = "<IIQQQQIIQQ"
        data.extend(struct.pack(section_header, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        data.extend(
            struct.pack(
                section_header,
                0,
                3,
                0,
                0,
                string_offset,
                len(strings),
                0,
                0,
                1,
                0,
            )
        )
        data.extend(
            struct.pack(
                section_header,
                0,
                11,
                0,
                0,
                symbol_offset,
                len(symbols),
                1,
                0,
                8,
                24,
            )
        )
        data.extend(
            struct.pack(
                section_header,
                0,
                6,
                0,
                0,
                dynamic_offset,
                len(dynamic),
                1,
                0,
                8,
                16,
            )
        )
        path.write_bytes(data)
        return path

    def report(
        self,
        severity="High",
        fix=None,
        image_digest=None,
        revision=None,
        base_layers=None,
        app_layer=None,
        component_layer=None,
        locations=True,
    ):
        image_digest = image_digest or self.TEST_IMAGE_DIGEST
        revision = revision or self.TEST_REVISION
        base_layers = base_layers or [self.BASE_LAYER_1, self.BASE_LAYER_2]
        app_layer = app_layer or self.APP_LAYER
        component_layer = component_layer or base_layers[0]
        image_ref = f"registry.example/test@{image_digest}"
        vulnerability = {
            "id": "CVE-2026-0001",
            "severity": severity,
            "fix": (fix if fix is not None else {"versions": [], "state": "not-fixed"}),
        }
        artifact = {
            "id": "artifact-1",
            "name": "openssl",
            "version": "3.0.0",
            "type": "deb",
        }
        if locations:
            artifact["locations"] = [
                {
                    "path": "/var/lib/dpkg/status.d/openssl",
                    "layerID": component_layer,
                    "accessPath": "/var/lib/dpkg/status.d/openssl",
                    "annotations": {"evidence": "primary"},
                }
            ]
        return {
            "source": {
                "type": "image",
                "target": {
                    "userInput": image_ref,
                    "repoDigests": [image_ref],
                    "architecture": "amd64",
                    "os": "linux",
                    "layers": [
                        {"digest": layer} for layer in [*base_layers, app_layer]
                    ],
                    "labels": {
                        "org.opencontainers.image.revision": revision,
                    },
                },
            },
            "matches": [{"vulnerability": vulnerability, "artifact": artifact}],
        }

    def syft_report(self, report):
        target = copy.deepcopy(report["source"]["target"])
        return {
            "source": {"type": "image", "metadata": target},
            "artifacts": [copy.deepcopy(report["matches"][0]["artifact"])],
            "files": [
                {
                    "location": {
                        "path": "/app/service",
                        "layerID": target["layers"][-1]["digest"],
                    },
                    "digests": None,
                }
            ],
        }

    def finding(self, report=None):
        report = report or self.report()
        return self.module.normalize_grype(
            report, self.SUBJECT, self.syft_report(report)
        )[0]

    def file_assertion(self, digest=None):
        digest = (
            digest
            or self.module.hashlib.sha256(
                (self.rootfs / "app/service").read_bytes()
            ).hexdigest()
        )
        assertion = {
            "kind": "file_digest_equals",
            "files": [
                {
                    "path": "/app/service",
                    "sha256": f"sha256:{digest}",
                }
            ],
        }
        assertion["definition_digest"] = self.module.assertion_definition_digest(
            assertion
        )
        return assertion

    def dynamic_assertion(self, symbols=None):
        assertion = {
            "kind": "dynamic_symbol_absent",
            "executables": ["/app/service"],
            "symbols": symbols or ["ungetwc"],
        }
        assertion["definition_digest"] = self.module.assertion_definition_digest(
            assertion
        )
        return assertion

    def package_assertion(self):
        assertion = {
            "kind": "package_absent_from_executable_closure",
            "executables": ["/app/service"],
            "package": "libblocked",
        }
        assertion["definition_digest"] = self.module.assertion_definition_digest(
            assertion
        )
        return assertion

    def review(self, finding, assertion=None, **overrides):
        base = {
            "tool": finding.tool,
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "status": "accepted_risk",
            "component_layer_id": finding.component_layer_id,
            "runtime_base": {
                "image": "gcr.io/example/base@sha256:" + "9" * 64,
                "layer_ids": [self.BASE_LAYER_1, self.BASE_LAYER_2],
            },
            "exposure_assertion": assertion or self.file_assertion(),
            "evidence_image_digest": finding.image_digest,
            "evidence_revision": finding.source_revision,
            "rereview_triggers": sorted(self.module.REQUIRED_REREVIEW_TRIGGERS),
            "owner": "@maintainers",
            "reason": "Reviewed existing advisory signal for the exact exposure invariant.",
            "reviewed_at": "2026-06-02",
            "expires_at": "2026-09-01",
        }
        base.update(overrides)
        return base

    def baseline(self, reviewed=None):
        return {
            "version": 2,
            "service": "test-service",
            "field_semantics": self.module.FIELD_SEMANTICS,
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
            "reviewed_findings": reviewed or [],
        }

    def write_baseline(self, reviewed=None, baseline=None):
        self.baseline_path.write_text(
            json.dumps(baseline or self.baseline(reviewed)), encoding="utf-8"
        )
        return self.module.load_baseline(self.baseline_path)

    def check(self, finding, baseline, rootfs=True, today="2026-06-02"):
        return self.module.check_findings(
            "grype",
            [finding],
            baseline,
            self.module.parse_date(today, "today"),
            self.SUBJECT,
            self.rootfs if rootfs else None,
        )

    def test_schema_v2_states_field_semantics(self):
        baseline = self.write_baseline()
        self.assertEqual(baseline["field_semantics"], self.module.FIELD_SEMANTICS)
        baseline["field_semantics"]["reviewed_findings[].evidence_revision"] = (
            "enforced"
        )
        self.baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.module.load_baseline(self.baseline_path)

    def test_unrelated_application_layer_change_retains_review(self):
        reviewed = self.finding()
        baseline = self.write_baseline([self.review(reviewed)])
        changed_report = self.report(
            image_digest="sha256:" + "c" * 64,
            revision="d" * 40,
            app_layer="sha256:" + "4" * 64,
        )
        changed = self.finding(changed_report)
        self.assertEqual(reviewed.component_layer_id, changed.component_layer_id)
        self.assertEqual(self.check(changed, baseline), 0)

    def test_component_layer_change_invalidates_review(self):
        reviewed = self.finding()
        baseline = self.write_baseline([self.review(reviewed)])
        changed = self.finding(self.report(component_layer=self.BASE_LAYER_2))
        self.assertEqual(self.check(changed, baseline), 1)

    def test_runtime_base_change_invalidates_review(self):
        reviewed = self.finding()
        baseline = self.write_baseline([self.review(reviewed)])
        changed_base = "sha256:" + "5" * 64
        changed = self.finding(
            self.report(base_layers=[self.BASE_LAYER_1, changed_base])
        )
        self.assertEqual(self.check(changed, baseline), 1)

    def test_missing_component_location_fails_closed(self):
        reviewed = self.finding()
        baseline = self.write_baseline([self.review(reviewed)])
        changed = self.finding(self.report(locations=False))
        self.assertEqual(self.check(changed, baseline), 1)

    def test_component_locations_must_resolve_to_one_real_layer(self):
        report = self.report()
        second = copy.deepcopy(report["matches"][0]["artifact"]["locations"][0])
        second["path"] = "/usr/share/doc/openssl/copyright"
        report["matches"][0]["artifact"]["locations"].append(second)
        finding = self.finding(report)
        self.assertEqual(finding.component_layer_id, self.BASE_LAYER_1)
        report["matches"][0]["artifact"]["locations"][1]["layerID"] = self.BASE_LAYER_2
        changed = self.finding(report)
        self.assertIn("multiple component layers", changed.component_layer_error)

    def test_severity_change_invalidates_review(self):
        reviewed = self.finding()
        baseline = self.write_baseline([self.review(reviewed)])
        changed = self.finding(self.report(severity="Critical"))
        self.assertEqual(self.check(changed, baseline), 1)

    def test_fix_becoming_available_cannot_be_dispositioned(self):
        reviewed = self.finding()
        baseline = self.write_baseline([self.review(reviewed)])
        fixed = self.finding(
            self.report(
                severity="Low",
                fix={"versions": ["3.0.1"], "state": "fixed"},
            )
        )
        self.assertEqual(self.check(fixed, baseline), 1)

    def test_unknown_fix_state_fails_closed(self):
        report = self.report(fix={"versions": [], "state": "maybe-later"})
        with self.assertRaises(SystemExit):
            self.finding(report)

    def test_assertion_definition_change_requires_rereview(self):
        finding = self.finding()
        review = self.review(finding)
        review["exposure_assertion"]["files"][0]["path"] = "/app/other"
        with self.assertRaises(SystemExit):
            self.write_baseline([review])

    def test_assertion_false_fails_closed(self):
        finding = self.finding()
        assertion = self.file_assertion("0" * 64)
        baseline = self.write_baseline([self.review(finding, assertion)])
        self.assertEqual(self.check(finding, baseline), 1)

    def test_file_digest_assertion_checks_every_file_in_closed_list(self):
        finding = self.finding()
        helper = self.rootfs / "app/helper"
        helper.write_bytes(b"reviewed helper")
        report = self.report()
        syft = self.syft_report(report)
        syft["files"].append(
            {
                "location": {
                    "path": "/app/helper",
                    "layerID": self.APP_LAYER,
                },
                "digests": None,
            }
        )
        finding = self.module.normalize_grype(report, self.SUBJECT, syft)[0]
        assertion = self.file_assertion()
        assertion["files"].append(
            {
                "path": "/app/helper",
                "sha256": "sha256:" + "0" * 64,
            }
        )
        assertion["definition_digest"] = self.module.assertion_definition_digest(
            assertion
        )
        baseline = self.write_baseline([self.review(finding, assertion)])
        self.assertEqual(self.check(finding, baseline), 1)

    def test_assertion_unevaluable_fails_closed(self):
        finding = self.finding()
        baseline = self.write_baseline([self.review(finding)])
        self.assertEqual(self.check(finding, baseline, rootfs=False), 1)

    def test_unknown_assertion_kind_fails_closed(self):
        finding = self.finding()
        review = self.review(finding)
        review["exposure_assertion"] = {
            "kind": "source_comment_says_safe",
            "definition_digest": "sha256:" + "0" * 64,
        }
        with self.assertRaises(SystemExit):
            self.write_baseline([review])

    def test_expired_review_fails(self):
        finding = self.finding()
        baseline = self.write_baseline(
            [
                self.review(
                    finding,
                    reviewed_at="2026-05-01",
                    expires_at="2026-06-01",
                )
            ]
        )
        self.assertEqual(self.check(finding, baseline), 1)

    def test_future_dated_review_fails(self):
        finding = self.finding()
        baseline = self.write_baseline([self.review(finding, reviewed_at="2026-06-03")])
        self.assertEqual(self.check(finding, baseline), 1)

    def test_dynamic_symbol_absent_passes_and_present_fails(self):
        finding = self.finding()
        baseline = self.write_baseline([self.review(finding, self.dynamic_assertion())])
        self.assertEqual(self.check(finding, baseline), 0)
        self.write_elf("/app/service", undefined=["ungetwc"])
        self.assertEqual(self.check(finding, baseline), 1)

    def test_dynamic_lookup_makes_symbol_assertion_unevaluable(self):
        finding = self.finding()
        baseline = self.write_baseline([self.review(finding, self.dynamic_assertion())])
        self.write_elf("/app/service", undefined=["dlsym"])
        self.assertEqual(self.check(finding, baseline), 1)

    def write_package_metadata(self, package, files):
        path = self.rootfs / f"var/lib/dpkg/status.d/{package}.md5sums"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(f"{'0' * 32}  {file.lstrip('/')}\n" for file in files),
            encoding="utf-8",
        )

    def test_package_absent_from_executable_closure(self):
        finding = self.finding()
        self.write_elf("/lib/libsafe.so")
        self.write_elf("/lib/libblocked.so")
        self.write_package_metadata("libblocked", ["/lib/libblocked.so"])
        self.write_elf("/app/service", needed=["libsafe.so"])
        baseline = self.write_baseline([self.review(finding, self.package_assertion())])
        self.assertEqual(self.check(finding, baseline), 0)
        self.write_elf("/app/service", needed=["libblocked.so"])
        self.assertEqual(self.check(finding, baseline), 1)

    def test_unresolved_executable_dependency_is_unevaluable(self):
        finding = self.finding()
        self.write_elf("/lib/libblocked.so")
        self.write_package_metadata("libblocked", ["/lib/libblocked.so"])
        self.write_elf("/app/service", needed=["libmissing.so"])
        baseline = self.write_baseline([self.review(finding, self.package_assertion())])
        self.assertEqual(self.check(finding, baseline), 1)

    def test_dynamic_lookup_makes_package_closure_unevaluable(self):
        finding = self.finding()
        self.write_elf("/lib/libblocked.so")
        self.write_package_metadata("libblocked", ["/lib/libblocked.so"])
        self.write_elf("/app/service", undefined=["dlsym"])
        baseline = self.write_baseline([self.review(finding, self.package_assertion())])
        self.assertEqual(self.check(finding, baseline), 1)

    def test_grype_and_syft_must_describe_same_candidate(self):
        report = self.report()
        syft = self.syft_report(report)
        syft["source"]["metadata"]["layers"][-1]["digest"] = "sha256:" + "8" * 64
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(report, self.SUBJECT, syft)

    def test_grype_artifact_must_match_syft_package_model(self):
        report = self.report()
        syft = self.syft_report(report)
        syft["artifacts"][0]["locations"][0]["layerID"] = self.BASE_LAYER_2
        with self.assertRaises(SystemExit):
            self.module.normalize_grype(report, self.SUBJECT, syft)

    def test_unreviewed_blocking_finding_fails(self):
        finding = self.finding()
        self.assertEqual(self.check(finding, self.write_baseline()), 1)

    def test_below_threshold_finding_passes(self):
        finding = self.finding(self.report(severity="Medium"))
        self.assertEqual(self.check(finding, self.write_baseline()), 0)

    def test_zizmor_policy_is_preserved(self):
        baseline = self.write_baseline()
        report = [
            {
                "ident": "unpinned-uses",
                "desc": "action is not pinned",
                "determinations": {"severity": "High"},
                "locations": [],
                "ignored": False,
            }
        ]
        findings = self.module.normalize_zizmor(report)
        self.assertEqual(
            self.module.check_findings(
                "zizmor",
                findings,
                baseline,
                self.module.parse_date("2026-06-02", "today"),
            ),
            1,
        )

    def test_recorded_evidence_shape_is_validated_but_not_compared(self):
        finding = self.finding()
        review = self.review(
            finding,
            evidence_image_digest="sha256:" + "7" * 64,
            evidence_revision="f" * 40,
        )
        baseline = self.write_baseline([review])
        self.assertEqual(self.check(finding, baseline), 0)
        review["evidence_revision"] = "not-a-revision"
        with self.assertRaises(SystemExit):
            self.write_baseline([review])

    def test_structured_rereview_triggers_are_required(self):
        finding = self.finding()
        review = self.review(finding)
        review["rereview_triggers"].remove("runtime_base_changed")
        with self.assertRaises(SystemExit):
            self.write_baseline([review])


if __name__ == "__main__":
    unittest.main()
