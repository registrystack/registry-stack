#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shlex
import stat
import subprocess
import tempfile
from contextlib import redirect_stderr
from pathlib import Path
from unittest import TestCase, main, mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "integration-e2-runner.py"


def load_module():
    spec = importlib.util.spec_from_file_location("integration_e2_runner", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IntegrationE2RunnerTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tag = "v1.0.0"
        self.commit = "1" * 40
        self.relay = "ghcr.io/registrystack/registry-relay@sha256:" + "2" * 64
        self.notary = "ghcr.io/registrystack/registry-notary@sha256:" + "3" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def make_candidate(self) -> Path:
        candidate = self.root / "candidate"
        candidate.mkdir()
        binary_name = f"registryctl-{self.tag}-linux-amd64"
        lock_name = f"registryctl-{self.tag}-image-lock.json"
        capsule_name = f"registry-stack-{self.tag}-release-capsule.json"
        (candidate / binary_name).write_text(
            "#!/bin/sh\nprintf 'registryctl 1.0.0\\n'\n",
            encoding="utf-8",
        )
        lock = {
            "schema_version": "registryctl.release_image_lock.v1",
            "release_tag": self.tag,
            "manifest_source_ref": "4" * 40,
            "tag_target": self.commit,
            "platform": "linux/amd64",
            "images": {
                "registry-relay": self.relay,
                "registry-notary": self.notary,
            },
        }
        self.write_json(candidate / lock_name, lock)
        lock_sha = hashlib.sha256((candidate / lock_name).read_bytes()).hexdigest()
        lock_sbom_name = f"{lock_name}.spdx.json"
        lock_subject_id = "SPDXRef-lock-subject"
        self.write_json(
            candidate / lock_sbom_name,
            {
                "documentDescribes": [lock_subject_id],
                "packages": [
                    {
                        "SPDXID": lock_subject_id,
                        "name": lock_name,
                        "packageFileName": lock_name,
                        "checksums": [
                            {"algorithm": "SHA256", "checksumValue": lock_sha}
                        ],
                    }
                ],
            },
        )
        (candidate / "registry-relay.digest").write_text(
            self.relay + "\n", encoding="utf-8"
        )
        (candidate / "registry-notary.digest").write_text(
            self.notary + "\n", encoding="utf-8"
        )
        capsule = {
            "release_tag": self.tag,
            "version": "1.0.0",
            "repository": self.module.CAPSULE_REPOSITORY,
            "source": {
                "source_tag": self.tag,
                "source_ref": "4" * 40,
                "source_commit": self.commit,
                "lineage": {
                    "tag_matches_source_tag": True,
                    "head_matches_tag_target": True,
                    "source_ref_ancestor_or_equal": True,
                    "default_branch_reachable": True,
                },
            },
            "binaries": [
                {
                    "name": binary_name,
                    "sha256": hashlib.sha256(
                        (candidate / binary_name).read_bytes()
                    ).hexdigest(),
                }
            ],
            "release_files": [
                {
                    "name": lock_name,
                    "kind": "registryctl-release-image-lock",
                    "sha256": lock_sha,
                    "sbom": {
                        "asset_name": lock_sbom_name,
                        "subject": lock_name,
                        "format": "spdx-json",
                        "sha256": hashlib.sha256(
                            (candidate / lock_sbom_name).read_bytes()
                        ).hexdigest(),
                    },
                }
            ],
            "images": [
                {"name": "registry-relay", "digest_ref": self.relay},
                {"name": "registry-notary", "digest_ref": self.notary},
            ],
        }
        self.write_json(candidate / capsule_name, capsule)
        binary_sha = hashlib.sha256((candidate / binary_name).read_bytes()).hexdigest()
        (candidate / "SHA256SUMS").write_text(
            f"{binary_sha}  {binary_name}\n{lock_sha}  {lock_name}\n",
            encoding="utf-8",
        )
        for name in self.module.signed_subject_names(self.tag):
            self.assertTrue((candidate / name).exists())
            (candidate / f"{name}.sig").write_text(
                "fixture signature\n", encoding="utf-8"
            )
            (candidate / f"{name}.pem").write_text(
                "fixture certificate\n", encoding="utf-8"
            )
        (
            candidate / f"registry-stack-{self.tag}-release-provenance.intoto.jsonl"
        ).write_text("fixture provenance\n", encoding="utf-8")
        self.assertEqual(
            self.module.required_asset_names(self.tag),
            {path.name for path in candidate.iterdir()},
        )
        return candidate

    @staticmethod
    def binary_result(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 0, "registryctl 1.0.0\n", "")

    def candidate_metadata(self, candidate: Path) -> dict[str, str]:
        return self.module.verify_candidate_assets(
            candidate,
            self.tag,
            authenticate=lambda _directory, _tag: None,
            binary_runner=self.binary_result,
        )

    def make_canary_file(self) -> Path:
        path = self.root / "canaries"
        path.write_text("registry-secret-canary-72\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def make_result(self, profile_id: str, candidate: Path) -> dict[str, object]:
        profile = self.module.load_profile(profile_id)
        operation = next(
            item for item in profile["source"]["operations"] if item["role"] == "data"
        )
        hash_value = "sha256:" + "a" * 64
        cases = []
        for expected in profile["cases"]:
            not_applicable = expected["expected_source_data_access"] == "not_applicable"
            cases.append(
                {
                    "case_id": expected["id"],
                    "outcome": "not_applicable" if not_applicable else "passed",
                    "started_at": "2026-07-19T01:00:00Z",
                    "completed_at": "2026-07-19T01:00:01Z",
                    "duration_ms": 1000,
                    "result_code": expected["expected_result_code"],
                    "source_data_access": expected["expected_source_data_access"],
                    "source_data_access_evidence_sha256": hash_value,
                    "audit_correlation_sha256": hash_value,
                    "evidence_sha256": hash_value,
                }
            )
        candidate_metadata = self.candidate_metadata(candidate)
        return {
            "schema_version": self.module.RESULT_SCHEMA,
            "record_kind": "candidate_evidence",
            "run_id": "candidate-1",
            "profile_id": profile_id,
            "support_status": self.module.SUPPORT_STATUS,
            "status": "passed",
            "started_at": "2026-07-19T01:00:00Z",
            "completed_at": "2026-07-19T01:03:00Z",
            "release": {
                **candidate_metadata,
                "candidate_assets_verified": True,
                "authenticity_verified": True,
            },
            "source": {
                "product": profile["source"]["product"],
                "baseline": profile["source"]["baseline"],
                "operation_id": operation["id"],
                "method": operation["method"],
                "path": operation["path"],
                "owner_attestation_sha256": hash_value,
            },
            "project": {
                "starter": profile["starter"],
                "starter_content_digest": hash_value,
                "authored_inputs_sha256": hash_value,
                "build_review_sha256": hash_value,
                "relay_closure_sha256": hash_value,
                "notary_closure_sha256": hash_value,
                "generated_files_unchanged": True,
            },
            "cases": cases,
            "redaction": {
                "passed": True,
                "scanned_artifacts": 1,
                "scanned_bytes": 65536,
                "seeded_canaries": 1,
                "forbidden_values_found": 0,
                "restricted_raw_evidence_bytes": 4096,
                "raw_evidence_retained_restricted": True,
                "report_sha256": hash_value,
            },
            "teardown": {
                "attempted": True,
                "status": "completed",
                "started_at": "2026-07-19T01:01:59Z",
                "duration_ms": 1000,
                "completed_at": "2026-07-19T01:02:00Z",
                "evidence_sha256": hash_value,
            },
            "limitations": [
                "unofficial-integration-profile",
                "single-pinned-product-version",
                "single-reviewed-read-operation",
                "non-production-instance",
                "not-product-certification",
                "not-general-country-system-conformance",
            ],
        }

    def write_result(self, result: dict[str, object]) -> Path:
        path = self.root / "public-result.json"
        self.write_json(path, result)
        return path

    def test_checked_in_packet_is_closed_and_valid(self) -> None:
        self.module.validate_packet()

    def test_pilot_report_template_preserves_the_public_contract(self) -> None:
        readme = (self.module.CONFIG_DIR / "README.md").read_text(encoding="utf-8")
        template = (
            self.module.CONFIG_DIR / "pilot-report.template.md"
        ).read_text(encoding="utf-8")
        normalized_template = " ".join(template.split())
        self.assertIn("(pilot-report.template.md)", readme)
        self.assertIn(
            "Do not include credentials, network origins, operator or source "
            "identifiers, record identifiers, raw audits, private evidence, or "
            "links to restricted evidence.",
            normalized_template,
        )
        for text in (
            "Sanitized run result:",
            "Plans, dry runs",
            "One completed pilot is not proof of broad production readiness.",
            "Frozen Registry Stack candidate:",
            "Immutable Solmara release",
            "Independent operator:",
            "Owner-approved non-production source:",
            "### Blocking findings",
            "### Accepted limitations and narrowed support",
            "Operator handoff and independence",
            "Install or deployment",
            "Configuration and environment binding",
            "Diagnostics and ordinary source failures",
            "Upgrade or rollback",
            "Restart, teardown, and other operations",
            "Security boundaries and redaction",
            "Documentation and operator journey",
        ):
            self.assertIn(text, template)

    def test_nested_result_objects_must_remain_closed(self) -> None:
        schema = self.module.load_json(self.module.SCHEMA_PATH)
        schema["$defs"]["case"]["additionalProperties"] = True
        with self.assertRaisesRegex(self.module.RunnerError, "open object schema"):
            self.module.assert_closed_schema(schema)

    def test_profile_rejects_a_drifted_upstream_pin(self) -> None:
        profile = self.module.load_profile("opencrvs-dci-v1.9")
        profile["source"]["baseline"][0]["commit"] = "0" * 40
        with self.assertRaisesRegex(
            self.module.RunnerError, "exact reviewed upstream baseline"
        ):
            self.module.validate_profile(profile, "tampered profile")

    def test_dry_run_is_explicitly_not_evidence_and_hides_values(self) -> None:
        profile = self.module.load_profile("opencrvs-dci-v1.9")
        plan = self.module.plan_document(profile)
        self.assertFalse(plan["candidate_evidence"])
        self.assertEqual("planned_not_executed", plan["status"])
        self.assertEqual("approved_operator_wrapper", plan["executor"])
        self.assertIn("OPENCRVS_CLIENT_SECRET", plan["required_input_names"])
        self.assertEqual(
            self.module.CASE_IDS, tuple(case["id"] for case in plan["cases"])
        )
        self.assertIn(
            "/registry/sync/search",
            [operation["path"] for operation in plan["source_operations"]],
        )
        serialized = json.dumps(plan)
        self.assertNotIn("secret value", serialized)
        self.assertTrue(
            any("compatibility probe" in item for item in plan["prerequisites"])
        )

    def test_candidate_assets_cross_validate_all_release_bindings(self) -> None:
        candidate = self.make_candidate()
        metadata = self.candidate_metadata(candidate)
        self.assertEqual(self.relay, metadata["relay_image"])
        self.assertEqual(self.commit, metadata["source_commit"])

    def test_authenticity_precedes_candidate_binary_execution(self) -> None:
        candidate = self.make_candidate()
        events = []

        def authenticate(directory, _tag):
            self.assertNotEqual(candidate, directory)
            events.append("authenticated")

        def execute(*_args, **_kwargs):
            self.assertEqual(["authenticated"], events)
            events.append("executed")
            return self.binary_result()

        self.module.verify_candidate_assets(
            candidate,
            self.tag,
            authenticate=authenticate,
            binary_runner=execute,
        )
        self.assertEqual(["authenticated", "executed"], events)

    def test_authenticity_failure_prevents_candidate_binary_execution(self) -> None:
        candidate = self.make_candidate()
        events = []
        snapshots = []

        def reject_authenticity(directory, _tag):
            snapshots.append(directory)
            events.append("authenticity-rejected")
            raise self.module.RunnerError("invalid signature fixture")

        def execute(*_args, **_kwargs):
            events.append("executed")
            return self.binary_result()

        with self.assertRaisesRegex(self.module.RunnerError, "invalid signature"):
            self.module.verify_candidate_assets(
                candidate,
                self.tag,
                authenticate=reject_authenticity,
                binary_runner=execute,
            )
        self.assertEqual(["authenticity-rejected"], events)
        self.assertEqual(1, len(snapshots))
        self.assertFalse(snapshots[0].exists())

    def test_subject_change_during_authenticity_prevents_binary_execution(self) -> None:
        candidate = self.make_candidate()
        events = []

        def mutate_during_authenticity(directory, _tag):
            binary = directory / f"registryctl-{self.tag}-linux-amd64"
            binary.chmod(0o700)
            binary.write_bytes(b"changed-after-passive-checks")
            events.append("mutated")

        def execute(*_args, **_kwargs):
            events.append("executed")
            return self.binary_result()

        with self.assertRaisesRegex(self.module.RunnerError, "changed during"):
            self.module.verify_candidate_assets(
                candidate,
                self.tag,
                authenticate=mutate_during_authenticity,
                binary_runner=execute,
            )
        self.assertEqual(["mutated"], events)

    def test_original_binary_replacement_after_final_hash_never_executes(self) -> None:
        candidate = self.make_candidate()
        original_binary = candidate / f"registryctl-{self.tag}-linux-amd64"
        replacement_marker = self.root / "replacement-executed"
        snapshots = []

        def authenticate(directory, _tag):
            snapshots.append(directory)
            self.assertEqual(0o500, stat.S_IMODE(directory.stat().st_mode))
            self.assertEqual(os.geteuid(), directory.stat().st_uid)
            for asset in directory.iterdir():
                self.assertEqual(0, asset.stat().st_mode & 0o222)

        def replace_original_then_execute(command, **kwargs):
            self.assertNotEqual(original_binary, Path(command[0]))
            original_binary.write_text(
                "#!/bin/sh\n"
                f": > {shlex.quote(str(replacement_marker))}\n"
                "printf 'registryctl 1.0.0\\n'\n",
                encoding="utf-8",
            )
            original_binary.chmod(0o700)
            return subprocess.run(command, **kwargs)

        self.module.verify_candidate_assets(
            candidate,
            self.tag,
            authenticate=authenticate,
            binary_runner=replace_original_then_execute,
        )
        self.assertFalse(replacement_marker.exists())
        self.assertEqual(1, len(snapshots))
        self.assertFalse(snapshots[0].exists())

    def test_late_passive_binding_failure_prevents_binary_execution(self) -> None:
        candidate = self.make_candidate()
        capsule_path = candidate / f"registry-stack-{self.tag}-release-capsule.json"
        capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
        capsule["images"][1]["digest_ref"] = (
            "ghcr.io/registrystack/registry-notary@sha256:" + "9" * 64
        )
        self.write_json(capsule_path, capsule)
        events = []

        def authenticate(_directory, _tag):
            events.append("authenticated")

        def execute(*_args, **_kwargs):
            events.append("executed")
            return self.binary_result()

        with self.assertRaisesRegex(self.module.RunnerError, "capsule images"):
            self.module.verify_candidate_assets(
                candidate,
                self.tag,
                authenticate=authenticate,
                binary_runner=execute,
            )
        self.assertEqual([], events)

    def test_candidate_rejects_an_unexpected_asset(self) -> None:
        candidate = self.make_candidate()
        (candidate / "unreviewed-output.txt").write_text("no\n", encoding="utf-8")
        with self.assertRaisesRegex(self.module.RunnerError, "asset set is not closed"):
            self.candidate_metadata(candidate)

    def test_candidate_rejects_digest_not_bound_by_image_lock(self) -> None:
        candidate = self.make_candidate()
        (candidate / "registry-relay.digest").write_text(
            "ghcr.io/registrystack/registry-relay@sha256:" + "9" * 64 + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.RunnerError, "do not match the image lock"
        ):
            self.candidate_metadata(candidate)

    def test_candidate_rejects_an_image_lock_sbom_for_the_wrong_subject(self) -> None:
        candidate = self.make_candidate()
        sbom = candidate / f"registryctl-{self.tag}-image-lock.json.spdx.json"
        document = json.loads(sbom.read_text(encoding="utf-8"))
        document["packages"][0]["checksums"][0]["checksumValue"] = "0" * 64
        self.write_json(sbom, document)
        with self.assertRaisesRegex(self.module.RunnerError, "does not describe"):
            self.candidate_metadata(candidate)

    def test_candidate_authenticity_cannot_silently_skip_missing_tools(self) -> None:
        candidate = self.make_candidate()
        with mock.patch.object(self.module.shutil, "which", return_value=None):
            with self.assertRaisesRegex(self.module.RunnerError, "requires installed"):
                self.module.verify_authenticity(candidate, self.tag)

    def test_candidate_authenticity_binds_every_subject_to_tagged_workflow(
        self,
    ) -> None:
        candidate = self.make_candidate()
        commands = []
        with mock.patch.object(
            self.module.shutil,
            "which",
            side_effect=["/tools/cosign", "/tools/slsa-verifier"],
        ):
            self.module.verify_authenticity(
                candidate, self.tag, command_runner=commands.append
            )
        self.assertEqual(12, len(commands))
        cosign_commands = [
            command for command in commands if command[0].endswith("cosign")
        ]
        self.assertEqual(6, len(cosign_commands))
        identity = self.module.RELEASE_WORKFLOW.format(tag=self.tag)
        self.assertTrue(
            all(
                command[command.index("--certificate-identity") + 1] == identity
                for command in cosign_commands
            )
        )

    def test_cli_rejects_symlink_candidate_directory_before_normalization(self) -> None:
        candidate = self.make_candidate()
        candidate_link = self.root / "candidate-link"
        candidate_link.symlink_to(candidate, target_is_directory=True)
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = self.module.main(
                [
                    "validate",
                    "--candidate-dir",
                    str(candidate_link),
                    "--tag",
                    self.tag,
                ]
            )
        self.assertEqual(1, status)
        self.assertIn("non-symlink directory", stderr.getvalue())

    def test_json_const_does_not_accept_integer_for_true(self) -> None:
        with self.assertRaisesRegex(self.module.RunnerError, "must equal True"):
            self.module.validate_against_schema(1, {"const": True}, {})

    def test_json_boolean_enum_does_not_accept_integer(self) -> None:
        with self.assertRaisesRegex(self.module.RunnerError, "closed allowed set"):
            self.module.validate_against_schema(1, {"enum": [True, False]}, {})

    def test_full_result_rejects_integer_for_boolean_attestation(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["project"]["generated_files_unchanged"] = 1
        with self.assertRaisesRegex(self.module.RunnerError, "must equal True"):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_valid_opencrvs_result_passes(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        path = self.write_result(result)
        validated = self.module.validate_result(
            path, self.module.load_profile("opencrvs-dci-v1.9"), self.make_canary_file()
        )
        self.assertEqual("passed", validated["status"])

    def test_valid_dhis2_result_records_singleton_ambiguity_as_not_applicable(
        self,
    ) -> None:
        candidate = self.make_candidate()
        result = self.make_result("dhis2-tracker-2.41.9", candidate)
        path = self.write_result(result)
        self.module.validate_result(
            path,
            self.module.load_profile("dhis2-tracker-2.41.9"),
            self.make_canary_file(),
        )

    def test_pre_source_denial_cannot_pass_after_source_contact(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        invalid_selector = next(
            case for case in result["cases"] if case["case_id"] == "invalid-selector"
        )
        invalid_selector["source_data_access"] = "contacted_once"
        with self.assertRaisesRegex(
            self.module.RunnerError, "expected source-side access evidence"
        ):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_passed_case_requires_the_reviewed_safe_result_code(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["cases"][0]["result_code"] = "unexpected-result"
        with self.assertRaisesRegex(
            self.module.RunnerError, "reviewed safe result code"
        ):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_unknown_public_raw_evidence_field_is_rejected(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["raw_output"] = "must never be public"
        with self.assertRaisesRegex(self.module.RunnerError, "unknown fields"):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_seeded_canary_in_public_result_is_rejected_before_schema_validation(
        self,
    ) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["run_id"] = "registry-secret-canary-72"
        with self.assertRaisesRegex(
            self.module.RunnerError, "seeded restricted-value canary"
        ):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_canary_file_must_be_owner_only(self) -> None:
        canaries = self.make_canary_file()
        canaries.chmod(0o644)
        with self.assertRaisesRegex(self.module.RunnerError, "group or other"):
            self.module.read_canaries(canaries)

    def test_failed_run_is_accepted_as_honest_non_closing_evidence(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["status"] = "failed"
        result["cases"][0]["outcome"] = "failed"
        result["cases"][0]["source_data_access"] = "unknown"
        self.module.validate_result(
            self.write_result(result),
            self.module.load_profile("opencrvs-dci-v1.9"),
            self.make_canary_file(),
        )

    def test_passed_status_requires_successful_teardown(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["teardown"]["status"] = "failed"
        with self.assertRaisesRegex(self.module.RunnerError, "status is inconsistent"):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_case_duration_must_match_timestamps(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["cases"][0]["duration_ms"] = 999
        with self.assertRaisesRegex(
            self.module.RunnerError, "duration_ms does not match"
        ):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_case_duration_supports_millisecond_timestamp_precision(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["cases"][0]["completed_at"] = "2026-07-19T01:00:00.250Z"
        result["cases"][0]["duration_ms"] = 250
        self.module.validate_result(
            self.write_result(result),
            self.module.load_profile("opencrvs-dci-v1.9"),
            self.make_canary_file(),
        )

    def test_case_timestamp_elapsed_time_must_respect_profile_bound(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["cases"][0]["completed_at"] = "2026-07-19T01:01:01Z"
        result["cases"][0]["duration_ms"] = 61000
        with self.assertRaisesRegex(self.module.RunnerError, "profile case timeout"):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_teardown_started_at_is_required_by_closed_schema(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        del result["teardown"]["started_at"]
        with self.assertRaisesRegex(self.module.RunnerError, "started_at"):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_teardown_duration_must_match_timestamps(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["teardown"]["duration_ms"] = 999
        with self.assertRaisesRegex(self.module.RunnerError, "teardown duration_ms"):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_teardown_timestamp_elapsed_time_must_respect_profile_bound(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["teardown"]["completed_at"] = "2026-07-19T01:07:00Z"
        result["teardown"]["duration_ms"] = 301000
        result["completed_at"] = "2026-07-19T01:08:00Z"
        with self.assertRaisesRegex(self.module.RunnerError, "teardown exceeds"):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_teardown_cannot_start_before_cases_complete(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["teardown"]["started_at"] = "2026-07-19T01:00:00Z"
        result["teardown"]["completed_at"] = "2026-07-19T01:00:01Z"
        with self.assertRaisesRegex(
            self.module.RunnerError, "before.*test cases complete"
        ):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )

    def test_public_result_must_retain_all_claim_limitations(self) -> None:
        candidate = self.make_candidate()
        result = self.make_result("opencrvs-dci-v1.9", candidate)
        result["limitations"].remove("non-production-instance")
        with self.assertRaisesRegex(
            self.module.RunnerError, "every profile limitation"
        ):
            self.module.validate_result(
                self.write_result(result),
                self.module.load_profile("opencrvs-dci-v1.9"),
                self.make_canary_file(),
            )


if __name__ == "__main__":
    main()
