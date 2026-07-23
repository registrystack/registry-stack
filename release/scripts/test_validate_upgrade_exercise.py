from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "validate-upgrade-exercise.py"
TEMPLATE = ROOT / "release" / "exercises" / "upgrade-exercise-v1.template.json"
TARGET_COMMIT = "e25f081ce800ade13e892503cc19b96588e081ef"
TARGET_MANIFEST = Path("release/manifests/registry-stack-beta-16.yaml")


def load_module():
    spec = importlib.util.spec_from_file_location("validate_upgrade_exercise", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class UpgradeExerciseValidatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.template = json.loads(TEMPLATE.read_text(encoding="utf-8"))

    def candidate(self):
        def replace(value):
            if isinstance(value, dict):
                return {key: replace(item) for key, item in value.items()}
            if isinstance(value, list):
                return [replace(item) for item in value]
            if not isinstance(value, str) or not value.startswith("<"):
                return value
            if value == "<EXERCISE_ID>":
                return "v1-upgrade-exercise"
            if value == "<RELAY_AUTHORITY_ID>":
                return "relay-authority-a"
            if value == "<NOTARY_AUTHORITY_ID>":
                return "notary-authority-a"
            if value == "<EVIDENCE_LABEL>":
                return "redacted-evidence"
            if "AT>" in value:
                return "2026-07-19T12:00:00Z"
            if value == "<SOURCE_VERSION>":
                return "v0.11.0"
            if value == "<TARGET_RELEASE_ID>":
                return "beta-16"
            if value == "<TARGET_SOURCE_REF>":
                return "0e76f5ea61f78bbc15d91fcb6e9dfcaa956c3df8"
            if value == "<TARGET_RELEASE_MANIFEST_PATH>":
                return TARGET_MANIFEST.as_posix()
            if "VERSION>" in value or "RELEASE_TAG>" in value:
                return "v0.12.2"
            if "COMMIT>" in value:
                return "a" * 40
            if "SHA256>" in value or "DIGEST>" in value:
                return "sha256:" + "b" * 64
            raise AssertionError(f"unhandled placeholder {value}")

        record = replace(copy.deepcopy(self.template))
        record["record_kind"] = "candidate_evidence"
        record["candidate_frozen"] = True
        record["candidate_independently_verified"] = True
        for result in record["results"]:
            result["outcome"] = "passed"
        record["target_release"]["source_commit"] = TARGET_COMMIT
        manifest = self.module.git_bytes(ROOT, TARGET_COMMIT, TARGET_MANIFEST)
        record["target_release_manifest"]["sha256"] = self.module.sha256_bytes(manifest)
        for product, path in self.module.CONFIG_SCHEMAS.items():
            record["config_schemas"][product]["sha256"] = self.module.sha256_bytes(
                self.module.git_bytes(ROOT, TARGET_COMMIT, path)
            )
        artifacts = record["candidate_artifact_set"]["artifacts"]
        artifacts["manifest"] = record["target_release_manifest"]["sha256"]
        artifacts["relay_image"] = record["target_release"]["relay_image_digest"]
        artifacts["notary_image"] = record["target_release"]["notary_image_digest"]
        artifacts["p_release_inputs"] = self.module.release_inputs_sha256(
            ROOT, record["target_release"]["source_ref"]
        )
        artifacts["t_release_inputs"] = self.module.release_inputs_sha256(
            ROOT, TARGET_COMMIT
        )
        record["candidate_artifact_set"]["sha256"] = self.module.canonical_sha256(artifacts)
        return record

    def test_template_is_valid_preparation_but_not_candidate_evidence(self) -> None:
        self.module.validate_record(self.template, allow_template=True)
        with self.assertRaisesRegex(self.module.ExerciseError, "not candidate evidence"):
            self.module.validate_record(self.template, allow_template=False)

    def test_complete_candidate_record_is_valid(self) -> None:
        self.module.validate_record(
            self.candidate(), allow_template=False, require_all_passed=True
        )

    def test_candidate_must_be_a_forward_version_upgrade(self) -> None:
        record = self.candidate()
        record["source_release"]["version"] = record["target_release"]["version"]
        with self.assertRaisesRegex(self.module.ExerciseError, "must be newer"):
            self.module.validate_record(record, allow_template=False)

    def test_candidate_release_identifiers_are_strict(self) -> None:
        for field, value in (
            ("source_commit", "main"),
            ("relay_image_digest", "latest"),
            ("notary_image_digest", "latest"),
        ):
            with self.subTest(field=field):
                record = self.candidate()
                record["target_release"][field] = value
                with self.assertRaisesRegex(self.module.ExerciseError, "invalid or unsafe"):
                    self.module.validate_record(record, allow_template=False)

    def test_unknown_field_is_rejected_to_prevent_raw_evidence(self) -> None:
        record = self.candidate()
        record["results"][0]["raw_output"] = "Authorization: Bearer secret"
        with self.assertRaisesRegex(self.module.ExerciseError, "unknown raw_output"):
            self.module.validate_record(record, allow_template=False)

    def test_authority_identifier_cannot_contain_a_url_or_subject_data(self) -> None:
        record = self.candidate()
        record["topology"]["relay_authorities"][0] = "https://registry.example.test/subject/1"
        with self.assertRaisesRegex(self.module.ExerciseError, "invalid or unsafe"):
            self.module.validate_record(record, allow_template=False)

    def test_failed_and_not_run_results_are_recordable_but_fail_promotion(self) -> None:
        record = self.candidate()
        record["results"][0]["outcome"] = "failed"
        record["results"][1].update(
            {"outcome": "not_run", "observed_at": None, "evidence_label": None, "evidence_sha256": None}
        )
        self.module.validate_record(record, allow_template=False)
        with self.assertRaisesRegex(self.module.ExerciseError, "--require-pass"):
            self.module.validate_record(
                record, allow_template=False, require_all_passed=True
            )

    def test_complete_release_specific_recovery_set_is_required(self) -> None:
        record = self.candidate()
        record["recovery_set"].pop()
        with self.assertRaisesRegex(self.module.ExerciseError, "complete release-specific"):
            self.module.validate_record(record, allow_template=False)

    def test_candidate_uses_historical_schema_not_ambient_checkout(self) -> None:
        record = self.candidate()
        ambient = "sha256:" + hashlib.sha256(
            (ROOT / self.module.CONFIG_SCHEMAS["registry-notary"]).read_bytes()
        ).hexdigest()
        self.assertNotEqual(ambient, record["config_schemas"]["registry-notary"]["sha256"])
        self.module.validate_record(record, allow_template=False)

    def test_manifest_hash_ref_and_artifact_set_drift_are_rejected(self) -> None:
        record = self.candidate()
        record["target_release_manifest"]["sha256"] = "sha256:" + "0" * 64
        record["candidate_artifact_set"]["artifacts"]["manifest"] = "sha256:" + "0" * 64
        record["candidate_artifact_set"]["sha256"] = self.module.canonical_sha256(
            record["candidate_artifact_set"]["artifacts"]
        )
        with self.assertRaisesRegex(self.module.ExerciseError, "does not match exact target"):
            self.module.validate_record(record, allow_template=False)
        record = self.candidate()
        record["target_release"]["source_ref"] = TARGET_COMMIT
        record["candidate_artifact_set"]["artifacts"]["p_release_inputs"] = (
            record["candidate_artifact_set"]["artifacts"]["t_release_inputs"]
        )
        record["candidate_artifact_set"]["sha256"] = self.module.canonical_sha256(
            record["candidate_artifact_set"]["artifacts"]
        )
        with self.assertRaisesRegex(self.module.ExerciseError, "identity does not match"):
            self.module.validate_record(record, allow_template=False)
        record = self.candidate()
        record["candidate_artifact_set"]["artifacts"]["t2_binaries"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(self.module.ExerciseError, "does not match its artifacts"):
            self.module.validate_record(record, allow_template=False)

    def test_topology_requires_one_dedicated_notary_per_relay(self) -> None:
        record = self.candidate()
        record["topology"]["relay_authorities"].append("relay-authority-b")
        record["topology"]["authority_pairs"].append(
            {"relay": "relay-authority-b", "notary": "notary-authority-a"}
        )
        with self.assertRaisesRegex(self.module.ExerciseError, "dedicated Notary"):
            self.module.validate_record(record, allow_template=False)


if __name__ == "__main__":
    unittest.main()
