from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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
        self.candidate_asset_root = Path("/authenticated-candidate-assets")
        self.real_load_candidate = self.module.load_candidate
        self.load_candidate = mock.patch.object(
            self.module,
            "load_candidate",
            return_value={
                "release_id": "beta-16",
                "version": "0.12.2",
                "source_ref": "0e76f5ea61f78bbc15d91fcb6e9dfcaa956c3df8",
                "source_tag": "v0.12.2",
                "tag_target": TARGET_COMMIT,
                "image_lock_sha256": "sha256:" + "b" * 64,
                "relay_image": (
                    "ghcr.io/registrystack/registry-relay@sha256:" + "b" * 64
                ),
                "notary_image": (
                    "ghcr.io/registrystack/registry-notary@sha256:" + "b" * 64
                ),
            },
        )
        self.load_candidate.start()
        self.addCleanup(self.load_candidate.stop)

    def validate_record(self, data, **kwargs):
        kwargs.setdefault("candidate_asset_root", self.candidate_asset_root)
        return self.module.validate_record(data, **kwargs)

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
        self.validate_record(self.template, allow_template=True)
        with self.assertRaisesRegex(self.module.ExerciseError, "not candidate evidence"):
            self.validate_record(self.template, allow_template=False)

    def test_complete_candidate_record_is_valid(self) -> None:
        self.module.load_candidate.reset_mock()
        self.validate_record(
            self.candidate(), allow_template=False, require_all_passed=True
        )
        self.module.load_candidate.assert_called_once_with(
            ROOT / TARGET_MANIFEST,
            (
                self.candidate_asset_root
                / "v0.12.2"
                / "registryctl-v0.12.2-image-lock.json"
            ),
        )

    def test_artifact_coordinate_digest_prefixes_are_equivalent(self) -> None:
        record = self.candidate()
        artifacts = record["candidate_artifact_set"]["artifacts"]
        artifacts["relay_image"] = artifacts["relay_image"].removeprefix("sha256:")
        record["candidate_artifact_set"]["sha256"] = self.module.canonical_sha256(
            artifacts
        )

        self.validate_record(
            record, allow_template=False, require_all_passed=True
        )

    def test_candidate_tag_must_resolve_to_exact_target_commit(self) -> None:
        record = self.candidate()
        tag_ref = f"refs/tags/{record['target_release']['version']}^{{commit}}"
        run = self.module.subprocess.run

        def mismatched_tag(arguments, **kwargs):
            if arguments == ["git", "rev-parse", "--verify", tag_ref]:
                return mock.Mock(
                    returncode=0,
                    stdout=record["target_release"]["source_ref"] + "\n",
                )
            return run(arguments, **kwargs)

        with mock.patch.object(
            self.module.subprocess, "run", side_effect=mismatched_tag
        ) as git_run:
            with self.assertRaisesRegex(
                self.module.ExerciseError,
                "release tag v0.12.2 does not resolve to target_release.source_commit",
            ):
                self.validate_record(record, allow_template=False)
        git_run.assert_any_call(
            ["git", "rev-parse", "--verify", "refs/tags/v0.12.2^{commit}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_candidate_must_be_a_forward_version_upgrade(self) -> None:
        record = self.candidate()
        record["source_release"]["version"] = record["target_release"]["version"]
        with self.assertRaisesRegex(self.module.ExerciseError, "must be newer"):
            self.validate_record(record, allow_template=False)

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
                    self.validate_record(record, allow_template=False)

    def test_unknown_field_is_rejected_to_prevent_raw_evidence(self) -> None:
        record = self.candidate()
        record["results"][0]["raw_output"] = "Authorization: Bearer secret"
        with self.assertRaisesRegex(self.module.ExerciseError, "unknown raw_output"):
            self.validate_record(record, allow_template=False)

    def test_authority_identifier_cannot_contain_a_url_or_subject_data(self) -> None:
        record = self.candidate()
        record["topology"]["relay_authorities"][0] = "https://registry.example.test/subject/1"
        with self.assertRaisesRegex(self.module.ExerciseError, "invalid or unsafe"):
            self.validate_record(record, allow_template=False)

    def test_failed_and_not_run_results_are_recordable_but_fail_promotion(self) -> None:
        record = self.candidate()
        record["results"][0]["outcome"] = "failed"
        record["results"][1].update(
            {"outcome": "not_run", "observed_at": None, "evidence_label": None, "evidence_sha256": None}
        )
        self.validate_record(record, allow_template=False)
        with self.assertRaisesRegex(self.module.ExerciseError, "--require-pass"):
            self.validate_record(
                record, allow_template=False, require_all_passed=True
            )

    def test_discovery_requires_candidate_passes_and_preserves_templates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary)
            (records / "template.json").write_text(
                json.dumps(self.template), encoding="utf-8"
            )
            with mock.patch.object(
                sys,
                "argv",
                [str(SCRIPT), "--discover", str(records)],
            ), mock.patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(self.module.main(), 0)

            candidate = self.candidate()
            candidate["results"][0]["outcome"] = "failed"
            (records / "candidate.json").write_text(
                json.dumps(candidate), encoding="utf-8"
            )
            stderr = io.StringIO()
            with mock.patch.object(
                sys,
                "argv",
                [
                    str(SCRIPT),
                    "--discover",
                    str(records),
                    "--candidate-asset-root",
                    str(self.candidate_asset_root),
                ],
            ), mock.patch("sys.stderr", new=stderr):
                self.assertEqual(self.module.main(), 1)
            self.assertIn(
                "--require-pass requires every check to pass", stderr.getvalue()
            )

    def test_promotion_rejects_product_oci_layout_drift(self) -> None:
        for product in ("notary", "relay"):
            with self.subTest(product=product):
                record = self.candidate()
                artifacts = record["candidate_artifact_set"]["artifacts"]
                artifacts[f"t_{product}_layouts"] = "sha256:" + "0" * 64
                record["candidate_artifact_set"]["sha256"] = (
                    self.module.canonical_sha256(artifacts)
                )
                with self.assertRaisesRegex(
                    self.module.ExerciseError,
                    f"--require-pass rejects P/T {product} OCI layout drift",
                ):
                    self.validate_record(
                        record, allow_template=False, require_all_passed=True
                    )

    def test_complete_release_specific_recovery_set_is_required(self) -> None:
        record = self.candidate()
        record["recovery_set"].pop()
        with self.assertRaisesRegex(self.module.ExerciseError, "complete release-specific"):
            self.validate_record(record, allow_template=False)

    def test_candidate_uses_historical_schema_not_ambient_checkout(self) -> None:
        record = self.candidate()
        notary_schema = self.module.CONFIG_SCHEMAS["registry-notary"]
        historical_schema = b'{"historical_target_schema": true}\n'
        record["config_schemas"]["registry-notary"]["sha256"] = (
            self.module.sha256_bytes(historical_schema)
        )
        ambient = "sha256:" + hashlib.sha256(
            (ROOT / notary_schema).read_bytes()
        ).hexdigest()
        self.assertNotEqual(ambient, record["config_schemas"]["registry-notary"]["sha256"])
        read_git_bytes = self.module.git_bytes

        def historical_git_bytes(root: Path, commit: str, path: Path) -> bytes:
            if commit == TARGET_COMMIT and path == notary_schema:
                return historical_schema
            return read_git_bytes(root, commit, path)

        with mock.patch.object(
            self.module, "git_bytes", side_effect=historical_git_bytes
        ) as git_bytes:
            self.module.validate_config_schemas(
                record["config_schemas"],
                template=False,
                root=ROOT,
                target_commit=TARGET_COMMIT,
            )
        git_bytes.assert_any_call(ROOT, TARGET_COMMIT, notary_schema)

    def test_manifest_hash_ref_and_artifact_set_drift_are_rejected(self) -> None:
        record = self.candidate()
        record["target_release_manifest"]["sha256"] = "sha256:" + "0" * 64
        record["candidate_artifact_set"]["artifacts"]["manifest"] = "sha256:" + "0" * 64
        record["candidate_artifact_set"]["sha256"] = self.module.canonical_sha256(
            record["candidate_artifact_set"]["artifacts"]
        )
        with self.assertRaisesRegex(self.module.ExerciseError, "does not match exact target"):
            self.validate_record(record, allow_template=False)
        record = self.candidate()
        record["target_release"]["source_ref"] = TARGET_COMMIT
        record["candidate_artifact_set"]["artifacts"]["p_release_inputs"] = (
            record["candidate_artifact_set"]["artifacts"]["t_release_inputs"]
        )
        record["candidate_artifact_set"]["sha256"] = self.module.canonical_sha256(
            record["candidate_artifact_set"]["artifacts"]
        )
        with self.assertRaisesRegex(self.module.ExerciseError, "identity does not match"):
            self.validate_record(record, allow_template=False)
        record = self.candidate()
        record["candidate_artifact_set"]["artifacts"]["t2_binaries"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(self.module.ExerciseError, "does not match its artifacts"):
            self.validate_record(record, allow_template=False)

    def test_candidate_image_lock_digest_matches_authenticated_asset_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            asset_root = Path(temporary)
            asset_dir = asset_root / "v0.12.2"
            asset_dir.mkdir()
            image_lock = asset_dir / "registryctl-v0.12.2-image-lock.json"
            image_lock.write_bytes(b'{"authenticated":"release image lock"}')
            record = self.candidate()
            artifacts = record["candidate_artifact_set"]["artifacts"]
            artifacts["image_lock"] = self.module.sha256_bytes(
                image_lock.read_bytes()
            )
            record["candidate_artifact_set"]["sha256"] = (
                self.module.canonical_sha256(artifacts)
            )
            candidate = self.module.load_candidate.return_value.copy()

            def authenticated_candidate(_manifest_path, lock_path):
                metadata = candidate.copy()
                metadata["image_lock_sha256"] = self.module.sha256_bytes(
                    lock_path.read_bytes()
                )
                return metadata

            with mock.patch.object(
                self.module,
                "load_candidate",
                side_effect=authenticated_candidate,
            ):
                self.validate_record(
                    record,
                    allow_template=False,
                    candidate_asset_root=asset_root,
                )
                image_lock.write_bytes(image_lock.read_bytes() + b"\n")
                with self.assertRaisesRegex(
                    self.module.ExerciseError,
                    "exact authenticated release image-lock",
                ):
                    self.validate_record(
                        record,
                        allow_template=False,
                        candidate_asset_root=asset_root,
                    )

    def test_candidate_evidence_requires_release_asset_directory(self) -> None:
        with self.assertRaisesRegex(
            self.module.ExerciseError, "--candidate-asset-root"
        ):
            self.module.validate_record(
                self.candidate(),
                allow_template=False,
                candidate_asset_root=None,
            )

    def test_missing_authentication_tools_or_assets_fail_closed(self) -> None:
        for detail in (
            "candidate authenticity verification requires installed cosign",
            "required file is unavailable: image lock",
        ):
            with self.subTest(detail=detail):
                with mock.patch.object(
                    self.module,
                    "load_candidate",
                    side_effect=self.module.CandidateError(detail),
                ):
                    with self.assertRaisesRegex(
                        self.module.ExerciseError,
                        "could not be authenticated",
                    ) as caught:
                        self.validate_record(
                            self.candidate(), allow_template=False
                        )
                self.assertNotIn(detail, str(caught.exception))

    def test_upgrade_consumer_enforces_candidate_to_released_closeout(
        self,
    ) -> None:
        candidate_module = sys.modules["conformance_candidate"]
        tagged_candidate = self.module.git_bytes(
            ROOT, TARGET_COMMIT, TARGET_MANIFEST
        )
        local_released = (ROOT / TARGET_MANIFEST).read_bytes()
        cases = (
            ("valid closeout", tagged_candidate, local_released, True),
            ("released at tag", local_released, local_released, False),
            (
                "post-tag drift",
                tagged_candidate,
                local_released + b"# Invalid post-tag manifest drift.\n",
                False,
            ),
        )
        for label, tagged, local, valid in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                asset_root = Path(temporary)
                asset_dir = asset_root / "v0.12.2"
                asset_dir.mkdir()
                image_lock = asset_dir / "registryctl-v0.12.2-image-lock.json"
                lock = {
                    "schema_version": "registryctl.release_image_lock.v1",
                    "release_tag": "v0.12.2",
                    "manifest_source_ref": (
                        "0e76f5ea61f78bbc15d91fcb6e9dfcaa956c3df8"
                    ),
                    "tag_target": TARGET_COMMIT,
                    "platform": "linux/amd64",
                    "images": {
                        "registry-notary": (
                            "ghcr.io/registrystack/registry-notary@sha256:"
                            + "b" * 64
                        ),
                        "registry-relay": (
                            "ghcr.io/registrystack/registry-relay@sha256:"
                            + "b" * 64
                        ),
                    },
                }
                lock_bytes = json.dumps(lock).encode("utf-8")
                image_lock.write_bytes(lock_bytes)
                record = self.candidate()
                artifacts = record["candidate_artifact_set"]["artifacts"]
                artifacts["image_lock"] = self.module.sha256_bytes(lock_bytes)
                record["candidate_artifact_set"]["sha256"] = (
                    self.module.canonical_sha256(artifacts)
                )

                @contextlib.contextmanager
                def snapshot(_image_lock_path):
                    yield asset_dir, lock_bytes

                real_git_output = candidate_module.git_output

                def git_output(arguments, max_bytes):
                    if arguments[0] == "cat-file":
                        return str(len(tagged)).encode("ascii")
                    if arguments[0] == "show":
                        return tagged
                    return real_git_output(arguments, max_bytes)

                with mock.patch.object(
                    self.module, "load_candidate", self.real_load_candidate
                ), mock.patch.object(
                    candidate_module,
                    "candidate_asset_snapshot",
                    snapshot,
                ), mock.patch.object(
                    candidate_module,
                    "read_regular_file_no_follow",
                    return_value=local,
                ), mock.patch.object(
                    candidate_module,
                    "git_output",
                    side_effect=git_output,
                ), mock.patch.object(
                    candidate_module,
                    "verify_release_asset_binding",
                    return_value="c" * 64,
                ):
                    if valid:
                        self.validate_record(
                            record,
                            allow_template=False,
                            candidate_asset_root=asset_root,
                        )
                    else:
                        with self.assertRaisesRegex(
                            self.module.ExerciseError,
                            "could not be authenticated",
                        ):
                            self.validate_record(
                                record,
                                allow_template=False,
                                candidate_asset_root=asset_root,
                            )

    def test_real_v0122_release_image_lock_authenticates(self) -> None:
        asset_root_value = os.environ.get("REGISTRY_TEST_UPGRADE_ASSET_ROOT")
        if not asset_root_value:
            self.skipTest(
                "REGISTRY_TEST_UPGRADE_ASSET_ROOT is required for real release assets"
            )
        asset_root = Path(asset_root_value)
        asset_dir = asset_root / "v0.12.2"
        image_lock = asset_dir / "registryctl-v0.12.2-image-lock.json"
        lock = json.loads(image_lock.read_text(encoding="utf-8"))
        record = self.candidate()
        artifacts = record["candidate_artifact_set"]["artifacts"]
        record["target_release"]["relay_image_digest"] = lock["images"][
            "registry-relay"
        ].split("@", 1)[1]
        record["target_release"]["notary_image_digest"] = lock["images"][
            "registry-notary"
        ].split("@", 1)[1]
        artifacts["relay_image"] = record["target_release"]["relay_image_digest"]
        artifacts["notary_image"] = record["target_release"][
            "notary_image_digest"
        ]
        artifacts["image_lock"] = self.module.sha256_bytes(
            image_lock.read_bytes()
        )
        record["candidate_artifact_set"]["sha256"] = (
            self.module.canonical_sha256(artifacts)
        )

        with mock.patch.object(
            self.module, "load_candidate", self.real_load_candidate
        ):
            self.validate_record(
                record,
                allow_template=False,
                require_all_passed=True,
                candidate_asset_root=asset_root,
            )

    def test_topology_requires_one_dedicated_notary_per_relay(self) -> None:
        record = self.candidate()
        record["topology"]["relay_authorities"].append("relay-authority-b")
        record["topology"]["authority_pairs"].append(
            {"relay": "relay-authority-b", "notary": "notary-authority-a"}
        )
        with self.assertRaisesRegex(self.module.ExerciseError, "dedicated Notary"):
            self.validate_record(record, allow_template=False)


if __name__ == "__main__":
    unittest.main()
