#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPT = Path(__file__).with_name("release_candidate.py")
SOURCE_SHA = "a" * 40
ARCHIVE_SHA = "b" * 64
IMAGE_DIGEST = "sha256:" + "c" * 64
CONFIG_DIGEST = "sha256:" + "d" * 64
LAYER_DIGEST = "sha256:" + "e" * 64
ATTESTATION_DIGEST = "sha256:" + "f" * 64


def load_module():
    spec = importlib.util.spec_from_file_location("release_candidate", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def fixture(root: Path, *, now: datetime) -> dict:
    payload = "registry-stack-release-candidate-payload-123-2"
    files = {
        "registry-stack-candidate-build-a-123-2/build.json": b'{"build":"a"}\n',
        "registry-stack-candidate-build-b-123-2/build.json": b'{"build":"b"}\n',
        "registry-stack-candidate-macos-arm64-123-2/build.json": b'{"platform":"macos"}\n',
        "registry-stack-candidate-linux-arm64-123-2/build.json": b'{"platform":"linux"}\n',
        f"{payload}/dist/bin/registryctl-v1.2.3-linux-amd64": b"registryctl",
        f"{payload}/dist/images/storage-measurement.json": b'{"peak_bytes":123}\n',
        f"{payload}/dist/grype/grype-db-status.json": b'{"status":"valid"}\n',
    }
    for name in ("registry-notary", "registry-relay"):
        files[f"{payload}/dist/sbom/{name}.spdx.json"] = f"{name} spdx".encode()
        files[f"{payload}/dist/sbom/{name}.syft.json"] = f"{name} syft".encode()
        files[f"{payload}/dist/grype/{name}.grype.json"] = f"{name} grype".encode()
    inventories: dict[str, list[dict]] = {}
    for relative, payload in sorted(files.items()):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        artifact_name = relative.split("/", 1)[0]
        inventories.setdefault(artifact_name, []).append(
            {"path": relative, "sha256": sha256(payload), "size": len(payload)}
        )
    payload = "registry-stack-release-candidate-payload-123-2"
    images = []
    for name in ("registry-notary", "registry-relay"):
        images.append(
            {
                "name": name,
                "staging_repository": f"ghcr.io/registrystack/{name}-candidate",
                "index_digest": IMAGE_DIGEST,
                "application_manifest_digest": ATTESTATION_DIGEST,
                "platform": "linux/amd64",
                "config_digest": CONFIG_DIGEST,
                "ordered_layer_digests": [LAYER_DIGEST],
                "topology": {
                    "application_descriptor": {
                        "digest": ATTESTATION_DIGEST,
                        "media_type": "application/vnd.oci.image.manifest.v1+json",
                        "platform": "linux/amd64",
                    },
                    "provenance_descriptors": [
                        {
                            "digest": "sha256:" + "8" * 64,
                            "media_type": "application/vnd.oci.image.manifest.v1+json",
                            "platform": "unknown/unknown",
                            "subject_digest": ATTESTATION_DIGEST,
                            "kind": "buildkit-provenance",
                        }
                    ],
                },
                "sbom": {
                    "spdx_path": f"{payload}/dist/sbom/{name}.spdx.json",
                    "spdx_sha256": sha256(
                        files[f"{payload}/dist/sbom/{name}.spdx.json"]
                    ),
                    "syft_json_path": f"{payload}/dist/sbom/{name}.syft.json",
                    "syft_json_sha256": sha256(
                        files[f"{payload}/dist/sbom/{name}.syft.json"]
                    ),
                },
                "scan": {
                    "grype_path": f"{payload}/dist/grype/{name}.grype.json",
                    "grype_sha256": sha256(
                        files[f"{payload}/dist/grype/{name}.grype.json"]
                    ),
                    "subject": (
                        f"ghcr.io/registrystack/{name}-candidate@{IMAGE_DIGEST}"
                    ),
                    "tool": {
                        "version": "0.114.0",
                        "binary_sha256": "33932517107dbb633f31756a757dc51433e520b81ba9b51f44c626ef9960b955",
                    },
                    "database": {
                        "checksum": "sha256:" + "7" * 64,
                        "built": (now - timedelta(hours=1)).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                        "fresh_until": (now + timedelta(days=4)).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                        "status_path": f"{payload}/dist/grype/grype-db-status.json",
                        "status_sha256": sha256(
                            files[f"{payload}/dist/grype/grype-db-status.json"]
                        ),
                    },
                },
                "comparison": {"config_equal": True, "layers_equal": True},
            }
        )
    created = now - timedelta(hours=1)
    return {
        "schema_version": "registry-stack.release-candidate-receipt.v1",
        "repository": "registrystack/registry-stack",
        "workflow": {
            "path": ".github/workflows/release-candidate.yml",
            "ref": "refs/heads/main",
            "sha": SOURCE_SHA,
            "run_id": 123,
            "run_attempt": 2,
            "event": "repository_dispatch",
        },
        "release": {
            "version": "1.2.3",
            "release_id": "beta-20",
            "source_sha": SOURCE_SHA,
            "tag": "v1.2.3",
            "proof_level": "standard",
        },
        "validity": {
            "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (created + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "builders": {
            "binary_image": "rust:1.95-trixie@sha256:" + "0" * 64,
            "binary_fingerprint": "1" * 64,
            "binary_recipe_fingerprint": "2" * 64,
            "image_buildkit_image": "moby/buildkit:v1@sha256:" + "3" * 64,
            "image_buildx_version": "v0.33.0",
            "image_recipe_fingerprint": "4" * 64,
        },
        "builds": {
            "a": {
                "job_id": "build-a-111",
                "cargo_cache": {
                    "mode": "exact-key-restore",
                    "primary_key": "candidate-cache-key",
                    "exact_key_hit": True,
                    "action_output": "true",
                },
            },
            "b": {
                "job_id": "build-b-222",
                "cargo_cache": {
                    "mode": "cold",
                    "primary_key": None,
                    "exact_key_hit": False,
                },
            },
            "other_platforms": [
                {"platform": "linux-arm64", "job_id": "platform-linux"},
                {"platform": "macos-arm64", "job_id": "platform-macos"},
            ],
        },
        "artifacts": [
            {
                "name": name,
                "artifact_id": 987 + index,
                "archive_sha256": ARCHIVE_SHA,
                "files": inventories[name],
            }
            for index, name in enumerate(sorted(inventories))
        ],
        "images": images,
        "comparisons": {
            "binary_bytes": True,
            "image_config_and_layers": True,
        },
        "scans": {"policy": "passed", "immutable_digests": True},
        "storage": {
            "budget_status": "measurement_required",
            "measurement_path": f"{payload}/dist/images/storage-measurement.json",
            "measurement_sha256": sha256(
                files[f"{payload}/dist/images/storage-measurement.json"]
            ),
        },
        "attestation": {
            "receipt_subject": "release-candidate-receipt.json",
            "workflow_identity": (
                "registrystack/registry-stack/"
                ".github/workflows/release-candidate.yml@refs/heads/main"
            ),
        },
        "promotion": {"state": "candidate", "identity": "beta-20:1.2.3"},
    }


class ReleaseCandidateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.now = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.receipt = fixture(self.root, now=self.now)
        self.expected_builders = copy.deepcopy(self.receipt["builders"])
        self.workflow_run_metadata = {
            "id": 123,
            "run_attempt": 2,
            "event": "repository_dispatch",
            "head_sha": SOURCE_SHA,
            "path": ".github/workflows/release-candidate.yml",
            "conclusion": "success",
            "created_at": (self.now - timedelta(hours=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        self.artifact_metadata = {
            record["artifact_id"]: (record["name"], record["archive_sha256"])
            for record in self.receipt["artifacts"]
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verify(self, receipt: dict | None = None, **kwargs):
        workflow_run_metadata = kwargs.pop(
            "workflow_run_metadata", self.workflow_run_metadata
        )
        return self.module.validate_receipt(
            receipt or self.receipt,
            artifact_root=self.root,
            artifact_metadata=self.artifact_metadata,
            expected_source_sha=SOURCE_SHA,
            expected_version="1.2.3",
            expected_release_id="beta-20",
            expected_run_id=123,
            expected_run_attempt=2,
            now=self.now,
            promotion=True,
            workflow_run_metadata=workflow_run_metadata,
            expected_builders=self.expected_builders,
            **kwargs,
        )

    def test_valid_closed_receipt_passes_promotion(self) -> None:
        validated = self.verify()
        self.assertEqual("beta-20:1.2.3", validated["promotion"]["identity"])

    def test_single_build_candidate_records_comparisons_as_not_performed(self) -> None:
        candidate = copy.deepcopy(self.receipt)
        del candidate["builds"]["b"]
        candidate["artifacts"] = [
            artifact
            for artifact in candidate["artifacts"]
            if not artifact["name"].startswith("registry-stack-candidate-build-b-")
        ]
        (
            self.root
            / "registry-stack-candidate-build-b-123-2"
            / "build.json"
        ).unlink()
        candidate["comparisons"] = {
            "binary_bytes": False,
            "image_config_and_layers": False,
        }
        for image in candidate["images"]:
            image["comparison"] = {
                "config_equal": False,
                "layers_equal": False,
            }

        self.verify(candidate)

    def test_exact_attempt_artifact_inventory_includes_receipt(self) -> None:
        artifacts = []
        for index, name in enumerate(
            sorted(self.module.expected_attempt_artifact_names(123, 2))
        ):
            artifacts.append(
                {
                    "id": 1000 + index,
                    "name": name,
                    "digest": "sha256:" + f"{index + 1:064x}",
                    "expired": False,
                    "workflow_run": {"id": 123},
                }
            )
        for index, name in enumerate(
            sorted(self.module.expected_attempt_artifact_names(123, 1))
        ):
            artifacts.append(
                {
                    "id": 2000 + index,
                    "name": name,
                    "digest": "sha256:" + f"{index + 20:064x}",
                    "expired": False,
                    "workflow_run": {"id": 123},
                }
            )
        selected = self.module.validate_attempt_artifact_inventory(
            {"artifacts": artifacts},
            run_id=123,
            run_attempt=2,
        )
        self.assertEqual(
            self.module.expected_attempt_artifact_names(123, 2), set(selected)
        )

        platform_report = {
            "id": 9998,
            "name": "registry-stack-candidate-cli-linux-arm64-123-2",
            "digest": "sha256:" + "8" * 64,
            "expired": False,
            "workflow_run": {"id": 123},
        }
        selected = self.module.validate_attempt_artifact_inventory(
            {"artifacts": [*artifacts, platform_report]},
            run_id=123,
            run_attempt=2,
        )
        self.assertIn(platform_report["name"], selected)

        with self.assertRaisesRegex(self.module.CandidateError, "incomplete"):
            self.module.validate_attempt_artifact_inventory(
                {
                    "artifacts": [
                        item
                        for item in artifacts
                        if item["name"] != "registry-stack-candidate-build-a-123-2"
                    ]
                },
                run_id=123,
                run_attempt=2,
            )

        unexpected = copy.deepcopy(artifacts)
        unexpected.append(
            {
                "id": 9999,
                "name": "registry-stack-candidate-unknown-123-2",
                "digest": "sha256:" + "9" * 64,
                "expired": False,
                "workflow_run": {"id": 123},
            }
        )
        with self.assertRaisesRegex(self.module.CandidateError, "unexpected"):
            self.module.validate_attempt_artifact_inventory(
                {"artifacts": unexpected},
                run_id=123,
                run_attempt=2,
            )

    def test_full_github_run_api_response_is_normalized_to_closed_metadata(
        self,
    ) -> None:
        response = {
            **self.workflow_run_metadata,
            "html_url": "https://github.com/registrystack/registry-stack/actions/runs/123",
            "actor": {"login": "release-operator"},
            "repository": {"full_name": "registrystack/registry-stack"},
            "jobs_url": "https://api.github.test/runs/123/jobs",
        }
        self.assertEqual(
            self.workflow_run_metadata,
            self.module.workflow_run_from_json(response),
        )
        self.verify(workflow_run_metadata=self.module.workflow_run_from_json(response))

    def test_slsa_subject_contract_rejects_one_extra_provenance_subject(self) -> None:
        contract = self.root / "subjects.json"
        provenance = self.root / "provenance.intoto.jsonl"
        expected = [
            {"name": "registryctl-v1.2.3-linux-amd64", "sha256": "1" * 64},
            {"name": "SHA256SUMS", "sha256": "2" * 64},
        ]
        contract.write_text(json.dumps(expected), encoding="utf-8")

        def write_provenance(subjects: list[dict]) -> None:
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {"name": item["name"], "digest": {"sha256": item["sha256"]}}
                    for item in subjects
                ],
            }
            envelope = {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                "signatures": [{"keyid": "", "sig": "signature"}],
            }
            provenance.write_text(json.dumps(envelope) + "\n", encoding="utf-8")

        write_provenance(expected)
        self.assertEqual(
            {
                ("registryctl-v1.2.3-linux-amd64", "1" * 64),
                ("SHA256SUMS", "2" * 64),
            },
            self.module.validate_slsa_subject_set(provenance, contract),
        )

        write_provenance(
            [
                *expected,
                {"name": "uncontracted", "sha256": "3" * 64},
            ]
        )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "subject set mismatch",
        ):
            self.module.validate_slsa_subject_set(provenance, contract)

        contract.write_text(
            json.dumps(
                [
                    *expected,
                    {
                        "name": "SHA256SUMS",
                        "sha256": "4" * 64,
                    },
                ]
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "duplicates name",
        ):
            self.module.validate_slsa_subject_set(provenance, contract)

    def test_artifact_archive_hash_and_paths_fail_closed(self) -> None:
        archive = self.root / "artifact.zip"
        destination = self.root / "extracted"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("payload/file.txt", b"candidate")
        archive_sha = self.module.sha256_file(archive)
        self.module.extract_artifact_archive(
            archive,
            destination,
            expected_sha256=archive_sha,
        )
        self.assertEqual(b"candidate", (destination / "payload/file.txt").read_bytes())
        with self.assertRaisesRegex(self.module.CandidateError, "sha256 mismatch"):
            self.module.extract_artifact_archive(
                archive,
                self.root / "bad-hash",
                expected_sha256="9" * 64,
            )

        unsafe = self.root / "unsafe.zip"
        with zipfile.ZipFile(unsafe, "w") as bundle:
            bundle.writestr("../escape", b"no")
        with self.assertRaisesRegex(self.module.CandidateError, "unsafe path"):
            self.module.extract_artifact_archive(
                unsafe,
                self.root / "unsafe-extracted",
                expected_sha256=self.module.sha256_file(unsafe),
            )

    def test_promotion_state_rejects_replay_and_partial_publication(self) -> None:
        receipt_sha = sha256(self.module.canonical_json(self.receipt))
        empty = {
            "schema_version": "registry-stack.release-promotion-state.v1",
            "github_release": {"exists": False, "asset_names": []},
            "public_images": {
                "registry-notary": None,
                "registry-relay": None,
            },
            "promoted_candidates": [],
        }
        self.module.validate_promotion_state(
            empty,
            receipt=self.receipt,
            receipt_sha256=receipt_sha,
            phase="prewrite",
        )

        partial = copy.deepcopy(empty)
        partial["public_images"]["registry-notary"] = IMAGE_DIGEST
        with self.assertRaisesRegex(self.module.CandidateError, "partial publication"):
            self.module.validate_promotion_state(
                partial,
                receipt=self.receipt,
                receipt_sha256=receipt_sha,
                phase="prewrite",
            )

        replay = copy.deepcopy(empty)
        replay["promoted_candidates"].append(
            {
                "identity": "beta-20:1.2.3",
                "run_id": 999,
                "run_attempt": 1,
                "receipt_sha256": "9" * 64,
            }
        )
        with self.assertRaisesRegex(
            self.module.CandidateError, "already been promoted"
        ):
            self.module.validate_promotion_state(
                replay,
                receipt=self.receipt,
                receipt_sha256=receipt_sha,
                phase="prewrite",
            )

        promoted = copy.deepcopy(empty)
        promoted["public_images"] = {
            "registry-notary": IMAGE_DIGEST,
            "registry-relay": IMAGE_DIGEST,
        }
        self.module.validate_promotion_state(
            promoted,
            receipt=self.receipt,
            receipt_sha256=receipt_sha,
            phase="prerelease",
        )

    def test_cache_restore_miss_is_recorded_not_rejected(self) -> None:
        self.receipt["builds"]["a"]["cargo_cache"]["exact_key_hit"] = False
        self.receipt["builds"]["a"]["cargo_cache"]["action_output"] = "false"
        self.verify()

    def test_payload_mutation_fails(self) -> None:
        (
            self.root
            / "registry-stack-release-candidate-payload-123-2/dist/bin/registryctl-v1.2.3-linux-amd64"
        ).write_bytes(b"tampered")
        with self.assertRaisesRegex(self.module.CandidateError, "sha256 mismatch"):
            self.verify()

    def test_partial_or_extra_upload_fails_exact_inventory(self) -> None:
        missing = (
            self.root
            / "registry-stack-release-candidate-payload-123-2/dist/grype/registry-relay.grype.json"
        )
        missing.unlink()
        with self.assertRaisesRegex(self.module.CandidateError, "regular non-symlink"):
            self.verify()
        missing.write_bytes(b"registry-relay grype")
        (self.root / "unexpected").write_text("unexpected", encoding="utf-8")
        with self.assertRaisesRegex(self.module.CandidateError, "inventory mismatch"):
            self.verify()

    def test_replay_of_promoted_identity_fails(self) -> None:
        with self.assertRaisesRegex(
            self.module.CandidateError, "already been promoted"
        ):
            self.verify(promoted_identities={"beta-20:1.2.3"})

    def test_stale_expired_and_future_dated_candidates_fail(self) -> None:
        stale = copy.deepcopy(self.receipt)
        stale["validity"]["created_at"] = (self.now - timedelta(hours=73)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        stale["validity"]["expires_at"] = (self.now + timedelta(days=3)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self.assertRaisesRegex(self.module.CandidateError, "stale"):
            workflow_run = dict(self.workflow_run_metadata)
            workflow_run["created_at"] = (self.now - timedelta(hours=74)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.module.validate_receipt(
                stale,
                artifact_root=self.root,
                artifact_metadata=self.artifact_metadata,
                now=self.now,
                promotion=True,
                workflow_run_metadata=workflow_run,
                expected_builders=self.expected_builders,
            )

        future = copy.deepcopy(self.receipt)
        future["validity"]["created_at"] = (self.now + timedelta(minutes=6)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        future["validity"]["expires_at"] = (self.now + timedelta(days=6)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self.assertRaisesRegex(self.module.CandidateError, "future-dated"):
            self.verify(future)

    def test_mutation_matrix_fails_closed(self) -> None:
        mutations = {
            "source sha": lambda r: r["release"].__setitem__("source_sha", "9" * 40),
            "workflow identity": lambda r: r["workflow"].__setitem__(
                "path", ".github/workflows/ci.yml"
            ),
            "run attempt": lambda r: r["workflow"].__setitem__("run_attempt", 3),
            "release input": lambda r: r["release"].__setitem__(
                "release_id", "beta-21"
            ),
            "builder fingerprint": lambda r: r["builders"].__setitem__(
                "binary_fingerprint", "9" * 64
            ),
            "artifact digest": lambda r: r["artifacts"][0].__setitem__(
                "archive_sha256", "9" * 64
            ),
            "OCI digest": lambda r: r["images"][0].__setitem__(
                "index_digest", "sha256:" + "9" * 64
            ),
            "scan coordinate": lambda r: r["images"][0]["scan"].__setitem__(
                "subject",
                "ghcr.io/registrystack/registry-notary-candidate@" + CONFIG_DIGEST,
            ),
            "receipt attestation identity": lambda r: r["attestation"].__setitem__(
                "workflow_identity",
                "registrystack/other/.github/workflows/release.yml@main",
            ),
            "binary comparison": lambda r: r["comparisons"].__setitem__(
                "binary_bytes", False
            ),
            "image config comparison": lambda r: r["images"][0][
                "comparison"
            ].__setitem__("config_equal", False),
            "scan policy": lambda r: r["scans"].__setitem__("policy", "failed"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                candidate = copy.deepcopy(self.receipt)
                mutate(candidate)
                with self.assertRaises(self.module.CandidateError):
                    self.verify(candidate)

    def test_unknown_fields_fail_closed_at_every_security_boundary(self) -> None:
        for path in (
            (),
            ("workflow",),
            ("release",),
            ("builders",),
            ("builds", "a", "cargo_cache"),
            ("artifacts", 0),
            ("images", 0, "scan"),
            ("attestation",),
            ("promotion",),
        ):
            candidate = copy.deepcopy(self.receipt)
            target = candidate
            for part in path:
                target = target[part]
            target["unexpected"] = True
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                    self.module.CandidateError, "non-closed schema"
                ):
                    self.verify(candidate)

    def test_artifact_api_cross_attempt_mismatch_fails(self) -> None:
        with self.assertRaisesRegex(self.module.CandidateError, "metadata mismatch"):
            self.module.validate_receipt(
                self.receipt,
                artifact_root=self.root,
                artifact_metadata={
                    key + 100: value for key, value in self.artifact_metadata.items()
                },
                expected_run_id=123,
                expected_run_attempt=2,
                now=self.now,
                promotion=True,
                workflow_run_metadata=self.workflow_run_metadata,
                expected_builders=self.expected_builders,
            )

    def test_attempt_bound_artifact_name_substitution_or_extra_fails(self) -> None:
        substituted = copy.deepcopy(self.receipt)
        substituted["artifacts"][0]["name"] = "registry-stack-candidate-build-a-123-1"
        with self.assertRaisesRegex(self.module.CandidateError, "attempt-bound"):
            self.module.validate_receipt(
                substituted,
                now=self.now,
                promotion=True,
                workflow_run_metadata=self.workflow_run_metadata,
                expected_builders=self.expected_builders,
            )

        extra = copy.deepcopy(self.receipt)
        record = copy.deepcopy(extra["artifacts"][0])
        record["name"] = "registry-stack-candidate-extra-123-2"
        record["artifact_id"] = 9999
        record["files"][0]["path"] = "extra/file"
        extra["artifacts"].append(record)
        with self.assertRaises(self.module.CandidateError):
            self.module.validate_receipt(
                extra,
                now=self.now,
                promotion=True,
                workflow_run_metadata=self.workflow_run_metadata,
                expected_builders=self.expected_builders,
            )

    def test_topology_change_extra_and_misbound_provenance_fail(self) -> None:
        changed = copy.deepcopy(self.receipt)
        changed["images"][0]["topology"]["application_descriptor"]["digest"] = (
            "sha256:" + "7" * 64
        )
        with self.assertRaisesRegex(
            self.module.CandidateError, "application descriptor"
        ):
            self.verify(changed)

        extra = copy.deepcopy(self.receipt)
        extra["images"][0]["topology"]["unexpected_descriptors"] = []
        with self.assertRaisesRegex(self.module.CandidateError, "non-closed schema"):
            self.verify(extra)

        misbound = copy.deepcopy(self.receipt)
        misbound["images"][0]["topology"]["provenance_descriptors"][0][
            "subject_digest"
        ] = CONFIG_DIGEST
        with self.assertRaisesRegex(self.module.CandidateError, "not bound"):
            self.verify(misbound)

    def test_trusted_run_age_and_timestamp_substitution_fail(self) -> None:
        fresh_receipt = copy.deepcopy(self.receipt)
        workflow_run = dict(self.workflow_run_metadata)
        workflow_run["created_at"] = (self.now - timedelta(hours=73)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self.assertRaisesRegex(self.module.CandidateError, "stale"):
            self.module.validate_receipt(
                fresh_receipt,
                artifact_root=self.root,
                artifact_metadata=self.artifact_metadata,
                now=self.now,
                promotion=True,
                workflow_run_metadata=workflow_run,
            )

        substituted = copy.deepcopy(self.receipt)
        substituted["validity"]["created_at"] = (
            self.now - timedelta(hours=3)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        substituted["validity"]["expires_at"] = (
            self.now - timedelta(hours=3) + timedelta(days=7)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(self.module.CandidateError, "predates"):
            self.verify(substituted)

    def test_tag_binding_is_closed_and_binds_exact_receipt(self) -> None:
        receipt_path = self.root.parent / "receipt.json"
        receipt_path.write_bytes(self.module.canonical_json(self.receipt))
        receipt_sha = self.module.sha256_file(receipt_path)
        message = self.module.render_tag_binding(123, 2, receipt_sha)
        self.assertEqual(
            {
                "run_id": 123,
                "run_attempt": 2,
                "receipt_sha256": receipt_sha,
            },
            self.module.parse_tag_binding(message),
        )
        self.assertEqual(
            self.module.parse_tag_binding(message),
            self.module.parse_tag_binding(message + "\n"),
        )
        for tampered in (
            message + "\n\n",
            message + "extra: accepted\n",
            message.replace("run_attempt: 2", "run_attempt: 3"),
            message.replace(
                TAG_LINE := f"receipt_sha256: {receipt_sha}", TAG_LINE.upper()
            ),
        ):
            if "run_attempt: 3" in tampered:
                parsed = self.module.parse_tag_binding(tampered)
                self.assertNotEqual(2, parsed["run_attempt"])
            else:
                with self.assertRaises(self.module.CandidateError):
                    self.module.parse_tag_binding(tampered)

    def test_seal_writes_canonical_bytes_and_refuses_open_draft(self) -> None:
        draft = self.root.parent / "draft.json"
        output = self.root.parent / "sealed.json"
        draft.write_text(json.dumps(self.receipt), encoding="utf-8")
        self.module.write_closed_receipt(draft, output)
        self.assertEqual(self.module.canonical_json(self.receipt), output.read_bytes())
        self.receipt["unknown"] = True
        draft.write_text(json.dumps(self.receipt), encoding="utf-8")
        with self.assertRaisesRegex(self.module.CandidateError, "non-closed schema"):
            self.module.write_closed_receipt(draft, output)


if __name__ == "__main__":
    unittest.main()
