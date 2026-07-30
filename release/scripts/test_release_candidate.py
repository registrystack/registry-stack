#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("release_candidate.py")
SOURCE_SHA = "a" * 40
ARCHIVE_SHA = "b" * 64
IMAGE_DIGEST = "sha256:" + "c" * 64
CONFIG_DIGEST = "sha256:" + "d" * 64
LAYER_DIGEST = "sha256:" + "e" * 64
ATTESTATION_DIGEST = "sha256:" + "f" * 64
POSTGRESQL_REF = (
    SCRIPT.parent.parent / "registryctl-postgresql-image.ref"
).read_text(encoding="utf-8").strip()


def load_module():
    spec = importlib.util.spec_from_file_location("release_candidate", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def security_evidence_members() -> dict[str, bytes]:
    refs = {
        name: f"ghcr.io/registrystack/{name}-candidate@{IMAGE_DIGEST}"
        for name in ("registry-notary", "registry-relay")
    }
    refs["postgresql"] = POSTGRESQL_REF
    members = {
        "images/postgresql.digest": f"{POSTGRESQL_REF}\n".encode(),
        "grype/grype-db-status.json": json_bytes({"status": "valid"}),
        "advisory-verdict.json": json_bytes(
            {
                "schema_version": "registry-stack.advisory-verdict.v2",
                "verdict": "passed",
                "subjects": [
                    "registry-notary-image",
                    "registry-relay-image",
                    "postgresql-runtime",
                ],
            }
        ),
    }
    for name, image_ref in refs.items():
        spdx = {"spdxVersion": "SPDX-2.3", "packages": []}
        if name == "postgresql":
            subject_id = "SPDXRef-RegistryStack-postgresql-digest-subject"
            spdx["documentDescribes"] = [subject_id]
            spdx["packages"] = [
                {
                    "SPDXID": subject_id,
                    "name": image_ref,
                    "externalRefs": [
                        {
                            "referenceLocator": (
                                "pkg:oci/postgresql@"
                                f"{image_ref.rsplit('@', 1)[1]}"
                            )
                        }
                    ],
                }
            ]
        members[f"image-sbom/{name}.spdx.json"] = json_bytes(spdx)
        members[f"syft/{name}.syft.json"] = json_bytes(
            {
                "artifacts": [],
                "source": {
                    "type": "image",
                    "target": {"userInput": image_ref},
                },
            }
        )
        members[f"grype/{name}.grype.json"] = json_bytes(
            {
                "matches": [],
                "source": {
                    "type": "image",
                    "target": {"userInput": image_ref},
                },
                "descriptor": {
                    "db": {
                        "built": "2026-07-29T00:00:00Z",
                        "checksum": "sha256:" + "2" * 64,
                    }
                },
            }
        )
    return members


def security_evidence_tar(
    entries: list[tuple[str, bytes]],
    *,
    link: tuple[str, str] | None = None,
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for directory in ("images", "image-sbom", "syft", "grype"):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(info)
        for name, payload in entries:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
        if link is not None:
            name, target = link
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)
    return output.getvalue()


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

        def write_provenance(
            subjects: list[dict],
            *,
            github_attestation_bundle: bool = False,
        ) -> None:
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
            document = (
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "dsseEnvelope": envelope,
                    "verificationMaterial": {},
                }
                if github_attestation_bundle
                else envelope
            )
            provenance.write_text(json.dumps(document) + "\n", encoding="utf-8")

        write_provenance(expected)
        self.assertEqual(
            {
                ("registryctl-v1.2.3-linux-amd64", "1" * 64),
                ("SHA256SUMS", "2" * 64),
            },
            self.module.validate_slsa_subject_set(provenance, contract),
        )

        write_provenance(expected, github_attestation_bundle=True)
        self.assertEqual(
            {
                ("registryctl-v1.2.3-linux-amd64", "1" * 64),
                ("SHA256SUMS", "2" * 64),
            },
            self.module.validate_slsa_subject_set(provenance, contract),
        )

        provenance.write_text(
            json.dumps({"dsseEnvelope": []}) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "not a valid DSSE statement",
        ):
            self.module.validate_slsa_subject_set(provenance, contract)

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

    def test_stale_scan_database_fails(self) -> None:
        stale = copy.deepcopy(self.receipt)
        stale["images"][0]["scan"]["database"]["built"] = (
            self.now - timedelta(days=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        stale["images"][0]["scan"]["database"]["fresh_until"] = (
            self.now - timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(self.module.CandidateError, "database is stale"):
            self.verify(stale)

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

    def test_tag_binding_is_closed_and_binds_exact_manifest(self) -> None:
        receipt_path = self.root.parent / "receipt.json"
        receipt_path.write_bytes(self.module.canonical_json(self.receipt))
        receipt_sha = self.module.sha256_file(receipt_path)
        message = self.module.render_tag_binding(123, 2, receipt_sha)
        self.assertEqual(
            {
                "schema_version": "registry-stack.release-candidate.v2",
                "run_id": 123,
                "run_attempt": 2,
                "manifest_sha256": receipt_sha,
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
                TAG_LINE := f"manifest_sha256: {receipt_sha}", TAG_LINE.upper()
            ),
        ):
            if "run_attempt: 3" in tampered:
                parsed = self.module.parse_tag_binding(tampered)
                self.assertNotEqual(2, parsed["run_attempt"])
            else:
                with self.assertRaises(self.module.CandidateError):
                    self.module.parse_tag_binding(tampered)

        legacy = self.module.render_legacy_tag_binding(123, 2, receipt_sha)
        self.assertEqual(
            {
                "schema_version": "registry-stack.release-candidate-receipt.v1",
                "run_id": 123,
                "run_attempt": 2,
                "receipt_sha256": receipt_sha,
            },
            self.module.parse_tag_binding(legacy),
        )

    def replace_security_evidence(
        self,
        candidate: dict,
        bundle_root: Path,
        payload: bytes,
    ) -> Path:
        record = next(
            item
            for item in candidate["payloads"]
            if item["kind"] == "security-evidence"
        )
        path = bundle_root / record["name"]
        path.write_bytes(payload)
        record["size"] = len(payload)
        record["sha256"] = sha256(payload)
        return path

    def make_v2_candidate(self) -> tuple[dict, Path, Path, dict]:
        bundle_root = self.root.parent / "v2-bundle"
        evidence_members = security_evidence_members()
        evidence_name = "registry-stack-v1.2.3-security-evidence.tar.gz"
        files = {
            "registryctl-v1.2.3-linux-amd64": b"registryctl",
            "registry-docs-v1.2.3.tar.gz": b"docs",
            "registry-stack-v1.2.3.sbom.spdx.json": b"sbom",
            "security/registry-notary.grype.json": evidence_members[
                "grype/registry-notary.grype.json"
            ],
            "security/registry-relay.grype.json": evidence_members[
                "grype/registry-relay.grype.json"
            ],
            "security/advisory-verdict.json": evidence_members[
                "advisory-verdict.json"
            ],
            evidence_name: security_evidence_tar(
                sorted(evidence_members.items())
            ),
        }
        for name, payload in files.items():
            path = bundle_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        bundle_path = self.root.parent / "registry-stack-v1.2.3-candidate.tar.gz"
        with tarfile.open(bundle_path, "w:gz") as archive:
            for name in sorted(files):
                archive.add(bundle_root / name, arcname=name)
        workflow_revision = SOURCE_SHA
        created = self.now - timedelta(hours=1)
        candidate = {
            "schema_version": "registry-stack.release-candidate.v2",
            "repository": "registrystack/registry-stack",
            "release": {
                "version": "1.2.3",
                "release_id": "beta-20",
                "tag": "v1.2.3",
                "source_sha": SOURCE_SHA,
            },
            "workflow": {
                "path": ".github/workflows/release-candidate.yml",
                "revision": workflow_revision,
                "run_id": 123,
                "run_attempt": 2,
            },
            "validity": {
                "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": (created + timedelta(hours=24)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            },
            "payloads": [
                {
                    "name": name,
                    "kind": kind,
                    "size": len(files[name]),
                    "sha256": sha256(files[name]),
                }
                for name, kind in (
                    ("registryctl-v1.2.3-linux-amd64", "binary"),
                    ("registry-docs-v1.2.3.tar.gz", "docs"),
                    ("registry-stack-v1.2.3.sbom.spdx.json", "sbom"),
                    (evidence_name, "security-evidence"),
                )
            ],
            "images": [
                {
                    "name": name,
                    "candidate_ref": (
                        f"ghcr.io/registrystack/{name}-candidate@{IMAGE_DIGEST}"
                    ),
                    "digest": IMAGE_DIGEST,
                    "final_ref": f"ghcr.io/registrystack/{name}:v1.2.3",
                }
                for name in ("registry-notary", "registry-relay")
            ],
            "docs": {
                "name": "registry-docs-v1.2.3.tar.gz",
                "sha256": sha256(files["registry-docs-v1.2.3.tar.gz"]),
            },
            "sbom": {
                "name": "registry-stack-v1.2.3.sbom.spdx.json",
                "sha256": sha256(
                    files["registry-stack-v1.2.3.sbom.spdx.json"]
                ),
            },
            "scans": [
                {
                    "image": name,
                    "name": f"security/{name}.grype.json",
                    "sha256": sha256(files[f"security/{name}.grype.json"]),
                    "status": "passed",
                }
                for name in ("registry-notary", "registry-relay")
            ],
            "advisory": {
                "name": "security/advisory-verdict.json",
                "sha256": sha256(files["security/advisory-verdict.json"]),
                "verdict": "passed",
            },
            "bundle": {
                "name": bundle_path.name,
                "size": bundle_path.stat().st_size,
                "sha256": sha256(bundle_path.read_bytes()),
            },
        }
        run = {
            "id": 123,
            "run_attempt": 2,
            "event": "repository_dispatch",
            "head_sha": workflow_revision,
            "path": ".github/workflows/release-candidate.yml",
            "conclusion": "success",
            "created_at": (self.now - timedelta(hours=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        return candidate, bundle_path, bundle_root, run

    def test_v2_candidate_requires_source_to_equal_workflow_revision(self) -> None:
        candidate, bundle_path, bundle_root, run = self.make_v2_candidate()
        validated = self.module.validate_candidate_manifest(
            candidate,
            bundle_path=bundle_path,
            bundle_root=bundle_root,
            expected_source_sha=SOURCE_SHA,
            expected_workflow_revision=SOURCE_SHA,
            now=self.now,
            promotion=True,
            workflow_run_metadata=run,
        )
        self.assertEqual(
            validated["release"]["source_sha"],
            validated["workflow"]["revision"],
        )
        mismatched = copy.deepcopy(candidate)
        mismatched["workflow"]["revision"] = "b" * 40
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "release.source_sha must equal workflow.revision",
        ):
            self.module.validate_candidate_manifest(
                mismatched,
                now=self.now,
            )

    def test_v2_schema_and_runtime_require_one_named_security_evidence_payload(
        self,
    ) -> None:
        schema = json.loads(
            (
                SCRIPT.parent.parent
                / "schemas"
                / "release-candidate-v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        payload_schema = schema["properties"]["payloads"]
        self.assertEqual(1, payload_schema["minContains"])
        self.assertEqual(1, payload_schema["maxContains"])
        self.assertEqual(
            "security-evidence",
            payload_schema["contains"]["properties"]["kind"]["const"],
        )

        candidate, _, _, _ = self.make_v2_candidate()
        evidence = next(
            item
            for item in candidate["payloads"]
            if item["kind"] == "security-evidence"
        )
        removed = copy.deepcopy(candidate)
        removed["payloads"] = [
            item
            for item in removed["payloads"]
            if item["kind"] != "security-evidence"
        ]
        duplicated = copy.deepcopy(candidate)
        duplicate = copy.deepcopy(evidence)
        duplicate["name"] = "duplicate-security-evidence.tar.gz"
        duplicated["payloads"].append(duplicate)
        wrong_name = copy.deepcopy(candidate)
        next(
            item
            for item in wrong_name["payloads"]
            if item["kind"] == "security-evidence"
        )["name"] = "security-evidence.tar.gz"
        for changed, message in (
            (removed, "exactly one security-evidence"),
            (duplicated, "exactly one security-evidence"),
            (
                wrong_name,
                "security-evidence payload name must be "
                "registry-stack-v1.2.3-security-evidence.tar.gz",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.module.validate_candidate_manifest(
                        changed,
                        now=self.now,
                    )

    def test_v2_security_evidence_archive_requires_every_expected_file(
        self,
    ) -> None:
        candidate, _, bundle_root, _ = self.make_v2_candidate()
        members = security_evidence_members()
        for missing in sorted(self.module.SECURITY_EVIDENCE_REQUIRED_FILES):
            with self.subTest(missing=missing):
                incomplete = [
                    item
                    for item in sorted(members.items())
                    if item[0] != missing
                ]
                self.replace_security_evidence(
                    candidate,
                    bundle_root,
                    security_evidence_tar(incomplete),
                )
                with self.assertRaisesRegex(
                    self.module.CandidateError,
                    "security evidence archive is incomplete",
                ):
                    self.module.validate_candidate_manifest(
                        candidate,
                        bundle_root=bundle_root,
                        now=self.now,
                    )

    def test_v2_security_evidence_archive_rejects_unsafe_structure(
        self,
    ) -> None:
        candidate, _, bundle_root, _ = self.make_v2_candidate()
        members = sorted(security_evidence_members().items())
        cases = (
            (
                security_evidence_tar(members + [("../escape", b"escape")]),
                "unsafe path",
            ),
            (
                security_evidence_tar(members + [members[0]]),
                "duplicate path",
            ),
            (
                security_evidence_tar(
                    members,
                    link=("grype/latest", "postgresql.grype.json"),
                ),
                "non-regular entry",
            ),
            (
                security_evidence_tar(
                    members + [("metadata/unexpected.json", b"{}")]
                ),
                "unexpected top-level structure",
            ),
            (
                security_evidence_tar(
                    members + [("grype/unexpected.json", b"{}")]
                ),
                "unexpected member",
            ),
        )
        for payload, message in cases:
            with self.subTest(message=message):
                self.replace_security_evidence(candidate, bundle_root, payload)
                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.module.validate_candidate_manifest(
                        candidate,
                        bundle_root=bundle_root,
                        now=self.now,
                    )

    def test_v2_security_evidence_archive_enforces_resource_bounds(self) -> None:
        candidate, _, bundle_root, _ = self.make_v2_candidate()
        for limit, message in (
            ("SECURITY_EVIDENCE_MAX_ARCHIVE_SIZE", "archive size"),
            ("SECURITY_EVIDENCE_MAX_ENTRY_SIZE", "entry .* size bound"),
            ("SECURITY_EVIDENCE_MAX_TOTAL_SIZE", "total size bound"),
            ("SECURITY_EVIDENCE_MAX_MEMBERS", "too many entries"),
        ):
            with self.subTest(limit=limit):
                with (
                    mock.patch.object(self.module, limit, 1),
                    self.assertRaisesRegex(self.module.CandidateError, message),
                ):
                    self.module.validate_candidate_manifest(
                        candidate,
                        bundle_root=bundle_root,
                        now=self.now,
                    )

    def test_v2_security_evidence_archive_rejects_unbound_contents(self) -> None:
        candidate, _, bundle_root, _ = self.make_v2_candidate()
        base = security_evidence_members()

        invalid_digest = dict(base)
        invalid_digest["images/postgresql.digest"] = (
            b"docker.io/library/postgres:latest\n"
        )

        unreviewed_digest = dict(base)
        unreviewed_digest["images/postgresql.digest"] = (
            b"docker.io/library/postgres@sha256:" + b"9" * 64 + b"\n"
        )

        unbound_spdx = dict(base)
        spdx = json.loads(unbound_spdx["image-sbom/postgresql.spdx.json"])
        spdx["documentDescribes"] = []
        unbound_spdx["image-sbom/postgresql.spdx.json"] = json_bytes(spdx)

        incomplete_verdict = dict(base)
        verdict = json.loads(incomplete_verdict["advisory-verdict.json"])
        verdict["subjects"].remove("postgresql-runtime")
        incomplete_verdict["advisory-verdict.json"] = json_bytes(verdict)

        substituted_scan = dict(base)
        scan = json.loads(substituted_scan["grype/registry-notary.grype.json"])
        scan["substituted"] = True
        substituted_scan["grype/registry-notary.grype.json"] = json_bytes(scan)

        for members, message in (
            (invalid_digest, "PostgreSQL digest is not canonical or immutable"),
            (unreviewed_digest, "does not match the reviewed release image"),
            (unbound_spdx, "PostgreSQL SPDX subject is not bound"),
            (incomplete_verdict, "does not cover every runtime"),
            (substituted_scan, "does not match its scan payload"),
        ):
            with self.subTest(message=message):
                self.replace_security_evidence(
                    candidate,
                    bundle_root,
                    security_evidence_tar(sorted(members.items())),
                )
                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.module.validate_candidate_manifest(
                        candidate,
                        bundle_root=bundle_root,
                        now=self.now,
                    )

    def test_verify_candidate_cli_accepts_trusted_run_metadata(self) -> None:
        candidate, bundle_path, bundle_root, run = self.make_v2_candidate()
        current = datetime.now(timezone.utc).replace(microsecond=0)
        candidate["validity"] = {
            "created_at": (current - timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "expires_at": (current + timedelta(hours=23)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        run["created_at"] = (current - timedelta(hours=2)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        manifest_path = self.root.parent / "release-candidate-manifest.json"
        metadata_path = self.root.parent / "trusted-run.json"
        manifest_path.write_bytes(self.module.canonical_json(candidate))
        metadata_path.write_text(json.dumps(run), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = self.module.main(
                [
                    "verify-candidate",
                    "--manifest",
                    str(manifest_path),
                    "--bundle",
                    str(bundle_path),
                    "--bundle-root",
                    str(bundle_root),
                    "--source-sha",
                    SOURCE_SHA,
                    "--workflow-revision",
                    SOURCE_SHA,
                    "--version",
                    "1.2.3",
                    "--release-id",
                    "beta-20",
                    "--run-id",
                    "123",
                    "--run-attempt",
                    "2",
                    "--trusted-run-metadata",
                    str(metadata_path),
                ]
            )
        self.assertEqual(0, result)

    def test_v2_candidate_attempt_has_exactly_one_unexpired_artifact(self) -> None:
        artifact = {
            "id": 987,
            "name": "registry-stack-release-candidate-123-2",
            "digest": "sha256:" + "9" * 64,
            "expired": False,
            "workflow_run": {"id": 123},
        }
        self.assertEqual(
            artifact["name"],
            self.module.validate_candidate_artifact_inventory(
                {"artifacts": [artifact]},
                run_id=123,
                run_attempt=2,
            )["name"],
        )
        for changed, message in (
            ({**artifact, "expired": True}, "expired"),
            ({**artifact, "name": artifact["name"] + "-extra"}, "exactly one"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.module.validate_candidate_artifact_inventory(
                        {"artifacts": [changed]},
                        run_id=123,
                        run_attempt=2,
                    )

    def test_v2_candidate_rejects_expiry_open_fields_and_hash_mutation(self) -> None:
        candidate, bundle_path, bundle_root, run = self.make_v2_candidate()
        too_long = copy.deepcopy(candidate)
        too_long["validity"]["expires_at"] = (
            self.now + timedelta(hours=24, minutes=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(self.module.CandidateError, "24 hours"):
            self.module.validate_candidate_manifest(too_long, now=self.now)

        expired = copy.deepcopy(candidate)
        expired["validity"]["expires_at"] = (
            self.now - timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(self.module.CandidateError, "expired"):
            self.module.validate_candidate_manifest(
                expired,
                now=self.now,
            )

        opened = copy.deepcopy(candidate)
        opened["status"] = "candidate"
        with self.assertRaisesRegex(self.module.CandidateError, "non-closed"):
            self.module.validate_candidate_manifest(opened, now=self.now)

        (bundle_root / candidate["docs"]["name"]).write_bytes(b"mutated")
        with self.assertRaisesRegex(self.module.CandidateError, "sha256 mismatch"):
            self.module.validate_candidate_manifest(
                candidate,
                bundle_path=bundle_path,
                bundle_root=bundle_root,
                now=self.now,
            )

    def test_v2_candidate_rejects_scan_advisory_image_and_bundle_substitution(
        self,
    ) -> None:
        candidate, bundle_path, bundle_root, _ = self.make_v2_candidate()
        for pointer, replacement, message in (
            (("scans", 0, "status"), "incomplete", "status must be passed"),
            (("advisory", "verdict"), "failed", "verdict must be passed"),
            (
                ("images", 0, "final_ref"),
                "ghcr.io/registrystack/registry-notary:v9.9.9",
                "final_ref",
            ),
            (("bundle", "sha256"), "9" * 64, "bundle sha256 mismatch"),
        ):
            changed = copy.deepcopy(candidate)
            target = changed
            for key in pointer[:-1]:
                target = target[key]
            target[pointer[-1]] = replacement
            with self.subTest(pointer=pointer):
                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.module.validate_candidate_manifest(
                        changed,
                        bundle_path=bundle_path,
                        bundle_root=bundle_root,
                        now=self.now,
                    )

    def test_canary_requires_exact_revision_success_and_24_hour_recency(self) -> None:
        run = {
            "id": 456,
            "run_attempt": 1,
            "event": "workflow_dispatch",
            "head_sha": "b" * 40,
            "path": ".github/workflows/release-canary.yml",
            "conclusion": "success",
            "completed_at": (self.now - timedelta(hours=23)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        self.module.validate_canary_run(
            run, workflow_revision="b" * 40, now=self.now
        )
        for field, value, message in (
            ("head_sha", "c" * 40, "workflow revision"),
            ("conclusion", "failure", "did not succeed"),
            (
                "completed_at",
                (self.now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "older than 24 hours",
            ),
        ):
            changed = dict(run)
            changed[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.module.validate_canary_run(
                        changed, workflow_revision="b" * 40, now=self.now
                    )

    def test_verify_tag_binding_cli_rechecks_identity_and_expiry_before_public_write(
        self,
    ) -> None:
        candidate, bundle_path, bundle_root, run = self.make_v2_candidate()
        current = datetime.now(timezone.utc).replace(microsecond=0)
        candidate["validity"] = {
            "created_at": (current - timedelta(hours=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "expires_at": (current + timedelta(hours=22)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        run["created_at"] = (current - timedelta(hours=3)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        manifest_path = self.root.parent / "release-candidate-manifest.json"
        metadata_path = self.root.parent / "candidate-run.json"
        message_path = self.root.parent / "tag-message.txt"
        metadata_path.write_text(json.dumps(run), encoding="utf-8")

        def invoke(document: dict, *, tag_target: str = SOURCE_SHA) -> int:
            manifest_path.write_bytes(self.module.canonical_json(document))
            message_path.write_text(
                self.module.render_tag_binding(
                    123,
                    2,
                    self.module.sha256_file(manifest_path),
                ),
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                return self.module.main(
                    [
                        "verify-tag-binding",
                        "--message",
                        str(message_path),
                        "--manifest",
                        str(manifest_path),
                        "--bundle",
                        str(bundle_path),
                        "--bundle-root",
                        str(bundle_root),
                        "--trusted-run-metadata",
                        str(metadata_path),
                        "--tag-target",
                        tag_target,
                        "--workflow-revision",
                        SOURCE_SHA,
                        "--version",
                        "1.2.3",
                        "--release-id",
                        "beta-20",
                    ]
                )

        self.assertEqual(0, invoke(candidate))
        self.assertEqual(1, invoke(candidate, tag_target="f" * 40))
        expired = copy.deepcopy(candidate)
        expired["validity"] = {
            "created_at": (current - timedelta(hours=24)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "expires_at": (current - timedelta(seconds=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        self.assertEqual(1, invoke(expired))

        manifest_path.write_bytes(self.module.canonical_json(candidate))
        message_path.write_text(
            self.module.render_tag_binding(
                123, 2, self.module.sha256_file(manifest_path)
            ),
            encoding="utf-8",
        )
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            missing_identity = self.module.main(
                [
                    "verify-tag-binding",
                    "--message",
                    str(message_path),
                    "--manifest",
                    str(manifest_path),
                    "--trusted-run-metadata",
                    str(metadata_path),
                ]
            )
        self.assertEqual(1, missing_identity)

    def test_seal_writes_canonical_bytes_and_refuses_open_draft(self) -> None:
        draft = self.root.parent / "draft.json"
        output = self.root.parent / "sealed.json"
        receipt = fixture(
            self.root,
            now=datetime.now(timezone.utc).replace(microsecond=0),
        )
        draft.write_text(json.dumps(receipt), encoding="utf-8")
        self.module.write_closed_receipt(draft, output)
        self.assertEqual(self.module.canonical_json(receipt), output.read_bytes())
        receipt["unknown"] = True
        draft.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaisesRegex(self.module.CandidateError, "non-closed schema"):
            self.module.write_closed_receipt(draft, output)


if __name__ == "__main__":
    unittest.main()
