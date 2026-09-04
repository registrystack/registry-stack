#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase, main, mock


SCRIPT = Path(__file__).with_name("release_candidate.py")
ROOT = SCRIPT.parents[2]
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


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def security_evidence_members(
    image_names: tuple[str, ...] = (
        "discovery",
        "evidence",
        "mint",
        "breg",
        "relay",
    ),
) -> dict[str, bytes]:
    refs = {
        name: f"ghcr.io/registrystack/{name}-candidate@{IMAGE_DIGEST}"
        for name in image_names
    }
    members = {
        "grype/grype-db-status.json": json_bytes({"status": "valid"}),
        "advisory-verdict.json": json_bytes(
            {
                "schema_version": "registry-stack.advisory-verdict.v2",
                "verdict": "passed",
                "subjects": sorted(f"{name}-image" for name in image_names),
            }
        ),
    }
    for name, image_ref in refs.items():
        spdx = {"spdxVersion": "SPDX-2.3", "packages": []}
        members[f"image-sbom/{name}.spdx.json"] = json_bytes(spdx)
        members[f"syft/{name}.syft.json"] = json_bytes(
            {
                "artifacts": [],
                "source": {
                    "type": "image",
                    "metadata": {"userInput": image_ref},
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
        directories = ["image-sbom", "syft", "grype"]
        if any(name.startswith("images/") for name, _payload in entries):
            directories.insert(0, "images")
        for directory in directories:
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




class ReleaseCandidateTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.now = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workflow_run_metadata = {
            "id": 123,
            "run_attempt": 2,
            "event": "repository_dispatch",
            "head_sha": SOURCE_SHA,
            "path": ".github/workflows/release-candidate.yml",
            "status": "completed",
            "conclusion": "success",
            "created_at": (self.now - timedelta(hours=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def onboarding_repository(self) -> Path:
        root = self.root / "onboarding"
        paths = [
            "release/scripts/build-release-binaries.sh",
            "release/scripts/build-release-image.sh",
            "release/scripts/cleanup-release-candidates.py",
        ]
        for image_name in self.module._candidate_image_names("0.26.0"):
            paths.append(f"release/docker/Dockerfile.{image_name}")
            paths.append(
                "products/relay-v2/security/advisory-baseline.json"
                if image_name == "relay"
                else f"release/security/{image_name}-advisory-baseline.json"
            )
        for relative_path in paths:
            source = ROOT / relative_path
            destination = root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return root





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

    def test_slsa_subject_contract_rejects_one_extra_provenance_subject(self) -> None:
        contract = self.root / "subjects.json"
        provenance = self.root / "provenance.intoto.jsonl"
        expected = [
            {"name": "relayctl-v1.2.3-linux-amd64", "sha256": "1" * 64},
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
                ("relayctl-v1.2.3-linux-amd64", "1" * 64),
                ("SHA256SUMS", "2" * 64),
            },
            self.module.validate_slsa_subject_set(provenance, contract),
        )

        write_provenance(expected, github_attestation_bundle=True)
        self.assertEqual(
            {
                ("relayctl-v1.2.3-linux-amd64", "1" * 64),
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














    def test_tag_binding_is_closed_and_binds_exact_manifest(self) -> None:
        manifest_sha = "7" * 64
        message = self.module.render_tag_binding(123, 2, manifest_sha)
        self.assertEqual(
            {
                "schema_version": "registry-stack.release-candidate.v2",
                "run_id": 123,
                "run_attempt": 2,
                "manifest_sha256": manifest_sha,
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
                TAG_LINE := f"manifest_sha256: {manifest_sha}", TAG_LINE.upper()
            ),
        ):
            if "run_attempt: 3" in tampered:
                parsed = self.module.parse_tag_binding(tampered)
                self.assertNotEqual(2, parsed["run_attempt"])
            else:
                with self.assertRaises(self.module.CandidateError):
                    self.module.parse_tag_binding(tampered)

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
        bundle_root = self.root / "v2-bundle"
        image_names = (
            "discovery",
            "evidence",
            "mint",
            "breg",
            "relay",
        )
        evidence_members = security_evidence_members(image_names)
        evidence_name = "registry-stack-v1.2.3-security-evidence.tar.gz"
        payload_inventory = self.module._relay_v2_payload_inventory("1.2.3")
        files = {
            name: f"candidate payload: {name}\n".encode()
            for name in payload_inventory
        }
        files.update(
            {
                f"security/{name}.grype.json": evidence_members[
                    f"grype/{name}.grype.json"
                ]
                for name in image_names
            }
        )
        files.update(
            {
                "security/advisory-verdict.json": evidence_members[
                    "advisory-verdict.json"
                ],
                evidence_name: security_evidence_tar(
                    sorted(evidence_members.items())
                ),
            }
        )
        for name, payload in files.items():
            path = bundle_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        bundle_path = self.root / "registry-stack-v1.2.3-candidate.tar.gz"
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
                for name, kind in sorted(payload_inventory.items())
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
                for name in image_names
            ],
            "sbom": {
                "name": "registry-stack-v1.2.3.sbom.spdx.json",
                "sha256": sha256(
                    files["registry-stack-v1.2.3.sbom.spdx.json"]
                ),
            },
            "docs": {
                "name": "registry-docs-v1.2.3.tar.gz",
                "sha256": sha256(files["registry-docs-v1.2.3.tar.gz"]),
            },
            "scans": [
                {
                    "image": name,
                    "name": f"security/{name}.grype.json",
                    "sha256": sha256(files[f"security/{name}.grype.json"]),
                    "status": "passed",
                }
                for name in image_names
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
            "status": "completed",
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



    def test_pre_v0_19_candidate_uses_tag_checkout_diagnostic(self) -> None:
        candidate, _, _, _ = self.make_v2_candidate()
        candidate["release"]["version"] = "0.18.0"
        candidate["release"]["tag"] = "v0.18.0"
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "pre-v0.19 candidates.*corresponding release tag",
        ):
            self.module.validate_candidate_manifest(candidate, now=self.now)

    def test_v2_candidate_docs_contract_is_version_aware(self) -> None:
        current, _, _, _ = self.make_v2_candidate()
        self.module.validate_candidate_manifest(current, now=self.now)

        missing_field = copy.deepcopy(current)
        missing_field.pop("docs")
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "manifest has a non-closed schema: missing docs",
        ):
            self.module.validate_candidate_manifest(missing_field, now=self.now)

        missing_payload = copy.deepcopy(current)
        missing_payload["payloads"] = [
            item for item in missing_payload["payloads"] if item["kind"] != "docs"
        ]
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "payloads must contain exactly one docs payload",
        ):
            self.module.validate_candidate_manifest(missing_payload, now=self.now)

        v0_19_0 = copy.deepcopy(current)
        v0_19_0["release"]["version"] = "0.19.0"
        v0_19_0["release"]["tag"] = "v0.19.0"
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "manifest has a non-closed schema: unknown docs",
        ):
            self.module.validate_candidate_manifest(v0_19_0, now=self.now)

    def test_v2_candidate_payload_inventory_is_exact_and_excludes_registryctl(
        self,
    ) -> None:
        candidate, _, _, _ = self.make_v2_candidate()
        retired = copy.deepcopy(candidate)
        relay = next(
            record
            for record in retired["payloads"]
            if record["name"] == "relay-v1.2.3-linux-amd64"
        )
        retired["payloads"].remove(relay)
        retired["payloads"].append(
            {
                **relay,
                "name": "registryctl-v1.2.3-linux-amd64",
            }
        )

        with self.assertRaisesRegex(
            self.module.CandidateError,
            "payload inventory.*missing.*relay-v1.2.3-linux-amd64.*"
            "unexpected.*registryctl-v1.2.3-linux-amd64",
        ):
            self.module.validate_candidate_manifest(retired, now=self.now)

        docs_payload = copy.deepcopy(candidate)
        docs_payload["release"]["version"] = "0.19.0"
        docs_payload["release"]["tag"] = "v0.19.0"
        docs_payload.pop("docs")
        docs_payload["payloads"] = [
            item for item in docs_payload["payloads"] if item["kind"] != "docs"
        ]
        docs_payload["payloads"].append(
            {
                "name": "registry-docs-v1.2.3.tar.gz",
                "kind": "docs",
                "size": 1,
                "sha256": "9" * 64,
            }
        )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "payloads.*kind is unsupported",
        ):
            self.module.validate_candidate_manifest(docs_payload, now=self.now)

    def test_relay_installer_payloads_begin_after_v0_19_0(self) -> None:
        historical = self.module._relay_v2_payload_inventory("0.19.0")
        current = self.module._relay_v2_payload_inventory("0.19.1")

        self.assertNotIn("relay-v0.19.0-install.sh", historical)
        self.assertNotIn("relay-install.sh", historical)
        self.assertNotIn("registry-docs-v0.19.0.tar.gz", historical)
        self.assertEqual("installer", current["relay-v0.19.1-install.sh"])
        self.assertEqual("installer", current["relay-install.sh"])
        self.assertEqual("docs", current["registry-docs-v0.19.1.tar.gz"])

    def test_relay_client_payloads_begin_after_v0_19_0(self) -> None:
        historical = self.module._relay_v2_payload_inventory("0.19.0")
        current = self.module._relay_v2_payload_inventory("0.19.1")

        self.assertNotIn(
            "relay-client-node-v0.19.0-linux-amd64-glibc.tgz", historical
        )
        self.assertNotIn(
            "registry_relay_client-0.19.0-cp310-abi3-linux_x86_64.whl",
            historical,
        )
        self.assertEqual(
            "client-package",
            current["relay-client-node-v0.19.1-linux-amd64-glibc.tgz"],
        )
        self.assertEqual(
            "client-package",
            current["registry_relay_client-0.19.1-cp310-abi3-linux_x86_64.whl"],
        )

    def test_client_registry_payloads_begin_with_v0_21_1(self) -> None:
        historical = self.module._relay_v2_payload_inventory("0.21.0")
        current = self.module._relay_v2_payload_inventory("0.21.1")

        self.assertNotIn("registrystack-relay-client-0.21.0.tgz", historical)
        self.assertIn(
            "registry_relay_client-0.21.0-cp310-abi3-linux_x86_64.whl",
            historical,
        )
        self.assertNotIn(
            "registry_relay_client-0.21.1-cp310-abi3-linux_x86_64.whl",
            current,
        )
        self.assertEqual(
            "client-package",
            current[
                "registry_relay_client-0.21.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
            ],
        )
        self.assertEqual(
            "client-package",
            current[
                "registry_evidence_client-0.21.1-cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"
            ],
        )
        self.assertEqual(
            "client-package",
            current["registrystack-relay-client-0.21.1.tgz"],
        )
        self.assertEqual(
            "client-package",
            current[
                "registrystack-relay-client-linux-x64-gnu-0.21.1.tgz"
            ],
        )
        self.assertEqual(
            "client-package",
            current["registrystack-evidence-client-0.21.1.tgz"],
        )
        self.assertEqual(
            "client-package",
            current[
                "registrystack-evidence-client-linux-x64-gnu-0.21.1.tgz"
            ],
        )

    def test_discovery_client_payloads_begin_with_v0_23_0(self) -> None:
        historical = self.module._relay_v2_payload_inventory("0.22.0")
        current = self.module._relay_v2_payload_inventory("0.23.0")

        self.assertNotIn(
            "discovery-client-node-v0.22.0-linux-amd64-glibc.tgz", historical
        )
        self.assertNotIn(
            "registry_discovery_client-0.22.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            historical,
        )
        self.assertEqual(
            "client-package",
            current["discovery-client-node-v0.23.0-linux-amd64-glibc.tgz"],
        )
        self.assertEqual(
            "client-package",
            current[
                "registry_discovery_client-0.23.0-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
            ],
        )
        self.assertEqual(
            "client-package",
            current["registrystack-discovery-client-0.23.0.tgz"],
        )
        self.assertEqual(
            "client-package",
            current["registrystack-discovery-client-linux-x64-gnu-0.23.0.tgz"],
        )

    def test_discovery_runtime_payload_begins_with_v0_24_0(self) -> None:
        historical = self.module._relay_v2_payload_inventory("0.23.0")
        current = self.module._relay_v2_payload_inventory("0.24.0")

        self.assertNotIn("discovery-v0.23.0-linux-amd64", historical)
        self.assertEqual("binary", current["discovery-v0.24.0-linux-amd64"])

    def test_breg_payloads_begin_with_v0_26_0(self) -> None:
        historical = self.module._relay_v2_payload_inventory("0.25.0")
        current = self.module._relay_v2_payload_inventory("0.26.0")

        self.assertNotIn("breg-v0.25.0-linux-amd64", historical)
        for platform in ("linux-amd64", "linux-arm64", "macos-arm64"):
            self.assertEqual(
                "binary",
                current[f"breg-v0.26.0-{platform}"],
            )
            self.assertEqual(
                "binary",
                current[f"bregctl-v0.26.0-{platform}"],
            )
        self.assertEqual(
            "installer", current["breg-v0.26.0-install.sh"]
        )
        self.assertEqual("installer", current["breg-install.sh"])

    def test_unified_client_replaces_individual_packages_after_v0_26_0(self) -> None:
        historical = self.module._relay_v2_payload_inventory("0.26.0")
        current = self.module._relay_v2_payload_inventory("0.26.1")

        self.assertIn("registrystack-relay-client-0.26.0.tgz", historical)
        self.assertNotIn("registrystack-relay-client-0.26.1.tgz", current)
        self.assertNotIn(
            "registry_relay_client-0.26.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
            current,
        )
        self.assertEqual(
            "client-package", current["registrystack-client-0.26.1.tgz"]
        )
        self.assertEqual(
            "client-package",
            current["registrystack-client-linux-x64-gnu-0.26.1.tgz"],
        )
        self.assertEqual(
            "client-package",
            current[
                "registry_stack_client-0.26.1-cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
            ],
        )

    def test_v2_security_evidence_members_follow_candidate_images(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current_path = root / "current.tar.gz"
            current_members = security_evidence_members(("relay",))
            current_path.write_bytes(
                security_evidence_tar(sorted(current_members.items()))
            )
            current_refs = {
                "relay": (
                    "ghcr.io/registrystack/relay-candidate@"
                    f"{IMAGE_DIGEST}"
                )
            }
            self.module.validate_security_evidence_archive(
                current_path,
                product_image_refs=current_refs,
                product_scan_sha256={
                    "relay": sha256(
                        current_members["grype/relay.grype.json"]
                    )
                },
                advisory_sha256=sha256(
                    current_members["advisory-verdict.json"]
                ),
            )

    def test_official_runtime_image_roster_begins_at_v0_21(self) -> None:
        for version in ("0.19.0", "0.20.0", "0.20.1"):
            with self.subTest(version=version):
                self.assertEqual(
                    {"relay"},
                    self.module._candidate_image_names(version),
                )
        self.assertEqual(
            {"evidence", "mint", "relay"},
            self.module._candidate_image_names("0.21.0"),
        )

    def test_discovery_runtime_image_joins_the_roster_at_v0_24(self) -> None:
        for version in ("0.21.0", "0.22.0", "0.23.0"):
            with self.subTest(version=version):
                self.assertEqual(
                    {"evidence", "mint", "relay"},
                    self.module._candidate_image_names(version),
                )
        self.assertEqual(
            {"discovery", "evidence", "mint", "relay"},
            self.module._candidate_image_names("0.24.0"),
        )

    def test_breg_image_joins_the_roster_at_v0_26(self) -> None:
        self.assertEqual(
            {"discovery", "evidence", "mint", "relay"},
            self.module._candidate_image_names("0.25.0"),
        )
        self.assertEqual(
            {"discovery", "evidence", "mint", "breg", "relay"},
            self.module._candidate_image_names("0.26.0"),
        )

    def test_image_names_cli_emits_the_version_appropriate_roster(self) -> None:
        cases = (
            ("0.20.2", "relay\n"),
            ("0.21.0", "evidence mint relay\n"),
            ("0.24.0", "discovery evidence mint relay\n"),
            ("0.26.0", "breg discovery evidence mint relay\n"),
        )
        for version, expected in cases:
            with self.subTest(version=version):
                stdout = io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    result = self.module.main(
                        ["image-names", "--version", version]
                    )
                self.assertEqual(0, result)
                self.assertEqual(expected, stdout.getvalue())

    def test_image_onboarding_accepts_every_current_version_roster(self) -> None:
        for version in ("0.20.0", "0.21.0", "0.24.0", "0.26.0"):
            with self.subTest(version=version):
                self.assertEqual(
                    self.module._candidate_image_names(version),
                    self.module.check_image_onboarding(ROOT, version),
                )

    def test_image_onboarding_rejects_a_noncanonical_version(self) -> None:
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "version must be canonical semantic version text",
        ):
            self.module.check_image_onboarding(ROOT, "0.26")

    def test_image_onboarding_rejects_a_missing_dockerfile(self) -> None:
        root = self.onboarding_repository()
        (root / "release/docker/Dockerfile.breg").unlink()
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "breg release Dockerfile is missing",
        ):
            self.module.check_image_onboarding(
                root,
                "0.26.0",
                allow_missing_baseline=True,
            )

    def test_image_onboarding_rejects_symlinked_release_inputs(self) -> None:
        for relative_path, error in (
            (
                "release/docker/Dockerfile.breg",
                "breg release Dockerfile must not be a symlink",
            ),
            (
                "release/security/breg-advisory-baseline.json",
                "breg advisory baseline must not be a symlink",
            ),
        ):
            with self.subTest(relative_path=relative_path):
                root = self.onboarding_repository()
                path = root / relative_path
                path.unlink()
                path.symlink_to(ROOT / relative_path)
                with self.assertRaisesRegex(self.module.CandidateError, error):
                    self.module.check_image_onboarding(
                        root,
                        "0.26.0",
                        allow_missing_baseline=True,
                    )
                shutil.rmtree(root)

    def test_image_onboarding_rejects_an_unsupported_build_name(self) -> None:
        root = self.onboarding_repository()
        recipe = root / "release/scripts/build-release-image.sh"
        recipe.write_text(
            recipe.read_text(encoding="utf-8").replace(
                "discovery|evidence|mint|breg|relay",
                "discovery|evidence|mint|relay",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "release image recipe does not recognize breg",
        ):
            self.module.check_image_onboarding(
                root,
                "0.26.0",
                allow_missing_baseline=True,
            )

    def test_image_onboarding_rejects_a_missing_binary_staging_path(self) -> None:
        root = self.onboarding_repository()
        recipe = root / "release/scripts/build-release-binaries.sh"
        recipe.write_text(
            recipe.read_text(encoding="utf-8").replace(
                "cp target/release/breg dist/image-bin/breg",
                "cp target/release/breg dist/image-bin/wrong-breg",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "canonical binary recipe must stage dist/image-bin/breg",
        ):
            self.module.check_image_onboarding(
                root,
                "0.26.0",
                allow_missing_baseline=True,
            )

    def test_only_an_absent_baseline_has_an_explicit_allowance(self) -> None:
        root = self.onboarding_repository()
        baseline = root / "release/security/breg-advisory-baseline.json"
        baseline.unlink()
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "breg advisory baseline is missing",
        ):
            self.module.check_image_onboarding(root, "0.26.0")
        self.module.check_image_onboarding(
            root,
            "0.26.0",
            allow_missing_baseline=True,
        )
        cleanup = root / "release/scripts/cleanup-release-candidates.py"
        cleanup.write_text(
            cleanup.read_text(encoding="utf-8").replace(
                '    "breg-candidate",\n',
                "    # breg-candidate is not structurally allowlisted\n",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "CANDIDATE_PACKAGES must contain breg-candidate",
        ):
            self.module.check_image_onboarding(
                root,
                "0.26.0",
                allow_missing_baseline=True,
            )

    def test_image_onboarding_cli_reports_strict_failure_and_bootstrap_success(
        self,
    ) -> None:
        root = self.onboarding_repository()
        (root / "release/security/breg-advisory-baseline.json").unlink()
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            result = self.module.main(
                [
                    "check-image-onboarding",
                    "--version",
                    "0.26.0",
                    "--root",
                    str(root),
                ]
            )
        self.assertEqual(1, result)
        self.assertIn("breg advisory baseline is missing", stderr.getvalue())
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            result = self.module.main(
                [
                    "check-image-onboarding",
                    "--version",
                    "0.26.0",
                    "--root",
                    str(root),
                    "--allow-missing-baseline",
                ]
            )
        self.assertEqual(0, result)
        self.assertEqual(
            "checked image onboarding for breg discovery evidence mint relay\n",
            stdout.getvalue(),
        )

    def test_image_onboarding_rejects_a_malformed_baseline(self) -> None:
        root = self.onboarding_repository()
        baseline = root / "release/security/breg-advisory-baseline.json"
        baseline.write_text("not JSON\n", encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "cannot read JSON",
        ):
            self.module.check_image_onboarding(
                root,
                "0.26.0",
                allow_missing_baseline=True,
            )

    def test_image_onboarding_requires_v4_for_the_exact_service(self) -> None:
        for document, error in (
            ({"version": 3, "service": "breg"}, "must be JSON v4"),
            ({"version": 4, "service": "relay"}, "service must equal breg"),
        ):
            with self.subTest(document=document):
                root = self.onboarding_repository()
                baseline = root / "release/security/breg-advisory-baseline.json"
                baseline.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(self.module.CandidateError, error):
                    self.module.check_image_onboarding(
                        root,
                        "0.26.0",
                        allow_missing_baseline=True,
                    )
                shutil.rmtree(root)

    def test_image_onboarding_requires_structural_cleanup_identities(self) -> None:
        for entry, replacement, error in (
            (
                '    "breg-candidate",\n',
                "    # breg-candidate appears only in a comment\n",
                "CANDIDATE_PACKAGES must contain breg-candidate",
            ),
            (
                '    "breg",\n',
                "    # breg appears only in a comment\n",
                "PUBLIC_PACKAGES must contain breg",
            ),
        ):
            with self.subTest(entry=entry):
                root = self.onboarding_repository()
                cleanup = root / "release/scripts/cleanup-release-candidates.py"
                cleanup.write_text(
                    cleanup.read_text(encoding="utf-8").replace(entry, replacement),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(self.module.CandidateError, error):
                    self.module.check_image_onboarding(
                        root,
                        "0.26.0",
                        allow_missing_baseline=True,
                    )
                shutil.rmtree(root)

    def test_v2_candidate_allows_only_current_in_progress_run_before_oidc(
        self,
    ) -> None:
        candidate, bundle_path, bundle_root, run = self.make_v2_candidate()
        run["status"] = "in_progress"
        run["conclusion"] = None
        arguments = {
            "bundle_path": bundle_path,
            "bundle_root": bundle_root,
            "expected_source_sha": SOURCE_SHA,
            "expected_workflow_revision": SOURCE_SHA,
            "expected_version": "1.2.3",
            "expected_release_id": "beta-20",
            "expected_run_id": 123,
            "expected_run_attempt": 2,
            "now": self.now,
            "workflow_run_metadata": run,
        }

        with self.assertRaisesRegex(
            self.module.CandidateError,
            "trusted workflow run status mismatch",
        ):
            self.module.validate_candidate_manifest(candidate, **arguments)

        self.module.validate_candidate_manifest(
            candidate,
            allow_current_run_in_progress=True,
            **arguments,
        )

        for field, value in (
            ("status", "queued"),
            ("conclusion", "success"),
        ):
            changed = dict(run)
            changed[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    self.module.CandidateError,
                    f"trusted workflow run {field} mismatch",
                ):
                    self.module.validate_candidate_manifest(
                        candidate,
                        allow_current_run_in_progress=True,
                        **(arguments | {"workflow_run_metadata": changed}),
                    )

        with self.assertRaisesRegex(
            self.module.CandidateError,
            "cannot authorize promotion",
        ):
            self.module.validate_candidate_manifest(
                candidate,
                promotion=True,
                allow_current_run_in_progress=True,
                **arguments,
            )
        with self.assertRaisesRegex(
            self.module.CandidateError,
            "requires trusted workflow-run metadata",
        ):
            self.module.validate_candidate_manifest(
                candidate,
                allow_current_run_in_progress=True,
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
        self.assertNotIn("docs", schema["required"])
        self.assertIn("docs", schema["properties"])
        self.assertIn(
            "docs", payload_schema["items"]["properties"]["kind"]["enum"]
        )
        self.assertEqual(
            "^0\\.(?:[0-9]|1[0-8])\\.",
            schema["properties"]["release"]["properties"]["version"]["not"][
                "pattern"
            ],
        )
        version_branch = schema["allOf"][0]
        docs_version_patterns = [
            branch["pattern"]
            for branch in version_branch["if"]["properties"]["release"][
                "properties"
            ]["version"]["anyOf"]
        ]
        self.assertNotIn("^0\\.1[6-8]\\.[0-9]+$", docs_version_patterns)
        self.assertIn("^0\\.19\\.[1-9][0-9]*$", docs_version_patterns)
        self.assertIn(
            "^[1-9][0-9]*\\.[0-9]+\\.[0-9]+$",
            docs_version_patterns,
        )
        self.assertIn("docs", version_branch["then"]["required"])
        self.assertEqual(
            "docs",
            version_branch["then"]["properties"]["payloads"]["contains"][
                "properties"
            ]["kind"]["const"],
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
        required = self.module._security_evidence_required_files(
            self.module.DISCOVERY_RUNTIME_IMAGE_NAMES
        )
        for missing in sorted(required):
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
        members = sorted(
            security_evidence_members().items()
        )
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
                    link=("grype/latest", "relay.grype.json"),
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

        unbound_syft = dict(base)
        syft = json.loads(unbound_syft["syft/relay.syft.json"])
        syft["source"]["metadata"]["userInput"] = (
            "ghcr.io/registrystack/relay-candidate@sha256:"
            + "9" * 64
        )
        unbound_syft["syft/relay.syft.json"] = json_bytes(syft)

        incomplete_verdict = dict(base)
        verdict = json.loads(incomplete_verdict["advisory-verdict.json"])
        verdict["subjects"].remove("relay-image")
        incomplete_verdict["advisory-verdict.json"] = json_bytes(verdict)

        substituted_scan = dict(base)
        scan = json.loads(substituted_scan["grype/relay.grype.json"])
        scan["substituted"] = True
        substituted_scan["grype/relay.grype.json"] = json_bytes(scan)

        for members, message in (
            (unbound_syft, "relay.syft.json.*is not bound"),
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
            self.now + timedelta(days=7, minutes=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(self.module.CandidateError, "7 days"):
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

        (bundle_root / candidate["sbom"]["name"]).write_bytes(b"mutated")
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
                "ghcr.io/registrystack/relay:v9.9.9",
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

    def test_canary_selector_emits_the_complete_consumer_schema(self) -> None:
        revision = "b" * 40
        response = {
            "workflow_runs": [
                {
                    "id": 455,
                    "run_attempt": 1,
                    "event": "schedule",
                    "head_sha": revision,
                    "path": ".github/workflows/release-canary.yml",
                    "conclusion": "success",
                    "updated_at": "2026-07-30T01:00:00Z",
                },
                {
                    "id": 456,
                    "run_attempt": 2,
                    "event": "workflow_dispatch",
                    "head_sha": revision,
                    "path": ".github/workflows/release-canary.yml",
                    "conclusion": "success",
                    "updated_at": "2026-07-30T02:00:00Z",
                },
            ]
        }
        selected = self.module.select_canary_run(
            response,
            workflow_revision=revision,
        )
        self.assertEqual(
            selected,
            {
                "id": 456,
                "run_attempt": 2,
                "event": "workflow_dispatch",
                "head_sha": revision,
                "path": ".github/workflows/release-canary.yml",
                "conclusion": "success",
                "completed_at": "2026-07-30T02:00:00Z",
            },
        )
        self.module.validate_canary_run(
            selected,
            workflow_revision=revision,
            now=datetime(2026, 7, 30, 3, tzinfo=timezone.utc),
        )

    def test_canary_selector_rejects_incomplete_or_untrusted_runs(self) -> None:
        revision = "b" * 40
        base = {
            "id": 456,
            "run_attempt": 1,
            "event": "schedule",
            "head_sha": revision,
            "path": ".github/workflows/release-canary.yml",
            "conclusion": "success",
            "updated_at": "2026-07-30T02:00:00Z",
        }
        for field, value in [
            ("id", None),
            ("run_attempt", None),
            ("event", "push"),
            ("path", ".github/workflows/ci.yml"),
            ("conclusion", "failure"),
            ("head_sha", "c" * 40),
        ]:
            changed = dict(base)
            changed[field] = value
            with self.subTest(field=field):
                with self.assertRaises(self.module.CandidateError):
                    self.module.select_canary_run(
                        {"workflow_runs": [changed]},
                        workflow_revision=revision,
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

    def test_seal_candidate_writes_canonical_bytes_and_refuses_open_draft(self) -> None:
        draft = self.root.parent / "draft.json"
        output = self.root.parent / "sealed.json"
        candidate, _, _, _ = self.make_v2_candidate()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        candidate["validity"] = {
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        draft.write_text(json.dumps(candidate), encoding="utf-8")
        self.module.write_candidate_manifest(draft, output)
        self.assertEqual(self.module.canonical_json(candidate), output.read_bytes())
        candidate["unknown"] = True
        draft.write_text(json.dumps(candidate), encoding="utf-8")
        with self.assertRaisesRegex(self.module.CandidateError, "non-closed schema"):
            self.module.write_candidate_manifest(draft, output)


if __name__ == "__main__":
    main()
