#!/usr/bin/env python3
from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "release/scripts/verify_published_release.py"
MANIFEST = ROOT / "release/manifests/registry-stack-beta-14.yaml"


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "verify_published_release_tested", TOOL
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = load_tool()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def spdx_file_subject(name: str, digest: str) -> dict:
    return {
        "documentDescribes": ["SPDXRef-subject"],
        "packages": [
            {
                "SPDXID": "SPDXRef-subject",
                "name": name,
                "packageFileName": name,
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
            }
        ],
    }


def spdx_image_subject(digest_ref: str) -> dict:
    return {
        "documentDescribes": ["SPDXRef-subject"],
        "packages": [
            {
                "SPDXID": "SPDXRef-subject",
                "name": digest_ref,
                "downloadLocation": "NOASSERTION",
            }
        ],
    }


def provenance_bundle(subjects: dict[str, str]) -> str:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": name, "digest": {"sha256": digest}}
            for name, digest in sorted(subjects.items())
        ],
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return (
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": payload,
                    "signatures": [],
                },
                "verificationMaterial": {},
            }
        )
        + "\n"
    )


class RecordingIO(tool.SystemIO):
    def __init__(self) -> None:
        self.calls: list[
            tuple[tuple[str, ...], Path | None, dict[str, str] | None]
        ] = []
        self.http_calls: list[str] = []
        self.sleeps: list[float] = []

    def run(self, argv, *, cwd=None, env=None, timeout=120):
        self.calls.append((tuple(argv), cwd, dict(env) if env is not None else None))
        return tool.CommandResult(0)

    def get(self, url, *, timeout=20):
        self.http_calls.append(url)
        return tool.HttpResponse(200, "")

    def sleep(self, seconds):
        self.sleeps.append(seconds)


class PublishedReleasePureContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = tool.load_release_identity(MANIFEST)
        self.contract = tool.expected_asset_contract(self.identity)

    def test_current_contract_has_exact_pre_bundle_inventory(self) -> None:
        self.assertEqual(35, len(self.contract.payloads))
        self.assertEqual(35, len(self.contract.signatures))
        self.assertEqual(35, len(self.contract.certificates))
        self.assertEqual(106, len(self.contract.all_assets))
        self.assertEqual(
            "registry-stack-v0.12.0-release-provenance.intoto.jsonl",
            self.contract.provenance,
        )
        self.assertNotIn("release-evidence.json", self.contract.all_assets)

    def test_inventory_accepts_only_the_exact_35_35_35_1_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "assets"
            assets.mkdir()
            for name in self.contract.all_assets:
                (assets / name).write_bytes(name.encode())
            verifier = tool.PublishedReleaseVerifier(
                MANIFEST,
                root / "report.json",
                assets_dir=assets,
                io=RecordingIO(),
            )
            verifier.temp_root = root
            verifier.release_assets = {
                name: (assets / name).stat().st_size
                for name in self.contract.all_assets
            }
            verifier.release_metadata_loaded = True
            verifier.verify_inventory()
            self.assertEqual(
                tool.EXPECTED_COUNTS,
                verifier.report["artifact_scope"]["observed_counts"],
            )

            finalization = tool.expected_finalization_assets(self.identity)
            self.assertEqual(7, len(finalization))
            self.assertEqual(set(tool.EXCLUDED_ROLES), set(finalization.values()))
            for name in finalization:
                (assets / name).write_bytes(name.encode())
                verifier.release_assets[name] = (assets / name).stat().st_size
            verifier.verify_inventory()
            self.assertEqual(106, len(verifier.report["artifacts"]))
            self.assertTrue(
                set(finalization).isdisjoint(
                    artifact["name"] for artifact in verifier.report["artifacts"]
                )
            )
            self.assertIn(
                {
                    "code": "final_evidence_assets_excluded",
                    "subject": self.identity.tag,
                },
                verifier.report["warnings"],
            )

            partial_name = next(iter(finalization))
            (assets / partial_name).unlink()
            verifier.release_assets.pop(partial_name)
            verifier.verify_inventory()
            self.assertIn(
                {
                    "code": "partial_final_evidence_assets_excluded",
                    "subject": self.identity.tag,
                },
                verifier.report["warnings"],
            )
            self.assertEqual(106, len(verifier.report["artifacts"]))
            for name in finalization:
                path = assets / name
                if path.exists():
                    path.unlink()
            verifier.verify_inventory()
            self.assertEqual(106, len(verifier.report["artifacts"]))
            for name in finalization:
                path = assets / name
                if not path.exists():
                    path.write_bytes(name.encode())
                verifier.release_assets[name] = path.stat().st_size

            (assets / "release-evidence.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                tool.VerificationFailure, "release_asset_inventory_mismatch"
            ):
                verifier.verify_inventory()
            (assets / "release-evidence.json").unlink()

            missing = assets / self.contract.signatures[0]
            missing.unlink()
            with self.assertRaisesRegex(
                tool.VerificationFailure, "release_asset_inventory_mismatch"
            ):
                verifier.verify_inventory()

    def test_contract_rejects_pre_v012_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.yaml"
            manifest.write_text(
                """stack:
  release: beta-13
  version: 0.11.0
  source_repo: registrystack/registry-stack
  source_ref: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  source_tag: v0.11.0
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                tool.VerificationFailure, "unsupported_release_contract"
            ):
                tool.load_release_identity(manifest)

    def test_strict_checksum_parser_rejects_missing_extra_duplicate_and_malformed(
        self,
    ) -> None:
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "SHA256SUMS"
            path.write_text(f"{digest}  one\n{digest}  two\n", encoding="utf-8")
            self.assertEqual(
                {"one": digest, "two": digest},
                tool.strict_sha256s(path, {"one", "two"}),
            )

            cases = (
                (f"{digest}  one\n", "checksum_inventory_mismatch"),
                (
                    f"{digest}  one\n{digest}  two\n{digest}  three\n",
                    "checksum_inventory_mismatch",
                ),
                (f"{digest}  one\n{digest}  one\n", "duplicate_checksum_entry"),
                (f"{digest} one\n{digest}  two\n", "malformed_checksum_entry"),
                (f"{'A' * 64}  one\n{digest}  two\n", "malformed_checksum_entry"),
            )
            for body, code in cases:
                with self.subTest(code=code, body=body):
                    path.write_text(body, encoding="utf-8")
                    with self.assertRaisesRegex(tool.VerificationFailure, code):
                        tool.strict_sha256s(path, {"one", "two"})

    def test_provenance_requires_exact_subject_names_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subjects = {}
            for name in self.contract.payloads:
                path = root / name
                path.write_bytes(name.encode())
                subjects[name] = tool.file_sha256(path)
            provenance = root / self.contract.provenance
            provenance.write_text(provenance_bundle(subjects), encoding="utf-8")
            tool.verify_provenance_subjects(root, self.contract)

            wrong = dict(subjects)
            wrong[self.contract.payloads[0]] = "f" * 64
            provenance.write_text(provenance_bundle(wrong), encoding="utf-8")
            with self.assertRaisesRegex(
                tool.VerificationFailure, "provenance_subject_digest_mismatch"
            ):
                tool.verify_provenance_subjects(root, self.contract)

            missing = dict(subjects)
            missing.pop(self.contract.payloads[0])
            provenance.write_text(provenance_bundle(missing), encoding="utf-8")
            with self.assertRaisesRegex(
                tool.VerificationFailure, "provenance_subject_inventory_mismatch"
            ):
                tool.verify_provenance_subjects(root, self.contract)

            extra = dict(subjects)
            extra["unexpected"] = "e" * 64
            provenance.write_text(provenance_bundle(extra), encoding="utf-8")
            with self.assertRaisesRegex(
                tool.VerificationFailure, "provenance_subject_inventory_mismatch"
            ):
                tool.verify_provenance_subjects(root, self.contract)

    def test_closed_report_rejects_extra_and_diagnostic_fields(self) -> None:
        report = tool.initial_report(self.identity)
        tool.assert_closed_report(report)
        report["extra"] = True
        with self.assertRaisesRegex(ValueError, "top-level"):
            tool.assert_closed_report(report)
        report.pop("extra")
        report["warnings"] = [{"code": "x", "subject": "release", "stderr": "secret"}]
        with self.assertRaisesRegex(ValueError, "closed|prohibited"):
            tool.assert_closed_report(report)

    def test_dry_validation_is_closed_incomplete_and_network_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            fake = RecordingIO()
            verifier = tool.PublishedReleaseVerifier(
                MANIFEST,
                output,
                io=fake,
                dry_validate=True,
            )
            self.assertEqual(2, verifier.verify())
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("incomplete", report["status"])
            self.assertEqual(
                tool.EXPECTED_COUNTS, report["artifact_scope"]["expected_counts"]
            )
            self.assertEqual([], fake.calls)
            tool.assert_closed_report(report)


class PublishedReleaseBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = tool.load_release_identity(MANIFEST)
        self.contract = tool.expected_asset_contract(self.identity)
        self.tag_target = "b" * 40

    def make_image_binding_fixture(self, root: Path) -> dict[str, str]:
        images = {
            component: f"{repository}@sha256:{index * 64}"
            for component, repository, index in (
                ("registry-notary", tool.IMAGE_REPOSITORIES["registry-notary"], "a"),
                ("registry-relay", tool.IMAGE_REPOSITORIES["registry-relay"], "b"),
            )
        }
        write_json(
            root / f"registryctl-{self.identity.tag}-image-lock.json",
            {
                "schema_version": "registryctl.release_image_lock.v1",
                "release_tag": self.identity.tag,
                "manifest_source_ref": self.identity.source_ref,
                "tag_target": self.tag_target,
                "platform": "linux/amd64",
                "images": images,
            },
        )
        for component, digest_ref in images.items():
            (root / f"{component}.digest").write_text(
                digest_ref + "\n", encoding="utf-8"
            )
            digest = digest_ref.rsplit("@", 1)[1]
            write_json(
                root / f"{component}.metadata.json",
                {
                    "containerimage.digest": digest,
                    "containerimage.descriptor": {"digest": digest},
                    "image.name": f"{tool.IMAGE_REPOSITORIES[component]}:{self.identity.tag}",
                    "buildx.build.provenance": {
                        "request": {
                            "vcs:source": tool.SOURCE_URL,
                            "vcs:revision": self.tag_target,
                        }
                    },
                },
            )
        return images

    def test_image_lock_digest_and_metadata_are_one_exact_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = self.make_image_binding_fixture(root)
            self.assertEqual(
                expected,
                tool.verify_image_lock_and_metadata(
                    root, self.identity, self.tag_target
                ),
            )
            metadata = root / "registry-relay.metadata.json"
            data = json.loads(metadata.read_text(encoding="utf-8"))
            data["buildx.build.provenance"]["request"]["vcs:revision"] = "c" * 40
            write_json(metadata, data)
            with self.assertRaisesRegex(
                tool.VerificationFailure, "image_metadata_binding_mismatch"
            ):
                tool.verify_image_lock_and_metadata(
                    root, self.identity, self.tag_target
                )

    def test_file_image_and_grype_subject_bindings_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            locked = self.make_image_binding_fixture(root)
            file_subjects = [
                name
                for name in self.contract.payloads
                if name.endswith(("-linux-amd64", "-linux-arm64", "-macos-arm64"))
            ] + [f"registryctl-{self.identity.tag}-image-lock.json"]
            for name in file_subjects:
                path = root / name
                if not path.exists():
                    path.write_bytes(name.encode())
                write_json(
                    root / f"{name}.spdx.json",
                    spdx_file_subject(name, tool.file_sha256(path)),
                )
            for component, digest_ref in locked.items():
                write_json(
                    root / f"{component}.spdx.json", spdx_image_subject(digest_ref)
                )
                write_json(
                    root / f"{component}.grype.json",
                    {"source": {"target": {"userInput": digest_ref}}},
                )
            tool.verify_sbom_bindings(root, self.identity, self.contract, locked)
            tool.verify_grype_bindings(root, locked)

            write_json(
                root / "registry-notary.grype.json",
                {"source": {"target": {"userInput": "sha256:" + "c" * 64}}},
            )
            with self.assertRaisesRegex(
                tool.VerificationFailure, "grype_subject_mismatch"
            ):
                tool.verify_grype_bindings(root, locked)

    def test_capsule_binds_exact_files_images_manifest_and_canonical_markdown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            locked = self.make_image_binding_fixture(root)
            binary_names = [
                name
                for name in self.contract.payloads
                if name.endswith(("-linux-amd64", "-linux-arm64", "-macos-arm64"))
            ]
            binaries = []
            for name in binary_names:
                path = root / name
                path.write_bytes(name.encode())
                sbom_path = root / f"{name}.spdx.json"
                write_json(sbom_path, spdx_file_subject(name, tool.file_sha256(path)))
                binaries.append(
                    {
                        "name": name,
                        "path": f"dist/bin/{name}",
                        "sha256": tool.file_sha256(path),
                        "sbom": {
                            "asset_name": sbom_path.name,
                            "subject": name,
                            "format": "spdx-json",
                            "sha256": tool.file_sha256(sbom_path),
                        },
                    }
                )
            lock_name = f"registryctl-{self.identity.tag}-image-lock.json"
            lock_path = root / lock_name
            lock_sbom = root / f"{lock_name}.spdx.json"
            write_json(
                lock_sbom, spdx_file_subject(lock_name, tool.file_sha256(lock_path))
            )
            release_files = [
                {
                    "name": lock_name,
                    "path": f"dist/bin/{lock_name}",
                    "sha256": tool.file_sha256(lock_path),
                    "kind": "registryctl-release-image-lock",
                    "sbom": {
                        "asset_name": lock_sbom.name,
                        "subject": lock_name,
                        "format": "spdx-json",
                        "sha256": tool.file_sha256(lock_sbom),
                    },
                }
            ]
            images = []
            for component, digest_ref in locked.items():
                sbom_path = root / f"{component}.spdx.json"
                grype_path = root / f"{component}.grype.json"
                write_json(sbom_path, spdx_image_subject(digest_ref))
                write_json(
                    grype_path, {"source": {"target": {"userInput": digest_ref}}}
                )
                images.append(
                    {
                        "name": component,
                        "digest_ref": digest_ref,
                        "digest": digest_ref.rsplit("@", 1)[1],
                        "tag": self.identity.tag,
                        "tag_ref": f"{tool.IMAGE_REPOSITORIES[component]}:{self.identity.tag}",
                        "sbom": {
                            "asset_name": sbom_path.name,
                            "subject": digest_ref,
                            "format": "spdx-json",
                            "sha256": tool.file_sha256(sbom_path),
                        },
                        "vulnerability_scan": {
                            "asset_name": grype_path.name,
                            "subject": digest_ref,
                            "scanner": "grype",
                            "scanner_version": "fixture",
                            "vulnerability_db_timestamp": "fixture",
                            "severity_summary": {},
                            "release_decision_status": "fixture",
                            "sha256": tool.file_sha256(grype_path),
                        },
                    }
                )
            manifest_data = tool.yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
            capsule = {
                "release_tag": self.identity.tag,
                "version": self.identity.version,
                "repository": self.identity.repository,
                "source": {
                    "source_tag": self.identity.tag,
                    "source_ref": self.identity.source_ref,
                    "manifest_ref": self.identity.source_ref,
                    "source_commit": self.tag_target,
                },
                "workflow": {
                    "name": "RegistryStack Release",
                    "run_url": "https://example.invalid/run",
                    "run_id": "1",
                },
                "manifest": {
                    "path": "release/manifests/registry-stack-beta-14.yaml",
                    "sha256": self.identity.manifest_sha256,
                },
                "default_branch_protection": {"status": "unverified"},
                "external_pinned_inputs": manifest_data["external"],
                "binaries": binaries,
                "release_files": release_files,
                "images": images,
                "warnings": manifest_data["warnings"],
                "hosted_publication_status": "held",
            }
            capsule_name = f"registry-stack-{self.identity.tag}-release-capsule.json"
            markdown_name = f"registry-stack-{self.identity.tag}-release-capsule.md"
            write_json(root / capsule_name, capsule)
            (root / markdown_name).write_text(
                tool.RELEASE_HELPERS.capsule_markdown(capsule), encoding="utf-8"
            )
            tool.verify_capsule_bindings(
                root,
                MANIFEST,
                manifest_data,
                self.identity,
                self.tag_target,
                self.contract,
                locked,
            )
            (root / markdown_name).write_text("not canonical\n", encoding="utf-8")
            with self.assertRaisesRegex(
                tool.VerificationFailure, "capsule_markdown_mismatch"
            ):
                tool.verify_capsule_bindings(
                    root,
                    MANIFEST,
                    manifest_data,
                    self.identity,
                    self.tag_target,
                    self.contract,
                    locked,
                )

    def test_exact_oci_labels_and_numeric_user_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            verifier = tool.PublishedReleaseVerifier(
                MANIFEST, Path(directory) / "report.json", io=RecordingIO()
            )
            verifier.report["lineage"]["tag_target"] = self.tag_target
            verifier.locked_images = {
                component: f"{repository}@sha256:{character * 64}"
                for component, repository, character in (
                    (
                        "registry-notary",
                        tool.IMAGE_REPOSITORIES["registry-notary"],
                        "a",
                    ),
                    ("registry-relay", tool.IMAGE_REPOSITORIES["registry-relay"], "b"),
                )
            }
            verifier.image_configs = {
                component: {
                    "User": "65532",
                    "Labels": {
                        "org.opencontainers.image.source": tool.SOURCE_URL,
                        "org.opencontainers.image.revision": self.tag_target,
                        "org.opencontainers.image.version": self.identity.version,
                    },
                }
                for component in tool.IMAGE_COMPONENTS
            }
            verifier._ensure_image_records()
            verifier.verify_oci_labels()
            verifier.verify_non_root_users()
            self.assertTrue(
                all(
                    record["config_user"] == "65532"
                    for record in verifier.report["images"]
                )
            )
            verifier.image_configs["registry-notary"]["User"] = "root"
            with self.assertRaisesRegex(
                tool.VerificationFailure, "image_user_mismatch"
            ):
                verifier.verify_non_root_users()


class PublishedReleaseExternalBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = tool.load_release_identity(MANIFEST)
        self.contract = tool.expected_asset_contract(self.identity)

    def prepare_verifier(
        self, root: Path, io: RecordingIO
    ) -> tool.PublishedReleaseVerifier:
        verifier = tool.PublishedReleaseVerifier(MANIFEST, root / "report.json", io=io)
        verifier.temp_root = root
        verifier.asset_dir = root / "assets"
        verifier.asset_dir.mkdir()
        return verifier

    def test_release_download_selects_only_pre_evidence_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            io = RecordingIO()
            verifier = tool.PublishedReleaseVerifier(
                MANIFEST, root / "report.json", io=io
            )
            verifier.temp_root = root
            verifier.prepare_assets()
            command = io.calls[0][0]
            patterns = {
                command[index + 1]
                for index, value in enumerate(command[:-1])
                if value == "--pattern"
            }
            self.assertEqual(set(self.contract.all_assets), patterns)
            self.assertTrue(
                set(tool.expected_finalization_assets(self.identity)).isdisjoint(
                    patterns
                )
            )

    def test_source_lineage_uses_tag_target_reachability_and_binds_workflow(
        self,
    ) -> None:
        tag_target = "b" * 40
        default_commit = "c" * 40

        class SourceIO(RecordingIO):
            def run(self, argv, *, cwd=None, env=None, timeout=120):
                self.calls.append(
                    (tuple(argv), cwd, dict(env) if env is not None else None)
                )
                if argv[:2] == ("git", "rev-parse"):
                    revision = argv[-1]
                    if revision == "HEAD" or revision.startswith("refs/tags/"):
                        return tool.CommandResult(0, tag_target + "\n")
                    return tool.CommandResult(0, default_commit + "\n")
                if argv[:3] == ("gh", "repo", "view"):
                    return tool.CommandResult(0, "main\n")
                if argv[:3] == ("git", "merge-base", "--is-ancestor"):
                    return tool.CommandResult(0)
                return tool.CommandResult(127)

        with tempfile.TemporaryDirectory() as directory:
            io = SourceIO()
            verifier = tool.PublishedReleaseVerifier(
                MANIFEST, Path(directory) / "report.json", io=io
            )
            verifier.report["workflow"].update(
                {
                    "ref": f"refs/tags/{self.identity.tag}",
                    "head_sha": tag_target,
                    "event": "push",
                    "run_id": "123",
                    "run_url": f"https://github.com/{tool.REPOSITORY}/actions/runs/123",
                }
            )
            verifier.verify_source_identity()
            self.assertTrue(verifier.report["lineage"]["default_branch_reachable"])
            ancestry = [
                call
                for call, _, _ in io.calls
                if call[:3] == ("git", "merge-base", "--is-ancestor")
            ]
            self.assertIn(
                ("git", "merge-base", "--is-ancestor", tag_target, default_commit),
                ancestry,
            )
            verifier.report["workflow"]["head_sha"] = "d" * 40
            with self.assertRaisesRegex(
                tool.VerificationFailure, "workflow_head_mismatch"
            ):
                verifier.verify_source_identity()

    def test_cosign_and_slsa_run_for_all_35_exact_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            io = RecordingIO()
            verifier = self.prepare_verifier(root, io)
            subjects = {}
            for name in self.contract.payloads:
                path = verifier.asset_dir / name
                path.write_bytes(name.encode())
                subjects[name] = tool.file_sha256(path)
                (verifier.asset_dir / f"{name}.sig").write_text(
                    "signature\n", encoding="utf-8"
                )
                (verifier.asset_dir / f"{name}.pem").write_text(
                    "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
                    encoding="utf-8",
                )
                verifier.report["artifacts"].append(
                    {
                        "name": name,
                        "role": "payload",
                        "payload_name": None,
                        "size_bytes": path.stat().st_size,
                        "sha256": subjects[name],
                        "verification": {
                            "checksum": "failed",
                            "signature": "failed",
                            "provenance": "failed",
                        },
                    }
                )
            (verifier.asset_dir / self.contract.provenance).write_text(
                provenance_bundle(subjects), encoding="utf-8"
            )

            verifier.verify_cosign()
            cosign_calls = [
                call for call, _, _ in io.calls if call[:2] == ("cosign", "verify-blob")
            ]
            self.assertEqual(35, len(cosign_calls))
            expected_identity = f"{tool.SOURCE_URL}/.github/workflows/release.yml@refs/tags/{self.identity.tag}"
            self.assertTrue(all(expected_identity in call for call in cosign_calls))
            self.assertTrue(all(tool.COSIGN_ISSUER in call for call in cosign_calls))

            verifier.verify_slsa()
            slsa_calls = [
                call
                for call, _, _ in io.calls
                if call[:2] == ("slsa-verifier", "verify-artifact")
            ]
            self.assertEqual(35, len(slsa_calls))
            self.assertTrue(
                all(
                    tool.SOURCE_URI in call and self.identity.tag in call
                    for call in slsa_calls
                )
            )
            self.assertTrue(
                all(
                    artifact["verification"]
                    == {
                        "checksum": "passed",
                        "signature": "passed",
                        "provenance": "passed",
                    }
                    for artifact in verifier.report["artifacts"]
                )
            )

    def test_image_input_extraction_uses_empty_auth_and_exact_sboms(self) -> None:
        binary_bytes = {
            name: f"binary:{name}".encode()
            for names in tool.IMAGE_INPUTS.values()
            for name in names
        }
        builder = "ghcr.io/registrystack/release-builder@sha256:" + "c" * 64 + "\n"

        class ImageIO(RecordingIO):
            def run(self, argv, *, cwd=None, env=None, timeout=120):
                self.calls.append(
                    (tuple(argv), cwd, dict(env) if env is not None else None)
                )
                if "create" in argv:
                    component = "a" if "registry-notary" in " ".join(argv) else "b"
                    return tool.CommandResult(0, component * 64 + "\n")
                if "cp" in argv:
                    name = Path(argv[-2].split(":", 1)[1]).name
                    Path(argv[-1]).write_bytes(binary_bytes[name])
                return tool.CommandResult(0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            io = ImageIO()
            verifier = self.prepare_verifier(root, io)
            verifier.locked_images = {
                "registry-notary": tool.IMAGE_REPOSITORIES["registry-notary"]
                + "@sha256:"
                + "a" * 64,
                "registry-relay": tool.IMAGE_REPOSITORIES["registry-relay"]
                + "@sha256:"
                + "b" * 64,
            }
            (verifier.asset_dir / "release-builder-image.txt").write_text(
                builder, encoding="utf-8"
            )
            sums = {
                "RELEASE_BUILDER_IMAGE": tool.file_sha256(
                    verifier.asset_dir / "release-builder-image.txt"
                )
            }
            for name, body in binary_bytes.items():
                digest = tool.hashlib.sha256(body).hexdigest()
                sums[name] = digest
                write_json(
                    verifier.asset_dir / f"image-input-{name}.spdx.json",
                    spdx_file_subject(name, digest),
                )
            (verifier.asset_dir / "image-binaries.SHA256SUMS").write_text(
                "".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())),
                encoding="utf-8",
            )
            with unittest.mock.patch.dict(
                os.environ, {"DOCKER_AUTH_CONFIG": "secret"}, clear=False
            ):
                verifier.verify_image_inputs()
            docker_calls = [entry for entry in io.calls if entry[0][0] == "docker"]
            self.assertTrue(docker_calls)
            self.assertTrue(
                all(
                    env is not None and "DOCKER_AUTH_CONFIG" not in env
                    for _, _, env in docker_calls
                )
            )
            self.assertTrue(
                all(
                    "empty-docker-config" in env["DOCKER_CONFIG"]
                    for _, _, env in docker_calls
                )
            )

    def test_anonymous_tag_and_digest_pulls_require_public_linked_packages_and_lock_match(
        self,
    ) -> None:
        locked = {
            "registry-notary": tool.IMAGE_REPOSITORIES["registry-notary"]
            + "@sha256:"
            + "a" * 64,
            "registry-relay": tool.IMAGE_REPOSITORIES["registry-relay"]
            + "@sha256:"
            + "b" * 64,
        }

        class AnonymousIO(RecordingIO):
            def run(self, argv, *, cwd=None, env=None, timeout=120):
                self.calls.append(
                    (tuple(argv), cwd, dict(env) if env is not None else None)
                )
                if argv[:2] == ("gh", "api"):
                    component = argv[-1].rsplit("/", 1)[1]
                    return tool.CommandResult(
                        0,
                        json.dumps(
                            {
                                "visibility": "public",
                                "repository": {"full_name": tool.REPOSITORY},
                                "name": component,
                            }
                        ),
                    )
                if "imagetools" in argv:
                    component = (
                        "registry-notary"
                        if "registry-notary" in argv[-1]
                        else "registry-relay"
                    )
                    return tool.CommandResult(
                        0, json.dumps({"digest": locked[component].rsplit("@", 1)[1]})
                    )
                return tool.CommandResult(0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            io = AnonymousIO()
            verifier = self.prepare_verifier(root, io)
            verifier.locked_images = locked
            with unittest.mock.patch.dict(
                os.environ, {"DOCKER_AUTH_CONFIG": "secret"}, clear=False
            ):
                verifier.verify_anonymous_images()
            pulls = [entry for entry in io.calls if "pull" in entry[0]]
            self.assertEqual(4, len(pulls))
            self.assertTrue(
                all(
                    env is not None and "DOCKER_AUTH_CONFIG" not in env
                    for _, _, env in pulls
                )
            )
            for component, digest_ref in locked.items():
                refs = [call[-1] for call, _, _ in pulls if component in call[-1]]
                self.assertEqual(
                    {
                        digest_ref,
                        f"{tool.IMAGE_REPOSITORIES[component]}:{self.identity.tag}",
                    },
                    set(refs),
                )
            self.assertTrue(
                all(
                    image["anonymous_tag_pull"] == "passed"
                    for image in verifier.report["images"]
                )
            )
            self.assertTrue(
                all(
                    image["anonymous_digest_pull"] == "passed"
                    for image in verifier.report["images"]
                )
            )

    def test_registryctl_authoring_build_uses_downloaded_binary(self) -> None:
        class JourneyIO(RecordingIO):
            def run(self, argv, *, cwd=None, env=None, timeout=120):
                self.calls.append(
                    (tuple(argv), cwd, dict(env) if env is not None else None)
                )
                if argv[-1] == "--version" and len(argv) == 2:
                    return tool.CommandResult(0, "registryctl 0.12.0\n")
                if "init" in argv:
                    project = Path(argv[argv.index("--project-dir") + 1])
                    (project / ".registry-stack-editor").mkdir(
                        parents=True, exist_ok=True
                    )
                    write_json(
                        project / ".registry-stack-editor/manifest.json",
                        {"registry_stack_version": "0.12.0"},
                    )
                    for relative in (
                        "registry-stack.yaml",
                        "integrations/person-record/integration.yaml",
                        "environments/local.yaml",
                        ".registry-stack/build/local/reviewable/review.json",
                        ".registry-stack/build/local/private/relay/config/relay.yaml",
                        ".registry-stack/build/local/private/notary/config/notary.yaml",
                    ):
                        path = project / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("fixture\n", encoding="utf-8")
                return tool.CommandResult(0)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            io = JourneyIO()
            verifier = self.prepare_verifier(root, io)
            binary = verifier.asset_dir / f"registryctl-{self.identity.tag}-linux-amd64"
            binary.write_bytes(b"downloaded-registryctl")
            verifier.verify_registryctl_journey()
            calls = [call for call, _, _ in io.calls]
            self.assertEqual(
                ["init", "authoring", "test", "check", "build"],
                [call[1] for call in calls[1:]],
            )
            self.assertTrue(all(str(binary) == call[0] for call in calls))
            self.assertTrue(
                all(env is None or env.get("CI") == "1" for _, _, env in io.calls[1:])
            )

    def test_archived_docs_have_bounded_retries_and_exact_routes(self) -> None:
        class RetryIO(RecordingIO):
            def __init__(self):
                super().__init__()
                self.attempts: dict[str, int] = {}

            def get(self, url, *, timeout=20):
                self.http_calls.append(url)
                count = self.attempts.get(url, 0)
                self.attempts[url] = count + 1
                if count == 0:
                    return tool.HttpResponse(404, "")
                return tool.HttpResponse(
                    200,
                    "0.12.0 noindex,follow registryctl registryctl init --from http",
                )

        with tempfile.TemporaryDirectory() as directory:
            io = RetryIO()
            verifier = tool.PublishedReleaseVerifier(
                MANIFEST,
                Path(directory) / "report.json",
                io=io,
                docs_attempts=2,
                docs_retry_seconds=0,
            )
            verifier.verify_archived_docs()
            self.assertEqual(12, len(io.http_calls))
            self.assertEqual(6, len(io.sleeps))
            self.assertTrue(
                any(url.endswith("author-registry-project.md") for url in io.http_calls)
            )
            self.assertTrue(
                any(
                    url.endswith("reference/apis/registry-notary/")
                    for url in io.http_calls
                )
            )


if __name__ == "__main__":
    unittest.main()
