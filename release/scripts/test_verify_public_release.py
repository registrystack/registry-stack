#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock


SCRIPT = Path(__file__).with_name("verify_public_release.py")


def load_module():
    spec = importlib.util.spec_from_file_location("verify_public_release", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class PublicReleaseVerifierTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_client_registry_verification_begins_with_v0_21_1(self) -> None:
        self.assertFalse(self.module.version_uses_client_registries("0.21.0"))
        self.assertTrue(self.module.version_uses_client_registries("0.21.1"))
        self.assertTrue(self.module.version_uses_client_registries("1.0.0"))

    def test_discovery_registry_verification_begins_with_v0_23_0(self) -> None:
        self.assertEqual(
            ("evidence", "relay"),
            self.module.client_registry_clients("0.22.0"),
        )
        self.assertEqual(
            ("discovery", "evidence", "relay"),
            self.module.client_registry_clients("0.23.0"),
        )
        self.assertEqual(
            ("discovery", "evidence", "relay"),
            self.module.client_registry_clients("0.26.0"),
        )
        self.assertEqual(
            ("stack",),
            self.module.client_registry_clients("0.26.1"),
        )

    def test_release_provenance_asset_is_required_after_v0_27_0(self) -> None:
        self.assertFalse(self.module.version_requires_release_provenance("0.26.1"))
        self.assertFalse(self.module.version_requires_release_provenance("0.27.0"))
        self.assertTrue(self.module.version_requires_release_provenance("0.27.1"))
        self.assertTrue(self.module.version_requires_release_provenance("1.0.0"))

    def test_downloaded_provenance_is_outside_the_closure_and_returned(self) -> None:
        tag = "v0.27.1"
        payloads = {"payload.bin": b"payload\n"}
        sums = "".join(
            f"{digest(body)}  {name}\n" for name, body in sorted(payloads.items())
        ).encode()
        provenance_name = f"registry-stack-{tag}-SHA256SUMS.intoto.jsonl"
        files = {
            **payloads,
            "SHA256SUMS": sums,
            f"registry-stack-{tag}-SHA256SUMS.sigstore.json": b"{\"bundle\":true}\n",
            provenance_name: b"{\"dsseEnvelope\":{}}\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, body in files.items():
                (root / name).write_bytes(body)
            assets = {
                name: {
                    "name": name,
                    "digest": f"sha256:{digest(body)}",
                    "size": len(body),
                }
                for name, body in files.items()
            }
            checksums, _, provenance = self.module.verify_downloaded_assets(
                root,
                assets,
                tag=tag,
            )
            self.assertEqual(set(payloads), set(checksums))
            self.assertEqual(provenance_name, provenance)

            (root / provenance_name).unlink()
            del assets[provenance_name]
            with self.assertRaisesRegex(
                self.module.PublicReleaseError,
                f"missing {provenance_name}",
            ):
                self.module.verify_downloaded_assets(root, assets, tag=tag)

    def test_published_v0_27_0_verifies_without_a_provenance_asset(self) -> None:
        tag = "v0.27.0"
        payloads = {"payload.bin": b"payload\n"}
        sums = "".join(
            f"{digest(body)}  {name}\n" for name, body in sorted(payloads.items())
        ).encode()
        files = {
            **payloads,
            "SHA256SUMS": sums,
            f"registry-stack-{tag}-SHA256SUMS.sigstore.json": b"{\"bundle\":true}\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, body in files.items():
                (root / name).write_bytes(body)
            assets = {
                name: {
                    "name": name,
                    "digest": f"sha256:{digest(body)}",
                    "size": len(body),
                }
                for name, body in files.items()
            }
            _, _, provenance = self.module.verify_downloaded_assets(
                root,
                assets,
                tag=tag,
            )
            self.assertIsNone(provenance)

            provenance_name = f"registry-stack-{tag}-SHA256SUMS.intoto.jsonl"
            provenance_body = b'{"dsseEnvelope":{}}\n'
            (root / provenance_name).write_bytes(provenance_body)
            assets[provenance_name] = {
                "name": provenance_name,
                "digest": f"sha256:{digest(provenance_body)}",
                "size": len(provenance_body),
            }
            _, _, provenance = self.module.verify_downloaded_assets(
                root,
                assets,
                tag=tag,
            )
            self.assertEqual(provenance_name, provenance)

    def test_verify_rejects_bad_provenance_before_manifest_or_runtime_checks(
        self,
    ) -> None:
        repository = "registrystack/registry-stack"
        tag = "v0.27.1"
        source = "a" * 40
        manifest_name = f"registry-stack-{tag}-release-manifest.json"
        provenance_name = f"registry-stack-{tag}-SHA256SUMS.intoto.jsonl"
        payloads = {
            manifest_name: b"{}\n",
            self.module.smoke_asset_name(tag): b"binary\n",
        }
        sums = "".join(
            f"{digest(body)}  {name}\n" for name, body in sorted(payloads.items())
        ).encode()
        files = {
            **payloads,
            "SHA256SUMS": sums,
            f"registry-stack-{tag}-SHA256SUMS.sigstore.json": b'{"bundle":true}\n',
            provenance_name: b'{"dsseEnvelope":{}}\n',
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, body in files.items():
                (root / name).write_bytes(body)
            assets = [
                {
                    "name": name,
                    "digest": f"sha256:{digest(body)}",
                    "size": len(body),
                }
                for name, body in files.items()
            ]
            release = {
                "tag_name": tag,
                "draft": False,
                "prerelease": False,
                "published_at": "2026-09-07T00:00:00Z",
                "assets": assets,
            }
            commands: list[list[str]] = []

            def run_text(command: list[str], *, cwd: Path | None = None) -> str:
                del cwd
                commands.append(command)
                if command[:3] == ["git", "ls-remote", "--tags"]:
                    return (
                        f"{'b' * 40}\trefs/tags/{tag}\n"
                        f"{source}\trefs/tags/{tag}^{{}}\n"
                    )
                if command == ["gh", "api", f"repos/{repository}/releases/tags/{tag}"]:
                    return json.dumps(release)
                if command == ["gh", "api", f"repos/{repository}/releases/latest"]:
                    return json.dumps({"tag_name": tag})
                if command[:3] == ["gh", "release", "download"]:
                    return ""
                if command[:2] == ["cosign", "verify-blob"]:
                    return ""
                if command[:3] == ["gh", "attestation", "verify"]:
                    raise self.module.PublicReleaseError("attestation rejected")
                raise AssertionError(f"unexpected command after provenance: {command}")

            temporary_directory = mock.MagicMock()
            temporary_directory.__enter__.return_value = str(root)
            temporary_directory.__exit__.return_value = False
            with (
                mock.patch.object(self.module.shutil, "which", return_value="/tool"),
                mock.patch.object(self.module, "run_text", side_effect=run_text),
                mock.patch.object(
                    self.module.tempfile,
                    "TemporaryDirectory",
                    return_value=temporary_directory,
                ),
                mock.patch.object(
                    self.module, "validate_release_manifest"
                ) as validate_manifest,
                mock.patch.object(self.module, "run_binary_smoke") as smoke,
                self.assertRaisesRegex(
                    self.module.PublicReleaseError, "attestation rejected"
                ),
            ):
                self.module.verify(repo=root, repository=repository, tag=tag)

            expected_attestation = [
                "gh",
                "attestation",
                "verify",
                str(root / "SHA256SUMS"),
                "--bundle",
                str(root / provenance_name),
                "--repo",
                repository,
                "--signer-workflow",
                f"{repository}/.github/workflows/release.yml",
                "--source-ref",
                "refs/heads/main",
                "--deny-self-hosted-runners",
            ]
            self.assertIn(expected_attestation, commands)
            self.assertFalse(any(command[0] == "docker" for command in commands))
            validate_manifest.assert_not_called()
            smoke.assert_not_called()

    def test_checksum_parser_requires_one_local_unique_asset_per_line(self) -> None:
        parsed = self.module.parse_sha256sums(
            f"{'a' * 64}  payload.tar.gz\n{'b' * 64}  relay-v1.2.3-linux-amd64\n"
        )
        self.assertEqual(
            {"payload.tar.gz": "a" * 64, "relay-v1.2.3-linux-amd64": "b" * 64},
            parsed,
        )
        for body, expected in (
            (f"{'a' * 64}  ../payload\n", "nonlocal asset"),
            (
                f"{'a' * 64}  payload\n{'b' * 64}  payload\n",
                "repeats asset payload",
            ),
            ("", "SHA256SUMS is empty"),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(
                self.module.PublicReleaseError,
                expected,
            ):
                self.module.parse_sha256sums(body)

    def test_release_metadata_requires_latest_published_exact_assets(self) -> None:
        release = {
            "tag_name": "v1.2.3",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-08-12T00:00:00Z",
            "assets": [
                {
                    "name": "payload",
                    "digest": f"sha256:{'a' * 64}",
                    "size": 1,
                }
            ],
        }
        assets = self.module.validate_release_metadata(
            release,
            {"tag_name": "v1.2.3"},
            tag="v1.2.3",
        )
        self.assertEqual({"payload"}, set(assets))

        with self.assertRaisesRegex(
            self.module.PublicReleaseError,
            "latest release",
        ):
            self.module.validate_release_metadata(
                release,
                {"tag_name": "v1.2.2"},
                tag="v1.2.3",
            )

    def test_downloaded_asset_verification_closes_checksums_and_api_digests(
        self,
    ) -> None:
        tag = "v1.2.3"
        payloads = {
            "payload.bin": b"payload\n",
            f"registry-stack-{tag}-release-manifest.json": b"{}\n",
        }
        sums = "".join(
            f"{digest(body)}  {name}\n" for name, body in sorted(payloads.items())
        ).encode()
        files = {
            **payloads,
            "SHA256SUMS": sums,
            f"registry-stack-{tag}-SHA256SUMS.sigstore.json": b"{\"bundle\":true}\n",
            f"registry-stack-{tag}-SHA256SUMS.intoto.jsonl": b"{\"dsseEnvelope\":{}}\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, body in files.items():
                (root / name).write_bytes(body)
            assets = {
                name: {
                    "name": name,
                    "digest": f"sha256:{digest(body)}",
                    "size": len(body),
                }
                for name, body in files.items()
            }
            checksums, bundle, provenance = self.module.verify_downloaded_assets(
                root,
                assets,
                tag=tag,
            )
            self.assertEqual(set(payloads), set(checksums))
            self.assertEqual(
                f"registry-stack-{tag}-SHA256SUMS.sigstore.json",
                bundle,
            )
            self.assertEqual(
                f"registry-stack-{tag}-SHA256SUMS.intoto.jsonl",
                provenance,
            )

            (root / "payload.bin").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(
                self.module.PublicReleaseError,
                "wrong downloaded size|digest does not match",
            ):
                self.module.verify_downloaded_assets(root, assets, tag=tag)

    def test_manifest_binds_tag_source_workflow_and_final_images(self) -> None:
        source = "a" * 40
        payload_sha256 = "d" * 64
        document = {
            "schema_version": "registry-stack.release-candidate.v2",
            "repository": "registrystack/registry-stack",
            "release": {
                "tag": "v1.2.3",
                "version": "1.2.3",
                "release_id": "beta-1",
                "source_sha": source,
            },
            "workflow": {
                "path": ".github/workflows/release-candidate.yml",
                "revision": source,
                "run_id": 42,
                "run_attempt": 1,
            },
            "validity": {
                "created_at": "2026-08-12T00:00:00Z",
                "expires_at": "2026-08-19T00:00:00Z",
            },
            "payloads": [
                {
                    "name": "payload.bin",
                    "kind": "binary",
                    "sha256": payload_sha256,
                    "size": 7,
                }
            ],
            "images": [
                {
                    "digest": f"sha256:{'c' * 64}",
                    "final_ref": "ghcr.io/registrystack/evidence:v1.2.3",
                },
                {
                    "digest": f"sha256:{'d' * 64}",
                    "final_ref": "ghcr.io/registrystack/mint:v1.2.3",
                },
                {
                    "digest": f"sha256:{'e' * 64}",
                    "final_ref": "ghcr.io/registrystack/relay:v1.2.3",
                }
            ],
        }
        checksums = {
            "payload.bin": payload_sha256,
            "registry-stack-v1.2.3-release-manifest.json": "e" * 64,
        }
        assets = {"payload.bin": {"size": 7}}
        with mock.patch.object(
            self.module.release_candidate,
            "validate_candidate_manifest",
            return_value=document,
        ) as validate:
            images = self.module.validate_release_manifest(
                document,
                repository="registrystack/registry-stack",
                tag="v1.2.3",
                source_sha=source,
                checksums=checksums,
                assets=assets,
            )
        self.assertEqual(
            {
                "ghcr.io/registrystack/evidence:v1.2.3",
                "ghcr.io/registrystack/mint:v1.2.3",
                "ghcr.io/registrystack/relay:v1.2.3",
            },
            {image["final_ref"] for image in images},
        )
        self.assertEqual(source, validate.call_args.kwargs["expected_source_sha"])

        with (
            mock.patch.object(
                self.module.release_candidate,
                "validate_candidate_manifest",
                return_value=document,
            ),
            self.assertRaisesRegex(
                self.module.PublicReleaseError,
                "payload closure differs",
            ),
        ):
            self.module.validate_release_manifest(
                document,
                repository="registrystack/registry-stack",
                tag="v1.2.3",
                source_sha=source,
                checksums={**checksums, "unlisted.bin": "f" * 64},
                assets={**assets, "unlisted.bin": {"size": 1}},
            )

        document["images"][0]["final_ref"] = "ghcr.io/registrystack/relay:latest"
        with (
            mock.patch.object(
                self.module.release_candidate,
                "validate_candidate_manifest",
                return_value=document,
            ),
            self.assertRaisesRegex(
                self.module.PublicReleaseError,
                "image identity is invalid",
            ),
        ):
            self.module.validate_release_manifest(
                document,
                repository="registrystack/registry-stack",
                tag="v1.2.3",
                source_sha=source,
                checksums=checksums,
                assets=assets,
            )

    def test_binary_smoke_does_not_inherit_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "evidence"
            script.write_text(
                "#!/bin/sh\n"
                "test -z \"${GH_TOKEN:-}\"\n"
                "test -z \"${AWS_SECRET_ACCESS_KEY:-}\"\n"
                "printf 'evidence 1.2.3\\n'\n",
                encoding="utf-8",
            )
            script.chmod(0o700)
            original_gh = os.environ.get("GH_TOKEN")
            original_aws = os.environ.get("AWS_SECRET_ACCESS_KEY")
            os.environ["GH_TOKEN"] = "must-not-leak"
            os.environ["AWS_SECRET_ACCESS_KEY"] = "must-not-leak"
            try:
                observed = self.module.run_binary_smoke(script)
            finally:
                if original_gh is None:
                    os.environ.pop("GH_TOKEN", None)
                else:
                    os.environ["GH_TOKEN"] = original_gh
                if original_aws is None:
                    os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
                else:
                    os.environ["AWS_SECRET_ACCESS_KEY"] = original_aws
            self.assertEqual("evidence 1.2.3", observed)

    def test_client_registry_verifier_requires_all_exact_public_packages(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                self.module.client_registry,
                "validate_distribution",
            ),
            mock.patch.object(
                self.module.client_registry,
                "npm_tarballs",
                return_value=[Path(temporary) / "root.tgz"],
            ),
            mock.patch.object(
                self.module.client_registry,
                "npm_metadata",
                return_value={},
            ),
            mock.patch.object(
                self.module.client_registry,
                "npm_registry_state",
                return_value="present",
            ),
            mock.patch.object(
                self.module.client_registry,
                "wheel_paths",
                return_value=[Path(temporary) / "client.whl"],
            ),
            mock.patch.object(
                self.module.client_registry,
                "pypi_metadata",
                return_value={},
            ),
            mock.patch.object(
                self.module.client_registry,
                "pypi_registry_state",
                return_value="present",
            ),
        ):
            self.assertEqual(
                2,
                self.module.verify_client_registries(Path(temporary), "1.2.3"),
            )


if __name__ == "__main__":
    main()
