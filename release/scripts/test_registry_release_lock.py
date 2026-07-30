#!/usr/bin/env python3

from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("registry_release_lock.py")
SPEC = importlib.util.spec_from_file_location("registry_release_lock", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
release_lock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_lock)
ROOT = SCRIPT.parents[2]


class RegistryReleaseLockTests(unittest.TestCase):
    def test_create_payload_generates_complete_closed_example(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            starters = root / "starters"
            assets.mkdir()
            starters.mkdir()
            version = "1.0.0"
            tag = f"v{version}"
            source_sha = "1" * 40
            for platform in release_lock.PLATFORMS:
                (assets / f"registryctl-{tag}-{platform}").write_bytes(
                    f"registryctl {platform}".encode()
                )
            test_starters: dict[str, Path] = {}
            for index, starter_id in enumerate(sorted(release_lock.STARTERS), 1):
                path = starters / f"{starter_id}.yaml"
                path.write_text(
                    "starter:\n"
                    f"  id: {starter_id}\n"
                    f"  release: {version}\n"
                    f"  content_digest: sha256:{index:064x}\n",
                    encoding="utf-8",
                )
                test_starters[starter_id] = path
            image_lock = root / "image-lock.json"
            image_lock.write_text(
                json.dumps(
                    {
                        "release_tag": tag,
                        "manifest_source_ref": source_sha,
                        "images": {
                            "registry-relay": (
                                f"ghcr.io/registrystack/registry-relay@sha256:{'a' * 64}"
                            ),
                            "registry-notary": (
                                f"ghcr.io/registrystack/registry-notary@sha256:{'b' * 64}"
                            ),
                            "postgresql": (
                                f"docker.io/library/postgres@sha256:{'c' * 64}"
                            ),
                        },
                    }
                ),
                encoding="utf-8",
            )
            output = root / "payload.json"
            original_starters = release_lock.STARTERS
            release_lock.STARTERS = test_starters
            try:
                self.assertEqual(
                    release_lock.create_payload(
                        argparse.Namespace(
                            version=version,
                            source_sha=source_sha,
                            asset_dir=assets,
                            image_lock=image_lock,
                            output=output,
                        )
                    ),
                    0,
                )
            finally:
                release_lock.STARTERS = original_starters
            payload = json.loads(output.read_bytes())
            schema = json.loads(
                (
                    ROOT
                    / "release/registry-release-lock-payload.v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(output.read_bytes(), release_lock.canonical_json(payload))
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(set(payload), set(schema["required"]))
            self.assertEqual(len(payload["registryctl_artifacts"]), 3)
            self.assertEqual(len(payload["embedded_starters"]), 6)
            self.assertEqual(
                payload["runtime"]["relay_consultation"]["serve"],
                ["product-action", "relay-consultation", "serve"],
            )
            self.assertEqual(
                payload["images"]["private_namespace_holder"]["identity"],
                payload["images"]["postgresql_state_plane"]["identity"],
            )

    def test_assemble_carries_exact_payload_and_cosign_v3_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.json"
            bundle = root / "bundle.json"
            output = root / "registry-release-lock.v1.json"
            payload_value = {
                "schema_id": release_lock.SCHEMA_ID,
                "schema_version": release_lock.SCHEMA_VERSION,
            }
            payload.write_bytes(release_lock.canonical_json(payload_value))
            fixture = (
                ROOT
                / "crates/registryctl/tests/fixtures/release-lock/"
                "cosign-v3-blob.sigstore.json"
            )
            bundle.write_bytes(fixture.read_bytes())
            self.assertEqual(
                release_lock.assemble(
                    argparse.Namespace(
                        payload=payload,
                        bundle=bundle,
                        output=output,
                    )
                ),
                0,
            )
            self.assertEqual(
                release_lock.check(argparse.Namespace(input=output)),
                0,
            )
            envelope = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                envelope["sigstore_bundle"]["mediaType"],
                "application/vnd.dev.sigstore.bundle.v0.3+json",
            )

    def test_duplicate_json_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema_id":"a","schema_id":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
                release_lock.read_json(path)

    def test_release_workflow_pins_cosign_v3_and_checksums_final_lock(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        install = workflow.index("cosign-release: v3.0.4")
        lock_sign = workflow.index(
            "contract/registry-release-lock.payload.json", install
        )
        assemble = workflow.index(
            "--output release-assets/registry-release-lock.v1.json", lock_sign
        )
        checksum = workflow.index(
            "find . -maxdepth 1 -type f ! -name SHA256SUMS", assemble
        )
        checksum_sign = workflow.index(
            "registry-stack-${{ needs.verify.outputs.tag }}-SHA256SUMS.sigstore.json",
            checksum,
        )
        self.assertLess(install, lock_sign)
        self.assertLess(lock_sign, assemble)
        self.assertLess(assemble, checksum)
        self.assertLess(checksum, checksum_sign)


if __name__ == "__main__":
    unittest.main()
