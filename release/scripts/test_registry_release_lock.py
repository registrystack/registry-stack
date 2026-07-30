#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import hashlib
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
            manifest_source_ref = "1" * 40
            tag_target = "2" * 40
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
                        "manifest_source_ref": manifest_source_ref,
                        "tag_target": tag_target,
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
                            manifest_source_ref=manifest_source_ref,
                            tag_target=tag_target,
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
            self.assertEqual(
                payload["release"]["manifest_source_ref"],
                manifest_source_ref,
            )
            self.assertEqual(payload["release"]["tag_target"], tag_target)
            self.assertEqual(
                set(schema["properties"]["images"]["required"]),
                set(schema["properties"]["images"]["properties"]),
            )
            self.assertEqual(
                set(payload["images"]),
                {"relay", "notary", "postgresql_state_plane"},
            )
            self.assertEqual(
                set(payload["images"]),
                set(schema["properties"]["images"]["required"]),
            )
            self.assertEqual(
                set(schema["properties"]["runtime"]["required"]),
                set(schema["properties"]["runtime"]["properties"]),
            )
            self.assertNotIn("private_namespace_holder", payload["runtime"])
            self.assertNotIn("supporting_runtime", schema["$defs"])
            self.assertTrue(
                set(schema["properties"]["runtime"]["required"]).issubset(
                    payload["runtime"]
                )
            )
            self.assertEqual(
                set(payload["runtime"]),
                set(schema["properties"]["runtime"]["required"]),
            )
            missing_inventory = copy.deepcopy(payload)
            missing_inventory["runtime"].pop("operator_files")
            self.assertFalse(
                set(schema["properties"]["runtime"]["required"]).issubset(
                    missing_inventory["runtime"]
                )
            )
            self.assertEqual(len(payload["registryctl_artifacts"]), 3)
            self.assertEqual(
                schema["properties"]["embedded_starters"]["minItems"],
                len(payload["embedded_starters"]),
            )
            self.assertEqual(
                schema["properties"]["embedded_starters"]["maxItems"],
                len(payload["embedded_starters"]),
            )
            expected_starter_ids = {
                "dhis2-tracker",
                "fhir-r4",
                "http",
                "opencrvs-dci",
                "snapshot",
            }
            self.assertEqual(
                {starter["id"] for starter in payload["embedded_starters"]},
                expected_starter_ids,
            )
            self.assertEqual(
                set(schema["$defs"]["starter"]["properties"]["id"]["enum"]),
                expected_starter_ids,
            )
            self.assertEqual(
                payload["runtime"]["relay_consultation"]["serve"]["command"],
                ["product-action", "relay-consultation", "serve"],
            )
            self.assertEqual(
                payload["runtime"]["relay_consultation"][
                    "prepare_state_store"
                ]["mounts"],
                [
                    {
                        "source": "bundle",
                        "target": "/run/registry/bundle",
                        "read_only": True,
                    },
                    {
                        "source": "anchor",
                        "target": "/run/registry/anchor",
                        "read_only": True,
                    },
                    {
                        "source": "audit",
                        "target": "/var/lib/registry/audit",
                        "read_only": False,
                    },
                ],
            )
            self.assertNotIn(
                "anti_rollback_state",
                {
                    mount["source"]
                    for mount in payload["runtime"]["relay_consultation"][
                        "prepare_state_store"
                    ]["mounts"]
                },
            )
            postgresql = payload["runtime"]["postgresql_state_plane"]
            lane_secrets = {
                "relay-public": {
                    "preparation": [],
                    "serve": [
                        "relay-public-tls-certificate",
                        "relay-public-tls-private-key",
                    ],
                },
                "relay-consultation": {
                    "preparation": ["postgresql-tls-certificate"],
                    "serve": [
                        "postgresql-tls-certificate",
                        "relay-consultation-tls-certificate",
                        "relay-consultation-tls-private-key",
                    ],
                },
                "notary": {
                    "preparation": ["postgresql-tls-certificate"],
                    "serve": [
                        "postgresql-tls-certificate",
                        "relay-consultation-tls-certificate",
                        "notary-relay-workload-credential",
                        "notary-signing-key",
                        "notary-tls-certificate",
                        "notary-tls-private-key",
                    ],
                },
            }
            for lane, product in [
                ("relay-public", "registry-relay"),
                ("relay-consultation", "registry-relay"),
                ("notary", "registry-notary"),
            ]:
                recipe = payload["runtime"][lane.replace("-", "_")]
                prefix = ["product-action"]
                if product == "registry-relay":
                    prefix.append(lane)
                for action in [
                    "serve",
                    "prepare_state_store",
                    "initialize_state",
                    "verify_state",
                ]:
                    self.assertEqual(
                        recipe[action]["command"],
                        [*prefix, action],
                    )
                    self.assertEqual(
                        recipe[action]["environment_files"],
                        [f"{lane}-environment"],
                    )
                    expected_secrets = lane_secrets[lane][
                        "preparation"
                        if action in ["prepare_state_store", "initialize_state"]
                        else "serve"
                    ]
                    self.assertEqual(
                        [
                            projection["file_id"]
                            for projection in recipe[action]["secret_files"]
                        ],
                        expected_secrets,
                    )
                self.assertEqual(
                    recipe["health_probe"],
                    ["CMD", f"/usr/local/bin/{product}", "healthcheck"],
                )
            self.assertEqual(postgresql["hardening"]["user"], "999:999")
            self.assertEqual(
                postgresql["bootstrap"]["environment_files"],
                ["postgresql-bootstrap-environment"],
            )
            self.assertIn(
                "ssl_cert_file=/run/secrets/postgresql-tls.crt",
                postgresql["serve"]["command"],
            )
            self.assertEqual(
                hashlib.sha256(
                    postgresql["bootstrap"]["command"][2].encode()
                ).hexdigest(),
                "f0804dbb6564a08144ded38123daa40d6c1293ddec168dc37e0ad4d3bbf299aa",
            )
            bootstrap_file = next(
                file
                for file in payload["runtime"]["operator_files"]
                if file["id"] == "postgresql-bootstrap-environment"
            )
            self.assertEqual(
                bootstrap_file["required_keys"],
                release_lock.POSTGRESQL_BOOTSTRAP_KEYS,
            )
            product_environment_ids = {
                "relay-public-environment",
                "relay-consultation-environment",
                "notary-environment",
            }
            operator_files = payload["runtime"]["operator_files"]
            self.assertEqual(
                {file["id"] for file in operator_files},
                product_environment_ids
                | {
                    "relay-public-tls-certificate",
                    "relay-public-tls-private-key",
                    "relay-consultation-tls-certificate",
                    "relay-consultation-tls-private-key",
                    "notary-tls-certificate",
                    "notary-tls-private-key",
                    "notary-signing-key",
                    "notary-relay-workload-credential",
                    "postgresql-tls-certificate",
                    "postgresql-tls-private-key",
                    "postgresql-admin-password",
                    "postgresql-bootstrap-environment",
                },
            )
            self.assertEqual(
                schema["properties"]["runtime"]["properties"]["operator_files"][
                    "minItems"
                ],
                len(operator_files),
            )
            self.assertEqual(
                schema["properties"]["runtime"]["properties"]["operator_files"][
                    "maxItems"
                ],
                len(operator_files),
            )
            self.assertEqual(
                {
                    file["id"]
                    for file in operator_files
                    if file["id"] in product_environment_ids
                },
                product_environment_ids,
            )
            for file in operator_files:
                if file["id"] in product_environment_ids:
                    self.assertEqual(file["format"], "dotenv")
                    self.assertEqual(file["required_keys"], [])
            self.assertFalse(
                any(
                    action in file["id"]
                    for file in operator_files
                    for action in [
                        "-prepare-environment",
                        "-initialize-environment",
                        "-serve-environment",
                    ]
                )
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
