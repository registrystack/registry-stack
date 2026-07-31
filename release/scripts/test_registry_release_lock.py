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
            tag_target = manifest_source_ref
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
            image_indexes = {}
            image_identities = {}
            application_digests = {}
            for name, repository, value in [
                ("relay", "ghcr.io/registrystack/registry-relay", "d"),
                ("notary", "ghcr.io/registrystack/registry-notary", "e"),
                ("postgresql", "docker.io/library/postgres", "f"),
            ]:
                application_digest = f"sha256:{value * 64}"
                path = root / f"{name}.index.json"
                path.write_bytes(
                    release_lock.canonical_json(
                        {
                            "schemaVersion": 2,
                            "mediaType": "application/vnd.oci.image.index.v1+json",
                            "manifests": [
                                {
                                    "mediaType": (
                                        release_lock.OCI_IMAGE_MANIFEST_MEDIA_TYPE
                                    ),
                                    "digest": application_digest,
                                    "platform": {
                                        "os": "linux",
                                        "architecture": "amd64",
                                    },
                                }
                            ],
                        }
                    )
                )
                image_indexes[name] = path
                image_identities[name] = (
                    f"{repository}@{release_lock.sha256_file(path)}"
                )
                application_digests[name] = application_digest
            image_lock = root / "image-lock.json"
            image_lock.write_text(
                json.dumps(
                    {
                        "release_tag": tag,
                        "manifest_source_ref": manifest_source_ref,
                        "tag_target": tag_target,
                        "images": {
                            "registry-relay": image_identities["relay"],
                            "registry-notary": image_identities["notary"],
                            "postgresql": image_identities["postgresql"],
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
                            relay_image_index=image_indexes["relay"],
                            notary_image_index=image_indexes["notary"],
                            postgresql_image_index=image_indexes["postgresql"],
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
                payload["images"]["relay"],
                {
                    "identity": image_identities["relay"],
                    "platforms": [
                        {
                            "platform": "linux-amd64",
                            "manifest_digest": application_digests["relay"],
                        }
                    ],
                },
            )
            self.assertEqual(
                payload["images"]["notary"]["platforms"][0]["manifest_digest"],
                application_digests["notary"],
            )
            self.assertEqual(
                payload["images"]["postgresql_state_plane"]["platforms"][0][
                    "manifest_digest"
                ],
                application_digests["postgresql"],
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
            expected_starter_ids = {"http"}
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
                    "preview_state",
                    "accept_state",
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
                development_prefix = ["development-action"]
                if product == "registry-relay":
                    development_prefix.append(lane)
                for field, action in [
                    (
                        "development_prepare_state_store",
                        "prepare_state_store",
                    ),
                    ("development_initialize_state", "initialize_state"),
                    ("development_serve", "serve"),
                ]:
                    self.assertEqual(
                        recipe[field]["command"],
                        [*development_prefix, action],
                    )
                    self.assertEqual(
                        recipe[field]["environment_files"],
                        [f"{lane}-environment"],
                    )
                    expected_secrets = lane_secrets[lane][
                        "preparation"
                        if field
                        in {
                            "development_prepare_state_store",
                            "development_initialize_state",
                        }
                        else "serve"
                    ]
                    self.assertEqual(
                        [
                            projection["file_id"]
                            for projection in recipe[field]["secret_files"]
                        ],
                        expected_secrets,
                    )
                for field in [
                    "serve",
                    "verify_state",
                    "preview_state",
                    "development_serve",
                ]:
                    state_mount = next(
                        mount
                        for mount in recipe[field]["mounts"]
                        if mount["source"] == "anti_rollback_state"
                    )
                    self.assertTrue(state_mount["read_only"], field)
                for field in [
                    "initialize_state",
                    "accept_state",
                    "development_initialize_state",
                ]:
                    state_mount = next(
                        mount
                        for mount in recipe[field]["mounts"]
                        if mount["source"] == "anti_rollback_state"
                    )
                    self.assertFalse(state_mount["read_only"], field)
                self.assertNotIn(
                    "audit",
                    {
                        mount["source"]
                        for mount in recipe["preview_state"]["mounts"]
                    },
                )
                self.assertEqual(
                    recipe["health_probe"],
                    [
                        "CMD",
                        f"/usr/local/bin/{product}",
                        "healthcheck",
                        "--url",
                        "http://127.0.0.1:8080/ready",
                    ],
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
                "cbad443afb9700702df52be6513cf8afd95b97747d75a0a417df4fd079a2e79c",
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

    def test_postgresql_bootstrap_marker_refuses_a_second_mutating_run(
        self,
    ) -> None:
        script = release_lock.POSTGRESQL_BOOTSTRAP_SCRIPT
        marker_statement = "CREATE TABLE public.registry_stack_bootstrap_marker ("
        marker_position = script.index(marker_statement)
        self.assertEqual(script.count(marker_statement), 1)
        self.assertIn(f"<<'SQL'\n{marker_statement}", script)
        marker_block = script[
            marker_position : script.index(
                "REVOKE ALL ON TABLE "
                "public.registry_stack_bootstrap_marker FROM PUBLIC;"
            )
        ]
        self.assertNotIn("IF NOT EXISTS", marker_block)
        for mutation in [
            "CREATE ROLE",
            "ALTER ROLE",
            "GRANT registry_",
            "CREATE DATABASE",
            "ALTER DATABASE",
            "REVOKE ALL ON DATABASE",
            "GRANT CONNECT ON DATABASE",
        ]:
            self.assertLess(marker_position, script.index(mutation), mutation)

    def test_create_payload_rejects_a_distinct_tag_target(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be identical"):
            release_lock.create_payload(
                argparse.Namespace(
                    version="1.0.0",
                    manifest_source_ref="1" * 40,
                    tag_target="2" * 40,
                    asset_dir=Path("unused-assets"),
                    image_lock=Path("unused-image-lock.json"),
                    output=Path("unused-output.json"),
                )
            )

    def test_platform_manifest_resolution_selects_only_the_application_image(
        self,
    ) -> None:
        application_digest = f"sha256:{'a' * 64}"
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": release_lock.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                    "digest": application_digest,
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "mediaType": release_lock.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                    "digest": f"sha256:{'b' * 64}",
                    "platform": {"os": "unknown", "architecture": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest"
                    },
                },
                {
                    "mediaType": release_lock.OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                    "digest": f"sha256:{'c' * 64}",
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
            ],
        }

        self.assertEqual(
            release_lock.select_platform_manifest(index, "linux/amd64"),
            application_digest,
        )

        duplicate = copy.deepcopy(index)
        duplicate["manifests"].append(copy.deepcopy(index["manifests"][0]))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            release_lock.select_platform_manifest(duplicate, "linux/amd64")

        wrong_media_type = copy.deepcopy(index)
        wrong_media_type["manifests"][0]["mediaType"] = (
            "application/vnd.oci.image.index.v1+json"
        )
        with self.assertRaisesRegex(ValueError, "unsupported media type"):
            release_lock.select_platform_manifest(
                wrong_media_type,
                "linux/amd64",
            )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "index.json"
            path.write_bytes(release_lock.canonical_json(index))
            with self.assertRaisesRegex(ValueError, "locked image identity"):
                release_lock.read_platform_manifest_from_index(
                    path,
                    "Relay",
                    f"sha256:{'9' * 64}",
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
        lock_verify = workflow.index(
            "cosign verify-blob contract/registry-release-lock.payload.json",
            lock_sign,
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
        self.assertLess(lock_sign, lock_verify)
        self.assertLess(lock_verify, assemble)
        self.assertLess(assemble, checksum)
        self.assertLess(checksum, checksum_sign)
        verification = workflow[lock_verify:assemble]
        self.assertIn(
            ".github/workflows/release.yml@refs/tags/${tag}",
            workflow[lock_sign:assemble],
        )
        self.assertIn("--certificate-identity", verification)
        self.assertIn(
            "https://token.actions.githubusercontent.com",
            verification,
        )

    def test_release_workflow_resolves_platform_manifests_and_retries_finalization(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        for artifact in [
            "release-promotion-input-${{ github.run_id }}",
            "release-draft-contract-${{ github.run_id }}",
            "release-final-contract-${{ github.run_id }}",
        ]:
            self.assertIn(artifact, workflow)
            self.assertNotIn(f"{artifact}-${{{{ github.run_attempt }}}}", workflow)
        self.assertGreaterEqual(workflow.count("overwrite: true"), 3)

        cleanup = workflow.index(
            "Clean retryable final additions and reverify exact staged assets"
        )
        delete = workflow.index(
            '"repos/${GITHUB_REPOSITORY}/releases/assets/${asset_id}"',
            cleanup,
        )
        staged_diff = workflow.index(
            "diff -u contract/expected-assets contract/actual-assets",
            delete,
        )
        final_upload = workflow.index(
            'gh release upload "${tag}" "${additions[@]}"',
            staged_diff,
        )
        self.assertLess(cleanup, delete)
        self.assertLess(delete, staged_diff)
        self.assertLess(staged_diff, final_upload)
        self.assertIn("contract/retryable-final-assets", workflow[cleanup:delete])
        self.assertIn(
            "registry-stack-release-candidate-v2 manifest_sha256:",
            workflow[cleanup:delete],
        )

        render = workflow.index("Render the final P to T image lock")
        inspect = workflow.index('crane manifest "${image_ref}"', render)
        image_lock_compare = workflow.index(
            'select(.kind == "image-lock" and .name == $name)',
            inspect,
        )
        create = workflow.index("registry_release_lock.py create-payload", inspect)
        self.assertLess(render, inspect)
        self.assertLess(inspect, image_lock_compare)
        self.assertLess(image_lock_compare, create)
        for argument in [
            "--relay-image-index",
            "--notary-image-index",
            "--postgresql-image-index",
        ]:
            self.assertIn(argument, workflow[create:])
        publish = workflow.index("- name: Publish immutable release")
        dispatch = workflow.index("\n  dispatch-docs:", publish)
        self.assertIn(
            ".draft == true",
            workflow[publish:dispatch],
        )
        self.assertNotIn("is_draft", workflow[publish:dispatch])
        self.assertIn(
            "gh api --method PATCH",
            workflow[publish:dispatch],
        )
        self.assertIn(
            ".id == $release_id and\n             .draft == false",
            workflow[publish:dispatch],
        )


if __name__ == "__main__":
    unittest.main()
