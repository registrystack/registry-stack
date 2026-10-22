#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import jsonschema
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase, main


SCRIPT = Path(__file__).with_name("release_candidate.py")
SOURCE_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "c" * 64


def load_module():
    spec = importlib.util.spec_from_file_location("release_candidate_v3", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def evidence_archive(candidate_ref: str) -> tuple[bytes, bytes, bytes]:
    spdx = json_bytes({"spdxVersion": "SPDX-2.3", "packages": []})
    syft = json_bytes(
        {
            "artifacts": [],
            "source": {"type": "image", "metadata": {"userInput": candidate_ref}},
        }
    )
    grype = json_bytes(
        {
            "matches": [],
            "source": {"type": "image", "target": {"userInput": candidate_ref}},
            "descriptor": {
                "db": {
                    "built": "2026-10-23T00:00:00Z",
                    "checksum": "sha256:" + "2" * 64,
                }
            },
        }
    )
    advisory = json_bytes(
        {
            "schema_version": "registry-stack.advisory-verdict.v2",
            "verdict": "passed",
            "subjects": ["discovery-image"],
        }
    )
    entries = {
        "image-sbom/discovery.spdx.json": spdx,
        "syft/discovery.syft.json": syft,
        "grype/discovery.grype.json": grype,
        "grype/grype-db-status.json": json_bytes({"status": "valid"}),
        "advisory-verdict.json": advisory,
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for directory in ("image-sbom", "syft", "grype"):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        for name, payload in sorted(entries.items()):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue(), grype, advisory


class ReleaseCandidateV3Test(TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.now = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_candidate(self) -> tuple[dict, Path, Path]:
        version = "1.2.3"
        tag = "v1.2.3"
        bundle_root = self.root / "bundle"
        candidate_ref = f"ghcr.io/registrystack/discovery-candidate@{IMAGE_DIGEST}"
        evidence, grype, advisory = evidence_archive(candidate_ref)
        inventory = self.module.release_units.payload_inventory("discovery", version)
        files = {
            name: f"candidate payload: {name}\n".encode()
            for name in inventory
        }
        evidence_name = self.module.release_units.security_evidence_name(
            "discovery", version
        )
        files[evidence_name] = evidence
        files["security/discovery.grype.json"] = grype
        files["security/advisory-verdict.json"] = advisory
        for name, payload in files.items():
            path = bundle_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)

        bundle_path = self.root / self.module.release_units.candidate_bundle_name(
            "discovery", version
        )
        with tarfile.open(bundle_path, "w:gz") as archive:
            for name in sorted(files):
                archive.add(bundle_root / name, arcname=name)

        created = self.now - timedelta(hours=1)
        sbom_name = self.module.release_units.sbom_name("discovery", version)
        candidate = {
            "schema_version": "registry-stack.release-candidate.v3",
            "repository": "registrystack/registry-stack",
            "release": {
                "unit": "discovery",
                "version": version,
                "release_id": "discovery-beta-1",
                "tag": f"discovery/{tag}",
                "source_sha": SOURCE_SHA,
            },
            "workflow": {
                "path": ".github/workflows/release-candidate.yml",
                "revision": SOURCE_SHA,
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
                for name, kind in sorted(inventory.items())
            ],
            "images": [
                {
                    "name": "discovery",
                    "candidate_ref": candidate_ref,
                    "digest": IMAGE_DIGEST,
                    "final_ref": f"ghcr.io/registrystack/discovery:{tag}",
                }
            ],
            "sbom": {"name": sbom_name, "sha256": sha256(files[sbom_name])},
            "scans": [
                {
                    "image": "discovery",
                    "name": "security/discovery.grype.json",
                    "sha256": sha256(grype),
                    "status": "passed",
                }
            ],
            "advisory": {
                "name": "security/advisory-verdict.json",
                "sha256": sha256(advisory),
                "verdict": "passed",
            },
            "bundle": {
                "name": bundle_path.name,
                "size": bundle_path.stat().st_size,
                "sha256": self.module.sha256_file(bundle_path),
            },
        }
        return candidate, bundle_path, bundle_root

    def test_discovery_v3_candidate_validates_with_exact_unit_closure(self) -> None:
        candidate, bundle, bundle_root = self.make_candidate()
        result = self.module.validate_candidate_manifest(
            candidate,
            bundle_path=bundle,
            bundle_root=bundle_root,
            expected_unit="discovery",
            expected_version="1.2.3",
            now=self.now,
        )
        self.assertEqual("discovery/v1.2.3", result["release"]["tag"])
        self.assertNotIn("docs", result)
        schema = json.loads((SCRIPT.parent.parent / "schemas/release-candidate-v3.schema.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(candidate)

    def test_discovery_v3_refuses_wrong_tag_extra_payload_and_extra_image(self) -> None:
        candidate, _, _ = self.make_candidate()
        wrong_tag = copy.deepcopy(candidate)
        wrong_tag["release"]["tag"] = "v1.2.3"
        with self.assertRaisesRegex(self.module.CandidateError, "release.tag"):
            self.module.validate_candidate_manifest(wrong_tag, now=self.now)

        extra_payload = copy.deepcopy(candidate)
        extra_payload["payloads"].append(
            {
                "name": "evidence-v1.2.3-linux-amd64",
                "kind": "binary",
                "size": 1,
                "sha256": "1" * 64,
            }
        )
        with self.assertRaisesRegex(self.module.CandidateError, "supported release set"):
            self.module.validate_candidate_manifest(extra_payload, now=self.now)

        extra_image = copy.deepcopy(candidate)
        extra_image["images"].append(
            {
                "name": "evidence",
                "candidate_ref": f"ghcr.io/registrystack/evidence-candidate@{IMAGE_DIGEST}",
                "digest": IMAGE_DIGEST,
                "final_ref": "ghcr.io/registrystack/evidence:v1.2.3",
            }
        )
        with self.assertRaisesRegex(self.module.CandidateError, "image inventory"):
            self.module.validate_candidate_manifest(extra_image, now=self.now)

    def test_v3_schema_is_closed_and_names_the_discovery_unit(self) -> None:
        schema = json.loads(
            (
                SCRIPT.parent.parent
                / "schemas"
                / "release-candidate-v3.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertFalse(schema["additionalProperties"])
        release = schema["$defs"]["discoveryRelease"]
        self.assertIn("unit", release["required"])
        self.assertEqual("discovery", release["properties"]["unit"]["const"])
        self.assertIn("components", schema["properties"])
        self.assertEqual(2, len(schema["oneOf"]))

    def test_stack_v3_carries_component_lock_without_rebuilding_discovery(self) -> None:
        version = "0.45.0"
        component_inventory = self.module.release_units.payload_inventory(
            "discovery", "1.2.3"
        )
        component = {
            "unit": "discovery",
            "version": "1.2.3",
            "release_tag": "discovery/v1.2.3",
            "source_sha": SOURCE_SHA,
            "manifest": {
                "name": "registry-discovery-v1.2.3-release-manifest.json",
                "sha256": "4" * 64,
            },
            "payloads": [
                {
                    "name": name,
                    "kind": kind,
                    "size": index + 1,
                    "sha256": f"{index + 1:064x}",
                }
                for index, (name, kind) in enumerate(
                    sorted(component_inventory.items())
                )
            ],
            "images": [
                {
                    "name": "discovery",
                    "final_ref": "ghcr.io/registrystack/discovery:v1.2.3",
                    "digest": IMAGE_DIGEST,
                }
            ],
        }
        inventory = self.module.stack_payload_inventory(version, [component])
        image_names = self.module.stack_image_names(version, [component])
        self.assertNotIn(f"discovery-v{version}-linux-amd64", inventory)
        self.assertNotIn(f"discoveryctl-v{version}-linux-amd64", inventory)
        self.assertEqual(
            "distribution",
            inventory[f"registry-stack-v{version}-distribution.json"],
        )
        self.assertNotIn("discovery", image_names)
        created = self.now - timedelta(hours=1)
        manifest = {
            "schema_version": "registry-stack.release-candidate.v3",
            "repository": "registrystack/registry-stack",
            "release": {
                "version": version,
                "release_id": "stack-beta-1",
                "tag": f"v{version}",
                "source_sha": SOURCE_SHA,
            },
            "workflow": {
                "path": ".github/workflows/release-candidate.yml",
                "revision": SOURCE_SHA,
                "run_id": 123,
                "run_attempt": 1,
            },
            "validity": {
                "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": (created + timedelta(days=1)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            },
            "payloads": [
                {"name": name, "kind": kind, "size": 1, "sha256": "1" * 64}
                for name, kind in sorted(inventory.items())
            ],
            "images": [
                {
                    "name": name,
                    "candidate_ref": f"ghcr.io/registrystack/{name}-candidate@{IMAGE_DIGEST}",
                    "digest": IMAGE_DIGEST,
                    "final_ref": f"ghcr.io/registrystack/{name}:v{version}",
                }
                for name in sorted(image_names)
            ],
            "docs": {
                "name": f"registry-docs-v{version}.tar.gz",
                "sha256": "1" * 64,
            },
            "sbom": {
                "name": f"registry-stack-v{version}.sbom.spdx.json",
                "sha256": "1" * 64,
            },
            "scans": [
                {
                    "image": name,
                    "name": f"security/{name}.grype.json",
                    "sha256": "2" * 64,
                    "status": "passed",
                }
                for name in sorted(image_names)
            ],
            "advisory": {
                "name": "security/advisory-verdict.json",
                "sha256": "3" * 64,
                "verdict": "passed",
            },
            "bundle": {
                "name": f"registry-stack-v{version}-candidate.tar.gz",
                "size": 1,
                "sha256": "4" * 64,
            },
            "components": [component],
        }
        result = self.module.validate_candidate_manifest(manifest, now=self.now)
        self.assertEqual([component], result["components"])
        schema = json.loads((SCRIPT.parent.parent / "schemas/release-candidate-v3.schema.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(manifest)

        embedded = copy.deepcopy(manifest)
        embedded["payloads"].append(
            {
                "name": f"discovery-v{version}-linux-amd64",
                "kind": "binary",
                "size": 1,
                "sha256": "5" * 64,
            }
        )
        with self.assertRaisesRegex(self.module.CandidateError, "supported release set"):
            self.module.validate_candidate_manifest(embedded, now=self.now)

    def test_component_closure_retains_original_unit_provenance(self) -> None:
        inventory = self.module.release_units.payload_inventory("discovery", "1.2.3")
        component = {
            "unit": "discovery",
            "version": "1.2.3",
            "release_tag": "discovery/v1.2.3",
            "source_sha": SOURCE_SHA,
            "manifest": {
                "name": "registry-discovery-v1.2.3-release-manifest.json",
                "sha256": "4" * 64,
            },
            "payloads": [
                {
                    "name": name,
                    "kind": kind,
                    "size": index + 1,
                    "sha256": f"{index + 1:064x}",
                }
                for index, (name, kind) in enumerate(sorted(inventory.items()))
            ],
            "images": [
                {
                    "name": "discovery",
                    "final_ref": "ghcr.io/registrystack/discovery:v1.2.3",
                    "digest": IMAGE_DIGEST,
                }
            ],
        }
        self.assertEqual(
            [component], self.module.validate_release_components([component])
        )

        for field, value, message in (
            ("release_tag", "v1.2.3", "release_tag"),
            ("source_sha", "short", "source_sha"),
            ("unit", "unknown", "unknown release unit"),
        ):
            changed = copy.deepcopy(component)
            changed[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.module.validate_release_components([changed])

        incomplete = copy.deepcopy(component)
        incomplete["payloads"].pop()
        with self.assertRaisesRegex(self.module.CandidateError, "payload inventory"):
            self.module.validate_release_components([incomplete])

        duplicate = [component, copy.deepcopy(component)]
        with self.assertRaisesRegex(self.module.CandidateError, "duplicate component unit"):
            self.module.validate_release_components(duplicate)

    def test_v3_candidate_reuses_the_manifest_hash_binding_protocol(self) -> None:
        rendered = self.module.render_tag_binding(
            123,
            2,
            "5" * 64,
        )
        self.assertTrue(rendered.startswith("registry-stack-release-candidate-v2\n"))
        self.assertEqual(
            {
                "schema_version": self.module.V2_SCHEMA_VERSION,
                "run_id": 123,
                "run_attempt": 2,
                "manifest_sha256": "5" * 64,
            },
            self.module.parse_tag_binding(rendered),
        )

    def test_candidate_cli_accepts_a_unit_expectation(self) -> None:
        args = self.module.parse_args(
            [
                "verify-candidate",
                "--manifest",
                "candidate.json",
                "--unit",
                "discovery",
            ]
        )
        self.assertEqual("discovery", args.unit)


if __name__ == "__main__":
    main()
