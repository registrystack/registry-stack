#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "release" / "scripts"
TOOL = SCRIPTS / "registry-release"
SCHEMA = ROOT / "release" / "schemas" / "release-evidence-bundle-v1.schema.json"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import release_evidence  # noqa: E402


def load_registry_release() -> Any:
    loader = importlib.machinery.SourceFileLoader(
        "registry_release_evidence_cli", str(TOOL)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise ImportError(f"could not load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def load_verify_published() -> Any:
    path = SCRIPTS / "verify_published_release.py"
    name = "verify_published_release_evidence_contract"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EvidenceFixture:
    version = "1.2.3"
    tag = "v1.2.3"
    release_id = "beta-99"
    source_ref = "1" * 40
    tag_target = "2" * 40
    default_branch_commit = "3" * 40
    run_id = "123456789"

    def __init__(self, root: Path) -> None:
        self.root = root
        self.assets = root / "assets"
        self.assets.mkdir(parents=True)
        self.manifest = root / f"registry-stack-{self.release_id}.yaml"
        self.capsule = self.assets / "registry-stack-v1.2.3-release-capsule.json"
        self.verifier = root / "verify-published.json"
        self.output = root / "release-evidence.json"
        self.closeout = root / "release-closeout.md"
        self.warnings = [
            {
                "code": "hosted-publication-held",
                "classification": "hosted-gate-held",
                "detail": "Public announcement remains held until the recorded adopter condition passes.",
            },
            {
                "code": "adopter-repin-pending",
                "classification": "adopter-gate-pending",
                "detail": "The downstream immutable digest repin remains pending.",
            },
        ]
        self.workflow = {
            "name": "RegistryStack Release",
            "run_id": self.run_id,
            "run_attempt": "2",
            "run_url": (
                "https://github.com/registrystack/registry-stack/actions/runs/"
                f"{self.run_id}"
            ),
            "event": "push",
            "ref": f"refs/tags/{self.tag}",
            "head_sha": self.tag_target,
            "started_at": "2026-07-20T01:02:03Z",
            "completed_at": "2026-07-20T01:04:03Z",
            "duration_seconds": 120,
        }
        self.lineage = {
            "manifest_source_ref": self.source_ref,
            "tag_target": self.tag_target,
            "default_branch": "main",
            "default_branch_commit": self.default_branch_commit,
            "tag_matches_source_tag": True,
            "head_matches_tag_target": True,
            "source_ref_ancestor_or_equal": True,
            "default_branch_reachable": True,
        }
        self._write_inputs()

    def _write_inputs(self) -> None:
        manifest = {
            "stack": {
                "release": self.release_id,
                "version": self.version,
                "source_repo": "registrystack/registry-stack",
                "source_ref": self.source_ref,
                "source_tag": self.tag,
                "status": "release-candidate",
            },
            "artifacts": {"registryctl": self.version},
            "external": {
                "crosswalk": {
                    "repo": "PublicSchema/crosswalk",
                    "ref": "4" * 40,
                    "status": "tested external input",
                }
            },
            "warnings": self.warnings,
        }
        self.manifest.write_text(
            yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
        )
        manifest_sha256 = digest(self.manifest)
        capsule = {
            "release_tag": self.tag,
            "version": self.version,
            "repository": "registrystack/registry-stack",
            "source": {
                "source_tag": self.tag,
                "source_ref": self.source_ref,
                "source_commit": self.tag_target,
                "manifest_ref": self.source_ref,
                "lineage": {
                    key: self.lineage[key]
                    for key in (
                        "tag_matches_source_tag",
                        "head_matches_tag_target",
                        "source_ref_ancestor_or_equal",
                        "default_branch_reachable",
                    )
                },
            },
            "workflow": {
                "name": self.workflow["name"],
                "run_url": self.workflow["run_url"],
                "run_id": self.workflow["run_id"],
            },
            "manifest": {"path": str(self.manifest), "sha256": manifest_sha256},
            "default_branch_protection": {"status": "verified"},
            "external_pinned_inputs": manifest["external"],
            "binaries": [{"name": "registryctl"}],
            "release_files": [],
            "images": [{"name": "registry-notary"}],
            "warnings": self.warnings,
            "hosted_publication_status": "held",
        }
        self.capsule.write_text(
            json.dumps(capsule, sort_keys=True) + "\n", encoding="utf-8"
        )

        expected_names = release_evidence.expected_artifact_names(self.tag)
        payloads = [self.capsule]
        for name in sorted(expected_names["payload"] - {self.capsule.name}):
            path = self.assets / name
            path.write_bytes(f"payload {name}\n".encode())
            payloads.append(path)
        artifacts = [self._artifact(path, "payload", None) for path in payloads]
        for payload in payloads:
            for role, suffix in (("signature", ".sig"), ("certificate", ".pem")):
                path = self.assets / f"{payload.name}{suffix}"
                path.write_bytes(f"{role} for {payload.name}\n".encode())
                artifacts.append(self._artifact(path, role, payload.name))
        provenance = self.assets / next(iter(expected_names["provenance"]))
        provenance.write_text(
            '{"predicateType":"https://slsa.dev/provenance/v1"}\n', encoding="utf-8"
        )
        artifacts.append(self._artifact(provenance, "provenance", None))

        checks = [
            {
                "id": check_id,
                "phase": release_evidence.CHECK_SPECS[check_id][0],
                "subject": release_evidence.CHECK_SPECS[check_id][1],
                "status": "passed",
                "tool": release_evidence.CHECK_SPECS[check_id][2],
                "failure_codes": [],
            }
            for check_id in sorted(release_evidence.FIXED_CHECK_IDS, reverse=True)
        ]
        images = [
            {
                "component": component,
                "repository": f"ghcr.io/registrystack/{component}",
                "tag_ref": f"ghcr.io/registrystack/{component}:{self.tag}",
                "digest_ref": f"ghcr.io/registrystack/{component}@sha256:{marker * 64}",
                "digest": f"sha256:{marker * 64}",
                "anonymous_tag_pull": "passed",
                "anonymous_digest_pull": "passed",
                "config_user": "65532",
                "labels": {
                    "source": "https://github.com/registrystack/registry-stack",
                    "revision": self.tag_target,
                    "version": self.version,
                },
                "reported_version": f"{component} {self.version}",
            }
            for component, marker in (
                ("registry-relay", "b"),
                ("registry-notary", "a"),
            )
        ]
        verifier = {
            "schema_version": release_evidence.VERIFIER_SCHEMA,
            "classification": "public",
            "status": "passed",
            "release": {
                "repository": "registrystack/registry-stack",
                "release_id": self.release_id,
                "version": self.version,
                "tag": self.tag,
                "manifest_sha256": manifest_sha256,
            },
            "lineage": self.lineage,
            "workflow": self.workflow,
            "tools": [
                {
                    "name": "gh",
                    "version": "gh version 2.77.0",
                    "source": "observed",
                },
                {"name": "cosign", "version": "3.0.2", "source": "observed"},
                {"name": "slsa-verifier", "version": "2.7.1", "source": "observed"},
                {"name": "docker", "version": "28.3.2", "source": "observed"},
                {
                    "name": "docker-buildx",
                    "version": "github.com/docker/buildx 0.25.0",
                    "source": "observed",
                },
            ],
            "artifact_scope": {
                "name": release_evidence.SCOPE_NAME,
                "expected_counts": release_evidence.EXPECTED_COUNTS,
                "observed_counts": release_evidence.EXPECTED_COUNTS,
                "excluded_roles": release_evidence.EXCLUDED_ROLES,
            },
            "artifacts": list(reversed(artifacts)),
            "images": images,
            "checks": checks,
            "warnings": [{"code": "public_note", "subject": self.tag}],
        }
        self.write_verifier(verifier)

    @staticmethod
    def _artifact(path: Path, role: str, payload_name: str | None) -> dict[str, Any]:
        result = {
            "name": path.name,
            "role": role,
            "payload_name": payload_name,
            "size_bytes": path.stat().st_size,
            "sha256": digest(path),
            "verification": {
                "checksum": "not_applicable",
                "signature": "not_applicable",
                "provenance": "not_applicable",
            },
        }
        if role == "payload":
            result["verification"] = {
                "checksum": "passed",
                "signature": "passed",
                "provenance": "passed",
            }
        return result

    def read_verifier(self) -> dict[str, Any]:
        return json.loads(self.verifier.read_text(encoding="utf-8"))

    def write_verifier(self, value: dict[str, Any]) -> None:
        self.verifier.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def mutate_verifier(self, change: Callable[[dict[str, Any]], None]) -> None:
        value = self.read_verifier()
        change(value)
        self.write_verifier(value)

    def build(self) -> dict[str, Any]:
        return release_evidence.write_evidence_bundle(
            self.manifest,
            self.capsule,
            self.verifier,
            self.assets,
            self.output,
        )


class RegistryReleaseEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = EvidenceFixture(Path(self.temporary.name))

    def test_bundle_is_deterministic_public_and_exactly_scoped(self) -> None:
        first = self.fixture.build()
        first_bytes = self.fixture.output.read_bytes()
        second = self.fixture.build()

        self.assertEqual(first, second)
        self.assertEqual(first_bytes, self.fixture.output.read_bytes())
        self.assertEqual("public", first["classification"])
        self.assertEqual(
            "pre_evidence_bundle", first["artifact_inventory"]["scope_name"]
        )
        self.assertEqual(106, first["artifact_inventory"]["observed_counts"]["total"])
        self.assertEqual(106, len(first["artifact_inventory"]["artifacts"]))
        self.assertEqual(
            sorted(item["name"] for item in first["artifact_inventory"]["artifacts"]),
            [item["name"] for item in first["artifact_inventory"]["artifacts"]],
        )
        self.assertTrue(all(value is False for value in first["privacy"].values()))
        self.assertEqual(
            [{"code": "public_note", "subject": self.fixture.tag}],
            first["verification"]["warnings"],
        )
        self.assertEqual(
            ["adopter-repin-pending", "hosted-publication-held"],
            [gate["code"] for gate in first["gates"]],
        )
        self.assertNotIn(
            str(self.fixture.root), self.fixture.output.read_text(encoding="utf-8")
        )

    def test_bundle_matches_the_closed_bounded_public_schema_shape(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

        def inspect(node: Any) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(node.get("additionalProperties"), False, node)
                if node.get("type") == "array":
                    self.assertIn("maxItems", node, node)
                for child in node.values():
                    inspect(child)
            elif isinstance(node, list):
                for child in node:
                    inspect(child)

        inspect(schema)
        self.assertEqual(
            False,
            schema["$defs"]["privacy"]["properties"]["raw_logs_included"]["const"],
        )
        self.assertEqual(
            106, schema["$defs"]["expectedCounts"]["properties"]["total"]["const"]
        )
        self.assertEqual(
            release_evidence.BUNDLE_SCHEMA,
            schema["properties"]["schema_version"]["const"],
        )

    def test_collector_asset_contract_matches_published_verifier(self) -> None:
        verifier = load_verify_published()
        identity = verifier.ReleaseIdentity(
            self.fixture.release_id,
            self.fixture.version,
            self.fixture.tag,
            self.fixture.source_ref,
            verifier.REPOSITORY,
            "a" * 64,
        )
        verifier_contract = verifier.expected_asset_contract(identity)
        collector_contract = release_evidence.expected_artifact_names(self.fixture.tag)

        self.assertEqual(set(verifier_contract.payloads), collector_contract["payload"])
        self.assertEqual(
            set(verifier_contract.signatures), collector_contract["signature"]
        )
        self.assertEqual(
            set(verifier_contract.certificates), collector_contract["certificate"]
        )
        self.assertEqual(
            {verifier_contract.provenance}, collector_contract["provenance"]
        )

    def test_public_parser_has_help_for_every_command(self) -> None:
        parser = load_registry_release().build_parser()
        subparser_action = next(
            action
            for action in parser._actions
            if isinstance(action, __import__("argparse")._SubParsersAction)
        )
        self.assertEqual(
            {"collect-evidence-bundle", "render-release-closeout"},
            {
                name
                for name in subparser_action.choices
                if "evidence" in name or "closeout" in name
            },
        )
        for name, command_parser in subparser_action.choices.items():
            with self.subTest(command=name):
                self.assertTrue(command_parser.description)
                self.assertIn("usage: registry-release", command_parser.format_help())

    def test_cli_collects_the_same_stable_bundle(self) -> None:
        result = subprocess.run(
            [
                str(TOOL),
                "collect-evidence-bundle",
                "--manifest",
                str(self.fixture.manifest),
                "--capsule",
                str(self.fixture.capsule),
                "--verification-result",
                str(self.fixture.verifier),
                "--asset-dir",
                str(self.fixture.assets),
                "--output-json",
                str(self.fixture.output),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        first = self.fixture.output.read_bytes()
        result = subprocess.run(
            result.args, text=True, capture_output=True, check=False
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(first, self.fixture.output.read_bytes())

    def test_unknown_duplicate_and_private_verifier_fields_are_rejected(self) -> None:
        original = self.fixture.verifier.read_text(encoding="utf-8")
        cases = {
            "unknown": lambda value: value.__setitem__("unexpected", True),
            "raw_logs": lambda value: value.__setitem__("raw_logs", ["not public"]),
            "environment": lambda value: value.__setitem__(
                "environment", {"TOKEN": "secret"}
            ),
            "commands": lambda value: value.__setitem__("commands", ["cosign verify"]),
            "private": lambda value: value.__setitem__(
                "private", {"review": "internal"}
            ),
        }
        for label, mutation in cases.items():
            with self.subTest(label=label):
                value = json.loads(original)
                mutation(value)
                self.fixture.write_verifier(value)
                with self.assertRaisesRegex(release_evidence.EvidenceError, "unknown"):
                    self.fixture.build()
        self.fixture.verifier.write_text(
            '{"schema_version":"one","schema_version":"two"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "duplicate JSON key"
        ):
            self.fixture.build()

    def test_symlink_oversized_and_duplicate_yaml_inputs_are_rejected(self) -> None:
        verifier_link = self.fixture.root / "verifier-link.json"
        verifier_link.symlink_to(self.fixture.verifier)
        with self.assertRaisesRegex(release_evidence.EvidenceError, "non-symlink"):
            release_evidence.build_evidence_bundle(
                self.fixture.manifest,
                self.fixture.capsule,
                verifier_link,
                self.fixture.assets,
            )

        oversized = self.fixture.root / "oversized-verifier.json"
        with oversized.open("wb") as handle:
            handle.seek(release_evidence.MAX_JSON_BYTES)
            handle.write(b"x")
        with self.assertRaisesRegex(release_evidence.EvidenceError, "exceeds"):
            release_evidence.build_evidence_bundle(
                self.fixture.manifest,
                self.fixture.capsule,
                oversized,
                self.fixture.assets,
            )

        self.fixture.manifest.write_text(
            self.fixture.manifest.read_text(encoding="utf-8")
            + "stack:\n  release: duplicate\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "duplicate YAML key"
        ):
            self.fixture.build()

    def test_duplicate_artifacts_and_inconsistent_counts_are_rejected(self) -> None:
        original = self.fixture.read_verifier()
        duplicate = copy.deepcopy(original)
        duplicate["artifacts"][1]["name"] = duplicate["artifacts"][0]["name"]
        self.fixture.write_verifier(duplicate)
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "duplicate artifact"
        ):
            self.fixture.build()

        inconsistent = copy.deepcopy(original)
        inconsistent["artifact_scope"]["observed_counts"]["payloads"] = 34
        inconsistent["artifact_scope"]["observed_counts"]["total"] = 105
        self.fixture.write_verifier(inconsistent)
        with self.assertRaisesRegex(release_evidence.EvidenceError, "artifact array"):
            self.fixture.build()

    def test_missing_unknown_symlink_and_oversized_assets_are_rejected(self) -> None:
        original = self.fixture.read_verifier()
        target = self.fixture.assets / original["artifacts"][0]["name"]
        original_bytes = target.read_bytes()
        unknown = self.fixture.assets / "unexpected.txt"
        unknown.write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "unknown unexpected.txt"
        ):
            self.fixture.build()
        unknown.unlink()

        target.unlink()
        with self.assertRaisesRegex(release_evidence.EvidenceError, "missing"):
            self.fixture.build()
        target.write_bytes(original_bytes)

        target.unlink()
        target.symlink_to(self.fixture.manifest)
        with self.assertRaisesRegex(release_evidence.EvidenceError, "non-regular"):
            self.fixture.build()
        target.unlink()
        target.write_bytes(original_bytes)

        with target.open("wb") as handle:
            handle.seek(release_evidence.MAX_ARTIFACT_BYTES)
            handle.write(b"x")
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "invalid actual size"
        ):
            self.fixture.build()

    def test_recomputed_size_and_digest_must_match(self) -> None:
        original = self.fixture.read_verifier()
        artifact_name = original["artifacts"][0]["name"]
        target = self.fixture.assets / artifact_name
        target.write_bytes(target.read_bytes() + b"tampered")
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "size does not match"
        ):
            self.fixture.build()

        self.fixture = EvidenceFixture(Path(self.temporary.name) / "fresh")
        value = self.fixture.read_verifier()
        value["artifacts"][0]["sha256"] = "f" * 64
        self.fixture.write_verifier(value)
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "SHA-256 does not match"
        ):
            self.fixture.build()

    def test_release_capsule_lineage_and_workflow_bindings_are_enforced(self) -> None:
        original = self.fixture.read_verifier()
        cases = {
            "release identity": lambda value: value["release"].__setitem__(
                "version", "1.2.4"
            ),
            "lineage": lambda value: value["lineage"].__setitem__(
                "manifest_source_ref", "9" * 40
            ),
            "workflow ref": lambda value: value["workflow"].__setitem__(
                "ref", "refs/tags/v9.9.9"
            ),
            "workflow timing": lambda value: value["workflow"].__setitem__(
                "duration_seconds", 121
            ),
        }
        for label, mutation in cases.items():
            with self.subTest(label=label):
                value = copy.deepcopy(original)
                mutation(value)
                self.fixture.write_verifier(value)
                with self.assertRaises(release_evidence.EvidenceError):
                    self.fixture.build()

        self.fixture.write_verifier(original)
        capsule = json.loads(self.fixture.capsule.read_text(encoding="utf-8"))
        capsule["source"]["source_commit"] = "8" * 40
        self.fixture.capsule.write_text(
            json.dumps(capsule, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "capsule source source_commit"
        ):
            self.fixture.build()

    def test_status_tools_and_warning_contracts_are_enforced(self) -> None:
        original = self.fixture.read_verifier()
        cases = {
            "status": lambda value: value.__setitem__("status", "failed"),
            "duplicate tool": lambda value: value["tools"].append(
                copy.deepcopy(value["tools"][0])
            ),
            "unobserved tool": lambda value: value["tools"][0].__setitem__(
                "source", "declared"
            ),
            "invalid warning subject": lambda value: value["warnings"][0].__setitem__(
                "subject", "line\nbreak"
            ),
        }
        for label, mutation in cases.items():
            with self.subTest(label=label):
                value = copy.deepcopy(original)
                mutation(value)
                self.fixture.write_verifier(value)
                with self.assertRaises(release_evidence.EvidenceError):
                    self.fixture.build()

    def test_successful_closeout_is_stable_and_keeps_gates_open(self) -> None:
        bundle = self.fixture.build()
        first = release_evidence.render_closeout(bundle)
        second = release_evidence.render_closeout(
            json.loads(self.fixture.output.read_text(encoding="utf-8"))
        )

        self.assertEqual(first, second)
        self.assertIn("Release contract verification: PASSED", first)
        self.assertIn("remains **HELD**", first)
        self.assertIn("remains **PENDING**", first)
        self.assertIn("106 total", first)
        self.assertIn("deliberately excluded", first)
        self.assertNotIn(str(self.fixture.root), first)

    def test_failed_and_incomplete_closeouts_are_never_successful(self) -> None:
        for status in ("failed", "incomplete"):
            with self.subTest(status=status):
                self.fixture.build()
                bundle = json.loads(self.fixture.output.read_text(encoding="utf-8"))
                bundle["verification"]["status"] = status
                check = bundle["verification"]["checks"][0]
                check["status"] = status
                check["failure_codes"] = (
                    ["deliberate_failed"] if status == "failed" else []
                )
                self.fixture.output.write_text(
                    json.dumps(bundle, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                result = subprocess.run(
                    [
                        str(TOOL),
                        "render-release-closeout",
                        "--bundle",
                        str(self.fixture.output),
                        "--output-markdown",
                        str(self.fixture.closeout),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(1, result.returncode)
                body = self.fixture.closeout.read_text(encoding="utf-8")
                self.assertIn("NOT SUCCESSFUL", body)
                self.assertNotIn("verification: PASSED", body)

    def test_closeout_rejects_unknown_nested_fields_and_false_privacy_claims(
        self,
    ) -> None:
        bundle = self.fixture.build()
        bundle["verification"]["checks"][0]["stderr"] = "private output"
        with self.assertRaisesRegex(release_evidence.EvidenceError, "unknown stderr"):
            release_evidence.render_closeout(bundle)

        bundle = self.fixture.build()
        bundle["privacy"]["secret_values_included"] = True
        with self.assertRaisesRegex(release_evidence.EvidenceError, "privacy flags"):
            release_evidence.render_closeout(bundle)

    def test_outputs_cannot_overwrite_inputs_or_enter_the_prebundle_scope(self) -> None:
        for output in (
            self.fixture.manifest,
            self.fixture.capsule,
            self.fixture.verifier,
        ):
            with self.subTest(output=output.name):
                with self.assertRaisesRegex(
                    release_evidence.EvidenceError, "overwrite an input"
                ):
                    release_evidence.write_evidence_bundle(
                        self.fixture.manifest,
                        self.fixture.capsule,
                        self.fixture.verifier,
                        self.fixture.assets,
                        output,
                    )
        with self.assertRaisesRegex(
            release_evidence.EvidenceError, "must not be inside asset-dir"
        ):
            release_evidence.write_evidence_bundle(
                self.fixture.manifest,
                self.fixture.capsule,
                self.fixture.verifier,
                self.fixture.assets,
                self.fixture.assets / "release-evidence.json",
            )


if __name__ == "__main__":
    unittest.main()
