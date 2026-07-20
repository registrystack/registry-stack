#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-finalization-profile.py"
CROSSWALK_REF = "9" * 40


def load_module():
    spec = importlib.util.spec_from_file_location("check_finalization_profile", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def write_yaml(path: Path, value: object) -> None:
    write(path, yaml.safe_dump(value, sort_keys=False))


def write_json(path: Path, value: object) -> None:
    write(path, json.dumps(value, indent=2) + "\n")


class FixtureRepo:
    manifest_path = "release/manifests/registry-stack-beta-9.yaml"

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True)
        git(root, "init", "-b", "main")
        git(root, "config", "user.email", "release-test@example.invalid")
        git(root, "config", "user.name", "Release Test")
        write(root / "seed", "candidate\n")
        git(root, "add", "seed")
        git(root, "commit", "-m", "candidate")
        self.candidate = git(root, "rev-parse", "HEAD")
        git(root, "tag", "v1.0.0")
        self._write_surfaces(self.candidate)
        git(root, "add", ".")
        git(root, "commit", "-m", "promote release")
        self.base = git(root, "rev-parse", "HEAD")

    def manifest(self, source_ref: str) -> dict:
        return {
            "stack": {
                "release": "beta-9",
                "version": "1.1.0",
                "source_repo": "registrystack/registry-stack",
                "source_ref": source_ref,
                "source_tag": "v1.1.0",
                "status": "release-candidate",
            },
            "artifacts": {"registry-core": "1.1.0"},
            "external": {
                "crosswalk": {
                    "repo": "PublicSchema/crosswalk",
                    "ref": CROSSWALK_REF,
                    "status": "tested external input",
                }
            },
            "warnings": [{"code": "hosted-publication-held"}],
        }

    def docsets(self, source_ref: str) -> dict:
        return {
            "current": "latest",
            "docsets": [
                {
                    "id": "latest",
                    "status": "current",
                    "products": {
                        "registry-stack": {"version": "v1.1.0", "ref": "HEAD"}
                    },
                },
                {
                    "id": "v1.1.0",
                    "path": "/v/1.1.0/",
                    "status": "archived",
                    "source": "registry-stack-v1.1.0",
                    "products": {
                        "registry-stack": {
                            "version": "v1.1.0",
                            "ref": source_ref,
                        },
                        "registry-core": {
                            "version": "v1.1.0",
                            "ref": source_ref,
                        },
                        "crosswalk": {
                            "version": "crosswalk-core-v0.2.0",
                            "ref": CROSSWALK_REF,
                        },
                    },
                },
                {
                    "id": "v1.0.0",
                    "path": "/v/1.0.0/",
                    "status": "archived",
                    "source": "registry-stack-v1.0.0",
                    "products": {
                        "registry-stack": {
                            "version": "v1.0.0",
                            "ref": self.candidate,
                        }
                    },
                },
            ],
        }

    def contracts(self, source_ref: str) -> list[dict]:
        candidate_url = (
            "https://github.com/registrystack/registry-stack/blob/"
            f"{source_ref}/crates/registry-core/src/lib.rs"
        )
        return [
            {
                "id": "registry-core",
                "source_of_truth": {"url": candidate_url},
                "consumer_note": f"unplanned text retains {self.candidate}",
            },
            {
                "id": "external",
                "source_of_truth": {
                    "url": f"https://example.invalid/{self.candidate}/contract"
                },
            },
        ]

    def standards(self, source_ref: str) -> list[dict]:
        return [
            {
                "id": "example",
                "evidence_docs": [
                    {
                        "url": "https://github.com/registrystack/registry-stack/tree/"
                        f"{source_ref}/docs/standard"
                    },
                    {"url": "https://www.example.invalid/standard"},
                ],
                "last_checked": "2026-07-20",
            }
        ]

    def _write_surfaces(self, source_ref: str) -> None:
        data = self.root / "docs/site/src/data"
        manifest = self.manifest(source_ref)
        docsets = self.docsets(source_ref)
        contracts = self.contracts(source_ref)
        standards = self.standards(source_ref)
        write_yaml(self.root / self.manifest_path, manifest)
        write_yaml(data / "docsets.yaml", docsets)
        write_json(data / "generated/docsets.json", docsets)
        write_yaml(data / "contracts.yaml", contracts)
        write_json(data / "generated/contracts.json", contracts)
        write_yaml(data / "standards.yaml", standards)
        write_json(data / "generated/standards.json", standards)

    def finalize(self, promotion: str | None = None) -> str:
        self._write_surfaces(promotion or self.base)
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "finalize release")
        return git(self.root, "rev-parse", "HEAD")

    def commit(self, message: str = "mutate finalization") -> str:
        git(self.root, "add", "-A")
        git(self.root, "commit", "-m", message)
        return git(self.root, "rev-parse", "HEAD")


class FinalizationProfileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = FixtureRepo(Path(self.temporary.name) / "repo")
        self.module = load_module()

    def classify(self, head: str) -> dict:
        return self.module.classify(self.repo.root, self.repo.base, head)

    def assert_full_ci(self, result: dict, fragment: str) -> None:
        self.assertEqual("full-ci", result["classification"])
        self.assertTrue(all(result["selected_gates"].values()))
        self.assertTrue(any(fragment in error for error in result["errors"]), result)

    def test_exact_finalization_is_eligible_and_records_promotion(self) -> None:
        head = self.repo.finalize()

        result = self.classify(head)

        self.assertEqual("eligible", result["classification"])
        self.assertEqual(self.repo.candidate, result["candidate_source_ref"])
        self.assertEqual(self.repo.base, result["promotion_commit"])
        self.assertEqual(
            {
                "rust": False,
                "platform": False,
                "platform_hygiene": False,
                "release_tool": True,
                "release_source_proof": True,
                "docs": True,
                "editors": False,
                "registryctl_tutorial": False,
            },
            result["selected_gates"],
        )
        self.assertEqual(
            {
                self.repo.manifest_path,
                "docs/site/src/data/docsets.yaml",
                "docs/site/src/data/generated/docsets.json",
                "docs/site/src/data/contracts.yaml",
                "docs/site/src/data/generated/contracts.json",
                "docs/site/src/data/standards.yaml",
                "docs/site/src/data/generated/standards.json",
            },
            set(result["changed_paths"]),
        )
        self.assertEqual([], result["errors"])

    def test_cli_output_and_optional_evidence_are_stable(self) -> None:
        head = self.repo.finalize()
        output = Path(self.temporary.name) / "profile.json"
        command = [
            str(SCRIPT),
            "--repo",
            str(self.repo.root),
            "--base-ref",
            self.repo.base,
            "--head-ref",
            head,
            "--output",
            str(output),
        ]

        first = subprocess.run(command, check=True, capture_output=True, text=True).stdout
        second = subprocess.run(command, check=True, capture_output=True, text=True).stdout

        self.assertEqual(first, second)
        self.assertEqual(first, output.read_text(encoding="utf-8"))
        self.assertEqual("eligible", json.loads(first)["classification"])

    def test_non_finalization_manifest_change_is_not_applicable(self) -> None:
        path = self.repo.root / self.repo.manifest_path
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["warnings"].append({"code": "another-held-gate"})
        write_yaml(path, data)
        head = self.repo.commit("update release metadata")

        result = self.classify(head)

        self.assertEqual("not-applicable", result["classification"])
        self.assertIsNone(result["selected_gates"])
        self.assertIsNone(result["promotion_commit"])

    def test_product_or_unknown_path_forces_full_ci(self) -> None:
        for path in ("products/core/src/lib.rs", "unrecognized.txt"):
            with self.subTest(path=path):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                repo = FixtureRepo(Path(temporary.name) / "repo")
                repo._write_surfaces(repo.base)
                write(repo.root / path, "extra\n")
                head = repo.commit()
                result = self.module.classify(repo.root, repo.base, head)
                self.assert_full_ci(result, "extra=")

    def test_extra_content_in_allowed_file_forces_full_ci(self) -> None:
        self.repo._write_surfaces(self.repo.base)
        path = self.repo.root / self.repo.manifest_path
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["warnings"].append({"code": "unplanned"})
        write_yaml(path, data)
        head = self.repo.commit()

        self.assert_full_ci(self.classify(head), "planned pointer replacements")

    def test_formatting_only_change_in_allowed_file_forces_full_ci(self) -> None:
        self.repo._write_surfaces(self.repo.base)
        path = self.repo.root / "docs/site/src/data/contracts.yaml"
        path.write_text("# unplanned comment\n" + path.read_text(), encoding="utf-8")
        head = self.repo.commit()

        self.assert_full_ci(self.classify(head), "line structure")

    def test_missing_or_mismatched_generated_mirror_forces_full_ci(self) -> None:
        self.repo._write_surfaces(self.repo.base)
        generated = self.repo.root / "docs/site/src/data/generated/standards.json"
        generated.write_text(
            generated.read_text(encoding="utf-8").replace(self.repo.base, self.repo.candidate),
            encoding="utf-8",
        )
        head = self.repo.commit()

        result = self.classify(head)
        self.assert_full_ci(result, "missing=")

    def test_wrong_promotion_commit_forces_full_ci(self) -> None:
        git(self.repo.root, "checkout", "-b", "side", self.repo.candidate)
        write(self.repo.root / "side", "side\n")
        side = self.repo.commit("side promotion")
        git(self.repo.root, "checkout", "main")
        head = self.repo.finalize(side)

        self.assert_full_ci(self.classify(head), "must equal pull-request base")

    def test_multiple_manifest_source_ref_changes_force_full_ci(self) -> None:
        second = self.repo.root / "release/manifests/registry-stack-beta-10.yaml"
        second_data = self.repo.manifest(self.repo.candidate)
        second_data["stack"]["release"] = "beta-10"
        second_data["stack"]["version"] = "1.2.0"
        second_data["stack"]["source_tag"] = "v1.2.0"
        second_data["artifacts"]["registry-core"] = "1.2.0"
        write_yaml(second, second_data)
        self.repo.base = self.repo.commit("add next release manifest")
        self.repo._write_surfaces(self.repo.base)
        second_data["stack"]["source_ref"] = self.repo.base
        write_yaml(second, second_data)
        head = self.repo.commit()

        self.assert_full_ci(self.classify(head), "exactly one manifest")

    def test_mode_rename_symlink_or_binary_change_forces_full_ci(self) -> None:
        mutations = ("mode", "rename", "symlink", "binary")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                repo = FixtureRepo(Path(temporary.name) / "repo")
                repo._write_surfaces(repo.base)
                path = repo.root / "docs/site/src/data/standards.yaml"
                if mutation == "mode":
                    os.chmod(path, 0o755)
                elif mutation == "rename":
                    path.rename(path.with_name("renamed-standards.yaml"))
                elif mutation == "symlink":
                    path.unlink()
                    os.symlink("contracts.yaml", path)
                else:
                    path.write_bytes(b"\0not text")
                head = repo.commit()
                result = self.module.classify(repo.root, repo.base, head)
                self.assertEqual("full-ci", result["classification"])
                self.assertTrue(all(result["selected_gates"].values()))

    def test_unresolved_base_fails_closed_with_stable_json_shape(self) -> None:
        result = self.module.classify(self.repo.root, "missing-base", "HEAD")

        self.assert_full_ci(result, "base")
        self.assertEqual(self.module.SCHEMA_VERSION, result["schema_version"])
        self.assertEqual([], result["changed_paths"])


if __name__ == "__main__":
    unittest.main()
