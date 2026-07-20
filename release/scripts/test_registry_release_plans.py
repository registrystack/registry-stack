#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "release/scripts/registry-release"
CROSSWALK_REF = "1" * 40


def run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(TOOL), *args],
        cwd=cwd or ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def write_yaml(path: Path, data: object) -> None:
    write(path, yaml.safe_dump(data, sort_keys=False))


def write_json(path: Path, data: object) -> None:
    write(path, json.dumps(data, indent=2) + "\n")


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def manifest(version: str, release_id: str, source_ref: str, status: str) -> dict:
    return {
        "stack": {
            "release": release_id,
            "version": version,
            "source_repo": "registrystack/registry-stack",
            "source_ref": source_ref,
            "source_tag": f"v{version}",
            "status": status,
        },
        "artifacts": {"registry-core": version},
        "external": {
            "crosswalk": {
                "repo": "PublicSchema/crosswalk",
                "ref": CROSSWALK_REF,
                "status": "tested external input",
            }
        },
    }


class FixtureRepo:
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
        self._write_surfaces()
        git(root, "add", ".")
        git(root, "commit", "-m", "promote release metadata")
        self.promotion = git(root, "rev-parse", "HEAD")
        self.origin = root.parent / "origin.git"
        git(
            root.parent,
            "init",
            "--bare",
            "--initial-branch=main",
            str(self.origin),
        )
        git(root, "remote", "add", "origin", str(self.origin))
        git(root, "push", "--set-upstream", "origin", "main")
        git(root, "push", "origin", "refs/tags/v1.0.0")

    def _write_surfaces(self) -> None:
        root = self.root
        write(
            root / "Cargo.toml",
            f'''[workspace]
members = ["crates/registry-core"]

[workspace.package]
version = "1.1.0"

[workspace.dependencies]
registry-core = {{ path = "crates/registry-core", version = "1.1.0" }}
crosswalk-core = {{ git = "https://github.com/PublicSchema/crosswalk", rev = "{CROSSWALK_REF}", version = "0.2.0" }}
''',
        )
        write(
            root / "Cargo.lock",
            f'''version = 4

[[package]]
name = "registry-core"
version = "1.1.0"

[[package]]
name = "crosswalk-core"
version = "0.2.0"
source = "git+https://github.com/PublicSchema/crosswalk?rev={CROSSWALK_REF}#{CROSSWALK_REF}"
''',
        )
        write_yaml(
            root / "release/manifests/registry-stack-beta-7.yaml",
            manifest("1.0.0", "beta-7", self.candidate, "released"),
        )
        write_yaml(
            root / "release/manifests/registry-stack-beta-9.yaml",
            manifest("1.1.0", "beta-9", self.candidate, "release-candidate"),
        )
        docsets = {
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
                    "label": "v1.1.0",
                    "path": "/v/1.1.0/",
                    "status": "archived",
                    "source": "registry-stack-v1.1.0",
                    "products": {
                        "registry-stack": {
                            "version": "v1.1.0",
                            "ref": self.candidate,
                        },
                        "crosswalk": {
                            "version": "crosswalk-core-v0.2.0",
                            "ref": CROSSWALK_REF,
                        },
                    },
                },
                {
                    "id": "v1.0.0",
                    "label": "v1.0.0",
                    "path": "/v/1.0.0/",
                    "status": "archived",
                    "source": "registry-stack-v1.0.0",
                    "products": {
                        "registry-stack": {
                            "version": "v1.0.0",
                            "ref": self.candidate,
                        },
                        "crosswalk": {
                            "version": "crosswalk-core-v0.2.0",
                            "ref": CROSSWALK_REF,
                        },
                    },
                },
            ],
        }
        data = root / "docs/site/src/data"
        write_yaml(data / "docsets.yaml", docsets)
        write_json(data / "generated/docsets.json", docsets)
        write_yaml(
            data / "repo-docs.yaml",
            {
                "repos": {
                    "registry-core": {"ref": "HEAD", "version": "v1.1.0"}
                }
            },
        )
        candidate_url = (
            "https://github.com/registrystack/registry-stack/blob/"
            f"{self.candidate}/crates/registry-core/src/lib.rs"
        )
        contracts = [
            {
                "id": "registry-core",
                "source_of_truth": {"url": candidate_url},
                "consumer_note": f"arbitrary occurrence {self.candidate} is not a ref field",
            },
            {
                "id": "external",
                "source_of_truth": {
                    "url": f"https://example.invalid/{self.candidate}/contract"
                },
            },
        ]
        standards = [
            {
                "id": "example",
                "evidence_docs": [
                    {
                        "url": candidate_url.replace(
                            "crates/registry-core/src/lib.rs", "docs/standard.md"
                        )
                    },
                    {"url": "https://www.example.invalid/standard"},
                ],
            }
        ]
        write_yaml(data / "contracts.yaml", contracts)
        write_json(data / "generated/contracts.json", contracts)
        write_yaml(data / "standards.yaml", standards)
        write_json(data / "generated/standards.json", standards)
        write(root / "products/core/CHANGELOG.md", "# Changelog\n\n## [1.1.0]\n\n- Ready.\n")
        write(
            root / "products/core/docs/release-notes.md",
            "# Release Notes\n\n## 1.1.0\n\n- Ready.\n",
        )
        write(
            root / "release/notes/v1.1.0.md",
            "# Registry Stack v1.1.0\n\n"
            f"The beta-9 release uses Crosswalk `{CROSSWALK_REF}`.\n",
        )
        write_json(
            root / "products/core/openapi/registry-core.openapi.json",
            {"openapi": "3.1.0", "info": {"title": "Core", "version": "1.1.0"}},
        )

    def snapshot(self) -> dict[str, str]:
        return {
            str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.root.rglob("*")
            if path.is_file() and ".git" not in path.parts
        }

    def git_read_state(self) -> dict[str, str | None]:
        fetch_head = Path(git(self.root, "rev-parse", "--git-path", "FETCH_HEAD"))
        if not fetch_head.is_absolute():
            fetch_head = self.root / fetch_head
        return {
            "refs": git(
                self.root,
                "for-each-ref",
                "--format=%(refname) %(objectname)",
            ),
            "fetch_head": (
                fetch_head.read_text(encoding="utf-8") if fetch_head.exists() else None
            ),
        }


class RegistryReleasePlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = FixtureRepo(Path(self.temporary.name) / "repo")

    def prepare(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return run(
            "prepare",
            "--version",
            "1.1.0",
            "--release-id",
            "beta-9",
            "--repo",
            str(self.repo.root),
            *extra,
        )

    def finalize(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return run(
            "finalize",
            "--version",
            "1.1.0",
            "--release-id",
            "beta-9",
            "--repo",
            str(self.repo.root),
            "--promotion-commit",
            self.repo.promotion,
            "--default-branch",
            "main",
            *extra,
        )

    def test_commands_require_explicit_release_identity_and_promotion(self) -> None:
        cases = (
            (
                ("prepare", "--release-id", "beta-9", "--repo", str(self.repo.root)),
                "--version",
            ),
            (
                ("prepare", "--version", "1.1.0", "--repo", str(self.repo.root)),
                "--release-id",
            ),
            (
                (
                    "finalize",
                    "--version",
                    "1.1.0",
                    "--release-id",
                    "beta-9",
                    "--repo",
                    str(self.repo.root),
                ),
                "--promotion-commit",
            ),
        )
        for args, missing in cases:
            with self.subTest(missing=missing):
                result = run(*args)
                self.assertEqual(2, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn(f"the following arguments are required: {missing}", result.stderr)

    def test_prepare_emits_stable_json_plan_without_mutating_repo(self) -> None:
        before = self.repo.snapshot()
        result = self.prepare()

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(
            {
                "schema_version",
                "operation",
                "status",
                "requested",
                "previous",
                "selected",
                "crosswalk",
                "checks",
                "changes",
            },
            set(plan),
        )
        self.assertEqual("registry-release.plan.v1", plan["schema_version"])
        self.assertEqual("prepare", plan["operation"])
        self.assertEqual("1.0.0", plan["previous"]["version"])
        self.assertEqual("beta-8", plan["previous"]["advisory_next_release_id"])
        self.assertEqual(
            {"version": "1.1.0", "release_id": "beta-9"}, plan["requested"]
        )
        self.assertEqual("ready", plan["status"])
        self.assertEqual(
            {
                "release-history",
                "release-identity",
                "immutable-release-tag",
                "workspace-versions",
                "docsets",
                "repo-docs",
                "release-documents",
                "openapi-versions",
                "crosswalk-pin",
                "generated-docset-mirror",
            },
            {check["name"] for check in plan["checks"]},
        )
        self.assertTrue(all(check["status"] == "passed" for check in plan["checks"]))
        self.assertTrue(
            all(set(check) == {"name", "status", "detail"} for check in plan["checks"])
        )
        self.assertTrue(
            all(set(change) == {"path", "kind", "from", "to"} for change in plan["changes"])
        )
        keys = [(change["path"], change.get("pointer")) for change in plan["changes"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(
            json.dumps(plan, indent=2, sort_keys=True) + "\n", result.stdout
        )
        repeated = self.prepare()
        self.assertEqual(0, repeated.returncode, repeated.stderr)
        self.assertEqual(result.stdout, repeated.stdout)
        self.assertEqual(before, self.repo.snapshot())

    def test_prepare_writes_an_identical_optional_plan_output(self) -> None:
        output = Path(self.temporary.name) / "release-plan.json"
        result = self.prepare("--plan-output", str(output))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(result.stdout, output.read_text(encoding="utf-8"))

    def test_prepare_rejects_noncanonical_version_and_release_id(self) -> None:
        cases = (
            ("01.1.0", "beta-9", "canonical SemVer"),
            ("1.1.0", "bad/id", "release ID must start"),
        )
        for version, release_id, expected in cases:
            with self.subTest(version=version, release_id=release_id):
                result = run(
                    "prepare",
                    "--version",
                    version,
                    "--release-id",
                    release_id,
                    "--repo",
                    str(self.repo.root),
                )
                self.assertEqual(1, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn(expected, result.stderr)

    def test_prepare_rejects_reused_version_and_release_id(self) -> None:
        cases = (
            ("1.0.0", "beta-8", "already assigned to release ID beta-7"),
            ("1.0.0", "beta-9", "has version 1.1.0, not requested version 1.0.0"),
        )
        for version, release_id, expected in cases:
            with self.subTest(version=version, release_id=release_id):
                result = run(
                    "prepare",
                    "--version",
                    version,
                    "--release-id",
                    release_id,
                    "--repo",
                    str(self.repo.root),
                )
                self.assertEqual(1, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn(expected, result.stderr)

    def test_prepare_rejects_crosswalk_drift(self) -> None:
        lock = self.repo.root / "Cargo.lock"
        lock.write_text(lock.read_text().replace(CROSSWALK_REF, "2" * 40), encoding="utf-8")

        result = self.prepare()

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn("Crosswalk", result.stderr)

    def test_finalize_lists_only_bounded_candidate_ref_changes(self) -> None:
        before = self.repo.snapshot()
        result = self.finalize()

        self.assertEqual(0, result.returncode, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual("finalize", plan["operation"])
        self.assertEqual(self.repo.promotion, plan["selected"]["promotion_commit"])
        keys = [(change["path"], change["pointer"]) for change in plan["changes"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(
            {
                ("release/manifests/registry-stack-beta-9.yaml", "/stack/source_ref"),
                ("docs/site/src/data/docsets.yaml", "/docsets/1/products/registry-stack/ref"),
                (
                    "docs/site/src/data/generated/docsets.json",
                    "/docsets/1/products/registry-stack/ref",
                ),
                ("docs/site/src/data/contracts.yaml", "/0/source_of_truth/url"),
                ("docs/site/src/data/generated/contracts.json", "/0/source_of_truth/url"),
                ("docs/site/src/data/standards.yaml", "/0/evidence_docs/0/url"),
                (
                    "docs/site/src/data/generated/standards.json",
                    "/0/evidence_docs/0/url",
                ),
            },
            set(keys),
        )
        self.assertFalse(any("latest" in json.dumps(change) for change in plan["changes"]))
        self.assertFalse(any("/docsets/2/" in change["pointer"] for change in plan["changes"]))
        self.assertFalse(any("crosswalk" in change["pointer"] for change in plan["changes"]))
        self.assertFalse(any("example.invalid" in json.dumps(change) for change in plan["changes"]))
        self.assertFalse(
            any("registry-stack-beta-7.yaml" == change["path"] for change in plan["changes"])
        )
        self.assertEqual(before, self.repo.snapshot())

    def test_finalize_rejects_non_candidate_manifest(self) -> None:
        target = self.repo.root / "release/manifests/registry-stack-beta-9.yaml"
        data = yaml.safe_load(target.read_text())
        data["stack"]["status"] = "draft"
        write_yaml(target, data)
        not_candidate = self.finalize()
        self.assertNotEqual(0, not_candidate.returncode)
        self.assertIn("release-candidate status", not_candidate.stderr)
        self.assertEqual("", not_candidate.stdout)

    def test_finalize_enforces_candidate_and_default_branch_lineage(self) -> None:
        tree = git(self.repo.root, "rev-parse", f"{self.repo.candidate}^{{tree}}")
        unrelated = git(self.repo.root, "commit-tree", tree, "-m", "unrelated promotion")
        not_descendant = run(
            "finalize",
            "--version",
            "1.1.0",
            "--release-id",
            "beta-9",
            "--repo",
            str(self.repo.root),
            "--promotion-commit",
            unrelated,
            "--default-branch",
            "main",
        )
        self.assertEqual(1, not_descendant.returncode)
        self.assertEqual("", not_descendant.stdout)
        self.assertIn("is not an ancestor of promotion commit", not_descendant.stderr)

        git(self.repo.root, "checkout", "-b", "side", self.repo.candidate)
        write(self.repo.root / "side", "side promotion\n")
        git(self.repo.root, "add", "side")
        git(self.repo.root, "commit", "-m", "side promotion")
        side = git(self.repo.root, "rev-parse", "HEAD")
        git(self.repo.root, "checkout", "main")
        unreachable = run(
            "finalize",
            "--version",
            "1.1.0",
            "--release-id",
            "beta-9",
            "--repo",
            str(self.repo.root),
            "--promotion-commit",
            side,
            "--default-branch",
            "main",
        )
        self.assertNotEqual(0, unreachable.returncode)
        self.assertEqual("", unreachable.stdout)
        self.assertIn("not reachable from default branch", unreachable.stderr)

    def test_finalize_rejects_existing_target_tag(self) -> None:
        git(self.repo.root, "tag", "--annotate", "v1.1.0", "--message", "release")

        result = self.finalize()

        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn("already represented by release tag", result.stderr)

    def test_prepare_and_finalize_reject_stale_local_tags_when_origin_has_target(
        self,
    ) -> None:
        git(self.repo.root, "tag", "--annotate", "v1.1.0", "--message", "release")
        git(self.repo.root, "push", "origin", "refs/tags/v1.1.0")
        git(self.repo.root, "tag", "--delete", "v1.1.0")
        self.assertEqual("", git(self.repo.root, "tag", "--list", "v1.1.0"))
        before = self.repo.git_read_state()

        for operation in (self.prepare, self.finalize):
            with self.subTest(operation=operation.__name__):
                result = operation()
                self.assertEqual(1, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn(
                    "release tag v1.1.0 on origin",
                    result.stderr,
                )
                self.assertEqual(before, self.repo.git_read_state())

    def test_prepare_and_finalize_fail_closed_when_origin_cannot_be_read(self) -> None:
        git(
            self.repo.root,
            "remote",
            "set-url",
            "origin",
            str(Path(self.temporary.name) / "missing-origin.git"),
        )
        before = self.repo.git_read_state()

        for operation in (self.prepare, self.finalize):
            with self.subTest(operation=operation.__name__):
                result = operation()
                self.assertEqual(1, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn(
                    "cannot determine whether release tag v1.1.0 exists on origin",
                    result.stderr,
                )
                self.assertEqual(before, self.repo.git_read_state())


if __name__ == "__main__":
    unittest.main()
