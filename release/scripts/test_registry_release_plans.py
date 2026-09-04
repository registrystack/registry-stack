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
FIXTURE_IDENTIFIER_CATALOG = {
    "version": 1,
    "entries": [{"status": "active"}],
}
FIXTURE_IDENTIFIER_CATALOG_SHA256 = hashlib.sha256(
    (json.dumps(FIXTURE_IDENTIFIER_CATALOG, indent=2) + "\n").encode()
).hexdigest()
RELAY_V2_ARTIFACT_INVENTORY = (
    "evidence",
    "evidence-client-node",
    "evidence-client-python",
    "evidence-oid4vci",
    "evidencectl",
    "evidencectl-installer",
    "mint",
    "registry-docs",
    "registry-manifest",
    "relay",
    "relay-installer",
    "relayctl",
)
RELAY_CLIENT_PACKAGE_MINIMUM_VERSION = (0, 19, 1)
DISCOVERY_CLIENT_PACKAGE_MINIMUM_VERSION = (0, 23, 0)
DISCOVERY_RUNTIME_MINIMUM_VERSION = (0, 24, 0)
BREG_RELEASE_MINIMUM_VERSION = (0, 26, 0)
UNIFIED_CLIENT_PACKAGE_MINIMUM_VERSION = (0, 26, 1)


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
    version_tuple = tuple(int(part) for part in version.split("."))
    inventory = tuple(
        artifact
        for artifact in RELAY_V2_ARTIFACT_INVENTORY
        if artifact != "relay-installer" or version_tuple >= (0, 19, 1)
    )
    if version_tuple >= UNIFIED_CLIENT_PACKAGE_MINIMUM_VERSION:
        inventory = tuple(
            item
            for item in inventory
            if item not in {"evidence-client-node", "evidence-client-python"}
        )
        inventory += ("registry-client-node", "registry-client-python")
    else:
        if version_tuple >= RELAY_CLIENT_PACKAGE_MINIMUM_VERSION:
            inventory += ("relay-client-node", "relay-client-python")
        if version_tuple >= DISCOVERY_CLIENT_PACKAGE_MINIMUM_VERSION:
            inventory += ("discovery-client-node", "discovery-client-python")
    if version_tuple >= DISCOVERY_RUNTIME_MINIMUM_VERSION:
        inventory += ("discovery",)
    if version_tuple >= BREG_RELEASE_MINIMUM_VERSION:
        inventory += (
            "breg",
            "bregctl",
            "breg-installer",
        )
    data = {
        "stack": {
            "release": release_id,
            "version": version,
            "source_repo": "registrystack/registry-stack",
            "source_ref": source_ref,
            "source_tag": f"v{version}",
            "status": status,
        },
        "artifacts": {name: version for name in inventory},
        "external": {
            "crosswalk": {
                "repo": "PublicSchema/crosswalk",
                "ref": CROSSWALK_REF,
                "status": "tested external input",
            }
        },
    }
    if version_tuple >= (0, 19, 1):
        data["identifier_catalog"] = {
            "path": "products/identifiers/generated/catalog.v1.json",
            "sha256": FIXTURE_IDENTIFIER_CATALOG_SHA256,
            "entry_count": len(FIXTURE_IDENTIFIER_CATALOG["entries"]),
        }
    return data


class FixtureRepo:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True)
        git(root, "init", "-b", "main")
        git(root, "config", "user.email", "release-test@example.invalid")
        git(root, "config", "user.name", "Release Test")
        write(root / "seed", "candidate\n")
        write_json(
            root / "products/identifiers/generated/catalog.v1.json",
            FIXTURE_IDENTIFIER_CATALOG,
        )
        git(root, "add", "seed", "products/identifiers/generated/catalog.v1.json")
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
        write_json(
            root / "products/identifiers/generated/catalog.v1.json",
            FIXTURE_IDENTIFIER_CATALOG,
        )
        write(
            root / "Cargo.toml",
            f'''[workspace]
members = ["crates/registry-core", "crates/registry-evidence"]

[workspace.package]
version = "1.1.0"

[workspace.dependencies]
registry-core = {{ path = "crates/registry-core", version = "1.1.0" }}
''',
        )
        write(
            root / "Cargo.lock",
            f'''version = 4

[[package]]
name = "registry-core"
version = "1.1.0"

[[package]]
name = "registry-evidence"
version = "1.1.0"

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
                    "availability": "unreleased",
                    "products": {
                        "registry-stack": {
                            "version": "main source (unreleased)",
                            "ref": "HEAD",
                        }
                    },
                },
                {
                    "id": "v1.1.0",
                    "label": "v1.1.0",
                    "path": "/v/1.1.0/",
                    "status": "archived",
                    "availability": "candidate",
                    "source": "registry-stack-v1.1.0",
                    "products": {
                        "registry-stack": {
                            "version": "v1.1.0",
                            "ref": self.candidate,
                        },
                        "registry-platform": {
                            "version": "v1.1.0",
                            "ref": self.candidate,
                        },
                        "registry-manifest": {
                            "version": "v1.1.0",
                            "ref": self.candidate,
                        },
                        "registry-evidence": {
                            "version": "v1.1.0",
                            "ref": self.candidate,
                        },
                        "registry-relay-v2": {
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
                    "availability": "released",
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
            data / "archive-lock.yaml",
            {
                "schema_version": "registry-docs.archive-lock.v1",
                "archives": {
                    "v1.1.0": {
                        "bundle_sha256": "a" * 64,
                        "root_tree_sha256": "b" * 64,
                        "version_tree_sha256": "c" * 64,
                    }
                },
            },
        )
        write_yaml(
            data / "repo-docs.yaml",
            {
                "repos": {
                    "registry-core": {
                        "ref": "HEAD",
                        "version": "main source (unreleased)",
                    },
                    "registry-relay-v2": {
                        "ref": "HEAD",
                        "version": "main source (unreleased)",
                        "docs": [
                            {"src": "products/relay-v2/CONCEPT.md"},
                        ],
                    }
                }
            },
        )
        candidate_url = (
            "https://github.com/registrystack/registry-stack/blob/"
            f"{self.candidate}/crates/registry-core/src/lib.rs#L10"
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
                            "crates/registry-core/src/lib.rs#L10",
                            f"docs/standard.md?candidate={self.candidate}&plain=1#L4-L7",
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
        write(
            root / "docs/site/scripts/release-identity.test.mjs",
            "const version = 'v1.1.0'; const train = 'beta-9';\n",
        )
        write(
            root / "docs/site/src/content/docs/changelog.mdx",
            "---\ntitle: Changelog\n---\n\n## v1.1.0 beta-9\n",
        )
        for relative_root, name in (
            (
                "crates/registry-discovery-client-node",
                "@registrystack/discovery-client",
            ),
            (
                "crates/registry-evidence-client-node",
                "@registrystack/evidence-client",
            ),
            (
                "crates/registry-relay-client-node",
                "@registrystack/relay-client",
            ),
            (
                "crates/registry-breg-client-node",
                "@registrystack/breg-client-native",
            ),
        ):
            client_root = self.root / relative_root
            write_json(
                client_root / "package.json",
                {"name": name, "version": "1.1.0"},
            )
            write_json(
                client_root / "package-lock.json",
                {
                    "name": name,
                    "version": "1.1.0",
                    "lockfileVersion": 3,
                    "packages": {"": {"name": name, "version": "1.1.0"}},
                },
            )
            for platform in (
                "darwin-arm64",
                "linux-arm64-gnu",
                "linux-x64-gnu",
            ):
                write_json(
                    client_root / "npm" / platform / "package.json",
                    {
                        "name": f"{name}-{platform}",
                        "version": "1.1.0",
                    },
                )
            write(
                client_root / "index.js",
                "if (bindingPackageVersion !== '1.1.0') throw new Error();\n",
            )
        unified_node = self.root / "crates/registry-stack-client-node"
        write_json(
            unified_node / "package.json",
            {"name": "@registrystack/client", "version": "1.1.0"},
        )
        write_json(
            unified_node / "package-lock.json",
            {
                "name": "@registrystack/client",
                "version": "1.1.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "@registrystack/client", "version": "1.1.0"}
                },
            },
        )
        write(unified_node / "native.js", "const PACKAGE_VERSION = '1.1.0';\n")
        for platform in ("darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu"):
            write_json(
                unified_node / "npm" / platform / "package.json",
                {
                    "name": f"@registrystack/client-{platform}",
                    "version": "1.1.0",
                },
            )
        for relative_root, name, dependency in (
            (
                "crates/registry-discovery-client-py",
                "registry-discovery-client",
                "discovery-client-sdk",
            ),
            (
                "crates/registry-evidence-client-py",
                "registry-evidence-client",
                "evidence-client-sdk",
            ),
            (
                "crates/registry-relay-client-py",
                "registry-relay-client",
                "relay-client-sdk",
            ),
            (
                "crates/registry-breg-client-py",
                "registry-breg-client-native",
                "registry-breg-client",
            ),
        ):
            client_root = self.root / relative_root
            write(
                client_root / "pyproject.toml",
                f'''[project]
name = "{name}"
version = "1.1.0"
''',
            )
            write(
                client_root / "Cargo.toml",
                f'''[package]
name = "{name}-py"
version.workspace = true

[dependencies]
{dependency} = {{ package = "{name}", path = "../{name}", version = "1.1.0" }}
''',
            )
        write(
            self.root / "crates/registry-stack-client-py/pyproject.toml",
            '''[project]
name = "registry-stack-client"
version = "1.1.0"
''',
        )
        write(
            self.root
            / "crates/registry-stack-client-py/python/registry_client/__init__.py",
            '__version__ = "1.1.0"\n',
        )
        for relative in (
            "products/manifest/fuzz/Cargo.lock",
            "products/platform/fuzz/Cargo.lock",
        ):
            write(
                self.root / relative,
                '''version = 4

[[package]]
name = "registry-core"
version = "1.1.0"
''',
            )
        write(
            root / "products/manifest/CHANGELOG.md",
            "# Changelog\n\n## [1.1.0]\n\n- Ready.\n",
        )
        write(
            root / "products/platform/CHANGELOG.md",
            "# Changelog\n\n## [1.1.0]\n\n- Ready.\n",
        )
        write(
            root / "products/manifest/docs/release-notes.md",
            "# Release Notes\n\n## 1.1.0\n\n- Ready.\n",
        )
        write(
            root / "release/notes/v1.1.0.md",
            "# Registry Stack v1.1.0\n\n"
            f"The beta-9 release uses Crosswalk `{CROSSWALK_REF}`.\n",
        )
        write_json(
            root / "products/evidence/generated/registry-evidence.openapi.json",
            {
                "openapi": "3.1.0",
                "info": {"title": "Evidence", "version": "1.1.0"},
            },
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

    def test_prepare_requires_explicit_release_identity(self) -> None:
        cases = (
            (
                ("prepare", "--release-id", "beta-9", "--repo", str(self.repo.root)),
                "--version",
            ),
            (
                ("prepare", "--version", "1.1.0", "--repo", str(self.repo.root)),
                "--release-id",
            ),
        )
        for args, missing in cases:
            with self.subTest(missing=missing):
                result = run(*args)
                self.assertEqual(2, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn(f"the following arguments are required: {missing}", result.stderr)

    def test_prepare_rejects_pre_v0_19_before_manifest_discovery(self) -> None:
        result = run(
            "prepare",
            "--version",
            "0.18.0",
            "--release-id",
            "historical",
            "--repo",
            str(self.repo.root),
        )

        self.assertEqual(1, result.returncode)
        self.assertIn(
            "pre-v0.19 releases are immutable historical evidence; use the "
            "corresponding v0.18.0 Git tag and archived assets",
            result.stderr,
        )

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
                "client-package-versions",
                "excluded-fuzz-locks",
                "docsets",
                "docs-archive-lock",
                "active-release-identity-surfaces",
                "repo-docs",
                "release-documents",
                "openapi-versions",
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
        self.assertIn(
            "docs/site/src/data/repo-docs.yaml",
            {change["path"] for change in plan["changes"]},
        )
        self.assertIn(
            "docs/site/src/data/docsets.yaml",
            {change["path"] for change in plan["changes"]},
        )
        self.assertIn(
            "docs/site/src/data/generated/docsets.json",
            {change["path"] for change in plan["changes"]},
        )
        for required_surface in (
            "crates/registry-discovery-client-node/package.json",
            "crates/registry-discovery-client-node/index.js",
            "crates/registry-discovery-client-py/pyproject.toml",
            "crates/registry-evidence-client-node/package.json",
            "crates/registry-evidence-client-node/index.js",
            "crates/registry-relay-client-py/pyproject.toml",
            "products/manifest/fuzz/Cargo.lock",
            "products/platform/fuzz/Cargo.lock",
            "docs/site/src/data/archive-lock.yaml",
            "docs/site/src/data/repo-docs.yaml",
        ):
            self.assertIn(
                required_surface,
                {change["path"] for change in plan["changes"]},
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

    def test_prepare_requires_release_docs_metadata(self) -> None:
        data_dir = self.repo.root / "docs/site/src/data"
        (data_dir / "docsets.yaml").unlink()
        (data_dir / "generated/docsets.json").unlink()
        (data_dir / "repo-docs.yaml").unlink()

        result = self.prepare()

        self.assertEqual(1, result.returncode)
        self.assertIn("required release surface is missing", result.stderr)
        self.assertIn("docs/site/src/data/docsets.yaml", result.stderr)

    def test_prepare_rejects_stale_client_loader_and_excluded_fuzz_lock(self) -> None:
        loader = self.repo.root / "crates/registry-evidence-client-node/index.js"
        write(loader, "if (bindingPackageVersion !== '1.0.0') throw new Error();\n")
        stale_loader = self.prepare()
        self.assertEqual(1, stale_loader.returncode)
        self.assertIn("generated binding loader must use only version 1.1.0", stale_loader.stderr)

        write(loader, "if (bindingPackageVersion !== '1.1.0') throw new Error();\n")
        fuzz_lock = self.repo.root / "products/platform/fuzz/Cargo.lock"
        write(
            fuzz_lock,
            '''version = 4

[[package]]
name = "registry-core"
version = "1.0.0"
''',
        )
        stale_lock = self.prepare()
        self.assertEqual(1, stale_lock.returncode)
        self.assertIn(
            "products/platform/fuzz/Cargo.lock path packages must use version 1.1.0",
            stale_lock.stderr,
        )

    def test_prepare_rejects_stale_client_platform_package_version(self) -> None:
        for client in ("evidence", "relay"):
            with self.subTest(client=client):
                platform = (
                    self.repo.root
                    / f"crates/registry-{client}-client-node/npm/"
                    "linux-x64-gnu/package.json"
                )
                package = json.loads(platform.read_text(encoding="utf-8"))
                package["version"] = "1.0.0"
                write_json(platform, package)

                result = self.prepare()

                self.assertEqual(1, result.returncode)
                self.assertIn(
                    f"{client}-client-linux-x64-gnu at version 1.1.0",
                    result.stderr,
                )
                package["version"] = "1.1.0"
                write_json(platform, package)

    def test_prepare_rejects_checked_in_platform_version_binding(self) -> None:
        # The release binds these when it packs the root package. Carrying them
        # in the tree names a version that is unpublished at preparation time,
        # so npm writes placeholder lock entries and `npm ci` stops resolving
        # on the default branch from the moment that release publishes.
        client_root = self.repo.root / "crates/registry-evidence-client-node"
        optional = {"@registrystack/evidence-client-linux-x64-gnu": "1.1.0"}
        for relative, holder in (
            ("package.json", lambda document: document),
            ("package-lock.json", lambda document: document["packages"][""]),
        ):
            with self.subTest(surface=relative):
                path = client_root / relative
                original = path.read_text(encoding="utf-8")
                document = json.loads(original)
                holder(document)["optionalDependencies"] = optional
                write_json(path, document)

                result = self.prepare()

                self.assertEqual(1, result.returncode)
                self.assertIn(
                    "must not bind platform package versions",
                    result.stderr,
                )
                write(path, original)

    def test_prepare_requires_exact_release_archive_lock(self) -> None:
        archive_lock = self.repo.root / "docs/site/src/data/archive-lock.yaml"
        document = yaml.safe_load(archive_lock.read_text(encoding="utf-8"))
        document["archives"]["v1.1.0"].pop("root_tree_sha256")
        write_yaml(archive_lock, document)

        result = self.prepare()

        self.assertEqual(1, result.returncode)
        self.assertIn(
            "archive-lock.yaml v1.1.0 must contain exactly",
            result.stderr,
        )

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

    def test_prepare_binds_crosswalk_manifest_and_docset(self) -> None:
        target = self.repo.root / "release/manifests/registry-stack-beta-9.yaml"
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
        data["external"]["crosswalk"]["ref"] = "2" * 40
        write_yaml(target, data)

        result = self.prepare()

        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn(
            "docset v1.1.0 external crosswalk ref must match the selected manifest",
            result.stderr,
        )

    def test_prepare_selects_evidence_openapi_and_ignores_retired_surfaces(
        self,
    ) -> None:
        result = self.prepare()
        self.assertEqual(0, result.returncode, result.stderr)

        evidence_openapi = (
            self.repo.root
            / "products/evidence/generated/registry-evidence.openapi.json"
        )
        document = json.loads(evidence_openapi.read_text(encoding="utf-8"))
        document["info"]["version"] = "1.0.0"
        write_json(evidence_openapi, document)

        stale = self.prepare()
        self.assertEqual(1, stale.returncode)
        self.assertIn(
            "products/evidence/generated/registry-evidence.openapi.json",
            stale.stderr,
        )
        self.assertIn("info.version must be '1.1.0'", stale.stderr)

    def test_prepare_ignores_current_docset_product_inventory(self) -> None:
        data_dir = self.repo.root / "docs/site/src/data"
        docsets_path = data_dir / "docsets.yaml"
        docsets = yaml.safe_load(docsets_path.read_text(encoding="utf-8"))
        selected = next(
            item for item in docsets["docsets"] if item["id"] == "v1.1.0"
        )
        selected["products"]["archived-example"] = {
            "version": "v1.1.0",
            "ref": self.repo.candidate,
        }
        write_yaml(docsets_path, docsets)
        write_json(data_dir / "generated/docsets.json", docsets)

        result = self.prepare()

        self.assertEqual(0, result.returncode, result.stderr)

    def test_prepare_rejects_missing_required_artifacts(self) -> None:
        target = self.repo.root / "release/manifests/registry-stack-beta-9.yaml"
        data = yaml.safe_load(target.read_text())

        data["artifacts"].pop("relay")
        write_yaml(target, data)
        missing_relay = self.prepare()
        self.assertEqual(1, missing_relay.returncode)
        self.assertEqual("", missing_relay.stdout)
        self.assertIn("missing relay", missing_relay.stderr)

        data["artifacts"]["relay"] = "1.1.0"
        data["artifacts"]["registryctl"] = "1.1.0"
        write_yaml(target, data)
        incomplete_inventory = self.prepare()
        self.assertEqual(1, incomplete_inventory.returncode)
        self.assertEqual("", incomplete_inventory.stdout)
        self.assertIn(
            "artifact inventory for version 0.19.0 or later must be exactly",
            incomplete_inventory.stderr,
        )
        self.assertIn("unexpected registryctl", incomplete_inventory.stderr)

    def test_prepare_uses_identifier_catalog_from_recorded_source_ref(self) -> None:
        write_json(
            self.repo.root / "products/identifiers/generated/catalog.v1.json",
            {
                "version": 1,
                "entries": [{"status": "active"}, {"status": "active"}],
            },
        )

        result = self.prepare()

        self.assertEqual(0, result.returncode, result.stderr)

    def test_prepare_rejects_identifier_catalog_drift_at_recorded_source_ref(
        self,
    ) -> None:
        write_json(
            self.repo.root / "products/identifiers/generated/catalog.v1.json",
            {
                "version": 1,
                "entries": [{"status": "active"}, {"status": "active"}],
            },
        )
        git(self.repo.root, "add", "products/identifiers/generated/catalog.v1.json")
        git(self.repo.root, "commit", "-m", "change release catalog")
        changed_source = git(self.repo.root, "rev-parse", "HEAD")
        target = self.repo.root / "release/manifests/registry-stack-beta-9.yaml"
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
        data["stack"]["source_ref"] = changed_source
        write_yaml(target, data)

        result = self.prepare()

        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn(
            "identifier_catalog.sha256 does not match the committed catalog bytes",
            result.stderr,
        )


    def test_prepare_rejects_dangling_candidate_source_ref(self) -> None:
        target = self.repo.root / "release/manifests/registry-stack-beta-9.yaml"
        data = yaml.safe_load(target.read_text())
        data["stack"]["source_ref"] = "f" * 40
        write_yaml(target, data)

        result = self.prepare()

        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn(
            "selected manifest stack.source_ref does not resolve to an existing commit",
            result.stderr,
        )

    def test_prepare_accepts_stable_tag_identity_without_future_source_or_status(
        self,
    ) -> None:
        target = self.repo.root / "release/manifests/registry-stack-beta-9.yaml"
        data = yaml.safe_load(target.read_text())
        data["stack"].pop("source_ref")
        data["stack"].pop("status")
        write_yaml(target, data)
        data_dir = self.repo.root / "docs/site/src/data"
        docsets = yaml.safe_load(
            (data_dir / "docsets.yaml").read_text(encoding="utf-8")
        )
        selected = next(
            item for item in docsets["docsets"] if item["id"] == "v1.1.0"
        )
        for name, product in selected["products"].items():
            if name != "crosswalk":
                product["ref"] = "v1.1.0"
        write_yaml(data_dir / "docsets.yaml", docsets)
        write_json(data_dir / "generated/docsets.json", docsets)
        result = self.prepare()

        self.assertEqual(0, result.returncode, result.stderr)
        plan = json.loads(result.stdout)
        self.assertNotIn("source_ref", plan["selected"])
        self.assertNotIn("status", plan["selected"])

    def test_finalize_and_capsule_commands_are_not_active(self) -> None:
        help_result = run("--help")
        self.assertEqual(0, help_result.returncode, help_result.stderr)
        self.assertNotIn("finalize", help_result.stdout)
        self.assertNotIn("render-capsule", help_result.stdout)
        self.assertNotIn("closeout", help_result.stdout)
        self.assertNotIn("source-ref", help_result.stdout)
        self.assertIn("verify-candidate", help_result.stdout)
        self.assertIn("verify-public", help_result.stdout)
        request_help = run("request-candidate", "--help")
        self.assertEqual(0, request_help.returncode, request_help.stderr)
        self.assertNotIn("--proof-level", request_help.stdout)
        self.assertNotIn("--milestone", request_help.stdout)
        self.assertNotIn("--measurement-bootstrap", request_help.stdout)
        self.assertIn("--wait-for-ci", request_help.stdout)
        self.assertIn("--wait", request_help.stdout)
        public_help = run("verify-public", "--help")
        self.assertEqual(0, public_help.returncode, public_help.stderr)
        self.assertIn("--tag", public_help.stdout)

    def test_prepare_rejects_stale_local_tag_when_origin_has_target(self) -> None:
        git(self.repo.root, "tag", "--annotate", "v1.1.0", "--message", "release")
        git(self.repo.root, "push", "origin", "refs/tags/v1.1.0")
        git(self.repo.root, "tag", "--delete", "v1.1.0")
        before = self.repo.git_read_state()

        result = self.prepare()

        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn("release tag v1.1.0 on origin", result.stderr)
        self.assertEqual(before, self.repo.git_read_state())

    def test_prepare_fails_closed_when_origin_cannot_be_read(self) -> None:
        git(
            self.repo.root,
            "remote",
            "set-url",
            "origin",
            str(Path(self.temporary.name) / "missing-origin.git"),
        )
        before = self.repo.git_read_state()

        result = self.prepare()

        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn(
            "cannot determine whether release tag v1.1.0 exists on origin",
            result.stderr,
        )
        self.assertEqual(before, self.repo.git_read_state())


if __name__ == "__main__":
    unittest.main()
