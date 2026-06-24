#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "release/scripts/registry-release"
IMAGE_DIGEST = "sha256:" + "a" * 64
IMAGE_DIGEST_REF = f"ghcr.io/registrystack/registry-notary@{IMAGE_DIGEST}"


class RegistryReleaseTest(unittest.TestCase):
    def test_validate_beta_6_manifest(self) -> None:
        result = run_tool("validate", "release/manifests/registry-stack-beta-6.yaml")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated", result.stdout)

    def test_audit_import_map(self) -> None:
        result = run_tool("audit", "release/manifests/import-map-2026-06-24.yaml")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("audited 7 imports", result.stdout)

    def test_classify_known_warning(self) -> None:
        result = run_tool("classify-warning", "artifact-publication-held")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("artifact-gate-held", result.stdout.strip())

    def test_validate_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp), source_tag="v9.9.9")
            result = run_tool("validate", str(manifest))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stack.source_tag must be v0.8.0", result.stderr)

    def test_validate_source_accepts_ancestor_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            commit_file(repo, "release.txt", "release\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=source_ref)

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validated source lineage", result.stdout)

    def test_validate_source_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            source_ref = commit_file(repo, "source.txt", "source\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=source_ref, source_tag="v9.9.9")

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match checked-out release tag", result.stderr)

    def test_validate_source_rejects_non_ancestor_source_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            commit_file(repo, "main.txt", "main\n")
            git(repo, "checkout", "-b", "side")
            side_ref = commit_file(repo, "side.txt", "side\n")
            git(repo, "checkout", "main")
            commit_file(repo, "release.txt", "release\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref=side_ref)

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

        self.assertNotEqual(0, result.returncode)
        self.assertIn("is not an ancestor of release tag target", result.stderr)

    def test_validate_source_allows_draft_not_reachable_from_default_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = init_repo(Path(tmp))
            commit_file(repo, "main.txt", "main\n")
            git(repo, "checkout", "--orphan", "draft")
            commit_file(repo, "draft.txt", "draft\n")
            git(repo, "tag", "v0.8.0")
            manifest = write_manifest(repo, source_ref="HEAD", status="draft")

            result = run_tool("validate-source", str(manifest), "--tag", "v0.8.0", "--repo", str(repo), "--default-branch", "main")

        self.assertEqual(0, result.returncode, result.stderr)

    def test_render_capsule_combines_binary_and_image_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            output_json = root / "capsule.json"
            output_md = root / "capsule.md"

            result = render_capsule(manifest, binary_dir, image_dir, output_json, output_md, root)

            evidence = json.loads(output_json.read_text(encoding="utf-8"))
            capsule_markdown = output_md.read_text(encoding="utf-8")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(1, len(evidence["binaries"]))
        self.assertEqual(1, len(evidence["images"]))
        self.assertIn("Release Trust Capsule", capsule_markdown)

    def test_render_capsule_rejects_grype_subject_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root, grype_subject="ghcr.io/registrystack/registry-notary@sha256:" + "b" * 64)
            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match digest ref", result.stderr)

    def test_render_capsule_rejects_unknown_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.status.json").write_text(
                json.dumps({"signing_status": "unknown", "attestation_status": "not-present"}),
                encoding="utf-8",
            )
            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("must not be unknown", result.stderr)

    def test_render_capsule_rejects_missing_required_image_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.spdx.json").unlink()
            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing an SBOM file", result.stderr)

    def test_render_capsule_rejects_sbom_without_digest_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.spdx.json").write_text(
                json.dumps({"spdxVersion": "SPDX-2.3", "name": "unrelated"}),
                encoding="utf-8",
            )

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("SBOM subject does not contain digest", result.stderr)

    def test_render_capsule_rejects_digest_only_in_spdx_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "unrelated",
                        "documentDescribes": ["SPDXRef-unrelated"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-unrelated",
                                "name": "unrelated",
                                "comment": f"mentions {IMAGE_DIGEST_REF} but is not the subject",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("SBOM subject does not contain digest", result.stderr)

    def test_render_capsule_rejects_grype_without_digest_subject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.grype.json").write_text(
                json.dumps({"descriptor": {"version": "0.114.0"}, "matches": []}),
                encoding="utf-8",
            )

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("Grype report has no digest-bound subject", result.stderr)

    def test_render_capsule_rejects_bogus_binary_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (binary_dir / "SHA256SUMS").write_text(
                "0000000000000000000000000000000000000000000000000000000000000000  registryctl-v0.8.0-linux-amd64\n",
                encoding="utf-8",
            )

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("SHA256SUMS entry does not match file contents", result.stderr)

    def test_render_capsule_rejects_invalid_digest_ref_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)
            (image_dir / "registry-notary.digest").write_text(
                "ghcr.io/registrystack/registry-notary@sha256:1234\n",
                encoding="utf-8",
            )

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("digest ref must match image@sha256:<64 hex>", result.stderr)

    def test_render_capsule_rejects_mismatched_source_tag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref, source_tag="v9.9.9")
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root)

            result = render_capsule(manifest, binary_dir, image_dir, root / "capsule.json", root / "capsule.md", root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match checked-out release tag", result.stderr)


def run_tool(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def init_repo(repo: Path) -> Path:
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.email", "release-test@example.invalid")
    git(repo, "config", "user.name", "Release Test")
    return repo


def init_release_repo(repo: Path) -> str:
    init_repo(repo)
    source_ref = commit_file(repo, "source.txt", "source\n")
    commit_file(repo, "release.txt", "release\n")
    git(repo, "tag", "v0.8.0")
    return source_ref


def commit_file(repo: Path, name: str, body: str) -> str:
    path = repo / name
    path.write_text(body, encoding="utf-8")
    git(repo, "add", name)
    git(repo, "commit", "-m", f"add {name}")
    return git(repo, "rev-parse", "HEAD")


def write_manifest(
    directory: Path,
    *,
    source_ref: str = "f30a541df539c2e16de09733c5944c744a60493c",
    source_tag: str = "v0.8.0",
    status: str = "release-candidate",
) -> Path:
    manifest = {
        "stack": {
            "release": "beta-6",
            "version": "0.8.0",
            "source_repo": "registrystack/registry-stack",
            "source_ref": source_ref,
            "source_tag": source_tag,
            "status": status,
        },
        "artifacts": {
            "registry-notary": "0.8.0",
            "registry-relay": "0.8.0",
        },
        "external": {
            "crosswalk": {
                "repo": "PublicSchema/crosswalk",
                "ref": "1d44ec735fdc8a7c719264b339574371e8330337",
                "status": "tested external input",
            },
        },
    }
    path = directory / "release-manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path


def write_binary_fixture(root: Path) -> Path:
    binary_dir = root / "bin"
    binary_dir.mkdir()
    binary = binary_dir / "registryctl-v0.8.0-linux-amd64"
    binary.write_text("binary fixture\n", encoding="utf-8")
    checksum = subprocess.check_output(["sha256sum", binary.name], cwd=binary_dir, text=True)
    (binary_dir / "SHA256SUMS").write_text(checksum, encoding="utf-8")
    return binary_dir


def write_image_fixture(
    root: Path,
    *,
    grype_subject: str = IMAGE_DIGEST_REF,
) -> Path:
    image_dir = root / "image-evidence"
    image_dir.mkdir()
    (image_dir / "registry-notary.digest").write_text(
        f"{IMAGE_DIGEST_REF}\n",
        encoding="utf-8",
    )
    (image_dir / "registry-notary.spdx.json").write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "name": "registry-notary",
                "documentDescribes": ["SPDXRef-registry-notary-image"],
                "packages": [
                    {
                        "SPDXID": "SPDXRef-registry-notary-image",
                        "name": "ghcr.io/registrystack/registry-notary",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": f"pkg:oci/registry-notary@{IMAGE_DIGEST}",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (image_dir / "registry-notary.grype.json").write_text(
        json.dumps(
            {
                "descriptor": {
                    "version": "0.114.0",
                    "db": {"built": "2026-06-24T00:00:00Z"},
                },
                "source": {"target": {"userInput": grype_subject}},
                "matches": [{"vulnerability": {"severity": "High"}}],
            }
        ),
        encoding="utf-8",
    )
    return image_dir


def render_capsule(
    manifest: Path,
    binary_dir: Path,
    image_dir: Path,
    output_json: Path,
    output_md: Path,
    repo: Path,
) -> subprocess.CompletedProcess[str]:
    return run_tool(
        "render-capsule",
        str(manifest),
        "--tag",
        "v0.8.0",
        "--version",
        "0.8.0",
        "--binary-dir",
        str(binary_dir),
        "--image-evidence-dir",
        str(image_dir),
        "--output-json",
        str(output_json),
        "--output-markdown",
        str(output_md),
        "--workflow-run-url",
        "https://github.com/registrystack/registry-stack/actions/runs/1",
        "--workflow-run-id",
        "1",
        "--repo",
        str(repo),
        "--default-branch",
        "main",
    )


if __name__ == "__main__":
    unittest.main()
