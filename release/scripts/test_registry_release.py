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
    def test_release_image_packaging_keeps_lab_dockerfiles_source_building(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        release_dockerfiles = [
            "release/docker/Dockerfile.registry-notary",
            "release/docker/Dockerfile.registry-notary-openfn-sidecar",
            "release/docker/Dockerfile.registry-relay",
        ]
        lab_dockerfiles = [
            "lab/Dockerfile.registry-notary",
            "lab/Dockerfile.registry-notary-openfn-sidecar",
            "lab/Dockerfile.registry-relay",
        ]

        for dockerfile in release_dockerfiles:
            self.assertIn(dockerfile, workflow)
            text = (ROOT / dockerfile).read_text(encoding="utf-8")
            self.assertIn("dist/image-bin", text)

        for dockerfile in lab_dockerfiles:
            self.assertNotIn(dockerfile, workflow)
            text = (ROOT / dockerfile).read_text(encoding="utf-8")
            self.assertNotIn("dist/image-bin", text)
            self.assertIn("cargo build --release --locked", text)

    def test_release_workflow_publishes_cross_platform_registryctl_binaries(self) -> None:
        # The hermetic linux/amd64 builder cannot produce macOS or arm64 binaries,
        # so registryctl-<tag>-macos-arm64 and -linux-arm64 are built natively on a
        # runner matrix. install.sh expects exactly these asset names.
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("macos-14", workflow)
        self.assertIn("ubuntu-24.04-arm", workflow)
        self.assertIn("aarch64-apple-darwin", workflow)
        self.assertIn("aarch64-unknown-linux-gnu", workflow)
        for asset in ("macos-arm64", "linux-arm64"):
            self.assertIn(asset, workflow)
            self.assertIn(f"registry-stack-registryctl-{asset}", workflow)

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

    def test_validate_rejects_head_for_non_draft_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_manifest(Path(tmp), source_ref="HEAD", status="release-candidate")
            result = run_tool("validate", str(manifest))
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stack.source_ref may be HEAD only", result.stderr)

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

    def test_render_capsule_includes_cross_platform_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_multiplatform_binary_fixture(root)
            image_dir = write_image_fixture(root)
            output_json = root / "capsule.json"
            output_md = root / "capsule.md"

            result = render_capsule(manifest, binary_dir, image_dir, output_json, output_md, root)

            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        names = {binary["name"] for binary in evidence["binaries"]}
        self.assertEqual(
            {
                "registryctl-v0.8.0-linux-amd64",
                "registryctl-v0.8.0-linux-arm64",
                "registryctl-v0.8.0-macos-arm64",
            },
            names,
        )

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

    def test_render_capsule_prefers_digest_bound_backfill_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_ref = init_release_repo(root)
            manifest = write_manifest(root, source_ref=source_ref)
            binary_dir = write_binary_fixture(root)
            image_dir = write_image_fixture(root, grype_subject="ghcr.io/registrystack/registry-notary:v0.8.0")
            (image_dir / "registry-notary.digest-bound.spdx.json").write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "registry-notary-digest-bound",
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
            (image_dir / "registry-notary.digest-bound.grype.json").write_text(
                json.dumps(
                    {
                        "descriptor": {
                            "version": "0.114.0",
                            "db": {"built": "2026-06-24T00:00:00Z"},
                        },
                        "source": {"target": {"userInput": IMAGE_DIGEST_REF}},
                        "matches": [],
                    }
                ),
                encoding="utf-8",
            )
            output_json = root / "capsule.json"

            result = render_capsule(manifest, binary_dir, image_dir, output_json, root / "capsule.md", root)

            evidence = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("registry-notary.digest-bound.spdx.json", evidence["images"][0]["sbom"]["asset_name"])
        self.assertEqual(
            "registry-notary.digest-bound.grype.json",
            evidence["images"][0]["vulnerability_scan"]["asset_name"],
        )

    def test_stage_capsule_backfill_assets_copies_expected_release_assets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root)
            binary_dir = root / "staged-bin"
            image_dir = root / "staged-images"

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.8.0",
                "--binary-dir",
                str(binary_dir),
                "--image-evidence-dir",
                str(image_dir),
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((binary_dir / "registryctl-v0.8.0-linux-amd64").is_file())
            self.assertTrue((binary_dir / "registry-manifest-v0.8.0-linux-amd64").is_file())
            self.assertTrue((binary_dir / "registry-relay-v0.8.0-linux-amd64").is_file())
            self.assertTrue((binary_dir / "registry-notary-v0.8.0-linux-amd64").is_file())
            self.assertTrue((binary_dir / "SHA256SUMS").is_file())
            self.assertTrue((image_dir / "registry-notary.digest").is_file())
            self.assertTrue((image_dir / "registry-notary-source-adapter-sidecar.digest").is_file())
            self.assertTrue((image_dir / "registry-relay.digest").is_file())
            self.assertFalse((image_dir / "registry-notary-source-adapter-sidecar.spdx.json").exists())
            self.assertFalse((image_dir / "registry-relay.grype.json").exists())
            self.assertFalse((image_dir / "registry-stack-v0.8.0-release-evidence.json").exists())
            # Cross-platform binaries are optional and absent in this fixture.
            self.assertFalse((binary_dir / "registryctl-v0.8.0-macos-arm64").exists())
            self.assertFalse((binary_dir / "registryctl-v0.8.0-linux-arm64").exists())

    def test_stage_capsule_backfill_assets_stages_optional_cross_platform_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root, include_cross_platform=True)
            binary_dir = root / "staged-bin"
            image_dir = root / "staged-images"

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.8.0",
                "--binary-dir",
                str(binary_dir),
                "--image-evidence-dir",
                str(image_dir),
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((binary_dir / "registryctl-v0.8.0-macos-arm64").is_file())
            self.assertTrue((binary_dir / "registryctl-v0.8.0-linux-arm64").is_file())
            # Required amd64 binaries are still staged alongside the optional ones.
            self.assertTrue((binary_dir / "registryctl-v0.8.0-linux-amd64").is_file())

    def test_stage_capsule_backfill_assets_rejects_missing_release_asset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset_dir = write_release_asset_fixture(root)
            (asset_dir / "registry-relay.digest").unlink()

            result = run_tool(
                "stage-capsule-backfill-assets",
                str(asset_dir),
                "--tag",
                "v0.8.0",
                "--binary-dir",
                str(root / "staged-bin"),
                "--image-evidence-dir",
                str(root / "staged-images"),
            )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing release asset registry-relay.digest", result.stderr)

    def test_bind_spdx_subject_adds_digest_bound_described_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spdx = root / "sidecar.spdx.json"
            spdx.write_text(
                json.dumps(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": "syft-sidecar-output",
                        "documentDescribes": ["SPDXRef-DocumentRoot"],
                        "packages": [
                            {
                                "SPDXID": "SPDXRef-DocumentRoot",
                                "name": "registry-notary-source-adapter-sidecar",
                                "downloadLocation": "NOASSERTION",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_tool(
                "bind-spdx-subject",
                str(spdx),
                "--image-name",
                "registry-notary-source-adapter-sidecar",
                "--digest-ref",
                IMAGE_DIGEST_REF,
            )

            data = json.loads(spdx.read_text(encoding="utf-8"))

        self.assertEqual(0, result.returncode, result.stderr)
        described = set(data["documentDescribes"])
        subject_packages = [package for package in data["packages"] if package["SPDXID"] in described]
        self.assertTrue(any(package["name"] == IMAGE_DIGEST_REF for package in subject_packages))
        self.assertTrue(any(IMAGE_DIGEST in json.dumps(package) for package in subject_packages))


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


def write_multiplatform_binary_fixture(root: Path) -> Path:
    binary_dir = root / "bin"
    binary_dir.mkdir()
    names = [
        "registryctl-v0.8.0-linux-amd64",
        "registryctl-v0.8.0-linux-arm64",
        "registryctl-v0.8.0-macos-arm64",
    ]
    checksums = []
    for name in names:
        (binary_dir / name).write_text(f"{name} fixture\n", encoding="utf-8")
        checksums.append(subprocess.check_output(["sha256sum", name], cwd=binary_dir, text=True))
    (binary_dir / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    return binary_dir


def write_release_asset_fixture(root: Path, *, include_cross_platform: bool = False) -> Path:
    asset_dir = root / "release-assets"
    asset_dir.mkdir()
    binary_names = [
        "registryctl-v0.8.0-linux-amd64",
        "registry-manifest-v0.8.0-linux-amd64",
        "registry-relay-v0.8.0-linux-amd64",
        "registry-notary-v0.8.0-linux-amd64",
    ]
    if include_cross_platform:
        binary_names += [
            "registryctl-v0.8.0-macos-arm64",
            "registryctl-v0.8.0-linux-arm64",
        ]
    checksums = []
    for name in binary_names:
        path = asset_dir / name
        path.write_text(f"{name}\n", encoding="utf-8")
        checksums.append(subprocess.check_output(["sha256sum", name], cwd=asset_dir, text=True))
    (asset_dir / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    for image in ("registry-notary", "registry-notary-source-adapter-sidecar", "registry-relay"):
        (asset_dir / f"{image}.digest").write_text(f"{IMAGE_DIGEST_REF}\n", encoding="utf-8")
        (asset_dir / f"{image}.spdx.json").write_text("{}", encoding="utf-8")
        (asset_dir / f"{image}.grype.json").write_text("{}", encoding="utf-8")
        (asset_dir / f"{image}.metadata.json").write_text("{}", encoding="utf-8")
    (asset_dir / "registry-stack-v0.8.0-release-evidence.json").write_text("{}", encoding="utf-8")
    return asset_dir


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
