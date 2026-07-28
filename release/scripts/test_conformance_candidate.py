#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT = SCRIPT_DIR / "conformance_candidate.py"
sys.path.insert(0, str(SCRIPT_DIR))
import registryctl_image_lock as image_lock  # noqa: E402


def load_module():
    spec = importlib.util.spec_from_file_location("conformance_candidate", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ConformanceCandidateTest(TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tag = "v0.14.0"
        self.version = self.tag.removeprefix("v")
        self.relay = "ghcr.io/registrystack/registry-relay@sha256:" + "2" * 64
        self.notary = "ghcr.io/registrystack/registry-notary@sha256:" + "3" * 64
        self.postgresql = image_lock.reviewed_postgresql_image_ref()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def make_binding_fixture(
        self,
        *,
        candidate_name: str = "candidate",
        schema_version: str = image_lock.SCHEMA_V2,
    ) -> tuple[dict[str, object], dict[str, object], Path, str, Path]:
        candidate = self.root / candidate_name
        candidate.mkdir()
        images = {
            "registry-relay": self.relay,
            "registry-notary": self.notary,
        }
        if schema_version == image_lock.SCHEMA_V2:
            images["postgresql"] = self.postgresql
        lock = {
            "schema_version": schema_version,
            "release_tag": self.tag,
            "manifest_source_ref": "4" * 40,
            "tag_target": "1" * 40,
            "platform": image_lock.PLATFORM,
            "images": images,
        }
        lock_name = f"registryctl-{self.tag}-image-lock.json"
        lock_path = candidate / lock_name
        self.write_json(lock_path, lock)
        lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        capsule_path = candidate / f"registry-stack-{self.tag}-release-capsule.json"
        capsule_images = [
            {
                "name": "registry-relay",
                "role": "released-product-image",
                "digest_ref": self.relay,
            },
            {
                "name": "registry-notary",
                "role": "released-product-image",
                "digest_ref": self.notary,
            },
        ]
        if schema_version == image_lock.SCHEMA_V2:
            capsule_images.append(
                {
                    "name": "postgresql",
                    "role": "supporting-runtime-image",
                    "digest_ref": self.postgresql,
                }
            )
        self.write_json(
            capsule_path,
            {
                "release_tag": self.tag,
                "version": self.version,
                "repository": self.module.CAPSULE_REPOSITORY,
                "source": {
                    "source_tag": self.tag,
                    "source_ref": lock["manifest_source_ref"],
                    "source_commit": lock["tag_target"],
                    "lineage": {
                        "tag_matches_source_tag": True,
                        "head_matches_tag_target": True,
                        "source_ref_ancestor_or_equal": True,
                        "default_branch_reachable": True,
                    },
                },
                "release_files": [
                    {
                        "name": lock_name,
                        "kind": "registryctl-release-image-lock",
                        "sha256": lock_sha256,
                    }
                ],
                "images": capsule_images,
            },
        )
        (candidate / "SHA256SUMS").write_text(
            f"{lock_sha256}  {lock_name}\n", encoding="utf-8"
        )
        return (
            {"version": self.version},
            lock,
            lock_path,
            lock_sha256,
            capsule_path,
        )

    def verify_fixture(
        self,
        stack: dict[str, object],
        lock: dict[str, object],
        lock_path: Path,
        lock_sha256: str,
    ) -> str:
        with mock.patch.object(self.module, "verify_release_authenticity"):
            return self.module.verify_release_asset_binding(
                stack, lock, lock_path, lock_sha256
            )

    def test_v1_capsule_keeps_product_only_image_set(self) -> None:
        stack, lock, lock_path, lock_sha256, _capsule_path = self.make_binding_fixture(
            schema_version=image_lock.SCHEMA_V1
        )

        capsule_sha256 = self.verify_fixture(stack, lock, lock_path, lock_sha256)

        self.assertRegex(capsule_sha256, r"^[0-9a-f]{64}$")

    def test_v2_capsule_binds_postgresql_from_validated_image_lock(self) -> None:
        stack, lock, lock_path, lock_sha256, _capsule_path = self.make_binding_fixture()

        capsule_sha256 = self.verify_fixture(stack, lock, lock_path, lock_sha256)

        self.assertRegex(capsule_sha256, r"^[0-9a-f]{64}$")

    def test_v2_capsule_rejects_missing_drifted_extra_or_wrong_role_image(self) -> None:
        mutations = (
            (
                "missing",
                lambda images: images.pop(),
                "image-lock images",
            ),
            (
                "drifted",
                lambda images: images[-1].__setitem__(
                    "digest_ref", "docker.io/library/postgres@sha256:" + "9" * 64
                ),
                "do not match the release image lock",
            ),
            (
                "extra",
                lambda images: images.append(
                    {
                        "name": "unreviewed-image",
                        "digest_ref": "docker.io/example/unreviewed@sha256:"
                        + "9" * 64,
                    }
                ),
                "image-lock images",
            ),
            (
                "wrong-role",
                lambda images: images[-1].__setitem__(
                    "role", "released-product-image"
                ),
                "supporting-runtime-image",
            ),
        )
        for name, mutation, message in mutations:
            with self.subTest(name=name):
                (
                    stack,
                    lock,
                    lock_path,
                    lock_sha256,
                    capsule_path,
                ) = self.make_binding_fixture(candidate_name=name)
                capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
                mutation(capsule["images"])
                self.write_json(capsule_path, capsule)

                with self.assertRaisesRegex(self.module.CandidateError, message):
                    self.verify_fixture(stack, lock, lock_path, lock_sha256)

    def test_capsule_rejects_wrong_product_image_role(self) -> None:
        for component in ("registry-relay", "registry-notary"):
            with self.subTest(component=component):
                (
                    stack,
                    lock,
                    lock_path,
                    lock_sha256,
                    capsule_path,
                ) = self.make_binding_fixture(candidate_name=component)
                capsule = json.loads(capsule_path.read_text(encoding="utf-8"))
                image = next(
                    item for item in capsule["images"] if item["name"] == component
                )
                image["role"] = "supporting-runtime-image"
                self.write_json(capsule_path, capsule)

                with self.assertRaisesRegex(
                    self.module.CandidateError, "released-product-image"
                ):
                    self.verify_fixture(stack, lock, lock_path, lock_sha256)


if __name__ == "__main__":
    main()
