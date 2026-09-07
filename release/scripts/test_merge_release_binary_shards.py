#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/merge-release-binary-shards.py"
SPEC = importlib.util.spec_from_file_location("merge_release_binary_shards", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

VERSION = "0.27.0"
TAG = f"v{VERSION}"
BUILDER = "rust:fixture@sha256:" + "a" * 64
SOURCE_SHA = "1" * 40
CORE = [
    f"discovery-{TAG}-linux-amd64",
    f"evidence-{TAG}-linux-amd64",
    f"evidencectl-{TAG}-linux-amd64",
    f"mint-{TAG}-linux-amd64",
    f"evidence-oid4vci-{TAG}-linux-amd64",
    f"registry-manifest-{TAG}-linux-amd64",
    f"relay-{TAG}-linux-amd64",
    f"relayctl-{TAG}-linux-amd64",
]
BREG = [f"breg-{TAG}-linux-amd64", f"bregctl-{TAG}-linux-amd64"]
FINAL = [CORE[0], *BREG, *CORE[1:]]
IMAGE_SOURCES = {
    "discovery": CORE[0],
    "breg": BREG[0],
    "evidence": CORE[1],
    "mint": CORE[3],
    "relay": CORE[6],
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MergeReleaseBinaryShardsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.core = self.write_shard("core", CORE)
        self.breg = self.write_shard("breg", BREG)
        self.output = self.root / "dist"

    def write_shard(self, name: str, assets: list[str]) -> Path:
        root = self.root / name
        bin_dir = root / "bin"
        bin_dir.mkdir(parents=True)
        sums = []
        for asset in assets:
            contents = f"{name}:{asset}\n".encode()
            (bin_dir / asset).write_bytes(contents)
            sums.append(f"{digest(contents)}  {asset}\n")
        (bin_dir / "SHA256SUMS").write_text("".join(sums), encoding="utf-8")
        (root / "RELEASE_BUILDER_IMAGE").write_text(f"{BUILDER}\n", encoding="utf-8")
        (root / "RELEASE_BINARY_SHARD").write_text(
            "registry-stack.release-binary-shard.v1\n"
            f"source_sha={SOURCE_SHA}\n"
            f"version={VERSION}\n"
            f"group={name}\n",
            encoding="utf-8",
        )
        return root

    def merge(self) -> None:
        MODULE.merge(
            version=VERSION,
            source_sha=SOURCE_SHA,
            core=self.core,
            breg=self.breg,
            output=self.output,
            builder_image=BUILDER,
        )

    def test_reconstructs_the_exact_full_layout_from_download_binary_bytes(self) -> None:
        self.merge()
        bin_dir = self.output / "bin"
        image_dir = self.output / "image-bin"
        self.assertEqual(
            sorted([*FINAL, "SHA256SUMS"]),
            sorted(path.name for path in bin_dir.iterdir()),
        )
        self.assertEqual(
            sorted(["RELEASE_BUILDER_IMAGE", *IMAGE_SOURCES, "SHA256SUMS"]),
            sorted(path.name for path in image_dir.iterdir()),
        )
        for asset in FINAL:
            source_root = self.breg if asset in BREG else self.core
            self.assertEqual((source_root / "bin" / asset).read_bytes(), (bin_dir / asset).read_bytes())
            self.assertEqual(stat.S_IMODE((bin_dir / asset).stat().st_mode), 0o755)
        for image_name, source_name in IMAGE_SOURCES.items():
            source_root = self.breg if source_name in BREG else self.core
            self.assertEqual(
                (source_root / "bin" / source_name).read_bytes(),
                (image_dir / image_name).read_bytes(),
            )
            self.assertEqual(stat.S_IMODE((image_dir / image_name).stat().st_mode), 0o755)
        self.assertEqual(
            "".join(
                f"{digest((bin_dir / name).read_bytes())}  {name}\n" for name in FINAL
            ),
            (bin_dir / "SHA256SUMS").read_text(encoding="utf-8"),
        )
        image_order = ["RELEASE_BUILDER_IMAGE", *IMAGE_SOURCES]
        self.assertEqual(
            "".join(
                f"{digest((image_dir / name).read_bytes())}  {name}\n"
                for name in image_order
            ),
            (image_dir / "SHA256SUMS").read_text(encoding="utf-8"),
        )

    def test_version_gates_select_the_historical_exact_rosters(self) -> None:
        rosters_023, images_023 = MODULE.rosters("0.23.9")
        self.assertEqual([], rosters_023["breg"])
        self.assertFalse(any(name.startswith("discovery-") for name in rosters_023["core"]))
        self.assertEqual(["evidence", "mint", "relay"], [name for name, _ in images_023])
        rosters_024, images_024 = MODULE.rosters("0.24.0")
        self.assertTrue(rosters_024["core"][0].startswith("discovery-v0.24.0"))
        self.assertEqual([], rosters_024["breg"])
        self.assertEqual(["discovery", "evidence", "mint", "relay"], [name for name, _ in images_024])
        rosters_026, images_026 = MODULE.rosters("0.26.0")
        self.assertEqual(2, len(rosters_026["breg"]))
        self.assertEqual(["discovery", "breg", "evidence", "mint", "relay"], [name for name, _ in images_026])

    def test_rejects_incomplete_or_ambiguous_shards_before_staging_output(self) -> None:
        mutations = {
            "missing": lambda: (self.core / "bin" / CORE[0]).unlink(),
            "unexpected": lambda: (self.core / "bin" / "extra").write_text("extra"),
            "duplicate": lambda: (self.core / "bin" / "SHA256SUMS").write_text(
                (self.core / "bin" / "SHA256SUMS").read_text() +
                f"{digest((self.core / 'bin' / CORE[0]).read_bytes())}  {CORE[0]}\n"
            ),
            "corrupt": lambda: (self.core / "bin" / CORE[0]).write_text("corrupt"),
            "builder": lambda: (self.breg / "RELEASE_BUILDER_IMAGE").write_text(
                "rust:different@sha256:" + "b" * 64 + "\n"
            ),
            "source": lambda: (self.core / "RELEASE_BINARY_SHARD").write_text(
                "registry-stack.release-binary-shard.v1\n"
                f"source_sha={'2' * 40}\nversion={VERSION}\ngroup=core\n"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as directory:
                    fixture = Path(directory)
                    original_root = self.root
                    self.root = fixture
                    try:
                        self.core = self.write_shard("core", CORE)
                        self.breg = self.write_shard("breg", BREG)
                        self.output = fixture / "dist"
                        mutate()
                        with self.assertRaises(MODULE.ShardError):
                            self.merge()
                        self.assertFalse(self.output.exists())
                    finally:
                        self.root = original_root


if __name__ == "__main__":
    unittest.main()
