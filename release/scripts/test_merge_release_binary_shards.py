#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/merge-release-binary-shards.py"
SPEC = importlib.util.spec_from_file_location("merge_release_binary_shards", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

# breg-mcp and breg-review have not joined a release
# (release_roster.BREG_SERVICES_FIRST_RELEASE is None). The inclusion tests
# patch a hypothetical first release so their shard path stays covered without
# any production knob.
HYPOTHETICAL_BREG_SERVICES_FIRST_RELEASE = (0, 37, 0)
VERSION = "0.33.0"
TAG = f"v{VERSION}"
BUILDER = "rust:fixture@sha256:" + "a" * 64
SOURCE_SHA = "1" * 40
CORE = [
    f"discovery-{TAG}-linux-amd64",
    f"evidence-{TAG}-linux-amd64",
    f"evidencectl-{TAG}-linux-amd64",
    f"evidence-oid4vci-{TAG}-linux-amd64",
    f"registry-manifest-{TAG}-linux-amd64",
    f"relay-{TAG}-linux-amd64",
    f"relayctl-{TAG}-linux-amd64",
]
BREG = [f"breg-{TAG}-linux-amd64", f"bregctl-{TAG}-linux-amd64"]
CASEWORK = [
    f"casework-{TAG}-linux-amd64",
    f"caseworkctl-{TAG}-linux-amd64",
]
SCHEDULING = [f"scheduling-{TAG}-linux-amd64"]
FINAL = [CORE[0], *BREG, *CASEWORK, *CORE[1:]]
IMAGE_SOURCES = {
    "discovery": CORE[0],
    "breg": BREG[0],
    "casework": CASEWORK[0],
    "scheduling": SCHEDULING[0],
    "evidence": CORE[1],
    "relay": CORE[5],
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
        self.casework = self.write_shard("casework", CASEWORK)
        self.scheduling = self.write_shard("scheduling", SCHEDULING)
        self.output = self.root / "dist"

    def write_shard(
        self, name: str, assets: list[str], version: str = VERSION
    ) -> Path:
        root = self.root / version / name
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
            f"version={version}\n"
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
            casework=self.casework,
            scheduling=self.scheduling,
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
            source_root = (
                self.breg
                if asset in BREG
                else self.casework
                if asset in CASEWORK
                else self.scheduling
                if asset in SCHEDULING
                else self.core
            )
            self.assertEqual((source_root / "bin" / asset).read_bytes(), (bin_dir / asset).read_bytes())
            self.assertEqual(stat.S_IMODE((bin_dir / asset).stat().st_mode), 0o755)
        for image_name, source_name in IMAGE_SOURCES.items():
            source_root = (
                self.breg
                if source_name in BREG
                else self.casework
                if source_name in CASEWORK
                else self.scheduling
                if source_name in SCHEDULING
                else self.core
            )
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
        self.assertEqual([], rosters_026["casework"])
        rosters_030, images_030 = MODULE.rosters("0.30.0")
        self.assertEqual(2, len(rosters_030["casework"]))
        self.assertEqual(
            ["discovery", "breg", "casework", "evidence", "mint", "relay"],
            [name for name, _ in images_030],
        )
        rosters_032, images_032 = MODULE.rosters("0.32.0")
        self.assertEqual([], rosters_032["scheduling"])
        self.assertNotIn("scheduling", dict(images_032))
        rosters_033, images_033 = MODULE.rosters("0.33.0")
        self.assertEqual(
            ["scheduling-v0.33.0-linux-amd64"], rosters_033["scheduling"]
        )
        self.assertIn("scheduling", dict(images_033))
        rosters_035, images_035 = MODULE.rosters("0.35.0")
        self.assertEqual(
            ["breg-v0.35.0-linux-amd64", "bregctl-v0.35.0-linux-amd64"],
            rosters_035["breg"],
        )
        self.assertNotIn("breg-mcp", dict(images_035))
        self.assertNotIn("breg-review", dict(images_035))
        with mock.patch.object(
            MODULE.release_roster,
            "BREG_SERVICES_FIRST_RELEASE",
            HYPOTHETICAL_BREG_SERVICES_FIRST_RELEASE,
        ):
            rosters_036, _ = MODULE.rosters("0.36.0")
            rosters_037, images_037 = MODULE.rosters("0.37.0")
        self.assertEqual(
            ["breg-v0.36.0-linux-amd64", "bregctl-v0.36.0-linux-amd64"],
            rosters_036["breg"],
        )
        self.assertEqual(
            [
                "breg-v0.37.0-linux-amd64",
                "bregctl-v0.37.0-linux-amd64",
                "breg-mcp-v0.37.0-linux-amd64",
                "breg-review-v0.37.0-linux-amd64",
            ],
            rosters_037["breg"],
        )
        self.assertEqual(
            [
                "discovery",
                "breg",
                "bregctl",
                "breg-mcp",
                "breg-review",
                "casework",
                "caseworkctl",
                "scheduling",
                "schedulingctl",
                "evidence",
                "relay",
            ],
            [name for name, _ in images_037],
        )

    def test_no_version_ships_the_breg_services_until_the_roster_names_a_first_release(
        self,
    ) -> None:
        self.assertIsNone(MODULE.release_roster.BREG_SERVICES_FIRST_RELEASE)
        for version in ("0.36.0", "0.37.0", "1.0.0"):
            with self.subTest(version=version):
                rosters, images = MODULE.rosters(version)
                self.assertEqual(
                    [f"breg-v{version}-linux-amd64", f"bregctl-v{version}-linux-amd64"],
                    rosters["breg"],
                )
                self.assertFalse(
                    any(
                        name.startswith(("breg-mcp", "breg-review"))
                        for names in rosters.values()
                        for name in names
                    )
                )
                self.assertNotIn("breg-mcp", dict(images))
                self.assertNotIn("breg-review", dict(images))

    def test_breg_services_merge_from_the_breg_shard_from_the_first_release(
        self,
    ) -> None:
        roster_patch = mock.patch.object(
            MODULE.release_roster,
            "BREG_SERVICES_FIRST_RELEASE",
            HYPOTHETICAL_BREG_SERVICES_FIRST_RELEASE,
        )
        roster_patch.start()
        self.addCleanup(roster_patch.stop)
        version = "0.37.0"
        rosters, images = MODULE.rosters(version)
        shards = {
            name: self.write_shard(name, assets, version)
            for name, assets in rosters.items()
        }
        output = self.root / "dist-0.37.0"
        MODULE.merge(
            version=version,
            source_sha=SOURCE_SHA,
            core=shards["core"],
            breg=shards["breg"],
            casework=shards["casework"],
            scheduling=shards["scheduling"],
            output=output,
            builder_image=BUILDER,
        )
        for service in ("breg-mcp", "breg-review"):
            with self.subTest(service=service):
                asset = f"{service}-v{version}-linux-amd64"
                expected = f"breg:{asset}\n".encode()
                self.assertEqual(expected, (output / "bin" / asset).read_bytes())
                self.assertEqual(
                    expected, (output / "image-bin" / service).read_bytes()
                )
        self.assertEqual(
            ["RELEASE_BUILDER_IMAGE", *(name for name, _ in images)],
            [
                line.split("  ", 1)[1]
                for line in (output / "image-bin" / "SHA256SUMS")
                .read_text(encoding="utf-8")
                .splitlines()
            ],
        )
        (shards["breg"] / "bin" / "breg-review-v0.37.0-linux-amd64").unlink()
        with self.assertRaisesRegex(MODULE.ShardError, "breg"):
            MODULE.merge(
                version=version,
                source_sha=SOURCE_SHA,
                core=shards["core"],
                breg=shards["breg"],
                casework=shards["casework"],
                scheduling=shards["scheduling"],
                output=self.root / "dist-0.37.0-incomplete",
                builder_image=BUILDER,
            )

    def test_operator_tools_join_the_rosters_only_from_v0_36_0(self) -> None:
        rosters_035, images_035 = MODULE.rosters("0.35.0")
        self.assertEqual(
            ["scheduling-v0.35.0-linux-amd64"], rosters_035["scheduling"]
        )
        self.assertEqual(
            [
                ("discovery", "discovery-v0.35.0-linux-amd64"),
                ("breg", "breg-v0.35.0-linux-amd64"),
                ("casework", "casework-v0.35.0-linux-amd64"),
                ("scheduling", "scheduling-v0.35.0-linux-amd64"),
                ("evidence", "evidence-v0.35.0-linux-amd64"),
                ("relay", "relay-v0.35.0-linux-amd64"),
            ],
            images_035,
        )
        rosters_036, images_036 = MODULE.rosters("0.36.0")
        self.assertEqual(
            [
                "scheduling-v0.36.0-linux-amd64",
                "schedulingctl-v0.36.0-linux-amd64",
            ],
            rosters_036["scheduling"],
        )
        self.assertEqual(
            [
                ("discovery", "discovery-v0.36.0-linux-amd64"),
                ("breg", "breg-v0.36.0-linux-amd64"),
                ("bregctl", "bregctl-v0.36.0-linux-amd64"),
                ("casework", "casework-v0.36.0-linux-amd64"),
                ("caseworkctl", "caseworkctl-v0.36.0-linux-amd64"),
                ("scheduling", "scheduling-v0.36.0-linux-amd64"),
                ("schedulingctl", "schedulingctl-v0.36.0-linux-amd64"),
                ("evidence", "evidence-v0.36.0-linux-amd64"),
                ("relay", "relay-v0.36.0-linux-amd64"),
            ],
            images_036,
        )

    def test_v0_36_0_publishes_schedulingctl_and_stages_each_operator_tool(
        self,
    ) -> None:
        version = "0.36.0"
        tag = f"v{version}"
        rosters, images = MODULE.rosters(version)
        original_root = self.root
        self.root = original_root / version
        try:
            shards = {
                name: self.write_shard(name, rosters[name], version)
                for name in ("core", "breg", "casework", "scheduling")
            }
        finally:
            self.root = original_root
        output = self.root / "dist-036"
        MODULE.merge(
            version=version,
            source_sha=SOURCE_SHA,
            core=shards["core"],
            breg=shards["breg"],
            casework=shards["casework"],
            scheduling=shards["scheduling"],
            output=output,
            builder_image=BUILDER,
        )
        final = [
            f"discovery-{tag}-linux-amd64",
            f"breg-{tag}-linux-amd64",
            f"bregctl-{tag}-linux-amd64",
            f"casework-{tag}-linux-amd64",
            f"caseworkctl-{tag}-linux-amd64",
            f"schedulingctl-{tag}-linux-amd64",
            f"evidence-{tag}-linux-amd64",
            f"evidencectl-{tag}-linux-amd64",
            f"evidence-oid4vci-{tag}-linux-amd64",
            f"registry-manifest-{tag}-linux-amd64",
            f"relay-{tag}-linux-amd64",
            f"relayctl-{tag}-linux-amd64",
        ]
        bin_dir = output / "bin"
        self.assertEqual(
            "".join(
                f"{digest((bin_dir / name).read_bytes())}  {name}\n" for name in final
            ),
            (bin_dir / "SHA256SUMS").read_text(encoding="utf-8"),
        )
        self.assertFalse((bin_dir / f"scheduling-{tag}-linux-amd64").exists())
        image_dir = output / "image-bin"
        image_order = [
            "RELEASE_BUILDER_IMAGE",
            "discovery",
            "breg",
            "bregctl",
            "casework",
            "caseworkctl",
            "scheduling",
            "schedulingctl",
            "evidence",
            "relay",
        ]
        self.assertEqual(
            "".join(
                f"{digest((image_dir / name).read_bytes())}  {name}\n"
                for name in image_order
            ),
            (image_dir / "SHA256SUMS").read_text(encoding="utf-8"),
        )
        for image_name, source_name in images:
            owner = next(
                name for name, assets in rosters.items() if source_name in assets
            )
            self.assertEqual(
                (shards[owner] / "bin" / source_name).read_bytes(),
                (image_dir / image_name).read_bytes(),
            )
            self.assertEqual(
                stat.S_IMODE((image_dir / image_name).stat().st_mode), 0o755
            )

    def test_mint_is_retired_only_from_v0_31_0(self) -> None:
        for version in ("0.30.0", "0.30.1"):
            with self.subTest(version=version):
                rosters, images = MODULE.rosters(version)
                self.assertIn(f"mint-v{version}-linux-amd64", rosters["core"])
                self.assertIn("mint", dict(images))
        retired, retired_images = MODULE.rosters("0.31.0")
        self.assertNotIn("mint-v0.31.0-linux-amd64", retired["core"])
        self.assertNotIn("mint", dict(retired_images))

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
                        self.casework = self.write_shard("casework", CASEWORK)
                        self.scheduling = self.write_shard(
                            "scheduling", SCHEDULING
                        )
                        self.output = fixture / "dist"
                        mutate()
                        with self.assertRaises(MODULE.ShardError):
                            self.merge()
                        self.assertFalse(self.output.exists())
                    finally:
                        self.root = original_root


if __name__ == "__main__":
    unittest.main()
