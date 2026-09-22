#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "release/scripts/build-release-native-platform.sh"
MERGER = ROOT / "release/scripts/merge-release-native-platform-shards.py"
SPEC = importlib.util.spec_from_file_location("merge_release_native_shards", MERGER)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

VERSION = "0.31.0"
ARCHIVE_VERSION = "0.33.0"
SOURCE_SHA = subprocess.run(
    ["git", "rev-parse", "HEAD"],
    cwd=ROOT,
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
TARGET = "aarch64-apple-darwin"
CORE_ARGS = [
    "build",
    "--release",
    "--locked",
    "-p",
    "registry-relayctl",
    "-p",
    "registry-evidence",
    "-p",
    "registry-evidencectl",
    "-p",
    "registry-evidence-oid4vci",
    "--target",
    TARGET,
]
BREG_ARGS = [
    "build",
    "--release",
    "--locked",
    "-p",
    "registry-breg",
    "--bin",
    "breg",
    "--features",
    "runtime",
    "--target",
    TARGET,
]
BREGCTL_ARGS = [
    "build",
    "--release",
    "--locked",
    "-p",
    "registry-bregctl",
    "--target",
    TARGET,
]
CASEWORK_RUNTIME_ARGS = [
    "build",
    "--release",
    "--locked",
    "-p",
    "registry-casework",
    "--bin",
    "casework",
    "--target",
    TARGET,
]
CASEWORKCTL_ARGS = [
    "build",
    "--release",
    "--locked",
    "-p",
    "registry-caseworkctl",
    "--bin",
    "caseworkctl",
    "--target",
    TARGET,
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseNativePlatformTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fake_cargo = self.root / "fake-cargo"
        self.fake_cargo.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
version = os.environ["FAKE_VERSION"]
if os.environ.get("REGISTRY_RELEASE_TAG") != f"v{version}":
    raise SystemExit(43)
major, minor, patch = (int(part) for part in version.split("."))
archive_release = major > 0 or minor >= 33
if archive_release and os.environ.get("AWS_LC_FIPS_SYS_STATIC") != "0":
    raise SystemExit(44)
if archive_release and os.environ.get("MACOSX_DEPLOYMENT_TARGET") != "11.0":
    raise SystemExit(46)
if not archive_release and os.environ.get("AWS_LC_FIPS_SYS_STATIC") != "1":
    raise SystemExit(45)
binary_version = os.environ.get("FAKE_BINARY_VERSION", version)
log = Path(os.environ["FAKE_CARGO_LOG"])
calls = []
if log.exists():
    calls = [json.loads(line) for line in log.read_text().splitlines()]
with log.open("a") as handle:
    handle.write(json.dumps(args) + "\\n")
if os.environ.get("FAKE_CARGO_FAIL_CALL") == str(len(calls) + 1):
    raise SystemExit(42)
target = args[args.index("--target") + 1]
output = Path(os.environ["CARGO_TARGET_DIR"]) / target / "release"
output.mkdir(parents=True, exist_ok=True)
if archive_release:
    artifacts = output / "build/aws-lc-fips-sys-fixture/out/build/artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "libaws_lc_fips_0_14_2_crypto.dylib").write_text("fixture dylib\\n")
packages = [args[index + 1] for index, value in enumerate(args) if value == "-p"]
binaries = {
    "registry-relayctl": "relayctl",
    "registry-evidence": "evidence",
    "registry-evidencectl": "evidencectl",
    "registry-evidence-oid4vci": "evidence-oid4vci",
    "registry-breg": "breg",
    "registry-bregctl": "bregctl",
    "registry-casework": "casework",
    "registry-caseworkctl": "caseworkctl",
}
for package in packages:
    name = binaries[package]
    body = f'''#!/usr/bin/env bash
if [[ "${{1:-}}" == --version ]]; then
  printf '%s\\n' "{name}" >>"$FAKE_BINARY_SMOKE_LOG"
  printf '%s\\n' "{name} {binary_version}"
fi
'''
    path = output / name
    path.write_text(body)
    path.chmod(0o755)
""",
            encoding="utf-8",
        )
        self.fake_cargo.chmod(0o755)
        self.fake_otool = self.root / "otool"
        self.fake_otool.write_text(
            """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

path = Path(sys.argv[-1])
if sys.argv[1] == "-l":
    print("Load command 0")
    print("      cmd LC_BUILD_VERSION")
    print("  cmdsize 32")
    print(" platform 1")
    print("    minos 11.0")
    print("      sdk 26.5")
    raise SystemExit(0)
print(f"{path}:")
state = path.with_name(path.name + ".fips-load")
if path.suffix == ".dylib":
    print(
        f"\t@rpath/{path.name} "
        "(compatibility version 0.0.0, current version 0.0.0)"
    )
elif state.exists():
    print(
        f"\t{state.read_text().strip()} "
        "(compatibility version 0.0.0, current version 0.0.0)"
    )
elif os.environ.get("FAKE_OTOOL_FIPS_SHARED") == "1":
    print(
        "\t@rpath/libaws_lc_fips_0_14_2_crypto.dylib "
        "(compatibility version 0.0.0, current version 0.0.0)"
    )
else:
    print(
        "\t/usr/lib/libSystem.B.dylib "
        "(compatibility version 1.0.0, current version 1356.0.0)"
        )
""",
            encoding="utf-8",
        )
        self.fake_otool.chmod(0o755)
        self.fake_install_name_tool = self.root / "install_name_tool"
        self.fake_install_name_tool.write_text(
            """#!/usr/bin/env python3
import sys
from pathlib import Path

if sys.argv[1] != "-change":
    raise SystemExit(2)
old, new, filename = sys.argv[2:]
path = Path(filename)
if path.suffix != ".dylib":
    path.with_name(path.name + ".fips-load").write_text(new + "\\n")
""",
            encoding="utf-8",
        )
        self.fake_install_name_tool.chmod(0o755)
        self.fake_codesign = self.root / "codesign"
        self.fake_codesign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_codesign.chmod(0o755)

    def build(
        self,
        group: str,
        *,
        version: str = VERSION,
        purpose: str = "review_only",
        name: str | None = None,
        fail_call: int | None = None,
        binary_version: str | None = None,
        include_casework: bool = False,
        fips_shared: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], Path, list[list[str]]]:
        stem = name or group
        output = self.root / stem
        log = self.root / f"{stem}.jsonl"
        target = self.root / f"{stem}-target"
        environment = os.environ.copy()
        environment.update(
            {
                "CARGO": str(self.fake_cargo),
                "CARGO_TARGET_DIR": str(target),
                "FAKE_CARGO_LOG": str(log),
                "FAKE_BINARY_SMOKE_LOG": str(self.root / f"{stem}-smoke.log"),
                "FAKE_VERSION": version,
                "PATH": f"{self.root}{os.pathsep}{environment['PATH']}",
            }
        )
        if fail_call is not None:
            environment["FAKE_CARGO_FAIL_CALL"] = str(fail_call)
        if binary_version is not None:
            environment["FAKE_BINARY_VERSION"] = binary_version
        parsed = tuple(int(part) for part in version.split("."))
        if fips_shared or parsed >= (0, 33, 0):
            environment["FAKE_OTOOL_FIPS_SHARED"] = "1"
        result = subprocess.run(
            [
                "bash",
                str(BUILDER),
                *(["--include-casework"] if include_casework else []),
                "--group",
                group,
                "--purpose",
                purpose,
                "--source-sha",
                SOURCE_SHA,
                "--version",
                version,
                "--output",
                str(output),
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        calls = []
        if log.exists():
            calls = [json.loads(line) for line in log.read_text().splitlines()]
        return result, output, calls

    def test_all_mode_preserves_the_exact_ordered_cargo_invocations(self) -> None:
        result, output, calls = self.build("all")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([CORE_ARGS, BREG_ARGS, BREGCTL_ARGS, CASEWORK_RUNTIME_ARGS, CASEWORKCTL_ARGS], calls)
        self.assertEqual(
            [
                *MODULE.rosters(VERSION)["core"],
                *MODULE.rosters(VERSION)["breg"],
                *MODULE.rosters(VERSION)["bregctl"],
                *MODULE.rosters(VERSION)["casework"],
            ],
            [line.split("  ", 1)[1] for line in (output / "SHA256SUMS").read_text().splitlines()],
        )

    def test_groups_partition_the_exact_calls_without_feature_union(self) -> None:
        core_result, _, core_calls = self.build("core")
        breg_result, _, breg_calls = self.build("breg")
        bregctl_result, _, bregctl_calls = self.build("bregctl")
        self.assertEqual(0, core_result.returncode, core_result.stderr)
        self.assertEqual(0, breg_result.returncode, breg_result.stderr)
        self.assertEqual(0, bregctl_result.returncode, bregctl_result.stderr)
        self.assertEqual([CORE_ARGS], core_calls)
        self.assertEqual([BREG_ARGS], breg_calls)
        self.assertEqual([BREGCTL_ARGS], bregctl_calls)
        self.assertNotIn("tooling", BREG_ARGS)
        self.assertNotIn("--features", BREGCTL_ARGS)

    def test_explicit_casework_group_builds_the_local_pre_release_candidate(self) -> None:
        result, output, calls = self.build(
            "casework", include_casework=True, name="local-casework"
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([CASEWORK_RUNTIME_ARGS, CASEWORKCTL_ARGS], calls)
        self.assertEqual(
            [
                f"casework-v{VERSION}-macos-arm64",
                f"caseworkctl-v{VERSION}-macos-arm64",
            ],
            [
                line.split("  ", 1)[1]
                for line in (output / "SHA256SUMS").read_text().splitlines()
            ],
        )

    def test_merged_groups_match_all_mode_bytes_modes_and_roster(self) -> None:
        all_result, all_output, _ = self.build("all")
        core_result, core, _ = self.build("core")
        breg_result, breg, _ = self.build("breg")
        bregctl_result, bregctl, _ = self.build("bregctl")
        casework_result, casework, _ = self.build("casework")
        for result in (all_result, core_result, breg_result, bregctl_result, casework_result):
            self.assertEqual(0, result.returncode, result.stderr)
        merged = self.root / "merged"
        MODULE.merge(
            version=VERSION,
            source_sha=SOURCE_SHA,
            purpose="review_only",
            core=core,
            breg=breg,
            bregctl=bregctl,
            casework=casework,
            output=merged,
        )
        expected = sorted(path.name for path in (all_output / "platform").iterdir())
        self.assertEqual(
            sorted(expected),
            sorted(path.name for path in (merged / "platform").iterdir()),
        )
        for name in expected:
            whole = all_output / "platform" / name
            combined = merged / "platform" / name
            self.assertEqual(whole.read_bytes(), combined.read_bytes())
            self.assertEqual(stat.S_IMODE(combined.stat().st_mode), 0o755)

    def test_mint_is_retired_only_from_v0_31_0(self) -> None:
        for version in ("0.30.0", "0.30.1"):
            with self.subTest(version=version):
                self.assertIn(
                    f"mint-v{version}-macos-arm64",
                    MODULE.rosters(version)["core"],
                )
        self.assertNotIn(
            "mint-v0.31.0-macos-arm64",
            MODULE.rosters("0.31.0")["core"],
        )

    def test_pre_breg_version_produces_and_merges_an_exact_empty_shard(self) -> None:
        version = "0.25.0"
        core_result, core, _ = self.build("core", version=version, name="old-core")
        breg_result, breg, breg_calls = self.build(
            "breg", version=version, name="old-breg"
        )
        bregctl_result, bregctl, bregctl_calls = self.build(
            "bregctl", version=version, name="old-bregctl"
        )
        casework_result, casework, casework_calls = self.build(
            "casework", version=version, name="old-casework"
        )
        self.assertEqual(0, core_result.returncode, core_result.stderr)
        self.assertEqual(0, breg_result.returncode, breg_result.stderr)
        self.assertEqual(0, bregctl_result.returncode, bregctl_result.stderr)
        self.assertEqual(0, casework_result.returncode, casework_result.stderr)
        self.assertEqual([], breg_calls)
        self.assertEqual([], bregctl_calls)
        self.assertEqual([], casework_calls)
        self.assertEqual([], list((breg / "platform").iterdir()))
        self.assertEqual([], list((bregctl / "platform").iterdir()))
        self.assertEqual([], list((casework / "platform").iterdir()))
        self.assertEqual("", (breg / "SHA256SUMS").read_text())
        self.assertEqual("", (bregctl / "SHA256SUMS").read_text())
        self.assertEqual("", (casework / "SHA256SUMS").read_text())
        # Historical recovery still requires the Mint bytes built by the old
        # release source. Current builders omit them; supply immutable fixture
        # bytes here so this tests the historical merger rather than rebuilding Mint.
        legacy_mint = core / "platform" / f"mint-v{version}-macos-arm64"
        legacy_mint.write_bytes(b"historical Mint fixture\n")
        legacy_mint.chmod(0o755)
        (core / "SHA256SUMS").write_text("".join(
            f"{digest(core / 'platform' / name)}  {name}\n"
            for name in MODULE.rosters(version)["core"]
        ))
        # Artifact upload/download does not retain empty directories.
        (breg / "platform").rmdir()
        (bregctl / "platform").rmdir()
        (casework / "platform").rmdir()
        merged = self.root / "old-merged"
        MODULE.merge(
            version=version,
            source_sha=SOURCE_SHA,
            purpose="review_only",
            core=core,
            breg=breg,
            bregctl=bregctl,
            casework=casework,
            output=merged,
        )
        self.assertEqual(
            sorted(MODULE.rosters(version)["core"]),
            sorted(path.name for path in (merged / "platform").iterdir()),
        )

    def test_build_failure_or_bad_version_smoke_exposes_no_shard(self) -> None:
        failed, failed_output, calls = self.build(
            "bregctl", fail_call=1, name="failed"
        )
        self.assertEqual(42, failed.returncode)
        self.assertEqual([BREGCTL_ARGS], calls)
        self.assertFalse(failed_output.exists())

        # Cargo succeeds and writes binaries, then the real version smoke rejects them.
        wrong, wrong_output, wrong_calls = self.build(
            "core",
            version=VERSION,
            binary_version="0.27.1",
            name="wrong-version",
        )
        self.assertNotEqual(0, wrong.returncode)
        self.assertEqual([CORE_ARGS], wrong_calls)
        self.assertEqual(
            "relayctl\n", (self.root / "wrong-version-smoke.log").read_text()
        )
        self.assertFalse(wrong_output.exists())

    def test_shared_fips_dependency_exposes_no_shard(self) -> None:
        result, output, calls = self.build(
            "breg", name="shared-fips", fips_shared=True
        )
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([BREG_ARGS], calls)
        self.assertIn("unpackaged AWS-LC-FIPS dylib", result.stderr)
        self.assertFalse(output.exists())

    def test_v0_33_packages_each_binary_with_its_fips_runtime(self) -> None:
        first, output, calls = self.build(
            "all", version=ARCHIVE_VERSION, name="archive-all"
        )
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(
            [CORE_ARGS, BREG_ARGS, BREGCTL_ARGS, CASEWORK_RUNTIME_ARGS, CASEWORKCTL_ARGS],
            calls,
        )
        expected = [
            *MODULE.rosters(ARCHIVE_VERSION)["core"],
            *MODULE.rosters(ARCHIVE_VERSION)["breg"],
            *MODULE.rosters(ARCHIVE_VERSION)["bregctl"],
            *MODULE.rosters(ARCHIVE_VERSION)["casework"],
        ]
        self.assertEqual(
            expected,
            [
                line.split("  ", 1)[1]
                for line in (output / "SHA256SUMS").read_text().splitlines()
            ],
        )
        self.assertTrue(all(name.endswith(".tar.gz") for name in expected))
        self.assertTrue(
            (output / "RELEASE_NATIVE_PLATFORM_SHARD")
            .read_text()
            .startswith("registry-stack.release-native-platform-shard.v2\n")
        )
        asset = expected[0]
        executable = asset.removesuffix(".tar.gz")
        with tarfile.open(output / "platform" / asset, "r:gz") as package:
            self.assertEqual(
                [
                    executable,
                    "libaws_lc_fips_0_14_2_crypto.dylib",
                    "THIRD_PARTY_NOTICES",
                ],
                package.getnames(),
            )

        second, repeated, _ = self.build(
            "all", version=ARCHIVE_VERSION, name="archive-repeat"
        )
        self.assertEqual(0, second.returncode, second.stderr)
        for name in expected:
            self.assertEqual(
                (output / "platform" / name).read_bytes(),
                (repeated / "platform" / name).read_bytes(),
            )

        shards = {}
        for group in ("core", "breg", "bregctl", "casework"):
            result, shard, _ = self.build(
                group, version=ARCHIVE_VERSION, name=f"archive-{group}"
            )
            self.assertEqual(0, result.returncode, result.stderr)
            shards[group] = shard
        merged = self.root / "archive-merged"
        MODULE.merge(
            version=ARCHIVE_VERSION,
            source_sha=SOURCE_SHA,
            purpose="review_only",
            core=shards["core"],
            breg=shards["breg"],
            bregctl=shards["bregctl"],
            casework=shards["casework"],
            output=merged,
        )
        self.assertEqual(
            sorted(expected),
            sorted(path.name for path in (merged / "platform").iterdir()),
        )
        for name in expected:
            self.assertEqual(0o644, stat.S_IMODE((merged / "platform" / name).stat().st_mode))

    def test_merge_rejects_invalid_inputs_before_exposing_output(self) -> None:
        mutations = {
            "missing": lambda root: next((root / "platform").iterdir()).unlink(),
            "unexpected": lambda root: (root / "platform" / "extra").write_text("x"),
            "unexpected-root": lambda root: (root / "extra").write_text("x"),
            "duplicate-checksum": lambda root: (root / "SHA256SUMS").write_text(
                (root / "SHA256SUMS").read_text()
                + (root / "SHA256SUMS").read_text().splitlines(keepends=True)[0]
            ),
            "corrupt": lambda root: next((root / "platform").iterdir()).write_text("bad"),
            "nonregular": lambda root: self._replace_with_symlink(
                next((root / "platform").iterdir())
            ),
            "source": lambda root: (root / "RELEASE_NATIVE_PLATFORM_SHARD").write_text(
                (root / "RELEASE_NATIVE_PLATFORM_SHARD")
                .read_text()
                .replace(SOURCE_SHA, "2" * 40)
            ),
            "version": lambda root: (root / "RELEASE_NATIVE_PLATFORM_SHARD").write_text(
                (root / "RELEASE_NATIVE_PLATFORM_SHARD")
                .read_text()
                .replace(f"version={VERSION}", "version=0.28.0")
            ),
            "purpose": lambda root: (root / "RELEASE_NATIVE_PLATFORM_SHARD").write_text(
                (root / "RELEASE_NATIVE_PLATFORM_SHARD")
                .read_text()
                .replace("purpose=review_only", "purpose=candidate_input")
            ),
            "target": lambda root: (root / "RELEASE_NATIVE_PLATFORM_SHARD").write_text(
                (root / "RELEASE_NATIVE_PLATFORM_SHARD")
                .read_text()
                .replace(TARGET, "x86_64-apple-darwin")
            ),
            "builder": lambda root: (root / "RELEASE_NATIVE_PLATFORM_SHARD").write_text(
                (root / "RELEASE_NATIVE_PLATFORM_SHARD")
                .read_text()
                .replace("rust_toolchain=1.95.0", "rust_toolchain=1.94.0")
            ),
            "group": lambda root: (root / "RELEASE_NATIVE_PLATFORM_SHARD").write_text(
                (root / "RELEASE_NATIVE_PLATFORM_SHARD")
                .read_text()
                .replace("group=core", "group=breg")
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                core_result, core, _ = self.build("core", name=f"{name}-core")
                breg_result, breg, _ = self.build("breg", name=f"{name}-breg")
                bregctl_result, bregctl, _ = self.build(
                    "bregctl", name=f"{name}-bregctl"
                )
                casework_result, casework, _ = self.build(
                    "casework", name=f"{name}-casework"
                )
                self.assertEqual(0, core_result.returncode, core_result.stderr)
                self.assertEqual(0, breg_result.returncode, breg_result.stderr)
                self.assertEqual(0, bregctl_result.returncode, bregctl_result.stderr)
                self.assertEqual(0, casework_result.returncode, casework_result.stderr)
                mutate(core)
                output = self.root / f"{name}-merged"
                with self.assertRaises(MODULE.ShardError):
                    MODULE.merge(
                        version=VERSION,
                        source_sha=SOURCE_SHA,
                        purpose="review_only",
                        core=core,
                        breg=breg,
                        bregctl=bregctl,
                        casework=casework,
                        output=output,
                    )
                self.assertFalse(output.exists())

    @staticmethod
    def _replace_with_symlink(path: Path) -> None:
        path.unlink()
        path.symlink_to("missing")

    def test_rejects_invalid_cli_bindings(self) -> None:
        for arguments in (
            ["--group", "other"],
            ["--purpose", "publishable"],
            ["--source-sha", "abc"],
            ["--source-sha", "1" * 40],
            ["--version", "01.2.3"],
        ):
            with self.subTest(arguments=arguments):
                base = {
                    "--group": "core",
                    "--purpose": "review_only",
                    "--source-sha": SOURCE_SHA,
                    "--version": VERSION,
                }
                base[arguments[0]] = arguments[1]
                command = ["bash", str(BUILDER)]
                for key, value in base.items():
                    command.extend((key, value))
                command.extend(("--output", str(self.root / "invalid")))
                result = subprocess.run(command, text=True, capture_output=True, check=False)
                self.assertEqual(2, result.returncode)
                self.assertFalse((self.root / "invalid").exists())


if __name__ == "__main__":
    unittest.main()
