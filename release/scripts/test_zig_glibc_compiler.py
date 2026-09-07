#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPILER = ROOT / "release/scripts/zig-glibc-compiler"
BINARY_RECIPE = ROOT / "release/scripts/build-release-binaries.sh"


def product_glibc_floor() -> str:
    """The release floor the product binaries are built to, read from its home."""
    text = (ROOT / "release/glibc-floor.env").read_text(encoding="utf-8")
    match = re.search(r"^REGISTRY_GLIBC_FLOOR=([0-9]+\.[0-9]+)$", text, re.MULTILINE)
    assert match, "release/glibc-floor.env declares REGISTRY_GLIBC_FLOOR"
    return match.group(1)


class ZigGlibcCompilerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.log = self.root / "zig.jsonl"
        self.python = self.root / "python"
        self.python.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['ZIG_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        self.python.chmod(0o755)
        self.cc = self.root / "zig-cc"
        self.cxx = self.root / "zig-cxx"
        self.cc.symlink_to(COMPILER)
        self.cxx.symlink_to(COMPILER)
        self.env = {
            **os.environ,
            "REGISTRY_ZIG_PYTHON": str(self.python),
            "REGISTRY_ZIG_TARGET": "aarch64-linux-gnu.2.17",
            "ZIG_LOG": str(self.log),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_wrapper(
        self, wrapper: Path, *arguments: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(wrapper), *arguments],
            env=env or self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def logged_calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_dispatches_both_drivers_and_strips_only_incoming_targets(self) -> None:
        cc = self.run_wrapper(
            self.cc,
            "--target=aarch64-unknown-linux-gnu",
            "--target",
            "ignored-one",
            "-target",
            "ignored-two",
            "-O3",
            "source file.c",
            "-o",
            "output file.o",
        )
        cxx = self.run_wrapper(self.cxx, "-std=c++17", "source.cc")
        self.assertEqual(cc.returncode, 0, cc.stderr)
        self.assertEqual(cxx.returncode, 0, cxx.stderr)
        self.assertEqual(
            self.logged_calls(),
            [
                [
                    "-m",
                    "ziglang",
                    "cc",
                    "-target",
                    "aarch64-linux-gnu.2.17",
                    "-O3",
                    "source file.c",
                    "-o",
                    "output file.o",
                ],
                [
                    "-m",
                    "ziglang",
                    "c++",
                    "-target",
                    "aarch64-linux-gnu.2.17",
                    "-std=c++17",
                    "source.cc",
                ],
            ],
        )

    def test_approves_the_product_release_floor_on_both_architectures(self) -> None:
        """The product binaries are built to the floor release/glibc-floor.env holds."""
        floor = product_glibc_floor()
        for architecture in ("x86_64", "aarch64"):
            with self.subTest(architecture=architecture):
                target = f"{architecture}-linux-gnu.{floor}"
                result = self.run_wrapper(
                    self.cc,
                    "source.c",
                    env={**self.env, "REGISTRY_ZIG_TARGET": target},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [call[:5] for call in self.logged_calls()],
            [
                ["-m", "ziglang", "cc", "-target", f"x86_64-linux-gnu.{floor}"],
                ["-m", "ziglang", "cc", "-target", f"aarch64-linux-gnu.{floor}"],
            ],
        )

    def test_approves_targets_without_a_pipeline(self) -> None:
        """cc-rs runs the wrapper hundreds of times in parallel. Under pipefail a
        pipeline into grep -q fails whenever grep matches and exits before bash's
        line-buffered printf has written every candidate (SIGPIPE), which rejects
        an approved target in about one compile per hundred under CPU contention.
        The approval check is a plain comparison, never a pipeline."""
        text = COMPILER.read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"\|\s*grep\b", text), "target approval pipes into grep"
        )

    def test_rejects_unapproved_or_ambiguous_configuration(self) -> None:
        cases = (
            (COMPILER, (), self.env, "must be invoked"),
            (
                self.cc,
                (),
                {**self.env, "REGISTRY_ZIG_TARGET": "aarch64-linux-gnu.2.28"},
                "must name an approved target",
            ),
            (
                self.cc,
                (),
                {**self.env, "REGISTRY_ZIG_PYTHON": "python3"},
                "absolute executable",
            ),
            (self.cc, ("--target",), self.env, "requires a target argument"),
            (self.cc, ("-target=override",), self.env, "unsupported target selector"),
        )
        for wrapper, arguments, env, message in cases:
            with self.subTest(message=message):
                result = self.run_wrapper(wrapper, *arguments, env=env)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)


class CanonicalCompilerIdentityTest(unittest.TestCase):
    """Exercise the recipe's real setup and build calls without compiling Rust."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        for relative in (
            "rust-toolchain.toml",
            "Cargo.lock",
            "release/scripts/build-release-binaries.sh",
            "release/scripts/merge-release-binary-shards.py",
            "release/docker/Dockerfile.builder",
            "release/requirements/ziglang-0.12.1.txt",
            "release/glibc-floor.env",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        self.scripts = self.root / "release/scripts"
        # Stand in for Zig itself; the wrapper's real dispatch and argument
        # validation have their own tests above. Include a fixture identity so
        # independent test processes do not claim each other's /tmp directory.
        compiler = self.scripts / "zig-glibc-compiler"
        compiler.write_text(
            "#!/usr/bin/env python3\n"
            f"# fixture {self.root.name}\n"
            "import json, os, sys\n"
            "print(json.dumps([os.path.basename(sys.argv[0]), "
            "os.environ['REGISTRY_ZIG_TARGET'], *sys.argv[1:]]))\n",
            encoding="utf-8",
        )
        compiler.chmod(0o755)
        gate = self.scripts / "check-glibc-floor.sh"
        gate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        gate.chmod(0o755)
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        cargo = self.fake_bin / "cargo"
        cargo.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, subprocess, sys\n"
            "names = ['HOST_CC', 'HOST_CXX', 'TARGET_CC', 'TARGET_CXX', "
            "'REGISTRY_ZIG_PYTHON', 'REGISTRY_ZIG_TARGET', 'RUSTFLAGS', "
            "'ZIG_GLOBAL_CACHE_DIR', 'ZIG_LOCAL_CACHE_DIR']\n"
            "names += [name for name in os.environ if "
            "name.startswith(('CC_', 'CXX_', 'CARGO_TARGET_'))]\n"
            "record = {'args': sys.argv[1:], "
            "'env': {name: os.environ[name] for name in names}}\n"
            "record['drivers'] = [json.loads(subprocess.check_output("
            "[os.environ[name], '-c', 'probe.c'], text=True)) "
            "for name in ('HOST_CC', 'HOST_CXX')]\n"
            "with open(os.environ['CARGO_LOG'], 'a') as log:\n"
            "    log.write(json.dumps(record) + '\\n')\n"
            "if os.environ.get('FAIL_CARGO'):\n"
            "    sys.exit(7)\n"
            "target = pathlib.Path('target/release')\n"
            "target.mkdir(parents=True, exist_ok=True)\n"
            "for binary in ('registry-manifest', 'relay', 'relayctl', 'evidence', "
            "'evidencectl', 'mint', 'evidence-oid4vci', 'discovery', 'breg', 'bregctl'):\n"
            "    (target / binary).write_text('fixture binary\\n')\n",
            encoding="utf-8",
        )
        cargo.chmod(0o755)
        docker = self.fake_bin / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['DOCKER_LOG'], 'a') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[0] != 'run':\n"
            "    sys.exit(0)\n"
            "version = args[-1]\n"
            "group = args[-2] if args[-3] == '--group' else 'all'\n"
            "tag = 'v' + version\n"
            "root = pathlib.Path(os.environ['FIXTURE_ROOT'])\n"
            "bin_dir = root / 'dist/bin'\n"
            "image_dir = root / 'dist/image-bin'\n"
            "parsed = tuple(int(part) for part in version.split('.'))\n"
            "core = ['evidence', 'evidencectl', 'mint', 'evidence-oid4vci', "
            "'registry-manifest', 'relay', 'relayctl']\n"
            "if parsed >= (0, 24, 0):\n"
            "    core.insert(0, 'discovery')\n"
            "breg = ['breg', 'bregctl'] if parsed >= (0, 26, 0) else []\n"
            "selected = (core if group in ('all', 'core') else []) + "
            "(breg if group in ('all', 'breg') else [])\n"
            "for name in selected:\n"
            "    (bin_dir / f'{name}-{tag}-linux-amd64').write_text(name + '\\n')\n"
            "for name in ('discovery', 'breg', 'evidence', 'mint', 'relay'):\n"
            "    if name in selected:\n"
            "        (image_dir / name).write_text(name + '\\n')\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
        uname = self.fake_bin / "uname"
        uname.write_text('#!/bin/sh\nprintf "%s\\n" "$FIXTURE_MACHINE"\n')
        uname.chmod(0o755)
        self.log = self.root / "cargo.jsonl"
        self.docker_log = self.root / "docker.jsonl"
        self.env = {
            **os.environ,
            "PATH": f"{self.fake_bin}:{os.environ.get('PATH', '')}",
            "CARGO_LOG": str(self.log),
            "DOCKER_LOG": str(self.docker_log),
            "FIXTURE_ROOT": str(self.root),
            "FIXTURE_MACHINE": "x86_64",
            "RELEASE_RUSTFLAGS": "--remap-path-prefix=/workspace=/source",
        }
        for relative in ("dist/bin", "dist/image-bin"):
            (self.root / relative).mkdir(parents=True)

    def run_payload(
        self,
        *,
        version: str = "0.27.0",
        group: str = "all",
        env: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
        # Load the actual functions, stopping before Docker's outer entry
        # point. This keeps the fixture unprivileged and runs every real Cargo
        # invocation and staging copy. Cargo, the compiler, and the final
        # glibc gate use fixtures; glibc enforcement has its own tests.
        recipe = (self.scripts / BINARY_RECIPE.name).read_text(encoding="utf-8")
        definitions = recipe.split("\n# The outer invocation prepares", 1)[0]
        probe = self.scripts / "probe-build.sh"
        probe.write_text(definitions + '\nRELEASE_TAG="$tag"\nbuild_payload\n')
        self.log.unlink(missing_ok=True)
        for relative in ("dist/bin", "dist/image-bin"):
            directory = self.root / relative
            shutil.rmtree(directory)
            directory.mkdir()
        arguments = ["bash", str(probe)]
        if group != "all":
            arguments.extend(["--group", group])
        arguments.append(version)
        result = subprocess.run(
            arguments,
            cwd=self.root,
            env=env or self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        calls = (
            [json.loads(line) for line in self.log.read_text().splitlines()]
            if self.log.exists()
            else []
        )
        return result, calls

    def successful_paths(
        self, *, version: str = "0.27.0", env: dict[str, str] | None = None
    ) -> dict[str, str]:
        result, calls = self.run_payload(version=version, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 7)
        paths = calls[0]["env"]
        for call in calls:
            self.assertEqual(call["env"], paths)
            self.assertEqual(call["args"][:3], ["build", "--release", "--locked"])
            self.assertEqual(
                call["drivers"],
                [
                    [driver, paths["REGISTRY_ZIG_TARGET"], "-c", "probe.c"]
                    for driver in ("zig-cc", "zig-cxx")
                ],
            )
        wrapper = Path(paths["HOST_CC"]).parent
        self.assertEqual(wrapper.parent, Path("/tmp"))
        self.assertFalse(wrapper.exists(), "the recipe cleans only its owned directory")
        for variable in ("ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR"):
            self.assertEqual(Path(paths[variable]).parent, wrapper)
        self.assertEqual(paths["RUSTFLAGS"], self.env["RELEASE_RUSTFLAGS"])
        self.assertEqual(paths["REGISTRY_ZIG_PYTHON"], "/usr/bin/python3")
        return paths

    def test_full_and_group_builds_keep_the_exact_cargo_partition(self) -> None:
        expected = [
            ["build", "--release", "--locked", "-p", "registry-manifest-cli"],
            [
                "build",
                "--release",
                "--locked",
                "-p",
                "registry-relay-v2",
                "--bin",
                "relay",
                "--no-default-features",
            ],
            ["build", "--release", "--locked", "-p", "registry-relayctl"],
            [
                "build",
                "--release",
                "--locked",
                "-p",
                "registry-evidence",
                "-p",
                "registry-evidencectl",
                "-p",
                "registry-mint",
                "-p",
                "registry-evidence-oid4vci",
            ],
            [
                "build",
                "--release",
                "--locked",
                "-p",
                "registry-discovery",
                "--bin",
                "discovery",
            ],
            [
                "build",
                "--release",
                "--locked",
                "-p",
                "registry-breg",
                "--bin",
                "breg",
                "--features",
                "runtime",
            ],
            ["build", "--release", "--locked", "-p", "registry-bregctl"],
        ]
        for group, calls_expected in (
            ("all", expected),
            ("core", expected[:5]),
            ("breg", expected[5:]),
        ):
            with self.subTest(group=group):
                result, calls = self.run_payload(group=group)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls_expected, [call["args"] for call in calls])
        self.assertNotIn("tooling", str(expected))

    def test_group_builds_keep_the_release_version_gates(self) -> None:
        result, core = self.run_payload(version="0.23.9", group="core")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(4, len(core))
        self.assertFalse(any("registry-discovery" in call["args"] for call in core))
        result, breg = self.run_payload(version="0.25.9", group="breg")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([], breg)

    def test_outer_builder_dispatches_each_group_with_canonical_container_paths(
        self,
    ) -> None:
        for group in ("all", "core", "breg"):
            with self.subTest(group=group):
                self.docker_log.unlink(missing_ok=True)
                arguments = ["bash", str(self.scripts / BINARY_RECIPE.name)]
                if group != "all":
                    arguments.extend(["--group", group])
                arguments.append("0.27.0")
                result = subprocess.run(
                    arguments,
                    cwd=self.root,
                    env={
                        **self.env,
                        "RELEASE_CARGO_HOME": str(self.root / ".cargo-home"),
                        "RELEASE_TARGET_DIR": str(self.root / "target"),
                        "RELEASE_SOURCE_SHA": "1" * 40,
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [
                    json.loads(line) for line in self.docker_log.read_text().splitlines()
                ]
                self.assertEqual(["build", "run"], [call[0] for call in calls])
                run = calls[1]
                self.assertIn(f"{self.root}:/workspace", run)
                self.assertIn(f"{self.root / '.cargo-home'}:/workspace/.cargo-home", run)
                self.assertIn(f"{self.root / 'target'}:/workspace/target", run)
                self.assertIn("CARGO_HOME=/workspace/.cargo-home", run)
                self.assertIn("CARGO_TARGET_DIR=/workspace/target", run)
                self.assertEqual(
                    [
                        "/workspace/release/scripts/build-release-binaries.sh",
                        "--group",
                        group,
                        "0.27.0",
                    ],
                    run[-4:],
                )
                if group == "all":
                    self.assertFalse((self.root / "dist/RELEASE_BINARY_SHARD").exists())
                else:
                    self.assertIn(
                        f"group={group}\n",
                        (self.root / "dist/RELEASE_BINARY_SHARD").read_text(),
                    )

    def test_pre_breg_empty_producer_merges_with_the_core_shard(self) -> None:
        source_sha = "1" * 40
        shard_root = self.root / "downloaded"
        for group in ("core", "breg"):
            result = subprocess.run(
                [
                    "bash",
                    str(self.scripts / BINARY_RECIPE.name),
                    "--group",
                    group,
                    "0.25.0",
                ],
                cwd=self.root,
                env={
                    **self.env,
                    "RELEASE_CARGO_HOME": str(self.root / f".cargo-home-{group}"),
                    "RELEASE_TARGET_DIR": str(self.root / f"target-{group}"),
                    "RELEASE_SOURCE_SHA": source_sha,
                },
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            destination = shard_root / group
            destination.mkdir(parents=True)
            shutil.copytree(self.root / "dist/bin", destination / "bin")
            for marker in ("RELEASE_BINARY_SHARD", "RELEASE_BUILDER_IMAGE"):
                shutil.copy2(self.root / "dist" / marker, destination / marker)
        self.assertEqual(
            "", (shard_root / "breg/bin/SHA256SUMS").read_text(encoding="utf-8")
        )
        output = self.root / "merged"
        result = subprocess.run(
            [
                str(self.scripts / "merge-release-binary-shards.py"),
                "--version",
                "0.25.0",
                "--source-sha",
                source_sha,
                "--core",
                str(shard_root / "core"),
                "--breg",
                str(shard_root / "breg"),
                "--output",
                str(output),
                "--builder-image",
                "rust:1.95-trixie@sha256:"
                "f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(path.name.startswith("breg-") for path in (output / "bin").iterdir()))

    def test_merged_groups_are_byte_mode_and_inventory_equivalent_to_all(self) -> None:
        source_sha = "1" * 40

        def build(group: str, version: str = "0.27.0") -> subprocess.CompletedProcess[str]:
            arguments = ["bash", str(self.scripts / BINARY_RECIPE.name)]
            if group != "all":
                arguments.extend(["--group", group])
            arguments.append(version)
            return subprocess.run(
                arguments,
                cwd=self.root,
                env={
                    **self.env,
                    "RELEASE_CARGO_HOME": str(self.root / f"cargo-{group}"),
                    "RELEASE_TARGET_DIR": str(self.root / f"target-{group}"),
                    "RELEASE_SOURCE_SHA": source_sha,
                },
                capture_output=True,
                text=True,
                check=False,
            )

        result = build("all")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = self.root / "expected"
        shutil.copytree(self.root / "dist/bin", expected / "bin")
        shutil.copytree(self.root / "dist/image-bin", expected / "image-bin")

        shards = self.root / "shards"
        for group in ("core", "breg"):
            result = build(group)
            self.assertEqual(result.returncode, 0, result.stderr)
            destination = shards / group
            destination.mkdir(parents=True)
            shutil.copytree(self.root / "dist/bin", destination / "bin")
            for marker in ("RELEASE_BINARY_SHARD", "RELEASE_BUILDER_IMAGE"):
                shutil.copy2(self.root / "dist" / marker, destination / marker)

        output = self.root / "merged-groups"
        result = subprocess.run(
            [
                str(self.scripts / "merge-release-binary-shards.py"),
                "--version",
                "0.27.0",
                "--source-sha",
                source_sha,
                "--core",
                str(shards / "core"),
                "--breg",
                str(shards / "breg"),
                "--output",
                str(output),
                "--builder-image",
                "rust:1.95-trixie@sha256:"
                "f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        expected_paths = sorted(
            path.relative_to(expected) for path in expected.rglob("*") if path.is_file()
        )
        actual_paths = sorted(
            path.relative_to(output) for path in output.rglob("*") if path.is_file()
        )
        self.assertEqual(expected_paths, actual_paths)
        for relative in expected_paths:
            with self.subTest(path=str(relative)):
                expected_path = expected / relative
                actual_path = output / relative
                self.assertEqual(expected_path.read_bytes(), actual_path.read_bytes())
                self.assertEqual(
                    stat.S_IMODE(expected_path.stat().st_mode),
                    stat.S_IMODE(actual_path.stat().st_mode),
                )

    def test_identical_recipe_and_lock_update_keep_compiler_paths(self) -> None:
        first = self.successful_paths()
        self.assertEqual(first, self.successful_paths())
        (self.root / "Cargo.lock").write_text("# another release's lockfile\n")
        self.assertEqual(first, self.successful_paths(version="0.28.0"))
        for variable in (
            "TARGET_CC",
            "CC_x86_64_unknown_linux_gnu",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
        ):
            self.assertEqual(first[variable], first["HOST_CC"])
        for variable in ("TARGET_CXX", "CXX_x86_64_unknown_linux_gnu"):
            self.assertEqual(first[variable], first["HOST_CXX"])

    def test_changed_compiler_recipe_and_floor_change_compiler_paths(self) -> None:
        first = self.successful_paths()
        for relative in (
            "rust-toolchain.toml",
            "release/scripts/build-release-binaries.sh",
            "release/docker/Dockerfile.builder",
            "release/requirements/ziglang-0.12.1.txt",
            "release/scripts/zig-glibc-compiler",
            "release/glibc-floor.env",
        ):
            with self.subTest(input=relative):
                path = self.root / relative
                original = path.read_text()
                path.write_text(original + "\n# changed compiler input\n")
                try:
                    self.assertNotEqual(
                        first["HOST_CC"], self.successful_paths()["HOST_CC"]
                    )
                finally:
                    path.write_text(original)
        floor = self.root / "release/glibc-floor.env"
        floor.write_text("REGISTRY_GLIBC_FLOOR=2.36\n")
        changed = self.successful_paths()
        self.assertNotEqual(first["HOST_CC"], changed["HOST_CC"])
        self.assertEqual(changed["REGISTRY_ZIG_TARGET"], "x86_64-linux-gnu.2.36")
        arm = self.successful_paths(env={**self.env, "FIXTURE_MACHINE": "aarch64"})
        self.assertNotEqual(changed["HOST_CC"], arm["HOST_CC"])

    def test_occupied_directory_and_symlink_fail_without_cleanup_or_build(self) -> None:
        wrapper = Path(self.successful_paths()["HOST_CC"]).parent
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                if symlink:
                    wrapper.symlink_to(self.root, target_is_directory=True)
                else:
                    wrapper.mkdir()
                    (wrapper / "sentinel").write_text("keep")
                try:
                    result, calls = self.run_payload()
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(
                        "cannot create canonical compiler directory", result.stderr
                    )
                    self.assertEqual(calls, [])
                    self.assertTrue(wrapper.exists())
                    if symlink:
                        self.assertEqual(wrapper.readlink(), self.root)
                    else:
                        self.assertEqual((wrapper / "sentinel").read_text(), "keep")
                finally:
                    if symlink:
                        wrapper.unlink()
                    else:
                        shutil.rmtree(wrapper)

    def test_failed_cargo_still_cleans_owned_directory(self) -> None:
        result, calls = self.run_payload(env={**self.env, "FAIL_CARGO": "1"})
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertFalse(Path(calls[0]["env"]["HOST_CC"]).parent.exists())


if __name__ == "__main__":
    unittest.main()
