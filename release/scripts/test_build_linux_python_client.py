#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "release/scripts/build-linux-python-client"
COMPILER = ROOT / "release/scripts/zig-glibc-compiler"
FLOOR = ROOT / "release/glibc-floor.env"


class BuildLinuxPythonClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        scripts = self.root / "release/scripts"
        scripts.mkdir(parents=True)
        for source in (BUILD, COMPILER):
            destination = scripts / source.name
            shutil.copy2(source, destination)
            destination.chmod(0o755)
        shutil.copy2(FLOOR, self.root / "release" / FLOOR.name)
        self.build = scripts / BUILD.name

        self.log = self.root / "maturin.json"
        self.zig_log = self.root / "zig.jsonl"
        tool_dir = self.root / "maturin"
        tool_dir.mkdir()
        self.python = tool_dir / "python"
        self.python.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "if sys.argv[1:] == ['-m', 'ziglang', 'version']:\n"
            "    print(os.environ.get('ZIG_VERSION', '0.12.1'))\n"
            "    raise SystemExit\n"
            "with open(os.environ['ZIG_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n",
            encoding="utf-8",
        )
        self.python.chmod(0o755)
        self.maturin = tool_dir / "maturin"
        self.maturin.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, subprocess, sys\n"
            "selected = {key: value for key, value in os.environ.items() if "
            "key in {'HOST_CC', 'HOST_CXX', 'TARGET_CC', 'TARGET_CXX', "
            "'CARGO_PROFILE_CI_OPT_LEVEL'} or "
            "key.startswith('CC_') or key.startswith('CXX_') or "
            "key.startswith('CARGO_TARGET_')}\n"
            "pathlib.Path(os.environ['MATURIN_LOG']).write_text(json.dumps({"
            "'args': sys.argv[1:], 'cwd': os.getcwd(), 'env': selected}), "
            "encoding='utf-8')\n"
            "subprocess.run([os.environ['HOST_CC'], '-S', '-MD', '-MT', "
            "'bcm.c.o', '-MF', 'bcm.c.o.d', '-o', 'bcm.c.o', '-c', 'bcm.c'], "
            "check=True)\n",
            encoding="utf-8",
        )
        self.maturin.chmod(0o755)
        self.output = self.root / "wheels"
        self.output.mkdir()
        self.env = {
            **os.environ,
            "RUNNER_TEMP": str(self.root / "runner"),
            "MATURIN_LOG": str(self.log),
            "ZIG_LOG": str(self.zig_log),
        }
        Path(self.env["RUNNER_TEMP"]).mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_client(self, client: str = "evidence") -> None:
        client_dir = self.root / f"crates/registry-{client}-client-py"
        client_dir.mkdir(parents=True)
        (client_dir / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    def run_build(
        self,
        *,
        client: str = "evidence",
        target: str = "aarch64-unknown-linux-gnu",
        compatibility: str = "manylinux_2_17",
        profile: str = "release",
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.build),
                "--client",
                client,
                "--target",
                target,
                "--compatibility",
                compatibility,
                "--zig-python",
                str(self.python),
                "--maturin",
                str(self.maturin),
                "--out",
                str(self.output),
                "--profile",
                profile,
            ],
            cwd=self.root,
            env=env or self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_manylinux_build_uses_corrected_compiler_and_keeps_audit(self) -> None:
        self.make_client()
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = json.loads(self.log.read_text())
        self.assertEqual(
            invocation["args"],
            [
                "build",
                "--release",
                "--locked",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--compatibility",
                "manylinux_2_17",
                "--out",
                str(self.output),
            ],
        )
        self.assertNotIn("--zig", invocation["args"])
        self.assertEqual(
            Path(invocation["cwd"]).resolve(),
            (self.root / "crates/registry-evidence-client-py").resolve(),
        )
        env = invocation["env"]
        cc = env["HOST_CC"]
        self.assertEqual(env["TARGET_CC"], cc)
        self.assertEqual(env["CC_aarch64_unknown_linux_gnu"], cc)
        self.assertEqual(
            env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"], cc
        )
        calls = [json.loads(line) for line in self.zig_log.read_text().splitlines()]
        prefix = [
            "-m",
            "ziglang",
            "cc",
            "-target",
            "aarch64-linux-gnu.2.17",
        ]
        self.assertEqual(calls[0][0:5], prefix)
        self.assertIn("-E", calls[0])
        self.assertEqual(calls[1][0:5], prefix)
        self.assertIn("-S", calls[1])

    def test_ci_profile_and_linux_compatibility_are_forwarded(self) -> None:
        self.make_client("discovery")
        result = self.run_build(
            client="discovery",
            target="x86_64-unknown-linux-gnu",
            compatibility="linux",
            profile="ci",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        invocation = json.loads(self.log.read_text())
        self.assertEqual(invocation["args"][0:4], ["build", "--profile", "ci", "--locked"])
        self.assertIn("x86_64-unknown-linux-gnu", invocation["args"])
        self.assertIn("linux", invocation["args"])
        self.assertIn("CC_x86_64_unknown_linux_gnu", invocation["env"])
        self.assertEqual(invocation["env"]["CARGO_PROFILE_CI_OPT_LEVEL"], "1")

    def test_reuses_compiler_paths_for_all_products(self) -> None:
        compilers = []
        for client in ("discovery", "evidence", "relay", "breg", "casework"):
            self.make_client(client)
            result = self.run_build(client=client)
            self.assertEqual(result.returncode, 0, result.stderr)
            compilers.append(json.loads(self.log.read_text())["env"]["HOST_CC"])
        self.assertEqual(len(set(compilers)), 1)

    def test_rejects_unpinned_zig_and_unsupported_inputs(self) -> None:
        self.make_client()
        unpinned = self.run_build(env={**self.env, "ZIG_VERSION": "0.13.0"})
        self.assertEqual(unpinned.returncode, 2)
        self.assertIn("hash-pinned ziglang 0.12.1", unpinned.stderr)
        self.assertFalse(self.log.exists())

        bad_target = self.run_build(target="powerpc64-unknown-linux-gnu")
        self.assertEqual(bad_target.returncode, 2)
        self.assertIn("unsupported Linux Python target", bad_target.stderr)
        bad_compatibility = self.run_build(compatibility="manylinux_2_28")
        self.assertEqual(bad_compatibility.returncode, 2)
        self.assertIn("compatibility must be linux or manylinux_2_17", bad_compatibility.stderr)


if __name__ == "__main__":
    unittest.main()
