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
BUILD = ROOT / "release/scripts/build-linux-node-client"
COMPILER = ROOT / "release/scripts/zig-glibc-compiler"


class BuildLinuxNodeClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        scripts = self.root / "release/scripts"
        scripts.mkdir(parents=True)
        for source in (BUILD, COMPILER):
            destination = scripts / source.name
            shutil.copy2(source, destination)
            destination.chmod(0o755)
        self.build = scripts / BUILD.name

        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.zig_log = self.root / "zig.jsonl"
        self.napi_log = self.root / "napi.json"
        self.python = self.root / "maturin/bin/python"
        self.python.parent.mkdir(parents=True)
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

        readelf = self.bin / "readelf"
        readelf.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "if [[ \"$1\" == --wide ]]; then\n"
            "  case \"${READELF_MODE:-valid}\" in\n"
            "    strong) symbol='malloc' ;;\n"
            "    *) symbol='napi_create_function' ;;\n"
            "  esac\n"
            "  printf '  1: 0 0 FUNC GLOBAL DEFAULT UND %s\\n' \"$symbol\"\n"
            "else\n"
            "  printf 'Version needs section: %s\\n' \"${READELF_GLIBC:-GLIBC_2.17}\"\n"
            "fi\n",
            encoding="utf-8",
        )
        readelf.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "RUNNER_TEMP": str(self.root / "runner"),
            "ZIG_LOG": str(self.zig_log),
            "NAPI_LOG": str(self.napi_log),
        }
        Path(self.env["RUNNER_TEMP"]).mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_client(self, client: str, target: str, platform: str) -> Path:
        client_dir = self.root / f"crates/registry-{client}-client-node"
        napi = client_dir / "node_modules/.bin/napi"
        napi.parent.mkdir(parents=True)
        (client_dir / "package.json").write_text("{}\n", encoding="utf-8")
        napi.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, subprocess, sys\n"
            "target = sys.argv[sys.argv.index('--target') + 1]\n"
            "client = pathlib.Path.cwd().name.removeprefix('registry-').removesuffix('-node')\n"
            f"platform = {platform!r}\n"
            "selected = {key: value for key, value in os.environ.items() if "
            "key in {'HOST_CC', 'HOST_CXX', 'TARGET_CC', 'TARGET_CXX'} or "
            "key.startswith('CC_') or key.startswith('CXX_') or "
            "key.startswith('CARGO_TARGET_')}\n"
            "pathlib.Path(os.environ['NAPI_LOG']).write_text(json.dumps({"
            "'args': sys.argv[1:], 'env': selected}), encoding='utf-8')\n"
            "subprocess.run([os.environ['HOST_CC'], f'--target={target}', "
            "'--target', target, '-target', target, '-O3', 'source.c'], check=True)\n"
            "subprocess.run([os.environ['HOST_CXX'], '-std=c++17', 'source.cc'], check=True)\n"
            "pathlib.Path(f'{client}.{platform}.node').touch()\n",
            encoding="utf-8",
        )
        napi.chmod(0o755)
        return client_dir

    def run_build(
        self,
        client: str = "evidence",
        target: str = "aarch64-unknown-linux-gnu",
        platform: str = "linux-arm64-gnu",
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.build),
                "--client",
                client,
                "--target",
                target,
                "--napi-platform",
                platform,
                "--zig-python",
                str(self.python),
            ],
            cwd=self.root,
            env=env or self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_routes_every_compiler_and_linker_through_exact_zig_target(self) -> None:
        self.make_client("evidence", "aarch64-unknown-linux-gnu", "linux-arm64-gnu")
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        napi = json.loads(self.napi_log.read_text())
        self.assertEqual(
            napi["args"],
            [
                "build",
                "--platform",
                "--release",
                "--target",
                "aarch64-unknown-linux-gnu",
            ],
        )
        self.assertNotIn("--use-napi-cross", napi["args"])
        env = napi["env"]
        cc = env["HOST_CC"]
        cxx = env["HOST_CXX"]
        self.assertEqual(env["TARGET_CC"], cc)
        self.assertEqual(env["TARGET_CXX"], cxx)
        self.assertEqual(env["CC_aarch64_unknown_linux_gnu"], cc)
        self.assertEqual(env["CXX_aarch64_unknown_linux_gnu"], cxx)
        self.assertEqual(
            env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"], cc
        )
        calls = [json.loads(line) for line in self.zig_log.read_text().splitlines()]
        self.assertEqual(
            calls[0],
            [
                "-m",
                "ziglang",
                "cc",
                "-target",
                "aarch64-linux-gnu.2.17",
                "-O3",
                "source.c",
            ],
        )
        self.assertEqual(
            calls[1][0:5],
            ["-m", "ziglang", "c++", "-target", "aarch64-linux-gnu.2.17"],
        )

    def test_routes_x64_pair_through_exact_zig_target(self) -> None:
        self.make_client("discovery", "x86_64-unknown-linux-gnu", "linux-x64-gnu")
        result = self.run_build(
            client="discovery",
            target="x86_64-unknown-linux-gnu",
            platform="linux-x64-gnu",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        napi = json.loads(self.napi_log.read_text())
        cc = napi["env"]["HOST_CC"]
        self.assertEqual(napi["env"]["CC_x86_64_unknown_linux_gnu"], cc)
        self.assertEqual(
            napi["env"]["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"], cc
        )
        calls = [json.loads(line) for line in self.zig_log.read_text().splitlines()]
        self.assertEqual(
            calls[0][0:5],
            ["-m", "ziglang", "cc", "-target", "x86_64-linux-gnu.2.17"],
        )

    def test_accepts_internal_breg_binding_for_unified_package(self) -> None:
        self.make_client("breg", "aarch64-unknown-linux-gnu", "linux-arm64-gnu")
        result = self.run_build(client="breg")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (
                self.root
                / "crates/registry-breg-client-node/breg-client.linux-arm64-gnu.node"
            ).is_file()
        )

    def test_rejects_unpinned_zig_version_before_build(self) -> None:
        self.make_client("evidence", "aarch64-unknown-linux-gnu", "linux-arm64-gnu")
        result = self.run_build(env={**self.env, "ZIG_VERSION": "0.13.0"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("hash-pinned ziglang 0.12.1", result.stderr)
        self.assertFalse(self.napi_log.exists())

    def test_rejects_mismatched_target_platform_before_build(self) -> None:
        self.make_client("evidence", "aarch64-unknown-linux-gnu", "linux-x64-gnu")
        result = self.run_build(platform="linux-x64-gnu")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported Linux Node target/platform pair", result.stderr)
        self.assertFalse(self.napi_log.exists())

    def test_rejects_strong_unversioned_import(self) -> None:
        self.make_client("evidence", "aarch64-unknown-linux-gnu", "linux-arm64-gnu")
        result = self.run_build(env={**self.env, "READELF_MODE": "strong"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("strong unversioned imports:\nmalloc", result.stderr)

    def test_rejects_glibc_above_floor(self) -> None:
        self.make_client("evidence", "aarch64-unknown-linux-gnu", "linux-arm64-gnu")
        result = self.run_build(env={**self.env, "READELF_GLIBC": "GLIBC_2.18"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires GLIBC_2.18 above the GLIBC_2.17 floor", result.stderr)


if __name__ == "__main__":
    unittest.main()
