#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COMPILER = ROOT / "release/scripts/zig-glibc-compiler"


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

    def test_rejects_unapproved_or_ambiguous_configuration(self) -> None:
        cases = (
            (COMPILER, (), self.env, "must be invoked"),
            (
                self.cc,
                (),
                {**self.env, "REGISTRY_ZIG_TARGET": "aarch64-linux-gnu.2.28"},
                "approved glibc 2.17 target",
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


if __name__ == "__main__":
    unittest.main()
