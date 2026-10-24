"""Verify the additional Linux ARM build recipe and executable identity checks."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_roster

ROOT = Path(__file__).resolve().parents[2]


class AdditionalPlatformBinariesTest(unittest.TestCase):
    def run_builder(
        self, root, version, wrong_version=False, exclude_discovery=False
    ):
        cargo = root / "cargo"
        cargo.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
binary = args[args.index("--bin") + 1]
target = args[args.index("--target") + 1]
with Path(os.environ["CALLS"]).open("a") as log:
    log.write(json.dumps(args) + "\\n")
output = Path(os.environ["CARGO_TARGET_DIR"]) / target / "release" / binary
output.parent.mkdir(parents=True, exist_ok=True)
version = os.environ["FAKE_VERSION"]
suffix = " (typst " + os.environ["TYPST_PIN"] + ")" if binary == "registry-render" else ""
output.write_text("#!/bin/sh\\nprintf '%s\\n' '" + binary + " " + version + suffix + "'\\n")
output.chmod(0o755)
""")
        cargo.chmod(0o755)
        output = root / "platform"
        environment = os.environ | {
            "CARGO": str(cargo),
            "CARGO_TARGET_DIR": str(root / "target"),
            "CALLS": str(root / "calls.jsonl"),
            "FAKE_VERSION": "0.1.0" if wrong_version else version,
            "TYPST_PIN": re.search(
                r'pub const TYPST_PIN: &str = "([^"]+)"',
                (ROOT / "crates/registry-render/src/lib.rs").read_text(),
            )[1],
        }
        command = [
                "bash",
                str(ROOT / "release/scripts/build-additional-platform-binaries.sh"),
                version,
                f"v{version}",
                "aarch64-unknown-linux-gnu",
                str(output),
            ]
        if exclude_discovery:
            command.extend(["--exclude-unit", "discovery"])
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )
        return result, output

    def test_every_binary_is_built_separately_and_smoked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, output = self.run_builder(root, "0.44.0")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                {
                    f"{binary}-v0.44.0-linux-arm64"
                    for _, binary in release_roster.ADDITIONAL_PLATFORM_BUILDS
                },
                {path.name for path in output.iterdir()},
            )
            calls = [
                json.loads(line)
                for line in (root / "calls.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                [
                    [
                        "build",
                        "--release",
                        "--locked",
                        "-p",
                        crate,
                        "--bin",
                        binary,
                        "--target",
                        "aarch64-unknown-linux-gnu",
                    ]
                    for crate, binary in release_roster.ADDITIONAL_PLATFORM_BUILDS
                ],
                calls,
            )

    def test_historical_release_has_no_additional_builds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, output = self.run_builder(root, "0.43.0")
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(output.exists())
            self.assertFalse((root / "calls.jsonl").exists())

    def test_discovery_can_be_excluded_from_stack_platform_builds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, output = self.run_builder(
                root, "0.44.0", exclude_discovery=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(
                any(path.name.startswith("discovery") for path in output.iterdir())
            )
            calls = (root / "calls.jsonl").read_text().splitlines()
            self.assertFalse(any("registry-discovery" in call for call in calls))

    def test_wrong_binary_identity_refuses_the_platform(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, _ = self.run_builder(Path(temporary), "0.44.0", wrong_version=True)
            self.assertNotEqual(0, result.returncode)
            binary = release_roster.ADDITIONAL_PLATFORM_BUILDS[0][1]
            self.assertIn(
                f'{binary} reports "{binary} 0.1.0"; '
                f'the release identity expects "{binary} 0.44.0"',
                result.stderr,
            )
