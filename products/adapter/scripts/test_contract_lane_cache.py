#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The optional CI cleanup touches only the lane's explicit Cargo target."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).with_name("contract-lane-cache.sh")

class ContractLaneCacheTests(unittest.TestCase):
    def run_helper(self, enabled, target):
        with tempfile.TemporaryDirectory(prefix="adapter-lane-cache-") as directory:
            root = Path(directory)
            cargo = root / "cargo"
            cargo.write_text('#!/usr/bin/env bash\nset -euo pipefail\nprintf "%s\\n" "$@" > "$CARGO_LOG"\n')
            cargo.chmod(0o700)
            log = root / "cargo.log"
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", CARGO_LOG=str(log), CARGO_SHIM=str(cargo))
            env.pop("ADAPTER_CONTRACTS_CLEAN_BETWEEN_LANES", None)
            env.pop("CARGO_TARGET_DIR", None)
            if enabled is not None:
                env["ADAPTER_CONTRACTS_CLEAN_BETWEEN_LANES"] = enabled
            if target is not None:
                env["CARGO_TARGET_DIR"] = target
            result = subprocess.run(["bash", "-c", 'cargo() { "$CARGO_SHIM" "$@"; }; source "$1"; clear_completed_adapter_lane', "bash", str(HELPER)], env=env, capture_output=True, text=True)
            return result, log.read_text().splitlines() if log.exists() else []

    def test_local_default_never_cleans_a_shared_developer_target(self):
        result, calls = self.run_helper(None, "/private/tmp/owned-target")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])

    def test_opted_in_lane_cleans_only_its_named_packages_and_target(self):
        result, args = self.run_helper("1", "/private/tmp/owned target")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args[:3], ["clean", "--target-dir", "/private/tmp/owned target"])
        self.assertEqual(args[3::2], ["-p"] * 6)
        self.assertEqual(set(args[4::2]), {"registry-adapter", "registry-adapter-core", "registry-adapter-engine", "registry-adapterctl", "registry-adapter-job", "registry-adapter-connectors"})

    def test_missing_target_fails_before_any_cargo_call(self):
        result, calls = self.run_helper("1", None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CARGO_TARGET_DIR", result.stderr)
        self.assertEqual(calls, [])

if __name__ == "__main__":
    unittest.main()
