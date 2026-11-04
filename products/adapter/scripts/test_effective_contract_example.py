#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The effective-contract example generator owns its Adapter build."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("generate-effective-contract-example.sh")
REPO_ROOT = SCRIPT.parents[3]
EXAMPLE = REPO_ROOT / "products/adapter/examples/formats/effective-contract.json"


class EffectiveContractExampleTests(unittest.TestCase):
    def test_linux_cold_target_builds_adapter_before_checking_export(self):
        with tempfile.TemporaryDirectory(prefix="adapter-effective-contract-") as directory:
            root = Path(directory)
            binary_dir = root / "bin"
            target = root / "owned target"
            binary_dir.mkdir()
            target.mkdir()

            uname = binary_dir / "uname"
            uname.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "[[ \"${1:-}\" == -s ]]\n"
                "printf 'Linux\\n'\n",
                encoding="utf-8",
            )
            uname.chmod(0o700)

            adapter_stub = root / "adapter-stub"
            adapter_stub.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "[[ \"${1:-}\" == effective-contract ]]\n"
                "cat \"$EXPECTED_EFFECTIVE_CONTRACT\"\n",
                encoding="utf-8",
            )
            adapter_stub.chmod(0o700)

            cargo_log = root / "cargo.log"
            cargo = binary_dir / "cargo"
            cargo.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf '<%s>\\n' \"$@\" > \"$CARGO_LOG\"\n"
                "[[ \"${1:-}\" == build ]]\n"
                "target_dir=\n"
                "while (( $# > 0 )); do\n"
                "  if [[ \"$1\" == --target-dir ]]; then\n"
                "    target_dir=$2\n"
                "    shift 2\n"
                "  else\n"
                "    shift\n"
                "  fi\n"
                "done\n"
                "[[ -n \"$target_dir\" ]]\n"
                "mkdir -p \"$target_dir/debug\"\n"
                "cp \"$ADAPTER_STUB\" \"$target_dir/debug/adapter\"\n",
                encoding="utf-8",
            )
            cargo.chmod(0o700)

            environment = os.environ.copy()
            for name in (
                "ADAPTER_BIN",
                "DYLD_FALLBACK_LIBRARY_PATH",
                "REGISTRY_CARGO_RUNTIME_LIBRARY_PATH",
            ):
                environment.pop(name, None)
            environment.update(
                ADAPTER_STUB=str(adapter_stub),
                CARGO_LOG=str(cargo_log),
                CARGO_TARGET_DIR=str(target),
                EXPECTED_EFFECTIVE_CONTRACT=str(EXAMPLE),
                PATH=f"{binary_dir}:{environment['PATH']}",
            )

            result = subprocess.run(
                ["bash", str(SCRIPT), "--check"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "Effective-contract example matches the real CLI export.",
                result.stdout,
            )
            self.assertEqual(
                cargo_log.read_text(encoding="utf-8").splitlines(),
                [
                    "<build>",
                    "<--locked>",
                    "<-p>",
                    "<registry-adapter>",
                    "<--manifest-path>",
                    f"<{REPO_ROOT / 'Cargo.toml'}>",
                    "<--target-dir>",
                    f"<{target}>",
                ],
            )


if __name__ == "__main__":
    unittest.main()
