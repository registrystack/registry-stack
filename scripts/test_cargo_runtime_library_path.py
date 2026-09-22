#!/usr/bin/env python3
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("cargo_runtime_library_path.py")
SPEC = importlib.util.spec_from_file_location("cargo_runtime_library_path", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def message(out_dir: Path, *, libraries=("dylib=aws_lc_fips_0_14_2_crypto",)) -> str:
    return json.dumps(
        {
            "reason": "build-script-executed",
            "package_id": "registry+https://github.com/rust-lang/crates.io-index#aws-lc-fips-sys@0.14.2",
            "linked_libs": list(libraries),
            "out_dir": str(out_dir),
        }
    )


class CargoRuntimeLibraryPathTests(unittest.TestCase):
    def test_failed_macos_build_replays_the_rendered_diagnostic_and_status(self):
        helper = SCRIPT.with_name("cargo-runtime-library-path.sh")
        completed = subprocess.run(
            [
                "/bin/sh",
                "-c",
                """
. "$1"
uname() { printf '%s\\n' Darwin; }
cargo() {
  printf '%s\\n' '{"reason":"compiler-message","message":{"rendered":"visible compiler error\\n"}}'
  return 42
}
registry_cargo_build "$2" --locked
""",
                "test-cargo-runtime-helper",
                str(helper),
                str(helper.parents[1]),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 42)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "visible compiler error\n")

    def test_shell_helper_is_an_ordinary_cargo_build_on_linux(self):
        helper = SCRIPT.with_name("cargo-runtime-library-path.sh")
        completed = subprocess.run(
            [
                "/bin/sh",
                "-c",
                """
. "$1"
uname() { printf '%s\\n' Linux; }
cargo() { [ "$1" = build ] && [ "$2" = --locked ]; }
registry_cargo_build /unused --locked
[ -z "${DYLD_FALLBACK_LIBRARY_PATH:-}" ]
""",
                "test-cargo-runtime-helper",
                str(helper),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_prepare_runtime_builds_and_exports_exact_path_on_macos(self):
        helper = SCRIPT.with_name("cargo-runtime-library-path.sh")
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "target/debug/build/aws-lc-fips-sys-exact/out"
            artifacts = out_dir / "build/artifacts"
            artifacts.mkdir(parents=True)
            (artifacts / "libaws_lc_fips_0_14_2_crypto.dylib").touch()
            completed = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    """
. "$1"
message=$3
uname() { printf '%s\\n' Darwin; }
cargo() {
  [ "$1" = build ] || return 90
  printf '%s\\n' "$message"
}
registry_prepare_cargo_runtime "$2" --locked
printf '%s\\n' "$DYLD_FALLBACK_LIBRARY_PATH"
printf '%s\\n' "$REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"
""",
                    "test-cargo-runtime-helper",
                    str(helper),
                    str(helper.parents[1]),
                    message(out_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, f"{artifacts}\n{artifacts}\n")

    def test_resolves_the_exact_build_script_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "target/debug/build/aws-lc-fips-sys-exact/out"
            artifacts = out_dir / "build/artifacts"
            artifacts.mkdir(parents=True)
            (artifacts / "libaws_lc_fips_0_14_2_crypto.dylib").touch()
            self.assertEqual(MODULE.resolve_aws_lc_fips_artifacts([message(out_dir)]), artifacts)

    def test_rendered_diagnostics_ignore_non_diagnostic_messages(self):
        lines = [
            json.dumps({"reason": "build-finished", "success": False}),
            json.dumps(
                {
                    "reason": "compiler-message",
                    "message": {"rendered": "error: first\n"},
                }
            ),
            "not json",
            json.dumps(
                {
                    "reason": "compiler-message",
                    "message": {"rendered": "error: second\n"},
                }
            ),
        ]
        self.assertEqual(
            MODULE.rendered_diagnostics(lines), "error: first\nerror: second\n"
        )

    def test_a_stale_sibling_cannot_be_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "target/debug/build"
            stale = root / "aws-lc-fips-sys-stale/out/build/artifacts"
            stale.mkdir(parents=True)
            (stale / "libaws_lc_fips_0_14_2_crypto.dylib").touch()
            exact_out = root / "aws-lc-fips-sys-exact/out"
            exact_out.mkdir(parents=True)
            with self.assertRaisesRegex(MODULE.ResolutionError, "dylib is missing"):
                MODULE.resolve_aws_lc_fips_artifacts([message(exact_out)])

    def test_missing_build_message_fails_closed(self):
        with self.assertRaisesRegex(MODULE.ResolutionError, "identified 0"):
            MODULE.resolve_aws_lc_fips_artifacts([json.dumps({"reason": "build-finished"})])

    def test_multiple_build_outputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs = [Path(directory) / name / "out" for name in ("first", "second")]
            for out_dir in outputs:
                artifacts = out_dir / "build/artifacts"
                artifacts.mkdir(parents=True)
                (artifacts / "libaws_lc_fips_0_14_2_crypto.dylib").touch()
            with self.assertRaisesRegex(MODULE.ResolutionError, "identified 2"):
                MODULE.resolve_aws_lc_fips_artifacts([message(path) for path in outputs])

    def test_link_contract_must_name_one_fips_crypto_dylib(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODULE.ResolutionError, "exactly one"):
                MODULE.resolve_aws_lc_fips_artifacts(
                    [message(Path(directory), libraries=("dylib=unrelated",))]
                )


if __name__ == "__main__":
    unittest.main()
