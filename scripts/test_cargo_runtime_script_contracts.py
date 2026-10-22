#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = {
    "products/casework/scripts/check-review-journeys.sh": (
        "CASEWORK_BIN",
        "CASEWORKCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
    ),
    "products/breg/scripts/test-adopter-workflow.sh": (
        "BREG_BIN",
        "BREGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
    ),
    "products/breg/scripts/test-historical-workflow.sh": (
        "BREG_BIN",
        "BREGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
        "registry_prepare_cargo_runtime",
    ),
    "products/scheduling/scripts/check-checkpoint.sh": (
        "SCHEDULINGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_prepare_cargo_runtime",
    ),
    "products/messaging/scripts/check-checkpoint.sh": (
        "MESSAGINGCTL_BIN",
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
    ),
    "products/evidence/scripts/check-authoring-no-io.sh": ("CLIPPY_DRIVER_BIN",),
    "products/platform/scripts/check-yaml-reader-boundary.sh": ("CLIPPY_DRIVER_BIN",),
    "products/platform/scripts/run-config-conformance.sh": (
        "REGISTRY_CARGO_RUNTIME_LIBRARY_PATH",
        "run-config-conformance.py",
    ),
    "products/breg/loadtest/up.sh": (
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
        "--runtime-library-path",
    ),
    "products/breg/loadtest/run.sh": ("DYLD_FALLBACK_LIBRARY_PATH",),
    "products/breg/loadtest/down.sh": ("DYLD_FALLBACK_LIBRARY_PATH",),
    "products/evidence/loadtest/up.sh": (
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
        "--runtime-library-path",
    ),
    "products/evidence/loadtest/run.sh": ("DYLD_FALLBACK_LIBRARY_PATH",),
    "products/evidence/loadtest/down.sh": ("DYLD_FALLBACK_LIBRARY_PATH",),
    "products/casework/loadtest/up.sh": (
        "cargo-runtime-library-path.sh",
        "registry_cargo_build",
        "--runtime-library-path",
    ),
    "products/casework/loadtest/run.sh": ("DYLD_FALLBACK_LIBRARY_PATH",),
    "products/casework/loadtest/down.sh": ("DYLD_FALLBACK_LIBRARY_PATH",),
}


class CargoRuntimeScriptContractTests(unittest.TestCase):
    def test_every_reported_gate_keeps_its_runtime_and_override_contract(self):
        self.assertEqual(len(CONTRACTS), 17)
        for relative, markers in CONTRACTS.items():
            with self.subTest(script=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                for marker in markers:
                    self.assertIn(marker, source)


class ConfigConformanceRuntimeTests(unittest.TestCase):
    def test_relative_bin_directory_exports_an_absolute_runtime_path(self):
        temporary = tempfile.TemporaryDirectory(prefix="config conformance runtime ")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        artifacts = (
            root
            / "relative-target/debug/build/aws-lc-fips-sys-exact/out/build/artifacts"
        )
        artifacts.mkdir(parents=True)
        (artifacts / "libaws_lc_fips_0_14_2_crypto.dylib").touch()
        executable_directory = root / "bin"
        executable_directory.mkdir()
        environment_log = root / "environment.json"
        uv = executable_directory / "uv"
        uv.write_text(
            "#!" + sys.executable + "\n" + """import json
import os
from pathlib import Path
Path(os.environ["TEST_ENVIRONMENT_LOG"]).write_text(json.dumps({
    "fallback": os.environ.get("DYLD_FALLBACK_LIBRARY_PATH"),
    "runtime": os.environ.get("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"),
}))
""",
            encoding="utf-8",
        )
        uv.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": f"{executable_directory}{os.pathsep}{os.environ['PATH']}",
            "TEST_ENVIRONMENT_LOG": str(environment_log),
            "DYLD_FALLBACK_LIBRARY_PATH": "/caller/runtime",
        }
        environment.pop("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH", None)
        completed = subprocess.run(
            [
                str(ROOT / "products/platform/scripts/run-config-conformance.sh"),
                "--bin-dir",
                "relative-target/debug",
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        invocation = json.loads(environment_log.read_text())
        self.assertEqual(invocation["runtime"], str(artifacts.resolve()))
        stripped_fallback = str(artifacts.resolve())
        preserved_fallback = (
            stripped_fallback + os.pathsep + environment["DYLD_FALLBACK_LIBRARY_PATH"]
        )
        # On a developer Mac the protected /usr/bin/env launcher strips the
        # caller's DYLD_* variables, while the hosted macOS runner has been
        # seen to preserve them; other platforms preserve the existing
        # fallback path behind the artifacts directory.
        if sys.platform == "darwin":
            self.assertIn(invocation["fallback"], (stripped_fallback, preserved_fallback))
        else:
            self.assertEqual(invocation["fallback"], preserved_fallback)


class CaseworkCheckpointRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="casework runtime ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in ("cargo-runtime-library-path.sh", "cargo_runtime_library_path.py"):
            shutil.copyfile(ROOT / "scripts" / name, scripts / name)
        product_scripts = self.root / "products/casework/scripts"
        product_scripts.mkdir(parents=True)
        self.checkpoint = product_scripts / "check-checkpoint.sh"
        shutil.copyfile(ROOT / self.checkpoint.relative_to(self.root), self.checkpoint)
        # Isolate binary selection from the separately tested product/schema gates.
        for name in ("check_dependency_direction.py", "check_database_test_isolation.py"):
            (product_scripts / name).touch()
        (product_scripts / "test_fixture.py").write_text(
            "import unittest\nclass Fixture(unittest.TestCase):\n    def test_ready(self): pass\n",
            encoding="utf-8",
        )
        self.write_executable(product_scripts / "check-schemas.sh", "#!/bin/sh\nexit 0\n")
        self.target = self.root / "configured target"
        self.artifacts = self.target / "debug/build/aws-lc-fips-sys-exact/out/build/artifacts"
        self.artifacts.mkdir(parents=True)
        (self.artifacts / "libaws_lc_fips_0_14_2_crypto.dylib").touch()
        self.candidate = self.target / "debug/caseworkctl"
        self.write_candidate(self.candidate)
        self.breg_candidate = self.target / "debug/bregctl"
        self.write_executable(self.breg_candidate, "#!/bin/sh\nexit 0\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.write_executable(self.bin / "uname", '#!/bin/sh\nprintf "%s\\n" "$TEST_SYSTEM"\n')
        self.write_executable(
            self.bin / "cargo",
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
with open(os.environ["TEST_CARGO_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
target = Path(os.environ["TEST_TARGET"])
if sys.argv[1] == "build":
    print(json.dumps({
        "reason": "build-script-executed",
        "package_id": "registry+https://github.com/rust-lang/crates.io-index#aws-lc-fips-sys@0.14.2",
        "linked_libs": ["dylib=aws_lc_fips_0_14_2_crypto"],
        "out_dir": str(target / "debug/build/aws-lc-fips-sys-exact/out"),
    }))
elif sys.argv[1] == "metadata":
    print(json.dumps({"target_directory": str(target)}))
elif sys.argv[1] == "test":
    Path(os.environ["TEST_PROVIDER_ADD_LOG"]).write_text(json.dumps({
        "caseworkctl": os.environ.get("CASEWORKCTL_BIN"),
        "bregctl": os.environ.get("BREGCTL_BIN"),
    }))
else:
    sys.exit(90)
""",
        )
        self.cargo_log = self.root / "cargo.jsonl"
        self.candidate_log = self.root / "candidate.json"
        self.provider_add_log = self.root / "provider-add.json"
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEST_SYSTEM": "Darwin",
            "TEST_TARGET": str(self.target),
            "TEST_CARGO_LOG": str(self.cargo_log),
            "TEST_CANDIDATE_LOG": str(self.candidate_log),
            "TEST_PROVIDER_ADD_LOG": str(self.provider_add_log),
            "TEST_FALLBACK_PATH": "/caller/runtime",
        }
        for name in ("CASEWORKCTL_BIN", "BREGCTL_BIN", "REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"):
            self.env.pop(name, None)

    def write_executable(self, path, source):
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    def write_candidate(self, path):
        self.write_executable(
            path,
            "#!" + sys.executable + "\n" + """import json
import os
import sys
from pathlib import Path
Path(os.environ["TEST_CANDIDATE_LOG"]).write_text(json.dumps({
    "binary": str(Path(__file__).resolve()),
    "args": sys.argv[1:],
    "fallback": os.environ.get("DYLD_FALLBACK_LIBRARY_PATH"),
    "runtime": os.environ.get("REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"),
}))
# Stop after the first CLI invocation: the product journey has its own gate.
sys.exit(37)
""",
        )

    def run_checkpoint(self):
        return subprocess.run(
            # Set DYLD inside the shell: macOS strips it when launching /bin/sh.
            ["/bin/sh", "-c",
             'DYLD_FALLBACK_LIBRARY_PATH=$TEST_FALLBACK_PATH; export DYLD_FALLBACK_LIBRARY_PATH; . "$0"',
             str(self.checkpoint)],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def cargo_commands(self):
        return [json.loads(line) for line in self.cargo_log.read_text().splitlines()]

    def assert_candidate_reached(self, completed, candidate, breg_candidate=None):
        self.assertEqual(completed.returncode, 37, completed.stderr)
        invocation = json.loads(self.candidate_log.read_text())
        self.assertEqual(invocation["binary"], str(candidate.resolve()))
        self.assertEqual(invocation["args"][0], "init")
        self.assertEqual(invocation["args"][2:], ["--template", "standalone-decision"])
        self.assertEqual(
            json.loads(self.provider_add_log.read_text()),
            {
                "caseworkctl": str(candidate),
                "bregctl": str(breg_candidate or self.breg_candidate),
            },
        )
        self.assertEqual(
            self.cargo_commands()[-1],
            ["test", "--locked", "--offline", "-j2", "-p", "registry-caseworkctl",
             "--test", "provider_add"],
        )
        return invocation

    def test_default_binary_uses_cargo_target_and_runtime_on_each_platform(self):
        for system in ("Linux", "Darwin"):
            with self.subTest(system=system):
                self.env["TEST_SYSTEM"] = system
                self.cargo_log.unlink(missing_ok=True)
                invocation = self.assert_candidate_reached(self.run_checkpoint(), self.candidate)
                commands = self.cargo_commands()
                self.assertEqual(
                    [command[0] for command in commands],
                    ["build", "metadata", "build", "metadata", "test"],
                )
                for build, package in zip(
                    (commands[0], commands[2]),
                    ("registry-caseworkctl", "registry-bregctl"),
                ):
                    self.assertIn("--locked", build)
                    self.assertIn("--offline", build)
                    self.assertEqual(build[build.index("-p") + 1], package)
                expected = str(self.artifacts) if system == "Darwin" else None
                self.assertEqual(invocation["runtime"], expected)
                self.assertEqual(
                    invocation["fallback"],
                    f"{expected}:{expected}:/caller/runtime" if expected else "/caller/runtime",
                )

    def test_external_binaries_preserve_caller_runtime_and_candidate_selection(self):
        external = self.root / "external candidate"
        self.write_candidate(external)
        external_breg = self.root / "external breg candidate"
        self.write_executable(external_breg, "#!/bin/sh\nexit 0\n")
        self.env["CASEWORKCTL_BIN"] = str(external)
        self.env["BREGCTL_BIN"] = str(external_breg)
        self.env["REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"] = "/caller/runtime"
        invocation = self.assert_candidate_reached(self.run_checkpoint(), external, external_breg)
        self.assertEqual(invocation["fallback"], "/caller/runtime")
        self.assertEqual(invocation["runtime"], "/caller/runtime")
        self.assertEqual([command[0] for command in self.cargo_commands()], ["test"])

    def test_one_external_binary_builds_only_the_missing_peer(self):
        for external_kind in ("caseworkctl", "bregctl"):
            with self.subTest(external_kind=external_kind):
                self.cargo_log.unlink(missing_ok=True)
                self.env.pop("CASEWORKCTL_BIN", None)
                self.env.pop("BREGCTL_BIN", None)
                external = self.root / f"external {external_kind} candidate"
                self.write_candidate(external)
                self.env[f"{external_kind.upper()}_BIN"] = str(external)
                candidate = external if external_kind == "caseworkctl" else self.candidate
                breg_candidate = external if external_kind == "bregctl" else self.breg_candidate
                self.assert_candidate_reached(self.run_checkpoint(), candidate, breg_candidate)
                commands = self.cargo_commands()
                self.assertEqual(
                    [command[0] for command in commands], ["build", "metadata", "test"]
                )
                missing = "bregctl" if external_kind == "caseworkctl" else "caseworkctl"
                self.assertEqual(commands[0][commands[0].index("-p") + 1], f"registry-{missing}")

    def test_external_binary_must_be_executable(self):
        external = self.root / "nonexecutable candidate"
        external.touch()
        self.env["CASEWORKCTL_BIN"] = str(external)
        completed = self.run_checkpoint()
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertIn("CASEWORKCTL_BIN must name an executable candidate", completed.stderr)
        self.assertFalse(self.cargo_log.exists())
        self.assertFalse(self.candidate_log.exists())


if __name__ == "__main__":
    unittest.main()
