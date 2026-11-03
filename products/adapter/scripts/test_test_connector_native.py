#!/usr/bin/env python3
"""Hold the Adapter native runner to its source-built job proof."""

import contextlib
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent
SCRIPT = SCRIPTS / "test-connector-native.py"
JOB_GATE = SCRIPTS / "test-job-postgres.sh"
POSTGRES_TLS_GATE = SCRIPTS / "test-postgres-source-tls.sh"
PLAINTEXT_CONTAINER_ID = "a" * 64
TLS_CONTAINER_ID = "b" * 64
SPEC = importlib.util.spec_from_file_location("adapter_native_runner", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class NativeRunnerTests(unittest.TestCase):
    def native_module(self, target, messages, build_calls):
        def cargo_metadata(environment):
            return {"target_directory": str(target)}

        def cargo_build(command, log_path, environment):
            build_calls.append((command, log_path, environment.copy()))
            return messages

        return SimpleNamespace(
            cargo_metadata=cargo_metadata,
            cargo_build=cargo_build,
            exact_fips_library=lambda _messages: target / "synthetic-fips.dylib",
        )

    def executable_messages(self, target, names):
        messages = []
        for name in names:
            executable = target / "debug" / name
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_text(f"source-built {name}\n")
            executable.chmod(0o700)
            messages.append({
                "reason": "compiler-artifact",
                "target": {"name": name, "kind": ["bin"]},
                "executable": str(executable),
            })
        return messages

    def test_job_destination_suite_builds_and_runs_the_exact_native_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            names = ("breg", "bregctl", "coordinator", "coordinatorctl", "casework", "caseworkctl")
            messages = self.executable_messages(target, names)
            build_calls = []
            module = self.native_module(target, messages, build_calls)
            observed = []

            def run(command, **kwargs):
                observed.append((command, kwargs))
                return SimpleNamespace(returncode=0)

            environment = {
                "PATH": os.environ["PATH"],
                "CARGO_TARGET_DIR": str(target),
                "ADAPTER_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1:55432/adapter",
                "ADAPTER_BREG_BIN": "/stale/breg",
                "ADAPTER_COORDINATOR_BIN": "/stale/coordinator",
                "ADAPTER_CASEWORK_BIN": "/stale/casework",
                "ADAPTER_CASEWORKCTL_BIN": "/stale/caseworkctl",
            }
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(RUNNER, "native_fixture", return_value=module), \
                    patch.object(RUNNER.subprocess, "run", side_effect=run), \
                    patch.object(RUNNER.sys, "platform", "linux"):
                self.assertEqual(RUNNER.run(None, "job-destinations"), 0)

            self.assertEqual(len(build_calls), 1)
            build_command, log_path, build_environment = build_calls[0]
            self.assertEqual(build_command, [
                "cargo", "build", "--locked",
                "-p", "registry-breg", "-p", "registry-bregctl",
                "-p", "registry-coordinator",
                "-p", "registry-casework", "-p", "registry-caseworkctl",
                "--features", "registry-breg/runtime,registry-breg/postgres-test,registry-casework/postgres-test,registry-caseworkctl/postgres-test",
                "--bin", "breg", "--bin", "bregctl",
                "--bin", "coordinator", "--bin", "coordinatorctl",
                "--bin", "casework", "--bin", "caseworkctl",
                "--message-format", "json-render-diagnostics",
            ])
            self.assertEqual(build_environment["CARGO_TARGET_DIR"], str(target))
            self.assertFalse(log_path.parent.exists(), "the runner removes its private scratch")

            self.assertEqual(len(observed), 1)
            test_command, test_options = observed[0]
            self.assertEqual(test_command, [
                "cargo", "test", "--locked", "--no-fail-fast",
                "-p", "registry-adapter-job",
                "--features", "job-postgres,native-test-support,postgres-test,signed-coordinator-event",
                "--test", "direct_breg_native",
                "--test", "signed_coordinator_event_native",
                "--", "--ignored", "--nocapture", "--test-threads=1",
            ])
            test_environment = test_options["env"]
            for name in names:
                variable = "ADAPTER_" + name.upper().replace("-", "_") + "_BIN"
                self.assertEqual(test_environment[variable], str((target / "debug" / name).resolve()))

    def test_env_file_selects_only_runner_prerequisites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            env_file = root / "native.env"
            env_file.write_text(
                f"export CARGO_TARGET_DIR={target}\n"
                "ADAPTER_TEST_DATABASE_URL=postgresql://fixture@localhost:55432/adapter\n"
                "AWS_LC_FIPS_SYS_CMAKE_BUILDER=cmake\n"
                "DO_NOT_IMPORT=private-value\n"
            )
            messages = self.executable_messages(target, ("breg", "bregctl"))
            build_calls = []
            module = self.native_module(target, messages, build_calls)
            observed = []

            def run(command, **kwargs):
                observed.append(kwargs["env"].copy())
                return SimpleNamespace(returncode=0)

            with patch.dict(os.environ, {"PATH": os.environ["PATH"]}, clear=True), \
                    patch.object(RUNNER, "native_fixture", return_value=module), \
                    patch.object(RUNNER.subprocess, "run", side_effect=run), \
                    patch.object(RUNNER.sys, "platform", "linux"):
                self.assertEqual(RUNNER.run(env_file, "connector"), 0)
            self.assertNotIn("DO_NOT_IMPORT", build_calls[0][2])
            self.assertNotIn("DO_NOT_IMPORT", observed[0])
            self.assertEqual(observed[0]["AWS_LC_FIPS_SYS_CMAKE_BUILDER"], "cmake")

    def test_missing_or_unsafe_prerequisites_fail_before_cargo(self):
        cases = (
            ({"ADAPTER_TEST_DATABASE_URL": "postgresql://fixture@localhost/db"}, "CARGO_TARGET_DIR"),
            ({"CARGO_TARGET_DIR": "/tmp/target"}, "ADAPTER_TEST_DATABASE_URL"),
            ({"CARGO_TARGET_DIR": "/tmp/target", "ADAPTER_TEST_DATABASE_URL": "postgresql://fixture@example.test/db"}, "loopback"),
        )
        for fields, message in cases:
            with self.subTest(message=message), patch.dict(
                    os.environ, {"PATH": os.environ["PATH"], **fields}, clear=True), \
                    patch.object(RUNNER, "native_fixture") as fixture:
                with self.assertRaisesRegex(SystemExit, message):
                    RUNNER.run(None, "job-destinations")
                fixture.assert_not_called()

    def test_target_directory_must_match_cargo_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configured = root / "configured"
            actual = root / "actual"
            module = self.native_module(actual, [], [])
            environment = {
                "PATH": os.environ["PATH"],
                "CARGO_TARGET_DIR": str(configured),
                "ADAPTER_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1:55432/adapter",
            }
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(RUNNER, "native_fixture", return_value=module), \
                    self.assertRaisesRegex(SystemExit, "Cargo target"):
                RUNNER.run(None, "job-destinations")

    def test_missing_build_artifact_fails_without_running_native_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            messages = self.executable_messages(target, ("breg", "bregctl", "coordinator"))
            module = self.native_module(target, messages, [])
            environment = {
                "PATH": os.environ["PATH"],
                "CARGO_TARGET_DIR": str(target),
                "ADAPTER_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1:55432/adapter",
            }
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(RUNNER, "native_fixture", return_value=module), \
                    patch.object(RUNNER.subprocess, "run") as run, \
                    self.assertRaisesRegex(SystemExit, "coordinatorctl"):
                RUNNER.run(None, "job-destinations")
            run.assert_not_called()

    def test_native_test_failure_is_returned_and_private_scratch_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            messages = self.executable_messages(
                target, ("breg", "bregctl", "coordinator", "coordinatorctl", "casework", "caseworkctl")
            )
            build_calls = []
            module = self.native_module(target, messages, build_calls)
            environment = {
                "PATH": os.environ["PATH"],
                "CARGO_TARGET_DIR": str(target),
                "ADAPTER_TEST_DATABASE_URL": "postgresql://fixture@127.0.0.1:55432/adapter",
            }
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(RUNNER, "native_fixture", return_value=module), \
                    patch.object(RUNNER.subprocess, "run", return_value=SimpleNamespace(returncode=23)), \
                    patch.object(RUNNER.sys, "platform", "linux"):
                self.assertEqual(RUNNER.run(None, "job-destinations"), 23)
            self.assertFalse(build_calls[0][1].parent.exists())


class JobPostgresGateTests(unittest.TestCase):
    def fixture_bin(self, root):
        binary = root / ".cargo" / "bin"
        binary.mkdir(parents=True)
        docker = binary / "docker"
        docker.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf "docker:%s\\n" "$*" >> "$PROBE_LOG"\n'
            'case "$1" in\n'
            f'run) if [[ "$*" == *"adapter-job-pg-tls"* ]]; then printf "{TLS_CONTAINER_ID}\\n"; '
            f'else printf "{PLAINTEXT_CONTAINER_ID}\\n"; fi ;;\n'
            'exec) if [[ "$*" == *\'printf %s "$PGDATA"\'* ]]; then '
            'printf "/var/lib/postgresql/data\\n"; '
            'elif [[ "$*" == *"pg_stat_ssl"* ]]; then printf "t\\n"; '
            'elif [[ "$3" == psql ]]; then printf "1\\n"; fi ;;\n'
            'port) printf "127.0.0.1:55444\\n" ;;\n'
            'ps) ;;\n'
            'cp) ;;\n'
            'rm) ;;\n'
            '*) exit 2 ;;\n'
            "esac\n"
        )
        openssl = binary / "openssl"
        openssl.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf "openssl:%s\\n" "$*" >> "$PROBE_LOG"\n'
            "while (( $# > 0 )); do\n"
            '  case "$1" in\n'
            '    -out|-keyout) shift; : > "$1" ;;\n'
            "  esac\n"
            "  shift\n"
            "done\n"
        )
        cargo = binary / "cargo"
        cargo.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf "cargo:%s\\n" "$*" >> "$PROBE_LOG"\n'
        )
        python = binary / "python3"
        python.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            'printf "python:%s|db:%s|target:%s\\n" "$*" '
            '"${ADAPTER_TEST_DATABASE_URL:+set}" "$CARGO_TARGET_DIR" >> "$PROBE_LOG"\n'
            'exit "${NATIVE_EXIT:-0}"\n'
        )
        for path in (docker, openssl, cargo, python):
            path.chmod(0o700)
        return binary

    def test_owned_database_fixture_runs_native_destinations_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture_bin(root)
            log = root / "probes"
            target = root / "target"
            environment = {
                **os.environ,
                "MOCK_CARGO": str(binary / "cargo"),
                "BASH_FUNC_cargo%%": '() { "$MOCK_CARGO" "$@";\n}',
                "PATH": f"{binary}:{os.environ['PATH']}",
                "PROBE_LOG": str(log),
                "CARGO_TARGET_DIR": str(target),
            }
            result = __import__("subprocess").run(
                ["bash", str(JOB_GATE)], env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text().splitlines()
            native = [line for line in calls if line.startswith("python:")]
            self.assertEqual(native, [
                "python:products/adapter/scripts/test-connector-native.py --suite job-destinations"
                f"|db:set|target:{target}"
            ])
            cargo = [line for line in calls if line.startswith("cargo:")]
            self.assertTrue(any(
                "--features job-hook,postgres-test --test hook_ingress_postgres -- --test-threads=1" in line
                for line in cargo
            ), "the public gate must run every authenticated hook CLI/PostgreSQL scenario")
            for features, target_name in [
                ("postgres-test,signed-coordinator-event", "signed_coordinator_event_postgres"),
                ("job-file,postgres-test,signed-coordinator-event", "job_file_host"),
            ]:
                self.assertTrue(any(
                    f"--features {features} --test {target_name}" in line
                    and "--test-threads=1" in line for line in cargo
                ), f"the public gate must execute {target_name} with its real database features")
            runs = [line for line in calls if line.startswith("docker:run ")]
            self.assertEqual(len(runs), 2, "the public gate owns plaintext and TLS fixtures")
            self.assertTrue(all("127.0.0.1::5432" in line for line in runs))
            cargo = [line for line in calls if line.startswith("cargo:")]
            self.assertTrue(any(
                "postgres_source::tests::tls_cancelled_read_is_detached_before_same_pool_creates_fresh_backend"
                in line for line in cargo
            ), "the public gate must run the exact verified-TLS cancellation proof")
            removals = [line for line in calls if line.startswith("docker:rm ")]
            self.assertIn(f"docker:rm -fv {TLS_CONTAINER_ID}", removals)
            self.assertEqual(removals[-1], f"docker:rm -fv {PLAINTEXT_CONTAINER_ID}")

    def test_owned_database_fixture_is_removed_when_native_runner_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture_bin(root)
            log = root / "probes"
            environment = {
                **os.environ,
                "MOCK_CARGO": str(binary / "cargo"),
                "BASH_FUNC_cargo%%": '() { "$MOCK_CARGO" "$@";\n}',
                "PATH": f"{binary}:{os.environ['PATH']}",
                "PROBE_LOG": str(log),
                "CARGO_TARGET_DIR": str(root / "target"),
                "NATIVE_EXIT": "17",
            }
            result = __import__("subprocess").run(
                ["bash", str(JOB_GATE)], env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertEqual(
                log.read_text().splitlines()[-1],
                f"docker:rm -fv {PLAINTEXT_CONTAINER_ID}",
            )

    def test_caller_database_is_preserved_while_tls_proof_owns_its_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture_bin(root)
            log = root / "probes"
            environment = {
                **os.environ,
                "MOCK_CARGO": str(binary / "cargo"),
                "BASH_FUNC_cargo%%": '() { "$MOCK_CARGO" "$@";\n}',
                "PATH": f"{binary}:{os.environ['PATH']}",
                "PROBE_LOG": str(log),
                "CARGO_TARGET_DIR": str(root / "target"),
                "ADAPTER_TEST_DATABASE_URL":
                    "postgresql://caller-owned@localhost:55432/adapter",
            }
            result = __import__("subprocess").run(
                ["bash", str(JOB_GATE)], env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text().splitlines()
            runs = [line for line in calls if line.startswith("docker:run ")]
            self.assertEqual(len(runs), 1, "only the mandatory TLS fixture is owned")
            self.assertIn("adapter-job-pg-tls", runs[0])
            removals = [line for line in calls if line.startswith("docker:rm ")]
            self.assertEqual(removals, [f"docker:rm -fv {TLS_CONTAINER_ID}"])


class PostgresTlsGateTests(unittest.TestCase):
    def fixture_bin(self, root):
        return JobPostgresGateTests().fixture_bin(root)

    def test_owned_tls_fixture_runs_exact_proof_and_removes_only_captured_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture_bin(root)
            log = root / "probes"
            environment = {
                **os.environ,
                "MOCK_CARGO": str(binary / "cargo"),
                "BASH_FUNC_cargo%%": '() { "$MOCK_CARGO" "$@";\n}',
                "PATH": f"{binary}:{os.environ['PATH']}",
                "PROBE_LOG": str(log),
                "CARGO_TARGET_DIR": str(root / "target"),
                "TMPDIR": str(root),
            }
            result = __import__("subprocess").run(
                ["bash", str(POSTGRES_TLS_GATE)], env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text().splitlines()
            self.assertTrue(any(
                line.startswith("docker:run ") and "127.0.0.1::5432" in line
                for line in calls
            ))
            cargo = [line for line in calls if line.startswith("cargo:")]
            self.assertEqual(len(cargo), 1)
            self.assertIn("--features postgres-tls-test", cargo[0])
            self.assertIn(
                "postgres_source::tests::tls_cancelled_read_is_detached_before_same_pool_creates_fresh_backend",
                cargo[0],
            )
            self.assertEqual(calls[-1], f"docker:rm -fv {TLS_CONTAINER_ID}")

    def test_owned_tls_fixture_is_removed_when_proof_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.fixture_bin(root)
            cargo = binary / "cargo"
            cargo.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "cargo:%s\\n" "$*" >> "$PROBE_LOG"\n'
                "exit 19\n"
            )
            cargo.chmod(0o700)
            log = root / "probes"
            environment = {
                **os.environ,
                "MOCK_CARGO": str(binary / "cargo"),
                "BASH_FUNC_cargo%%": '() { "$MOCK_CARGO" "$@";\n}',
                "PATH": f"{binary}:{os.environ['PATH']}",
                "PROBE_LOG": str(log),
                "CARGO_TARGET_DIR": str(root / "target"),
                "TMPDIR": str(root),
            }
            result = __import__("subprocess").run(
                ["bash", str(POSTGRES_TLS_GATE)], env=environment,
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 19, result.stderr)
            self.assertEqual(
                log.read_text().splitlines()[-1],
                f"docker:rm -fv {TLS_CONTAINER_ID}",
            )


if __name__ == "__main__":
    unittest.main()
