from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("loadenv.py")
REPOSITORY = MODULE_PATH.parents[4]
SPEC = importlib.util.spec_from_file_location("loadtest_evidence", REPOSITORY / "scripts/loadtest/evidence.py")
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)
LOADENV_SPEC = importlib.util.spec_from_file_location("loadtest_environment", MODULE_PATH)
assert LOADENV_SPEC and LOADENV_SPEC.loader
loadenv = importlib.util.module_from_spec(LOADENV_SPEC)
LOADENV_SPEC.loader.exec_module(loadenv)
SEED_SPEC = importlib.util.spec_from_file_location("breg_loadtest_seed", MODULE_PATH.parent.parent / "seed.py")
assert SEED_SPEC and SEED_SPEC.loader
seed = importlib.util.module_from_spec(SEED_SPEC)
SEED_SPEC.loader.exec_module(seed)


class BaseRegistryEngineHarnessTests(unittest.TestCase):
    def test_profiles_pin_held_sweep_and_burst_recovery(self) -> None:
        loadtest = MODULE_PATH.parent.parent
        workload = (loadtest / "lib/workload.js").read_text(encoding="utf-8")
        sweep = (loadtest / "profiles/sweep.js").read_text(encoding="utf-8")
        burst = (loadtest / "profiles/burst.js").read_text(encoding="utf-8")
        steady = (loadtest / "profiles/steady.js").read_text(encoding="utf-8")
        runner = (loadtest / "run.sh").read_text(encoding="utf-8")
        self.assertIn("body.pageInfo.nextCursor", workload)
        self.assertIn("$skiptoken=", workload)
        self.assertIn("executor: 'constant-arrival-rate'", sweep)
        self.assertNotIn("ramping-arrival-rate", sweep)
        self.assertIn("recovery:", burst)
        self.assertIn("'http_req_failed{scenario:recovery}'", burst)
        self.assertIn("checks: ['rate>0.99']", burst)
        self.assertIn("'checks{scenario:recovery}': ['rate==1']", burst)
        self.assertIn("checks: ['rate==1']", steady)
        self.assertIn("checks: ['rate>0.99']", sweep)
        self.assertNotIn("token-soak", runner)
        self.assertNotIn("herd", runner)
        self.assertIn("dev token", runner)
        self.assertIn("--http-debug|--http-debug=*|--system-tags|--system-tags=*", runner)
        for profile in (sweep, burst):
            self.assertNotIn("sleep(", profile)

    @unittest.skipUnless(shutil.which("k6"), "k6 is not installed")
    def test_cursor_smoke_follows_page_info_with_skiptoken(self) -> None:
        requests: list[dict[str, list[str]]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"access_token": "header.payload.signature", "expires_in": 300}).encode())

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                requests.append(query)
                body = {"pageInfo": {"nextCursor": "cursor-value" if len(requests) == 1 else None}}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, _format: str, *args: object) -> None:
                _ = args

        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except PermissionError as error:
            raise unittest.SkipTest("loopback sockets are unavailable in this sandbox") from error
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifacts = root / "artifacts"
                artifacts.mkdir()
                seed = root / "ids.txt"
                secret = root / "operator.header"
                samples = artifacts / "samples.json"
                summary = artifacts / "summary.json"
                seed.write_text("record-1 LT-E-1\n", encoding="utf-8")
                secret.write_text("Authorization: Bearer header.payload.signature\n", encoding="ascii")
                secret.chmod(0o600)
                origin = f"http://127.0.0.1:{server.server_port}"
                profile = MODULE_PATH.parent.parent / "profiles/cursor-smoke.js"
                command = [
                        "k6",
                        "run",
                        "--quiet",
                        "--out",
                        f"json={samples}",
                        "-e",
                        f"ESTABLISHMENT_IDS_FILE={seed}",
                        "-e",
                        f"BREG_URL={origin}",
                        "-e",
                        f"AUTHORIZATION_HEADER_FILE={secret}",
                        "-e",
                        "FOLLOW_CURSOR=1",
                        "-e",
                        f"K6_SUMMARY_PATH={summary}",
                        str(profile),
                    ]
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                sample_summary = evidence._sample_summary(samples)
                self.assertIsNone(sample_summary["tagViolation"])
                self.assertNotIn("record-1", samples.read_text(encoding="utf-8"))
                self.assertNotIn("cursor-value", samples.read_text(encoding="utf-8"))
                self.assertIn("testRunDurationMs", summary.read_text(encoding="utf-8"))
                safety = artifacts / "safety.json"
                evidence.assert_safe(
                    argparse.Namespace(
                        artifact_dir=artifacts,
                        samples=samples,
                        secret_file=[secret],
                        seed_pool=[seed],
                        out=safety,
                    )
                )
                self.assertTrue(json.loads(safety.read_text(encoding="utf-8"))["safe"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(len(requests), 2)
        self.assertIn("$filter", requests[0])
        self.assertEqual(requests[1], {"accessProfile": ["business-operator"], "$skiptoken": ["cursor-value"]})

    def test_load_environment_prepares_one_dev_client_and_preserves_existing_output(self) -> None:
        fixture = REPOSITORY / "products/breg/acceptance/business-establishments"
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            loadenv.local_project(fixture, project)
            clients = (project / "dev-clients.yaml").read_text(encoding="utf-8")
            self.assertIn("id: loadtest-driver", clients)
            self.assertIn("accessProfiles: [business-operator]", clients)
            self.assertNotIn(
                "operator-without-purpose-is-concealed",
                (project / "tests/journeys.yaml").read_text(encoding="utf-8"),
            )
            sentinel = project / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.local_project(fixture, project)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
        self.assertIn(
            "operator-without-purpose-is-concealed",
            (fixture / "tests/journeys.yaml").read_text(encoding="utf-8"),
        )

    def test_dev_header_must_be_the_owned_private_session_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            header = project / ".breg/dev/secrets/loadtest-driver.header"
            header.parent.mkdir(parents=True)
            header.write_text("Authorization: Bearer header.payload.signature\n", encoding="ascii")
            header.chmod(0o600)
            fake = Path(directory) / "bregctl"
            fake.write_text(f"#!/bin/sh\nprintf '%s\\n' '{{\"headerFile\":\"{header}\"}}'\n", encoding="utf-8")
            fake.chmod(0o700)
            self.assertEqual(loadenv.fresh_header(fake, project, "loadtest-driver"), header.resolve())
            header.chmod(0o644)
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_header(fake, project, "loadtest-driver")

    def test_describe_accepts_only_the_recorded_build_of_this_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            root = repository / "products/breg/loadtest/.run"
            (root / "project").mkdir(parents=True)
            (root / ".launcher-owned").write_text("registry-stack-breg-loadtest-v2\n", encoding="ascii")
            bregctl = repository / "target/release/bregctl"
            bregctl.parent.mkdir(parents=True)
            bregctl.write_text("", encoding="utf-8")
            library = repository / "fips"
            library.mkdir()
            environment = {
                "breg_url": "http://127.0.0.1:1234",
                "bregctl": str(bregctl),
                "build_profile": "release",
                "project": str(root / "project"),
                "runtime_library_path": str(library),
            }
            (root / "env.json").write_text(json.dumps(environment), encoding="utf-8")
            self.assertEqual(
                loadenv.describe(root, repository),
                ("http://127.0.0.1:1234", str(bregctl), str(root / "project"), str(library)),
            )
            environment["build_profile"] = "debug"
            (root / "env.json").write_text(json.dumps(environment), encoding="utf-8")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.describe(root, repository)

    def test_seed_resumes_a_partial_seed_only_with_its_recorded_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / ".run"
            run_dir.mkdir()
            (run_dir / "env.json").write_text("{}", encoding="utf-8")
            described = subprocess.CompletedProcess([], 0, stdout="http://127.0.0.1:4321 /opt/bregctl /opt/project\n", stderr="")
            attempts: list[str] = []

            def seed_entity(_url, _route, records, _tokens, _workers, label):  # type: ignore[no-untyped-def]
                attempts.append(label)
                if label == "establishments" and attempts.count(label) == 1:
                    raise seed.SeedError("batch to establishments failed with 503")
                return [f"{label}-{index}" for index in range(len(records))]

            def run(*parameters: str) -> tuple[int, str]:
                stderr = io.StringIO()
                with (
                    unittest.mock.patch.object(seed.sys, "argv", ["seed.py", *parameters, "--run-dir", str(run_dir)]),
                    unittest.mock.patch.object(seed.subprocess, "run", return_value=described),
                    unittest.mock.patch.object(seed, "seed_entity", side_effect=seed_entity),
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(stderr),
                ):
                    return seed.main(), stderr.getvalue()

            marker = run_dir / "seed" / seed.SEED_IN_PROGRESS
            self.assertEqual(run("--count", "20", "--seed", "7")[0], 1)
            self.assertEqual(json.loads(marker.read_text(encoding="utf-8")), {"establishments": 20, "seed": 7})
            status, message = run("--count", "40", "--seed", "7")
            self.assertEqual(status, 2)
            self.assertIn("did not complete", message)
            self.assertIn("run down.sh and start a fresh environment", message)
            self.assertEqual(attempts, ["businesses", "establishments"])
            self.assertEqual(run("--count", "20", "--seed", "7")[0], 0)
            self.assertFalse(marker.exists())
            self.assertTrue((run_dir / "seed/seed-summary.json").is_file())
            status, message = run("--count", "20", "--seed", "7")
            self.assertEqual(status, 2)
            self.assertIn("already exists", message)

    def test_sampler_stop_fails_the_run_only_when_the_sampler_exited_early(self) -> None:
        runner = (MODULE_PATH.parent.parent / "run.sh").read_text(encoding="utf-8")
        start = runner.index("stop_samplers() {")
        function = runner[start : runner.index("\n}\n", start) + 3]
        # Each live sampler reports that it started, because a TERM that lands
        # between fork and exec meets the parent's trap and is lost.
        stops = """
bash -c 'touch "$1"; exec sleep 30' _ "$READY/running" &
db_pid=$!
until [[ -e "$READY/running" ]]; do sleep 0.01; done
stop_samplers
printf 'running %s\\n' "$sampler_status"
(exit 3) &
db_pid=$!
for _ in $(seq 1 100); do kill -0 "$db_pid" 2>/dev/null || break; sleep 0.05; done
stop_samplers
printf 'exited %s\\n' "$sampler_status"
"""
        # The trap leaves a live sampler behind at exit; if the trap did not stop
        # it, the sampler would hold the output pipes open past the timeout.
        traps = "".join(f"{line}\n" for line in runner.splitlines() if line.startswith("trap "))
        trapped = f"""
{traps}bash -c 'touch "$1"; exec sleep 30' _ "$READY/trapped" &
db_pid=$!
until [[ -e "$READY/trapped" ]]; do sleep 0.01; done
exit 7
"""
        with tempfile.TemporaryDirectory() as directory:
            results = [
                subprocess.run(
                    ["bash", "-c", f"set -euo pipefail\ndb_pid=\"\"\nsampler_status=0\n{function}{body}"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                    env={**os.environ, "READY": directory},
                )
                for body in (stops, trapped)
            ]
        self.assertEqual([result.returncode for result in results], [0, 7], [result.stderr for result in results])
        self.assertEqual(results[0].stdout.splitlines(), ["running 0", "exited 3"])
        self.assertEqual([result.stderr for result in results], ["", ""])
        self.assertIn("The database wait sampler failed with status $sampler_status", runner)
        self.assertIn('--db-sampler-exit-code "$sampler_status"', runner)

    def test_interrupt_ends_the_run_and_stops_a_live_sampler(self) -> None:
        runner = (MODULE_PATH.parent.parent / "run.sh").read_text(encoding="utf-8")
        start = runner.index("stop_samplers() {")
        function = runner[start : runner.index("\n}\n", start) + 3]
        traps = "".join(f"{line}\n" for line in runner.splitlines() if line.startswith("trap "))
        # Each rate starts a sampler and a k6 stand-in that, like k6, handles INT
        # and TERM and exits 105. A signal must end the loop, not only the current rate.
        loop = """
for rate in 1 2 3; do
  printf 'rate %s\\n' "$rate"
  bash -c 'printf "%s\\n" "$$" >"$1"; exec sleep 30' _ "$READY/sampler-$rate" >/dev/null 2>&1 &
  db_pid=$!
  until [[ -s "$READY/sampler-$rate" ]]; do sleep 0.01; done
  k6_status=0
  python3 -c 'import pathlib, signal, sys, time
for received in (signal.SIGINT, signal.SIGTERM): signal.signal(received, lambda *_: sys.exit(105))
pathlib.Path(sys.argv[1]).touch()
time.sleep(30)' "$READY/k6-$rate" || k6_status=$?
  stop_samplers
done
"""
        for received, expected in ((signal.SIGINT, 130), (signal.SIGTERM, 143)):
            with self.subTest(signal=received.name), tempfile.TemporaryDirectory() as directory:
                process = subprocess.Popen(
                    ["bash", "-c", f"set -euo pipefail\ndb_pid=\"\"\nsampler_status=0\n{function}{traps}{loop}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env={**os.environ, "READY": directory},
                    start_new_session=True,
                )
                try:
                    for _ in range(1000):
                        if (Path(directory) / "k6-1").exists():
                            break
                        time.sleep(0.01)
                    sampler = int((Path(directory) / "sampler-1").read_text(encoding="ascii"))
                    # A terminal delivers Ctrl-C to the whole foreground process group.
                    os.killpg(process.pid, received)
                    try:
                        stdout, stderr = process.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.fail(f"{received.name} did not end the loop; it moved on to the next rate")
                    self.assertEqual(process.returncode, expected, stderr)
                    self.assertEqual(stdout.splitlines(), ["rate 1"])
                    self.assertEqual(stderr, "")
                    with self.assertRaises(ProcessLookupError):
                        os.kill(sampler, 0)
                finally:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()

    def test_runner_refuses_to_disable_thresholds_or_replace_the_offered_load(self) -> None:
        runner = MODULE_PATH.parent.parent / "run.sh"
        environment = {name: value for name, value in os.environ.items() if not name.startswith("K6_")}
        load_changed = "without the manifest recording it"
        with tempfile.TemporaryDirectory() as directory:
            # Only dirname is on PATH, so an argument the runner fails to refuse
            # stops at the missing k6 instead of starting a run.
            os.symlink(shutil.which("dirname"), Path(directory) / "dirname")
            environment["PATH"] = directory
            for arguments, variables, message, reason in (
                (["--no-thresholds"], {}, "--no-thresholds is disabled", "a run without thresholds has no verdict"),
                (["--no-thresholds=true"], {}, "--no-thresholds=true is disabled", "a run without thresholds has no verdict"),
                ([], {"K6_NO_THRESHOLDS": "true"}, "K6_NO_THRESHOLDS is disabled", "a run without thresholds has no verdict"),
                (["-d", "30s"], {}, "-d is disabled", load_changed),
                (["-d30s"], {}, "-d30s is disabled", load_changed),
                (["-i", "5"], {}, "-i is disabled", load_changed),
                (["-i5"], {}, "-i5 is disabled", load_changed),
                (["--iterations=5"], {}, "--iterations=5 is disabled", load_changed),
                (["-u", "10"], {}, "-u is disabled", load_changed),
                (["--vus", "10"], {}, "--vus is disabled", load_changed),
                (["-s", "10s:5"], {}, "-s is disabled", load_changed),
                (["--stage=10s:5"], {}, "--stage=10s:5 is disabled", load_changed),
                (["--execution-segment", "0:1/2"], {}, "--execution-segment is disabled", load_changed),
                (["--config", "k6.json"], {}, "--config is disabled", load_changed),
                (["-ck6.json"], {}, "-ck6.json is disabled", load_changed),
                (["--execution-segment-sequence=0,1/2,1"], {}, "--execution-segment-sequence=0,1/2,1 is disabled", load_changed),
                (["--rps=10"], {}, "--rps=10 is disabled", load_changed),
                (["-e", "OPS=500"], {}, "-e is disabled", load_changed),
                (["-eDURATION=1h"], {}, "-eDURATION=1h is disabled", load_changed),
                (["--env", "OPS=500"], {}, "--env is disabled", load_changed),
                (["--env=DURATION=1h"], {}, "--env=DURATION=1h is disabled", load_changed),
                ([], {"K6_VUS": "10"}, "K6_VUS", load_changed),
                ([], {"K6_ITERATIONS": "5"}, "K6_ITERATIONS", load_changed),
                ([], {"K6_DURATION": "1h"}, "K6_DURATION", load_changed),
                ([], {"K6_STAGES": "10s:5"}, "K6_STAGES", load_changed),
                ([], {"K6_RPS": "10"}, "K6_RPS", load_changed),
                ([], {"K6_CONFIG": "k6.json"}, "K6_CONFIG", load_changed),
            ):
                with self.subTest(arguments=arguments, variables=variables):
                    result = subprocess.run(
                        [shutil.which("bash"), str(runner), "--profile", "steady", *arguments],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                        env={**environment, **variables},
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertIn(reason, result.stderr)
        # The sweep warmup is excluded from evidence and passes the flag to k6 itself.
        self.assertIn("k6 run --quiet --no-thresholds --summary-mode disabled", runner.read_text(encoding="utf-8"))

    def test_runner_takes_ops_and_duration_in_either_form_and_keeps_them_from_k6(self) -> None:
        runner = (MODULE_PATH.parent.parent / "run.sh").read_text(encoding="utf-8")
        start = runner.index("pass_through=()\n")
        parse = runner[start : runner.index("\ndone\n", start) + 6]
        report = 'printf \'%s|%s|%s\\n\' "${OPS-unset}" "${DURATION-unset}" "${pass_through[*]-}"\n'
        for arguments in (
            ["--ops", "75", "--duration", "90s", "--quiet"],
            ["--ops=75", "--duration=90s", "--quiet"],
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["bash", "-c", f"set -euo pipefail\nusage() {{ exit 2; }}\n{parse}{report}", "_", *arguments],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                    env={name: value for name, value in os.environ.items() if name not in ("OPS", "DURATION")},
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "75|90s|--quiet\n")

    def test_shell_entrypoints_parse(self) -> None:
        loadtest = MODULE_PATH.parent.parent
        # bash -n checks only its first file operand, so check each script alone.
        for script in ("up.sh", "down.sh", "run.sh", "dbstats.sh"):
            subprocess.run(["bash", "-n", str(loadtest / script)], check=True)
        up = (loadtest / "up.sh").read_text(encoding="utf-8")
        down = (loadtest / "down.sh").read_text(encoding="utf-8")
        self.assertIn("trap cleanup_failed_start EXIT", up)
        self.assertIn("registry_cargo_build", up)
        self.assertIn("--runtime-library-path", up)
        self.assertIn("bregctl\" --format json dev start", up)
        self.assertIn("dev stop --remove", down)
        self.assertNotIn("rm -rf", up + down)

    def test_database_samples_are_one_json_object_per_line(self) -> None:
        # psql prints json_agg arrays across several lines; jsonb text output is
        # always one line, which the JSON Lines wait sampler depends on.
        dbstats = (MODULE_PATH.parent.parent / "dbstats.sh").read_text(encoding="utf-8")
        self.assertNotIn(")::text;", dbstats)
        self.assertEqual(dbstats.count(")::jsonb::text;"), 2)


if __name__ == "__main__":
    unittest.main()
