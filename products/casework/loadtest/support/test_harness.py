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
LOADTEST = MODULE_PATH.parent.parent
REPOSITORY = MODULE_PATH.parents[4]
SPEC = importlib.util.spec_from_file_location("loadtest_evidence", REPOSITORY / "scripts/loadtest/evidence.py")
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)
LOADENV_SPEC = importlib.util.spec_from_file_location("casework_loadtest_environment", MODULE_PATH)
assert LOADENV_SPEC and LOADENV_SPEC.loader
loadenv = importlib.util.module_from_spec(LOADENV_SPEC)
LOADENV_SPEC.loader.exec_module(loadenv)
SEED_SPEC = importlib.util.spec_from_file_location("casework_loadtest_seed", LOADTEST / "seed.py")
assert SEED_SPEC and SEED_SPEC.loader
seed = importlib.util.module_from_spec(SEED_SPEC)
SEED_SPEC.loader.exec_module(seed)

EXAMPLE = REPOSITORY / "products/casework/examples/standalone-decision"
HEADER = "Authorization: Bearer header.payload.signature\n"


class LifecycleStub:
    """A loopback stand-in for the unified review surfaces the smoke profile drives."""

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []
        self.decided = False
        self.lock = threading.Lock()

    def handler(self) -> type[BaseHTTPRequestHandler]:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self) -> tuple[str, dict[str, list[str]]]:
                parts = urllib.parse.urlsplit(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with stub.lock:
                    stub.requests.append(
                        {
                            "method": self.command,
                            "path": parts.path,
                            "query": urllib.parse.parse_qs(parts.query),
                            "profile": self.headers.get("Registry-Casework-Profile"),
                            "ifMatch": self.headers.get("If-Match"),
                            "idempotencyKey": self.headers.get("Idempotency-Key"),
                            "authorization": self.headers.get("Authorization"),
                            "bodyLength": len(body),
                        }
                    )
                return parts.path, urllib.parse.parse_qs(parts.query)

            def _send(self, status: int, document: object | None = None) -> None:
                payload = json.dumps(document).encode() if document is not None else b""
                self.send_response(status)
                if payload:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
                path, _ = self._record()
                if path == "/v1/review-requests":
                    self._send(201, {"requestId": "request-new", "state": "reviewing"})
                elif path == "/v1/review-tasks/task-new/claim":
                    self._send(200, {"taskId": "task-new", "revision": 2, "state": "claimed"})
                elif path == "/v1/review-tasks/task-new/decisions":
                    stub.decided = True
                    self._send(204)
                else:
                    self._send(404, {"code": "not-found"})

            def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
                path, _ = self._record()
                self._send(200, {"revision": 3} if path == "/v1/review-tasks/task-new/draft" else None)

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                path, query = self._record()
                if path == "/v1/review-tasks":
                    if "cursor" in query:
                        items = [{"taskId": "task-new", "requestId": "request-new", "state": "open", "revision": 1}]
                        self._send(200, {"items": items, "nextCursor": None})
                    else:
                        items = [{"taskId": "task-read-1", "requestId": "request-read-1", "state": "open", "revision": 1}]
                        self._send(200, {"items": items, "nextCursor": "cursor-value"})
                elif path == "/v1/review-requests/request-new/result":
                    if stub.decided:
                        self._send(200, {"outcome": "confirmed"})
                    else:
                        self._send(202, {"state": "reviewing"})
                elif path in (
                    "/v1/review-requests/request-new",
                    "/v1/review-tasks/task-new",
                    "/v1/review-tasks/task-new/context",
                ):
                    self._send(200, {"ok": True})
                else:
                    self._send(404, {"code": "not-found"})

            def log_message(self, _format: str, *args: object) -> None:
                _ = args

        return Handler


class RegistryCaseworkHarnessTests(unittest.TestCase):
    def test_profiles_pin_guards_rates_and_recovery(self) -> None:
        workload = (LOADTEST / "lib/workload.js").read_text(encoding="utf-8")
        smoke = (LOADTEST / "profiles/smoke.js").read_text(encoding="utf-8")
        steady = (LOADTEST / "profiles/steady.js").read_text(encoding="utf-8")
        burst = (LOADTEST / "profiles/burst.js").read_text(encoding="utf-8")
        runner = (LOADTEST / "run.sh").read_text(encoding="utf-8")
        for profile in (smoke, steady, burst):
            self.assertIn("systemTags: SAFE_SYSTEM_TAGS", profile)
            self.assertIn("handleSummary = writeSummary", profile)
            self.assertNotIn("sleep(", profile)
            self.assertNotIn("export function setup", profile)
        self.assertIn("lifecycles_completed: ['count==1']", smoke)
        self.assertIn("task_pages_followed: ['count>0']", smoke)
        self.assertIn("dropped_iterations: ['count==0']", steady)
        self.assertIn("http_req_failed: ['rate==0']", steady)
        self.assertIn("executor: 'constant-arrival-rate'", steady)
        self.assertIn("recovery:", burst)
        self.assertIn("'http_req_failed{scenario:recovery}'", burst)
        self.assertIn("checks: ['rate>0.99']", burst)
        self.assertIn("'checks{scenario:recovery}': ['rate==1']", burst)
        self.assertIn("RANDOM_SEED", workload)
        self.assertNotIn("Math.random", workload)
        self.assertIn("--http-debug|--http-debug=*|--system-tags|--system-tags=*", runner)
        self.assertIn("K6_HTTP_DEBUG", runner)
        self.assertIn("require_token_window", runner)
        self.assertIn("--product casework", runner)
        self.assertIn("--secret-file \"$STAFF_HEADER_FILE\"", runner)
        self.assertIn("--secret-file \"$PRODUCER_HEADER_FILE\"", runner)
        self.assertIn("\"$evidence\" finish", runner)

    def test_manifest_parameters_are_accepted_by_the_shared_evidence_helper(self) -> None:
        runner = (LOADTEST / "run.sh").read_text(encoding="utf-8")
        for name in ("offeredOps", "flowOps", "duration", "followCursor", "randomSeed", "baselineOps", "peakOps",
                     "baselineDuration", "rampDuration", "peakDuration", "recoveryDuration"):
            self.assertIn(f"\"{name}=", runner)
            self.assertIn(name, evidence.ALLOWED_PARAMETERS)

    @unittest.skipUnless(shutil.which("k6"), "k6 is not installed")
    def test_steady_decision_flow_rate_defaults_to_a_tenth_and_is_adjustable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pool = root / "tasks.txt"
            pool.write_text("task-1 request-1\n", encoding="utf-8")
            header = root / "staff.header"
            header.write_text(HEADER, encoding="ascii")

            def inspect(*variables: str) -> subprocess.CompletedProcess[str]:
                command = ["k6", "inspect"]
                for variable in (
                    "CASEWORK_URL=http://127.0.0.1:9",
                    f"READ_TASKS_FILE={pool}",
                    f"STAFF_HEADER_FILE={header}",
                    f"PRODUCER_HEADER_FILE={header}",
                    "RUN_NONCE=20260925T000000Z-1",
                    *variables,
                ):
                    command += ["-e", variable]
                command.append(str(LOADTEST / "profiles/steady.js"))
                return subprocess.run(command, capture_output=True, text=True, timeout=60)

            def rates(*variables: str) -> tuple[int, int]:
                result = inspect(*variables)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                scenarios = json.loads(result.stdout)["scenarios"]
                return scenarios["inbox"]["rate"], scenarios["decisions"]["rate"]

            self.assertEqual(rates("OPS=20"), (18, 2))
            self.assertEqual(rates("OPS=20", "FLOW_OPS=5"), (15, 5))
            for invalid in ("FLOW_OPS=20", "FLOW_OPS=0", "FLOW_OPS=1.5"):
                result = inspect("OPS=20", invalid)
                self.assertNotEqual(result.returncode, 0, invalid)
                self.assertIn("FLOW_OPS", result.stderr + result.stdout)

    @unittest.skipUnless(shutil.which("k6"), "k6 is not installed")
    def test_smoke_lifecycle_follows_the_inbox_and_decides_with_current_revisions(self) -> None:
        stub = LifecycleStub()
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), stub.handler())
        except PermissionError as error:
            raise unittest.SkipTest("loopback sockets are unavailable in this sandbox") from error
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifacts = root / "artifacts"
                artifacts.mkdir()
                read_pool = root / "read-tasks.txt"
                read_pool.write_text("task-read-1 request-read-1\n", encoding="utf-8")
                staff = root / "staff.header"
                producer = root / "producer.header"
                for header in (staff, producer):
                    header.write_text(HEADER, encoding="ascii")
                    header.chmod(0o600)
                samples = artifacts / "k6-samples.json"
                summary = artifacts / "k6-summary.json"
                command = [
                    "k6",
                    "run",
                    "--quiet",
                    "--out",
                    f"json={samples}",
                    "-e",
                    f"CASEWORK_URL=http://127.0.0.1:{server.server_port}",
                    "-e",
                    f"READ_TASKS_FILE={read_pool}",
                    "-e",
                    f"STAFF_HEADER_FILE={staff}",
                    "-e",
                    f"PRODUCER_HEADER_FILE={producer}",
                    "-e",
                    "RUN_NONCE=20260925T000000Z-1",
                    "-e",
                    f"K6_SUMMARY_PATH={summary}",
                    str(LOADTEST / "profiles/smoke.js"),
                ]
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                sample_text = samples.read_text(encoding="utf-8")
                self.assertIsNone(evidence._sample_summary(samples)["tagViolation"])
                for value in ("task-new", "request-new", "cursor-value", "task-read-1", "signature"):
                    self.assertNotIn(value, sample_text)
                self.assertIn("testRunDurationMs", summary.read_text(encoding="utf-8"))
                safety = artifacts / "safety.json"
                evidence.assert_safe(
                    argparse.Namespace(
                        artifact_dir=artifacts,
                        samples=samples,
                        secret_file=[staff, producer],
                        seed_pool=[read_pool],
                        out=safety,
                    )
                )
                self.assertTrue(json.loads(safety.read_text(encoding="utf-8"))["safe"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        by_path = {(entry["method"], entry["path"]): entry for entry in stub.requests}
        self.assertEqual(by_path[("POST", "/v1/review-requests")]["profile"], "requester")
        self.assertRegex(str(by_path[("POST", "/v1/review-requests")]["idempotencyKey"]), r"^lt-20260925T000000Z-1-create-")
        claim = by_path[("POST", "/v1/review-tasks/task-new/claim")]
        self.assertEqual((claim["profile"], claim["ifMatch"], claim["bodyLength"]), ("staff", '"1"', 0))
        self.assertEqual(by_path[("PUT", "/v1/review-tasks/task-new/draft")]["ifMatch"], '"2"')
        self.assertEqual(by_path[("POST", "/v1/review-tasks/task-new/decisions")]["ifMatch"], '"3"')
        lists = [entry for entry in stub.requests if entry["path"] == "/v1/review-tasks"]
        self.assertEqual(len(lists), 2)
        self.assertEqual(lists[1]["query"]["cursor"], ["cursor-value"])
        self.assertTrue(all(entry["authorization"] == "Bearer header.payload.signature" for entry in stub.requests))
        results = [entry for entry in stub.requests if entry["path"] == "/v1/review-requests/request-new/result"]
        self.assertEqual(len(results), 2)

    def test_local_project_rewrites_the_producer_binding_and_preserves_existing_output(self) -> None:
        source_policy = (EXAMPLE / "casework.yaml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            loadenv.local_project(EXAMPLE, project, 45678, "agent-0123abcd")
            policy = (project / "casework.yaml").read_text(encoding="utf-8")
            self.assertIn("    issuer: http://127.0.0.1:45678\n", policy)
            self.assertIn("    subject: agent-0123abcd\n", policy)
            self.assertNotIn(loadenv.EXAMPLE_ISSUER_LINE, policy)
            clients = (project / "dev-clients.yaml").read_text(encoding="utf-8")
            self.assertIn("id: loadtest-producer", clients)
            self.assertIn("id: loadtest-staff", clients)
            self.assertIn("queue: decisions", clients)
            sentinel = project / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.local_project(EXAMPLE, project, 45678, "agent-0123abcd")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.local_project(EXAMPLE, Path(directory) / "other", 45678, "subject with spaces")
        self.assertEqual((EXAMPLE / "casework.yaml").read_text(encoding="utf-8"), source_policy)

    def test_dev_header_must_be_the_owned_private_session_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            header = project / ".casework/dev/secrets/loadtest-staff.header"
            header.parent.mkdir(parents=True)
            header.write_text(HEADER, encoding="ascii")
            header.chmod(0o600)
            fake = Path(directory) / "caseworkctl"
            fake.write_text(f"#!/bin/sh\nprintf '%s\\n' '{{\"headerFile\":\"{header}\"}}'\n", encoding="utf-8")
            fake.chmod(0o700)
            self.assertEqual(loadenv.fresh_header(fake, project, "loadtest-staff"), header.resolve())
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_header(fake, project, "loadtest-producer")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_header(fake, project, "loadtest-admin")
            header.write_text("Authorization: Bearer opaque\n", encoding="ascii")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_header(fake, project, "loadtest-staff")
            header.write_text(HEADER, encoding="ascii")
            header.chmod(0o644)
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.fresh_header(fake, project, "loadtest-staff")

    def test_environment_records_only_the_owned_ready_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / ".run"
            project = root / "project"
            state = project / ".casework/dev/state.json"
            state.parent.mkdir(parents=True)
            (root / ".launcher-owned").write_text(loadenv.MARKER + "\n", encoding="ascii")
            state.write_text(json.dumps({"containerId": "a" * 64}), encoding="utf-8")
            state.chmod(0o600)
            caseworkctl = Path(directory) / "caseworkctl"
            caseworkctl.write_text("", encoding="utf-8")
            report = {
                "status": "ready",
                "project": str(project),
                "stateFile": str(state),
                "caseworkUrl": "http://127.0.0.1:4321",
                "clients": [{"id": "loadtest-staff"}, {"id": "loadtest-producer"}],
            }
            report_path = root / "dev-report.json"
            report_path.write_text(json.dumps({**report, "caseworkUrl": "http://192.0.2.1:4321"}), encoding="utf-8")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.write_environment(root, report_path, caseworkctl, "release", "")
            report_path.write_text(json.dumps(report), encoding="utf-8")
            loadenv.write_environment(root, report_path, caseworkctl, "release", "")
            environment = json.loads((root / "env.json").read_text(encoding="utf-8"))
            self.assertEqual(environment["casework_url"], "http://127.0.0.1:4321")
            self.assertEqual(environment["pool_max"], 32)
            self.assertEqual(environment["database"], {"container": "a" * 64, "database": "casework_dev"})
            self.assertEqual(sorted(environment), sorted(
                ["build_profile", "casework_url", "caseworkctl", "database", "pool_max", "project",
                 "runtime_library_path"]
            ))
            with self.assertRaises(FileExistsError):
                loadenv.write_environment(root, report_path, caseworkctl, "release", "")

    def test_describe_accepts_only_the_recorded_build_of_this_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            root = repository / "products/casework/loadtest/.run"
            (root / "project").mkdir(parents=True)
            (root / ".launcher-owned").write_text(loadenv.MARKER + "\n", encoding="ascii")
            caseworkctl = repository / "target/release/caseworkctl"
            caseworkctl.parent.mkdir(parents=True)
            caseworkctl.write_text("", encoding="utf-8")
            library = repository / "fips"
            library.mkdir()
            environment = {
                "casework_url": "http://127.0.0.1:1234",
                "caseworkctl": str(caseworkctl),
                "build_profile": "release",
                "project": str(root / "project"),
                "runtime_library_path": str(library),
            }
            (root / "env.json").write_text(json.dumps(environment), encoding="utf-8")
            self.assertEqual(
                loadenv.describe(root, repository),
                ("http://127.0.0.1:1234", str(caseworkctl), str(root / "project"), str(library)),
            )
            for field, value in (
                ("build_profile", "debug"),
                ("casework_url", "http://127.0.0.1:1234/v1"),
                ("runtime_library_path", f"{library}:/tmp"),
            ):
                (root / "env.json").write_text(json.dumps({**environment, field: value}), encoding="utf-8")
                with self.assertRaises(loadenv.LoadtestError):
                    loadenv.describe(root, repository)
            (root / ".launcher-owned").write_text("registry-stack-breg-loadtest-v2\n", encoding="ascii")
            (root / "env.json").write_text(json.dumps(environment), encoding="utf-8")
            with self.assertRaises(loadenv.LoadtestError):
                loadenv.describe(root, repository)

    def test_seed_refuses_to_run_over_a_partial_seed(self) -> None:
        self.addCleanup(os.umask, os.umask(0o077))
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / ".run"
            run_dir.mkdir()
            (run_dir / "env.json").write_text("{}", encoding="utf-8")
            described = subprocess.CompletedProcess(
                [], 0, stdout="http://127.0.0.1:4321 /opt/caseworkctl /opt/project\n", stderr=""
            )
            arguments = ["seed.py", "--count", "200", "--run-dir", str(run_dir)]
            stderr = io.StringIO()
            with (
                unittest.mock.patch.object(seed.sys, "argv", arguments),
                unittest.mock.patch.object(seed.subprocess, "run", return_value=described),
                unittest.mock.patch.object(
                    seed, "create_requests", side_effect=seed.SeedError("create worker failed")
                ) as create,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(seed.main(), 1)
                marker = json.loads((run_dir / "seed" / seed.SEED_IN_PROGRESS).read_text(encoding="utf-8"))
                self.assertEqual(marker["reviewRequests"], 200)
                self.assertEqual(create.call_args.args[-1], marker["nonce"])
                self.assertEqual(seed.main(), 2)
            self.assertEqual(create.call_count, 1)
            self.assertIn("did not complete", stderr.getvalue())
            self.assertIn("run down.sh and start a fresh environment", stderr.getvalue())
            with self.assertRaisesRegex(seed.SeedError, "did not complete"):
                seed.begin_seed(run_dir / "seed", {"nonce": "another"})
            (run_dir / "seed" / seed.SEED_IN_PROGRESS).unlink()
            with self.assertRaisesRegex(seed.SeedError, "already exists"):
                seed.begin_seed(run_dir / "seed", {"nonce": "another"})

    def test_sampler_stop_fails_the_run_only_when_the_sampler_exited_early(self) -> None:
        runner = (LOADTEST / "run.sh").read_text(encoding="utf-8")
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
        runner = (LOADTEST / "run.sh").read_text(encoding="utf-8")
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
        runner = LOADTEST / "run.sh"
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
            ):
                with self.subTest(arguments=arguments, variables=variables):
                    result = subprocess.run(
                        [shutil.which("bash"), str(runner), "--profile", "smoke", *arguments],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                        env={**environment, **variables},
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertIn(reason, result.stderr)

    def test_runner_takes_ops_and_duration_in_either_form_and_keeps_them_from_k6(self) -> None:
        runner = (LOADTEST / "run.sh").read_text(encoding="utf-8")
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
        for script in ("up.sh", "down.sh", "run.sh", "dbstats.sh"):
            subprocess.run(["bash", "-n", str(LOADTEST / script)], check=True)
        up = (LOADTEST / "up.sh").read_text(encoding="utf-8")
        down = (LOADTEST / "down.sh").read_text(encoding="utf-8")
        run = (LOADTEST / "run.sh").read_text(encoding="utf-8")
        dbstats = (LOADTEST / "dbstats.sh").read_text(encoding="utf-8")
        self.assertIn("trap cleanup_failed_start EXIT", up)
        self.assertIn("registry_cargo_build", up)
        self.assertIn("--runtime-library-path", up)
        self.assertIn("caseworkctl\" --format json dev start", up)
        self.assertIn("dev stop --remove", up)
        self.assertIn("dev stop --remove", down)
        self.assertIn("registry-stack-casework-loadtest-v1", down)
        self.assertIn("DYLD_FALLBACK_LIBRARY_PATH", run + down)
        for name in ("auditLockWaiters", "lockWaiters", "blockedBackends"):
            self.assertIn(f"'{name}'", dbstats)
        # json_agg output spans lines; the jsonb cast keeps each wait sample on
        # the single line the JSON-lines reader expects.
        self.assertEqual(dbstats.count(")::jsonb::text;"), 2)
        self.assertNotIn(")::text;", dbstats)
        for text in (up, down, run, dbstats):
            self.assertNotIn("rm -rf", text)


if __name__ == "__main__":
    unittest.main()
