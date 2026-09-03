from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import tempfile
import threading
import unittest
import unittest.mock as mock
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("evidence.py")
SPEC = importlib.util.spec_from_file_location("loadtest_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class EvidenceTests(unittest.TestCase):
    def test_command_output_accepts_a_successful_command_with_no_output(self) -> None:
        self.assertEqual(evidence._command_output(["python3", "-c", "pass"]), "")

    def test_manifest_keeps_only_whitelisted_non_secret_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "env.json"
            seed = root / "seed.json"
            out = root / "manifest.json"
            environment.write_text(
                json.dumps(
                    {
                        "pool_max": 32,
                        "breg_url": "http://secret-host",
                        "driver_secret": "/secret/path",
                    }
                ),
                encoding="utf-8",
            )
            seed.write_text(
                json.dumps({"seed": 7, "establishments": 100, "first_record_id": "do-not-copy"}),
                encoding="utf-8",
            )
            arguments = argparse.Namespace(
                environment=environment,
                seed_summary=seed,
                out=out,
                repository=root,
                profile="steady",
                parameter=["offeredOps=50", "duration=10m"],
            )
            with (
                mock.patch.object(
                    evidence,
                    "_git_metadata",
                    return_value={"revision": "a" * 40, "dirty": False},
                ),
                mock.patch.object(evidence, "_command_output", return_value="test-version"),
            ):
                evidence.create_manifest(arguments)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            rendered = out.read_text(encoding="utf-8")
            self.assertEqual(manifest["seed"], {"establishments": 100, "seed": 7})
            self.assertEqual(manifest["configuration"]["parameters"]["offeredOps"], "50")
            self.assertNotIn("secret-host", rendered)
            self.assertNotIn("do-not-copy", rendered)

    def test_safety_check_rejects_secret_record_id_and_unsafe_sample_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "secret"
            seed_pool = root / "seed.txt"
            samples = root / "samples.json"
            secret.write_text("super-secret-value", encoding="utf-8")
            seed_pool.write_text("record-123 LT-E-1\n", encoding="utf-8")
            (root / "artifact.txt").write_text("super-secret-value record-123", encoding="utf-8")
            samples.write_text(
                json.dumps(
                    {
                        "type": "Point",
                        "metric": "http_req_duration",
                        "data": {"value": 1, "tags": {"name": "get", "url": "http://example.invalid"}},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            arguments = argparse.Namespace(
                artifact_dir=root,
                samples=samples,
                secret_file=[secret],
                seed_pool=[seed_pool],
                out=root / "safety.json",
            )
            with self.assertRaises(evidence.EvidenceError):
                evidence.assert_safe(arguments)
            report = json.loads(arguments.out.read_text(encoding="utf-8"))
            self.assertFalse(report["safe"])
            self.assertTrue(any("unsafe tags" in item for item in report["violations"]))

    def test_summary_reports_operations_http_rate_latency_and_wait_peaks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            k6_summary = root / "summary.json"
            samples = root / "samples.json"
            telemetry = root / "telemetry.jsonl"
            db_after = root / "db-after.json"
            db_waits = root / "db-waits.jsonl"
            safety = root / "safety.json"
            out = root / "result.json"
            manifest.write_text(
                json.dumps(
                    {
                        "profile": "steady",
                        "status": "passed",
                        "configuration": {"parameters": {"offeredOps": "2"}},
                    }
                ),
                encoding="utf-8",
            )
            k6_summary.write_text(
                json.dumps(
                    {
                        "state": {"testRunDurationMs": 2000},
                        "metrics": {
                            "iterations": {"values": {"count": 4}},
                            "http_reqs": {"values": {"count": 6}},
                            "dropped_iterations": {"values": {"count": 0}},
                            "http_req_failed": {
                                "values": {"rate": 0},
                                "thresholds": {"rate==0": {"ok": True}},
                            },
                            "http_req_duration": {"values": {"med": 20, "p(95)": 30, "p(99)": 40, "max": 50}},
                        },
                    }
                ),
                encoding="utf-8",
            )
            sample_items = [
                {
                    "type": "Point",
                    "metric": "http_req_duration",
                    "data": {
                        "value": value,
                        "tags": {"name": "get", "scenario": "steady", "status": "200"},
                    },
                }
                for value in (10, 20, 30, 40)
            ] + [
                {
                    "type": "Point",
                    "metric": "http_reqs",
                    "data": {
                        "value": 1,
                        "tags": {"name": "get", "scenario": "steady", "status": status},
                    },
                }
                for status in ("200", "200", "504")
            ]
            samples.write_text("".join(json.dumps(item) + "\n" for item in sample_items), encoding="utf-8")
            telemetry.write_text(
                json.dumps(
                    {
                        "timestamp": "now",
                        "metrics": [
                            {"name": "breg_pool_connections", "labels": {"state": "waiting"}, "value": 3}
                        ],
                        "processes": {"server": {"cpuPercent": 12.5, "rssBytes": 4096}},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            db_after.write_text(json.dumps({"auditRows": 10}), encoding="utf-8")
            db_waits.write_text(
                json.dumps({"auditLockWaiters": 2, "lockWaiters": 3, "blockedBackends": 1}) + "\n",
                encoding="utf-8",
            )
            safety.write_text(json.dumps({"safe": True}), encoding="utf-8")
            evidence.summarize(
                argparse.Namespace(
                    manifest=manifest,
                    k6_summary=k6_summary,
                    samples=samples,
                    telemetry=telemetry,
                    db_after=db_after,
                    db_waits=db_waits,
                    safety=safety,
                    k6_exit_code=0,
                    out=out,
                )
            )
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["achieved"]["operationsPerSecond"], 2)
            self.assertEqual(result["achieved"]["httpRequestsPerSecond"], 3)
            self.assertEqual(result["achieved"]["timeouts504"], 1)
            self.assertEqual(result["latency"]["byOperation"]["get"]["p95Ms"], 38.5)
            self.assertEqual(result["phases"]["steady"]["httpRequests"], 3)
            self.assertEqual(result["phases"]["steady"]["timeouts504"], 1)
            self.assertEqual(result["telemetry"]["poolWaitingPeak"], 3)
            self.assertEqual(result["database"]["waits"]["auditLockWaitersPeak"], 2)
            self.assertTrue(result["pass"])

    def test_profiles_pin_held_sweep_burst_recovery_and_one_shot_herd(self) -> None:
        loadtest = MODULE_PATH.parent.parent
        workload = (loadtest / "lib/workload.js").read_text(encoding="utf-8")
        sweep = (loadtest / "profiles/sweep.js").read_text(encoding="utf-8")
        burst = (loadtest / "profiles/burst.js").read_text(encoding="utf-8")
        herd = (loadtest / "profiles/herd.js").read_text(encoding="utf-8")
        runner = (loadtest / "run.sh").read_text(encoding="utf-8")
        self.assertIn("body.pageInfo.nextCursor", workload)
        self.assertIn("$skiptoken=", workload)
        self.assertIn("executor: 'constant-arrival-rate'", sweep)
        self.assertNotIn("ramping-arrival-rate", sweep)
        self.assertIn("recovery:", burst)
        self.assertIn("'http_req_failed{scenario:recovery}'", burst)
        self.assertIn("executor: 'per-vu-iterations'", herd)
        self.assertIn("--http-debug|--http-debug=*|--system-tags|--system-tags=*", runner)
        for profile in (sweep, burst, herd):
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
                secret = root / "secret.txt"
                samples = artifacts / "samples.json"
                summary = artifacts / "summary.json"
                seed.write_text("record-1 LT-E-1\n", encoding="utf-8")
                secret.write_text("unrelated-secret-value", encoding="utf-8")
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
                        f"TOKEN_URL={origin}/token",
                        "-e",
                        "CLIENT_ID=test",
                        "-e",
                        "CLIENT_SECRET=test",
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

    def test_shell_entrypoints_parse(self) -> None:
        loadtest = MODULE_PATH.parent.parent
        subprocess.run(
            [
                "bash",
                "-n",
                str(loadtest / "up.sh"),
                str(loadtest / "down.sh"),
                str(loadtest / "run.sh"),
                str(loadtest / "dbstats.sh"),
            ],
            check=True,
        )
        up = (loadtest / "up.sh").read_text(encoding="utf-8")
        down = (loadtest / "down.sh").read_text(encoding="utf-8")
        self.assertIn("trap cleanup_failed_start EXIT", up)
        self.assertIn("org.registrystack.loadtest=breg", up)
        self.assertIn("^breg-loadtest-[0-9]+-[0-9]+$", down)
        self.assertIn('ps -ww -p "$pid" -o command=', down)


if __name__ == "__main__":
    unittest.main()
