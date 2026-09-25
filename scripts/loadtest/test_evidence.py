from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock as mock
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
                        "build_profile": "release",
                        "breg_url": "http://secret-host",
                        "private_setting": "/secret/path",
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
                product="breg",
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
            self.assertEqual(manifest["configuration"]["buildProfile"], "release")
            self.assertEqual(manifest["configuration"]["poolMax"], 32)
            self.assertEqual(manifest["product"], "breg")
            self.assertNotIn("secret-host", rendered)
            self.assertNotIn("do-not-copy", rendered)

    def test_manifest_accepts_a_product_without_pool_or_seed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "env.json"
            environment.write_text(json.dumps({"evidence_url": "http://secret-host"}), encoding="utf-8")
            out = root / "manifest.json"
            arguments = argparse.Namespace(
                environment=environment,
                seed_summary=None,
                out=out,
                repository=root,
                product="evidence",
                profile="smoke",
                parameter=[],
            )
            with (
                mock.patch.object(evidence, "_git_metadata", return_value={"revision": "a" * 40, "dirty": False}),
                mock.patch.object(evidence, "_command_output", return_value="test-version"),
            ):
                evidence.create_manifest(arguments)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(manifest["seed"], {})
            self.assertEqual(manifest["configuration"], {"parameters": {}})
            self.assertNotIn("secret-host", out.read_text(encoding="utf-8"))

    def test_summary_without_database_evidence_reports_no_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"product": "evidence", "profile": "smoke", "configuration": {"parameters": {}}}),
                encoding="utf-8",
            )
            k6_summary = root / "summary.json"
            k6_summary.write_text(json.dumps({"state": {"testRunDurationMs": 1000}, "metrics": {}}), encoding="utf-8")
            safety = root / "safety.json"
            safety.write_text(json.dumps({"safe": True}), encoding="utf-8")
            out = root / "result.json"
            evidence.summarize(
                argparse.Namespace(
                    manifest=manifest,
                    k6_summary=k6_summary,
                    samples=root / "missing-samples.json",
                    db_after=None,
                    db_waits=None,
                    db_sampler_exit_code=0,
                    safety=safety,
                    k6_exit_code=0,
                    out=out,
                )
            )
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertIsNone(result["database"])
            self.assertEqual(result["product"], "evidence")

    def test_summary_fails_a_run_that_evaluated_no_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"product": "evidence", "profile": "steady", "configuration": {"parameters": {}}}),
                encoding="utf-8",
            )
            samples = root / "samples.json"
            samples.write_text("", encoding="utf-8")
            safety = root / "safety.json"
            safety.write_text(json.dumps({"safe": True}), encoding="utf-8")
            for name, failed_requests, passed in (
                ("evaluated", {"values": {"rate": 0}, "thresholds": {"rate==0": {"ok": True}}}, True),
                ("--no-thresholds", {"values": {"rate": 0}}, False),
                ("empty threshold set", {"values": {"rate": 0}, "thresholds": {}}, False),
            ):
                with self.subTest(name):
                    k6_summary = root / "summary.json"
                    k6_summary.write_text(
                        json.dumps(
                            {"state": {"testRunDurationMs": 1000}, "metrics": {"http_req_failed": failed_requests}}
                        ),
                        encoding="utf-8",
                    )
                    out = root / "result.json"
                    evidence.summarize(
                        argparse.Namespace(
                            manifest=manifest,
                            k6_summary=k6_summary,
                            samples=samples,
                            db_after=None,
                            db_waits=None,
                            db_sampler_exit_code=0,
                            safety=safety,
                            k6_exit_code=0,
                            out=out,
                        )
                    )
                    self.assertIs(json.loads(out.read_text(encoding="utf-8"))["pass"], passed)

    def test_summary_fails_when_the_wait_sampler_stopped_early(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps({"product": "casework", "profile": "steady", "configuration": {"parameters": {}}}),
                encoding="utf-8",
            )
            k6_summary = root / "summary.json"
            k6_summary.write_text(
                json.dumps(
                    {
                        "state": {"testRunDurationMs": 1000},
                        "metrics": {"http_req_failed": {"values": {"rate": 0}, "thresholds": {"rate==0": {"ok": True}}}},
                    }
                ),
                encoding="utf-8",
            )
            safety = root / "safety.json"
            safety.write_text(json.dumps({"safe": True}), encoding="utf-8")
            samples = root / "samples.json"
            samples.write_text("", encoding="utf-8")
            sample = json.dumps({"auditLockWaiters": 0, "lockWaiters": 0, "blockedBackends": 0}) + "\n"
            # A run shorter than the first sample passes, but reports its wait
            # peaks as unknown rather than as zero contention.
            for name, waits, sampler_exit_code, passed, peak in (
                ("sampled", sample, 0, True, 0),
                ("no samples", "", 0, True, None),
                ("sampler failed", sample, 2, False, 0),
            ):
                with self.subTest(name):
                    db_waits = root / "db-waits.jsonl"
                    db_waits.write_text(waits, encoding="utf-8")
                    out = root / "result.json"
                    evidence.summarize(
                        argparse.Namespace(
                            manifest=manifest,
                            k6_summary=k6_summary,
                            samples=samples,
                            db_after=None,
                            db_waits=db_waits,
                            db_sampler_exit_code=sampler_exit_code,
                            safety=safety,
                            k6_exit_code=0,
                            out=out,
                        )
                    )
                    result = json.loads(out.read_text(encoding="utf-8"))
                    self.assertEqual(result["database"]["waits"]["samplerExitCode"], sampler_exit_code)
                    self.assertIs(result["pass"], passed)
                    self.assertEqual(result["database"]["waits"]["lockWaitersPeak"], peak)

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
            db_after = root / "db-after.json"
            db_waits = root / "db-waits.jsonl"
            safety = root / "safety.json"
            out = root / "result.json"
            manifest.write_text(
                json.dumps(
                    {
                        "product": "breg",
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
            ] + [
                {
                    "type": "Point",
                    "metric": "iterations",
                    "data": {"time": time, "value": 1, "tags": {"scenario": scenario}},
                }
                for scenario, time in (
                    ("steady", "2026-09-24T18:00:00Z"),
                    ("steady", "2026-09-24T18:00:01.5Z"),
                    ("steady", "2026-09-24T18:00:02+00:00"),
                    ("recovery", "2026-09-24T18:00:03Z"),
                )
            ]
            samples.write_text("".join(json.dumps(item) + "\n" for item in sample_items), encoding="utf-8")
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
                    db_after=db_after,
                    db_waits=db_waits,
                    db_sampler_exit_code=0,
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
            self.assertEqual(result["phases"]["steady"]["windowSeconds"], 2)
            self.assertEqual(result["phases"]["steady"]["operationsPerSecond"], 1.5)
            self.assertIsNone(result["phases"]["recovery"]["operationsPerSecond"])
            self.assertEqual(result["phases"]["steady"]["latency"]["count"], 4)
            self.assertNotIn("byPhase", result["latency"])
            self.assertNotIn("execution", result)
            self.assertEqual(result["database"]["waits"]["auditLockWaitersPeak"], 2)
            self.assertTrue(result["pass"])

    def test_sweep_counts_a_held_rate_without_a_result_as_failed(self) -> None:
        def held_rate(root: Path, rate: str, passed: bool | None) -> None:
            directory = root / f"rate-{rate}"
            directory.mkdir()
            if passed is None:
                return
            result = {
                "offered": {"rateOps": float(rate)},
                "achieved": {
                    "operationsPerSecond": float(rate),
                    "httpRequestsPerSecond": float(rate),
                    "droppedOperations": 0,
                    "failedRequestRate": 0,
                },
                "latency": {"overall": {"p95Ms": 10, "p99Ms": 20}},
                "pass": passed,
            }
            (directory / "result.json").write_text(json.dumps(result), encoding="utf-8")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            held_rate(root, "50", True)
            held_rate(root, "75", None)
            held_rate(root, "100", False)
            out = root / "sweep-result.json"
            evidence.aggregate_sweep(argparse.Namespace(root=root, out=out))
            sweep = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual([row["offeredOperationsPerSecond"] for row in sweep["rates"]], [50, 75, 100])
            self.assertEqual([row["pass"] for row in sweep["rates"]], [True, False, False])
            self.assertEqual([row["missing"] for row in sweep["rates"]], [False, True, False])
            self.assertEqual(sweep["rates"][1]["artifact"], "rate-75")
            self.assertIsNone(sweep["rates"][1]["achievedOperationsPerSecond"])
            self.assertEqual(sweep["firstFailingRate"], 75)
            self.assertFalse(sweep["pass"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            held_rate(root, "50", True)
            held_rate(root, "75", True)
            out = root / "sweep-result.json"
            evidence.aggregate_sweep(argparse.Namespace(root=root, out=out))
            sweep = json.loads(out.read_text(encoding="utf-8"))
            self.assertIsNone(sweep["firstFailingRate"])
            self.assertTrue(sweep["pass"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "sweep-result.json"
            evidence.aggregate_sweep(argparse.Namespace(root=root, out=out))
            self.assertFalse(json.loads(out.read_text(encoding="utf-8"))["pass"])


@unittest.skipUnless(shutil.which("node"), "node is required to exercise the shared k6 modules")
class K6ConfigTests(unittest.TestCase):
    def duration_milliseconds(self, value: str) -> subprocess.CompletedProcess[str]:
        config = (MODULE_PATH.parent / "k6/config.js").as_uri()
        script = (
            f"import {{ durationMilliseconds }} from {json.dumps(config)};"
            "console.log(durationMilliseconds('DURATION', process.argv[1]));"
        )
        return subprocess.run(
            ["node", "--input-type=module", "-e", script, value],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_duration_accepts_every_form_the_runners_accept(self) -> None:
        for value, milliseconds in (("250ms", "250"), ("1.5s", "1500"), ("3m", "180000"), ("1m30s", "90000")):
            with self.subTest(value=value):
                result = self.duration_milliseconds(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), milliseconds)

    def test_duration_rejects_malformed_and_empty_values(self) -> None:
        for value in ("", "90", "1m 30s", "m", "0s", "1d"):
            with self.subTest(value=value):
                result = self.duration_milliseconds(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("DURATION must be", result.stderr)


if __name__ == "__main__":
    unittest.main()
