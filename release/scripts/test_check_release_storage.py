#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
import unittest.mock
from datetime import UTC, datetime
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-release-storage.py")


def load_module():
    spec = importlib.util.spec_from_file_location("check_release_storage", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckReleaseStorageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_only_sample_command_remains(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.module.parse_args(
                    [
                        "preflight",
                        "--budget",
                        "storage-budget.json",
                        "--workspace",
                        ".",
                    ]
                )

    def test_sampler_records_nonblocking_truthful_maxima_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "measurement.json"
            stop = root / "stop"
            samples = [
                {
                    "timestamp": "2026-07-25T12:00:00Z",
                    "label": "candidate",
                    "filesystem_total_bytes": 10_000,
                    "filesystem_used_bytes": 2_000,
                    "filesystem_available_bytes": 8_000,
                    "workspace_bytes": 500,
                },
                {
                    "timestamp": "2026-07-25T12:00:01Z",
                    "label": "candidate",
                    "filesystem_total_bytes": 10_000,
                    "filesystem_used_bytes": 4_000,
                    "filesystem_available_bytes": 6_000,
                    "workspace_bytes": 1_500,
                },
            ]
            with unittest.mock.patch.object(
                self.module, "sample_once", side_effect=samples
            ):
                result = self.module.monitor(
                    workspace=root,
                    output=output,
                    stop_file=stop,
                    interval_seconds=0.001,
                    label="candidate",
                    max_samples=2,
                )
            self.assertFalse(result["blocking"])
            self.assertEqual("github-hosted-per-job", result["runner_scope"])
            self.assertEqual("measured", result["status"])
            self.assertEqual(4_000, result["peak_filesystem_used_bytes"])
            self.assertEqual(2_000, result["baseline_filesystem_used_bytes"])
            self.assertEqual(
                2_000, result["peak_additional_filesystem_used_bytes"]
            )
            self.assertEqual(1_500, result["peak_workspace_bytes"])
            self.assertEqual(6_000, result["minimum_available_bytes"])
            self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))

    def test_measurement_failure_emits_warning_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "measurement.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(
                io.StringIO()
            ):
                result = self.module.main(
                    [
                        "sample",
                        "--workspace",
                        str(root / "missing"),
                        "--output",
                        str(output),
                        "--stop-file",
                        str(root / "stop"),
                    ]
                )
            self.assertEqual(0, result)
            rendered = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("unavailable", rendered["status"])
            self.assertFalse(rendered["blocking"])
            self.assertIn("telemetry warning", stderr.getvalue())

    def test_sample_once_counts_regular_files_not_symlink_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload").write_bytes(b"12345")
            (root / "link").symlink_to(root / "payload")
            sample = self.module.sample_once(
                root,
                label="test",
                now=datetime(2026, 7, 25, tzinfo=UTC),
            )
            self.assertEqual(5, sample["workspace_bytes"])
            self.assertEqual("2026-07-25T00:00:00Z", sample["timestamp"])

    def test_invalid_sample_interval_is_reported_not_raised_by_main(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "measurement.json"
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(
                io.StringIO()
            ):
                result = self.module.main(
                    [
                        "sample",
                        "--workspace",
                        str(root),
                        "--output",
                        str(output),
                        "--stop-file",
                        str(root / "stop"),
                        "--interval-seconds",
                        "0",
                    ]
                )
            self.assertEqual(0, result)
            self.assertEqual(
                "unavailable",
                json.loads(output.read_text(encoding="utf-8"))["status"],
            )


if __name__ == "__main__":
    unittest.main()
