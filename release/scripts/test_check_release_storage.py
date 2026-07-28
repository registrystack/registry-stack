#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import unittest.mock
from datetime import UTC, datetime
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-release-storage.py")
BUDGET = SCRIPT.parents[1] / "storage-budget.json"


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
        self.bootstrap = self.module.load_budget(BUDGET)

    def enforced_budget(self, required: int | None = None) -> dict:
        value = dict(self.bootstrap)
        peak_additional = 800
        if required is None:
            required = self.module.required_runway_bytes(
                peak_additional, value["safety_margin_ratio"]
            )
        value.update(
            {
                "status": "enforced",
                "required_available_bytes": required,
                "measurement": {
                    "candidate_run_url": (
                        "https://github.com/registrystack/registry-stack/actions/runs/1"
                    ),
                    "measured_at": "2026-07-25T12:00:00Z",
                    "limiting_job_label": "build-b",
                    "baseline_filesystem_used_bytes": 1_200,
                    "peak_filesystem_used_bytes": 2_000,
                    "peak_additional_filesystem_used_bytes": peak_additional,
                    "peak_workspace_bytes": 1_000,
                },
            }
        )
        return value

    def test_checked_in_budget_truthfully_requires_measurement(self) -> None:
        self.assertEqual("measurement_required", self.bootstrap["status"])
        self.assertIsNone(self.bootstrap["measurement"])
        self.assertIsNone(self.bootstrap["required_available_bytes"])

    def test_bootstrap_state_blocks_an_ordinary_build(self) -> None:
        with self.assertRaisesRegex(
            self.module.StorageError, "blocked on a real peak measurement"
        ):
            self.module.preflight(
                self.bootstrap, available_bytes=10_000, measurement_run=False
            )

    def test_explicit_measurement_run_is_labeled_and_has_no_fake_budget(self) -> None:
        result = self.module.preflight(
            self.bootstrap, available_bytes=10_000, measurement_run=True
        )
        self.assertEqual("bootstrap_measurement", result["mode"])
        self.assertIsNone(result["required_available_bytes"])

    def test_enforced_preflight_fails_before_build_when_insufficient(self) -> None:
        with self.assertRaisesRegex(self.module.StorageError, "1000 bytes required"):
            self.module.preflight(
                self.enforced_budget(), available_bytes=999, measurement_run=False
            )

    def test_enforced_preflight_accepts_exact_required_runway(self) -> None:
        result = self.module.preflight(
            self.enforced_budget(), available_bytes=1_000, measurement_run=False
        )
        self.assertTrue(result["passed"])
        self.assertEqual("enforced", result["mode"])

    def test_enforced_budget_accepts_exact_derived_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.json"
            expected = self.enforced_budget()
            path.write_text(json.dumps(expected), encoding="utf-8")
            self.assertEqual(expected, self.module.load_budget(path))

    def test_required_runway_rounds_fractional_byte_up(self) -> None:
        self.assertEqual(4, self.module.required_runway_bytes(3, 0.25))

    def test_enforced_budget_rejects_one_byte_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.json"
            path.write_text(
                json.dumps(self.enforced_budget(required=1)), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                self.module.StorageError,
                "required_available_bytes must equal ceil",
            ):
                self.module.load_budget(path)

    def test_enforced_budget_rejects_inconsistent_additional_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.json"
            invalid = self.enforced_budget()
            invalid["measurement"]["peak_additional_filesystem_used_bytes"] = 799
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(
                self.module.StorageError, "must equal peak minus baseline"
            ):
                self.module.load_budget(path)

    def test_measurement_required_rejects_an_invented_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.json"
            invalid = dict(self.bootstrap)
            invalid["required_available_bytes"] = 1
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(
                self.module.StorageError, "invented numeric budget"
            ):
                self.module.load_budget(path)

    def test_enforced_budget_requires_real_candidate_evidence_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.json"
            invalid = self.enforced_budget()
            invalid["measurement"]["candidate_run_url"] = "https://example.test/run"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(
                self.module.StorageError, "Registry Stack candidate run"
            ):
                self.module.load_budget(path)

    def test_sampler_records_truthful_maxima_and_stops(self) -> None:
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
            self.assertEqual(4_000, result["peak_filesystem_used_bytes"])
            self.assertEqual(2_000, result["baseline_filesystem_used_bytes"])
            self.assertEqual(
                2_000, result["peak_additional_filesystem_used_bytes"]
            )
            self.assertEqual(1_500, result["peak_workspace_bytes"])
            self.assertEqual(6_000, result["minimum_available_bytes"])
            self.assertEqual("candidate", result["job_label"])
            self.assertEqual(result, json.loads(output.read_text(encoding="utf-8")))

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


if __name__ == "__main__":
    unittest.main()
