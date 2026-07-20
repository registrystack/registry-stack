#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "check-dependabot-release-window.py"
CONFIG = ROOT / ".github" / "dependabot.yml"


def load_module():
    spec = importlib.util.spec_from_file_location("check_dependabot_release_window", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DependabotReleaseWindowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.valid = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))

    def assert_error(self, data, fragment: str) -> None:
        _, errors = self.module.validate_config(data)
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_repository_config_passes(self) -> None:
        checked, errors = self.module.validate_config(self.valid)
        self.assertEqual([], errors)
        self.assertEqual(6, len(checked))

    def test_missing_schedule_fields_fail(self) -> None:
        for field in ("day", "time", "timezone"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.valid)
                del data["updates"][0]["schedule"][field]
                self.assert_error(data, f"schedule {field}")

    def test_duplicate_slot_fails(self) -> None:
        data = copy.deepcopy(self.valid)
        data["updates"][1]["schedule"]["time"] = "04:00"
        self.assert_error(data, "duplicated")

    def test_unapproved_slot_fails(self) -> None:
        data = copy.deepcopy(self.valid)
        data["updates"][0]["schedule"]["time"] = "03:59"
        self.assert_error(data, "must be 04:00")

    def test_missing_or_excessive_routine_limit_fails(self) -> None:
        for value in (None, 0, 2, 10):
            with self.subTest(value=value):
                data = copy.deepcopy(self.valid)
                if value is None:
                    del data["updates"][0]["open-pull-requests-limit"]
                else:
                    data["updates"][0]["open-pull-requests-limit"] = value
                self.assert_error(data, "open-pull-requests-limit must be 1")

    def test_target_branch_fails(self) -> None:
        data = copy.deepcopy(self.valid)
        data["updates"][0]["target-branch"] = "release/1.0"
        self.assert_error(data, "must not set target-branch")

    def test_cli_json_is_stable_and_parseable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "dependabot.yml"
            path.write_text(yaml.safe_dump(self.valid, sort_keys=False), encoding="utf-8")
            first = subprocess.run(
                [str(SCRIPT), "--config", str(path)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            second = subprocess.run(
                [str(SCRIPT), "--config", str(path)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual("passed", payload["status"])
        self.assertEqual(6, len(payload["entries_checked"]))


if __name__ == "__main__":
    unittest.main()
