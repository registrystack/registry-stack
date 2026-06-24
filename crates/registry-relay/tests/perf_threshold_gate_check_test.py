# SPDX-License-Identifier: Apache-2.0
import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "check_perf_threshold_gate.py"
    spec = importlib.util.spec_from_file_location("check_perf_threshold_gate", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PerfThresholdGateCheckTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()

    def test_real_workflow_does_not_run_on_pull_requests(self):
        workflow = self.module.WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("pull_request:", workflow)
        self.assertEqual(self.module.main(), 0)

    def test_accepts_manual_and_main_only_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workflow = tmp_path / "perf-smoke.yml"
            common_js = tmp_path / "common.js"
            workflow.write_text(
                "name: perf-smoke\n"
                "on:\n"
                "  push:\n"
                "    branches: [main]\n"
                "  workflow_dispatch:\n"
                "jobs: {}\n",
                encoding="utf-8",
            )
            common_js.write_text(
                "if (__ENV.REGISTRY_RELAY_NO_THRESHOLD === '1') {}\n"
                "export const thresholds = {'http_req_duration{expected_status:false}': []};\n",
                encoding="utf-8",
            )
            self.module.WORKFLOW = workflow
            self.module.COMMON_JS = common_js

            self.assertEqual(self.module.main(), 0)

    def test_rejects_threshold_bypass_in_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workflow = tmp_path / "perf-smoke.yml"
            common_js = tmp_path / "common.js"
            workflow.write_text(
                "name: perf-smoke\n"
                "on:\n"
                "  push:\n"
                "    branches: [main]\n"
                "  workflow_dispatch:\n"
                "env:\n"
                "  REGISTRY_RELAY_NO_THRESHOLD: 1\n",
                encoding="utf-8",
            )
            common_js.write_text(
                "if (__ENV.REGISTRY_RELAY_NO_THRESHOLD === '1') {}\n"
                "export const thresholds = {'http_req_duration{expected_status:false}': []};\n",
                encoding="utf-8",
            )
            self.module.WORKFLOW = workflow
            self.module.COMMON_JS = common_js

            with self.assertRaises(SystemExit):
                self.module.main()


if __name__ == "__main__":
    unittest.main()
