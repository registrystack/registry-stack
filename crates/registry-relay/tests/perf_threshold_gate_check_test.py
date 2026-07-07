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

    def test_real_common_js_declares_thresholds(self):
        self.assertEqual(self.module.main(), 0)

    def test_accepts_thresholds_and_explicit_local_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            common_js = tmp_path / "common.js"
            common_js.write_text(
                "if (__ENV.REGISTRY_RELAY_NO_THRESHOLD === '1') {}\n"
                "export const thresholds = {'http_req_duration{expected_status:false}': []};\n",
                encoding="utf-8",
            )
            self.module.COMMON_JS = common_js

            self.assertEqual(self.module.main(), 0)

    def test_rejects_missing_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            common_js = tmp_path / "common.js"
            common_js.write_text(
                "if (__ENV.REGISTRY_RELAY_NO_THRESHOLD === '1') {}\n"
                "export const thresholds = {};\n",
                encoding="utf-8",
            )
            self.module.COMMON_JS = common_js

            with self.assertRaises(SystemExit):
                self.module.main()


if __name__ == "__main__":
    unittest.main()
