# SPDX-License-Identifier: Apache-2.0
import importlib.util
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

    def test_active_yaml_lines_ignores_whole_line_comments(self):
        active = self.module.active_yaml_lines(
            "# REGISTRY_RELAY_NO_THRESHOLD=1\n"
            "  # REGISTRY_RELAY_NO_THRESHOLD=1\n"
            "run: echo ok\n"
        )

        self.assertNotIn("REGISTRY_RELAY_NO_THRESHOLD", active)
        self.assertIn("run: echo ok", active)

    def test_active_yaml_lines_preserves_shell_after_inline_hash(self):
        active = self.module.active_yaml_lines(
            "run: echo '# keep shell literal'; REGISTRY_RELAY_NO_THRESHOLD=1\n"
        )

        self.assertIn("REGISTRY_RELAY_NO_THRESHOLD=1", active)

    def test_real_workflow_passes(self):
        self.assertEqual(self.module.main(), 0)


if __name__ == "__main__":
    unittest.main()
