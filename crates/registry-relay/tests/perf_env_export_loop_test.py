# SPDX-License-Identifier: Apache-2.0
"""Regression tests for literal perf env-file export snippets."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "perf" / "README.md",
]


class PerfEnvExportLoopTest(unittest.TestCase):
    def test_env_export_loops_preserve_equals_in_values(self) -> None:
        for path in FILES:
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("IFS='=' read -r key value", text)
                self.assertIn('key="${line%%=*}"', text)
                self.assertIn('value="${line#*=}"', text)


if __name__ == "__main__":
    unittest.main()
