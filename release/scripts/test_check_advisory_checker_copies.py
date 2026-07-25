# SPDX-License-Identifier: Apache-2.0
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).with_name("check_advisory_checker_copies.py")
    spec = importlib.util.spec_from_file_location("check_advisory_checker_copies", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AdvisoryCheckerCopiesTest(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.left = self.root / "left.py"
        self.right = self.root / "right.py"

    def tearDown(self):
        self.tmp.cleanup()

    def test_identical_copies_pass(self):
        self.left.write_bytes(b"same\n")
        self.right.write_bytes(b"same\n")
        self.assertIsNone(self.module.check_identical(self.left, self.right))

    def test_drift_fails(self):
        self.left.write_bytes(b"notary\n")
        self.right.write_bytes(b"relay\n")
        self.assertIn(
            "advisory checker copies differ",
            self.module.check_identical(self.left, self.right),
        )

    def test_missing_copy_fails(self):
        self.left.write_bytes(b"present\n")
        self.assertIn(
            "cannot read advisory checker copy",
            self.module.check_identical(self.left, self.right),
        )


if __name__ == "__main__":
    unittest.main()
