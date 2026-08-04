#!/usr/bin/env python3
"""Tests for the demonstration's provisioning plumbing.

Only the part that matters outside the demonstration: a private key or a bearer
token must not exist on disk readable by anyone else, not even for the moment
between creating the file and narrowing it.

Run with `uv run --with cryptography --no-project python -m unittest
crates/registry-mint/demo/support/test_provision.py`; the tests skip where
`cryptography` is unavailable.
"""

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

SUPPORT = Path(__file__).resolve().parent


def load_module():
    specification = importlib.util.spec_from_file_location(
        "demo_provision", SUPPORT / "provision.py"
    )
    module = importlib.util.module_from_spec(specification)
    try:
        specification.loader.exec_module(module)
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise unittest.SkipTest(f"provision.py needs {error.name}") from None
    return module


try:
    provision = load_module()
except unittest.SkipTest as skip:  # pragma: no cover - depends on the environment
    provision = None
    SKIP_REASON = str(skip)


@unittest.skipIf(provision is None, "cryptography is not installed")
class SecretFileModeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        previous = os.umask(0)
        self.addCleanup(os.umask, previous)

    def test_a_secret_is_never_wider_than_owner_read_write(self):
        path = provision.write_secret(self.root / "signing.jwk", "not-a-real-key")

        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual("not-a-real-key", path.read_text())

    def test_the_file_is_created_at_its_final_mode_not_narrowed_afterwards(self):
        modes = []
        real_open = os.open

        def spy(path, flags, mode=0o777, **rest):
            modes.append(mode)
            return real_open(path, flags, mode, **rest)

        os.open = spy
        self.addCleanup(setattr, os, "open", real_open)
        provision.write_secret(self.root / "audit-hash-key", "not-a-real-key")

        self.assertEqual([0o600], modes)

    def test_ordinary_files_keep_their_readable_mode(self):
        path = provision.write(self.root / "ca.pem", "not-a-real-certificate")

        self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
