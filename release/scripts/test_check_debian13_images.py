# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the maintained Debian 13 image policy."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-debian13-images.py")
SPEC = importlib.util.spec_from_file_location("check_debian13_images", SCRIPT)
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class RelayV2ImagePolicyTests(unittest.TestCase):
    def repository_copy(self, root: Path) -> None:
        for relative in POLICY.MAINTAINED_TEXT_PATHS:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(POLICY.ROOT.joinpath(relative).read_bytes())

    def test_relay_v2_image_is_a_required_maintained_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            dockerfile = root / "release/docker/Dockerfile.relay"
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    'ENTRYPOINT ["/usr/local/bin/relay"]',
                    'ENTRYPOINT ["relay"]',
                ),
                encoding="utf-8",
            )

            failures = POLICY.check_repository(root)

            self.assertTrue(
                any(
                    "Dockerfile.relay" in failure
                    and "absolute Relay V2 entrypoint" in failure
                    for failure in failures
                ),
                failures,
            )


if __name__ == "__main__":
    unittest.main()
