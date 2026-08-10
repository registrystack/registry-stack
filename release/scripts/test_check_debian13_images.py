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
        self.assertIn(Path("release/docker/Dockerfile.relay"), POLICY.DOCKERFILES)
        self.assertNotIn(
            Path("release/docker/Dockerfile.registry-relay"), POLICY.DOCKERFILES
        )
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

    def test_relay_v2_image_binds_the_runtime_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.repository_copy(root)
            dockerfile = root / "release/docker/Dockerfile.relay"
            dockerfile.write_text(
                dockerfile.read_text(encoding="utf-8").replace(
                    'CMD ["serve", "--runtime", "/etc/relay/runtime.yaml"]',
                    'CMD ["serve"]',
                ),
                encoding="utf-8",
            )

            failures = POLICY.check_repository(root)

            self.assertTrue(
                any(
                    "Dockerfile.relay" in failure
                    and "runtime configuration binding" in failure
                    for failure in failures
                ),
                failures,
            )

    def test_relay_v2_image_healthcheck_endpoint_is_configurable(self) -> None:
        mutations = (
            (
                "ENV RELAY_HEALTHCHECK_URL=http://127.0.0.1:8080/health",
                "ENV RELAY_HEALTHCHECK_URL=http://127.0.0.1:18080/health",
                "safe configurable Relay V2 healthcheck default",
            ),
            (
                'CMD ["/usr/local/bin/relay", "healthcheck"]',
                'CMD ["/usr/local/bin/relay", "healthcheck", "--url", '
                '"http://127.0.0.1:8080/health"]',
                "environment-aware Relay V2 healthcheck",
            ),
        )
        for original, replacement, expected in mutations:
            with self.subTest(expected=expected):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.repository_copy(root)
                    dockerfile = root / "release/docker/Dockerfile.relay"
                    dockerfile.write_text(
                        dockerfile.read_text(encoding="utf-8").replace(
                            original,
                            replacement,
                        ),
                        encoding="utf-8",
                    )

                    failures = POLICY.check_repository(root)

                    self.assertTrue(
                        any(
                            "Dockerfile.relay" in failure and expected in failure
                            for failure in failures
                        ),
                        failures,
                    )


if __name__ == "__main__":
    unittest.main()
