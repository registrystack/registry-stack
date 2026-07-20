#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-release-relay-features.py")


def load_module():
    spec = importlib.util.spec_from_file_location("check_release_relay_features", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CheckReleaseRelayFeaturesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def write_binary(self, root: Path, markers: list[bytes]) -> Path:
        binary = root / "registry-relay"
        binary.write_bytes(b"\x7fELF\x02\x01" + b"\x00".join(markers))
        return binary

    def test_accepts_binary_with_all_disabled_feature_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = self.write_binary(
                Path(directory), list(self.module.DISABLED_FEATURE_MARKERS.values())
            )

            self.module.check_binary(binary)

    def test_rejects_each_missing_disabled_feature_marker(self) -> None:
        markers = self.module.DISABLED_FEATURE_MARKERS
        for missing_feature in markers:
            with self.subTest(feature=missing_feature), tempfile.TemporaryDirectory() as directory:
                binary = self.write_binary(
                    Path(directory),
                    [
                        marker
                        for feature, marker in markers.items()
                        if feature != missing_feature
                    ],
                )

                with self.assertRaisesRegex(
                    self.module.FeatureCheckError, missing_feature
                ):
                    self.module.check_binary(binary)

    def test_rejects_non_elf_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "registry-relay"
            binary.write_bytes(b"not an executable")

            with self.assertRaisesRegex(self.module.FeatureCheckError, "not an ELF"):
                self.module.check_binary(binary)

    def test_rejects_truncated_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            markers = list(self.module.DISABLED_FEATURE_MARKERS.values())
            markers[-1] = markers[-1][:-1]
            binary = self.write_binary(Path(directory), markers)

            with self.assertRaisesRegex(
                self.module.FeatureCheckError, "spdci-api-standards"
            ):
                self.module.check_binary(binary)

    def test_reports_every_missing_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = self.write_binary(
                Path(directory),
                [self.module.DISABLED_FEATURE_MARKERS["attribute-release"]],
            )

            with self.assertRaises(self.module.FeatureCheckError) as context:
                self.module.check_binary(binary)
            message = str(context.exception)
            self.assertIn("ogcapi-features", message)
            self.assertIn("spdci-api-standards", message)

    def test_rejects_missing_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                self.module.FeatureCheckError, "does not exist"
            ):
                self.module.check_binary(Path(directory) / "registry-relay")


if __name__ == "__main__":
    unittest.main()
