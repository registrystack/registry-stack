from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "prepare-upgrade-exercise-assets.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "prepare_upgrade_exercise_assets", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrepareUpgradeExerciseAssetsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def write_record(self, directory: Path, name: str, version: str) -> None:
        (directory / name).write_text(
            json.dumps(
                {
                    "record_kind": "candidate_evidence",
                    "target_release": {"version": version},
                }
            ),
            encoding="utf-8",
        )

    def download_fixture(
        self, command: list[str], *, omit: str | None = None
    ) -> None:
        destination = Path(command[command.index("--dir") + 1])
        patterns = [
            command[index + 1]
            for index, value in enumerate(command)
            if value == "--pattern"
        ]
        for name in patterns:
            if name != omit:
                (destination / name).write_text("release asset", encoding="utf-8")

    def test_current_templates_require_no_download_or_asset_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            asset_root = Path(temporary) / "assets"
            downloader = unittest.mock.Mock(side_effect=AssertionError)
            versions = self.module.prepare_assets(
                ROOT / "release" / "exercises",
                asset_root,
                downloader=downloader,
            )

            self.assertEqual((), versions)
            self.assertFalse(asset_root.exists())
            downloader.assert_not_called()

    def test_one_candidate_downloads_exact_version_asset_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir()
            self.write_record(records, "candidate.json", "v0.12.2")
            commands: list[list[str]] = []

            def download(command: list[str]) -> None:
                commands.append(command)
                self.download_fixture(command)

            versions = self.module.prepare_assets(
                records, root / "assets", downloader=download
            )

            self.assertEqual(("v0.12.2",), versions)
            self.assertEqual(
                set(self.module.required_asset_names("v0.12.2")),
                {
                    path.name
                    for path in (root / "assets" / "v0.12.2").iterdir()
                },
            )
            self.assertEqual("v0.12.2", commands[0][3])

    def test_multiple_versions_use_separate_authenticated_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir()
            self.write_record(records, "candidate-a.json", "v0.11.0")
            self.write_record(records, "candidate-b.json", "v0.12.2")
            self.write_record(records, "candidate-c.json", "v0.12.2")

            versions = self.module.prepare_assets(
                records,
                root / "assets",
                downloader=self.download_fixture,
            )

            self.assertEqual(("v0.11.0", "v0.12.2"), versions)
            self.assertTrue((root / "assets" / "v0.11.0").is_dir())
            self.assertTrue((root / "assets" / "v0.12.2").is_dir())

    def test_missing_release_asset_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir()
            self.write_record(records, "candidate.json", "v0.12.2")
            with self.assertRaisesRegex(
                self.module.PreparationError, "incomplete or unsafe"
            ):
                self.module.prepare_assets(
                    records,
                    root / "assets",
                    downloader=lambda command: self.download_fixture(
                        command, omit="SHA256SUMS"
                    ),
                )

    def test_missing_github_cli_is_reported_without_command_output(self) -> None:
        with unittest.mock.patch.object(
            self.module.subprocess,
            "run",
            side_effect=FileNotFoundError("gh missing"),
        ):
            with self.assertRaisesRegex(
                self.module.PreparationError, "could not be downloaded"
            ) as caught:
                self.module.run_download(["gh", "release", "download", "v0.12.2"])

        self.assertNotIn("gh missing", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
