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

    def write_record(
        self,
        directory: Path,
        name: str,
        version: str,
        *,
        source_version: str = "v0.11.0",
    ) -> None:
        (directory / name).write_text(
            json.dumps(
                {
                    "record_kind": "candidate_evidence",
                    "source_release": {"version": source_version},
                    "target_release": {"version": version},
                }
            ),
            encoding="utf-8",
        )

    def write_product_input_record(
        self,
        directory: Path,
        name: str,
        version: str,
    ) -> None:
        (directory / name).write_text(
            json.dumps(
                {
                    "record_kind": "candidate_evidence",
                    "candidate": {"version": version},
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
                product_input_records=(
                    ROOT / "release" / "exercises" / "product-input-lifecycle"
                ),
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

            self.assertEqual(("v0.11.0", "v0.12.2"), versions)
            for version in versions:
                self.assertEqual(
                    set(self.module.required_asset_names(version)),
                    {
                        path.name
                        for path in (root / "assets" / version).iterdir()
                    },
                )
            self.assertEqual(
                ["v0.11.0", "v0.12.2"],
                [command[3] for command in commands],
            )

    def test_multiple_versions_use_separate_authenticated_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir()
            self.write_record(records, "candidate-a.json", "v0.12.1")
            self.write_record(records, "candidate-b.json", "v0.12.2")
            self.write_record(records, "candidate-c.json", "v0.12.2")

            versions = self.module.prepare_assets(
                records,
                root / "assets",
                downloader=self.download_fixture,
            )

            self.assertEqual(("v0.11.0", "v0.12.1", "v0.12.2"), versions)
            self.assertTrue((root / "assets" / "v0.11.0").is_dir())
            self.assertTrue((root / "assets" / "v0.12.1").is_dir())
            self.assertTrue((root / "assets" / "v0.12.2").is_dir())

    def test_product_input_candidate_prepares_release_assets_and_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upgrade_records = root / "upgrades"
            product_input_records = root / "product-input-lifecycle"
            upgrade_records.mkdir()
            product_input_records.mkdir()
            (
                product_input_records / "product-input-lifecycle-v1.schema.json"
            ).write_text("{}", encoding="utf-8")
            self.write_product_input_record(
                product_input_records,
                "candidate.json",
                "v0.12.2",
            )

            versions = self.module.prepare_assets(
                upgrade_records,
                root / "assets",
                product_input_records=product_input_records,
                downloader=self.download_fixture,
            )

            self.assertEqual(("v0.12.2",), versions)
            prepared = {
                path.name for path in (root / "assets" / "v0.12.2").iterdir()
            }
            self.assertEqual(
                set(self.module.required_asset_names("v0.12.2"))
                | {"release-candidate-receipt.json"},
                prepared,
            )
            self.assertNotIn(
                "registry-stack-v0.12.2-candidate-receipt.json",
                prepared,
            )

    def test_product_input_candidate_requires_published_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upgrade_records = root / "upgrades"
            product_input_records = root / "product-input-lifecycle"
            upgrade_records.mkdir()
            product_input_records.mkdir()
            self.write_product_input_record(
                product_input_records,
                "candidate.json",
                "v0.12.2",
            )

            with self.assertRaisesRegex(
                self.module.PreparationError,
                "incomplete or unsafe",
            ):
                self.module.prepare_assets(
                    upgrade_records,
                    root / "assets",
                    product_input_records=product_input_records,
                    downloader=lambda command: self.download_fixture(
                        command,
                        omit="registry-stack-v0.12.2-candidate-receipt.json",
                    ),
                )

    def test_upgrade_and_product_input_candidate_share_one_asset_download(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upgrade_records = root / "upgrades"
            product_input_records = root / "product-input-lifecycle"
            upgrade_records.mkdir()
            product_input_records.mkdir()
            self.write_record(
                upgrade_records,
                "candidate.json",
                "v0.12.2",
                source_version="v0.12.2",
            )
            self.write_product_input_record(
                product_input_records,
                "candidate.json",
                "v0.12.2",
            )
            commands: list[list[str]] = []

            def download(command: list[str]) -> None:
                commands.append(command)
                self.download_fixture(command)

            versions = self.module.prepare_assets(
                upgrade_records,
                root / "assets",
                product_input_records=product_input_records,
                downloader=download,
            )

            self.assertEqual(("v0.12.2",), versions)
            self.assertEqual(1, len(commands))
            self.assertIn(
                "registry-stack-v0.12.2-candidate-receipt.json",
                commands[0],
            )

    def test_invalid_product_input_candidate_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upgrade_records = root / "upgrades"
            product_input_records = root / "product-input-lifecycle"
            upgrade_records.mkdir()
            product_input_records.mkdir()
            self.write_product_input_record(
                product_input_records,
                "candidate.json",
                "v0.12",
            )
            downloader = unittest.mock.Mock()

            with self.assertRaisesRegex(
                self.module.PreparationError,
                "product-input lifecycle candidate version is invalid",
            ):
                self.module.prepare_assets(
                    upgrade_records,
                    root / "assets",
                    product_input_records=product_input_records,
                    downloader=downloader,
                )

            downloader.assert_not_called()

    def test_duplicate_upgrade_field_is_rejected_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir()
            (records / "candidate.json").write_text(
                '{"record_kind":"candidate_evidence",'
                '"record_kind":"template"}',
                encoding="utf-8",
            )
            downloader = unittest.mock.Mock()

            with self.assertRaisesRegex(
                self.module.PreparationError,
                "upgrade exercise record contains a duplicate JSON field",
            ):
                self.module.prepare_assets(
                    records,
                    root / "assets",
                    downloader=downloader,
                )

            downloader.assert_not_called()

    def test_duplicate_product_input_field_is_rejected_before_download(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upgrade_records = root / "upgrades"
            product_input_records = root / "product-input-lifecycle"
            upgrade_records.mkdir()
            product_input_records.mkdir()
            (product_input_records / "candidate.json").write_text(
                '{"record_kind":"candidate_evidence",'
                '"candidate":{"version":"v0.12.2","version":"v0.12.3"}}',
                encoding="utf-8",
            )
            downloader = unittest.mock.Mock()

            with self.assertRaisesRegex(
                self.module.PreparationError,
                "product-input lifecycle record contains a duplicate JSON field",
            ):
                self.module.prepare_assets(
                    upgrade_records,
                    root / "assets",
                    product_input_records=product_input_records,
                    downloader=downloader,
                )

            downloader.assert_not_called()

    def test_invalid_source_version_is_rejected_before_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "records"
            records.mkdir()
            self.write_record(
                records,
                "candidate.json",
                "v0.12.2",
                source_version="v0.11.0-rc..1",
            )
            downloader = unittest.mock.Mock()
            with self.assertRaisesRegex(
                self.module.PreparationError, "source version is invalid"
            ):
                self.module.prepare_assets(
                    records,
                    root / "assets",
                    downloader=downloader,
                )
            downloader.assert_not_called()

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
