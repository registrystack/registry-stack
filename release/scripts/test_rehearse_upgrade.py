#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release/scripts/rehearse-upgrade.py"
SPEC = importlib.util.spec_from_file_location("rehearse_upgrade", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

WORKFLOW = ROOT / ".github/workflows/release-upgrade-rehearsal.yml"
API_STABILITY = ROOT / "docs/site/src/content/docs/reference/api-stability.mdx"
Error = MODULE.RehearsalError


def write_tar(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))


class ReleaseSelectionTest(unittest.TestCase):
    def test_selects_the_release_this_source_succeeds_before_and_after_the_bump(self) -> None:
        published = ["v0.31.0", "v0.32.0", "v0.33.0", "v0.34.0-rc.1", "nightly"]
        self.assertEqual(MODULE.select_from_tag(published, "0.33.0"), "v0.33.0")
        self.assertEqual(MODULE.select_from_tag(published, "0.34.0"), "v0.33.0")
        self.assertEqual(MODULE.select_from_tag([*published, "v0.34.0"], "0.34.0"), "v0.34.0")

    def test_compares_versions_numerically(self) -> None:
        self.assertEqual(MODULE.select_from_tag(["v0.9.0", "v0.10.0"], "0.10.1"), "v0.10.0")

    def test_refuses_when_no_release_precedes_the_source(self) -> None:
        with self.assertRaisesRegex(Error, "no published release"):
            MODULE.select_from_tag(["v0.34.0"], "0.33.0")

    def test_refuses_the_v032_to_v033_exception_explicitly(self) -> None:
        for tag in ("v0.32.0", "v0.31.4", "v0.1.0"):
            with self.subTest(tag=tag), self.assertRaisesRegex(Error, "v0.32 to v0.33"):
                MODULE.check_forward_path(tag, "0.34.0")
        MODULE.check_forward_path("v0.33.0", "0.33.0")
        MODULE.check_forward_path("v0.33.0", "0.34.0")

    def test_refuses_to_move_state_backward(self) -> None:
        with self.assertRaisesRegex(Error, "only moves state forward"):
            MODULE.check_forward_path("v0.34.0", "0.33.0")

    def test_refuses_malformed_tags_and_versions(self) -> None:
        for tag in ("0.33.0", "v0.33", "v0.33.0-rc.1", "v01.2.3"):
            with self.subTest(tag=tag), self.assertRaises(Error):
                MODULE.parse_tag(tag)
        with self.assertRaises(Error):
            MODULE.parse_version("0.33.0-dev")

    def test_reads_the_workspace_version(self) -> None:
        MODULE.parse_version(MODULE.workspace_version(ROOT))

    def test_main_refuses_the_exception_before_any_download_or_container(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(stderr):
            work = Path(temporary) / "work"
            status = MODULE.main([
                "--from-tag", "v0.32.0", "--platform", "linux-amd64",
                "--to-bin-dir", temporary, "--work-dir", str(work),
            ])
            self.assertFalse(work.exists())
        self.assertEqual(status, 1)
        self.assertIn("no forward state path", stderr.getvalue())


class AssetAuthenticationTest(unittest.TestCase):
    def test_names_one_asset_per_rehearsed_binary(self) -> None:
        linux = MODULE.asset_names("v0.33.0", "linux-amd64")
        self.assertEqual(sorted(linux), sorted(MODULE.BINARIES))
        self.assertEqual(linux["bregctl"], "bregctl-v0.33.0-linux-amd64")
        macos = MODULE.asset_names("v0.33.0", "macos-arm64")
        self.assertEqual(macos["evidence"], "evidence-v0.33.0-macos-arm64.tar.gz")
        with self.assertRaises(Error):
            MODULE.asset_names("v0.33.0", "windows-amd64")

    def test_parses_sha256sums_strictly(self) -> None:
        digest = "a" * 64
        self.assertEqual(MODULE.parse_sha256sums(f"{digest}  breg\n"), {"breg": digest})
        for text in (
            f"{digest} breg\n",
            f"{digest}  ../breg\n",
            f"{'A' * 64}  breg\n",
            f"{digest}  breg\n{digest}  breg\n",
        ):
            with self.subTest(text=text), self.assertRaises(Error):
                MODULE.parse_sha256sums(text)

    def test_verifies_each_asset_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "breg").write_bytes(b"breg")
            (directory / "other").write_bytes(b"breg")
            digests = {"breg": hashlib.sha256(b"breg").hexdigest()}
            MODULE.verify_assets_by_name(directory, ["breg"], digests)
            with self.assertRaisesRegex(Error, "does not cover other"):
                MODULE.verify_assets_by_name(directory, ["other"], digests)
            (directory / "breg").write_bytes(b"tampered")
            with self.assertRaisesRegex(Error, "does not match"):
                MODULE.verify_assets_by_name(directory, ["breg"], digests)
            with self.assertRaisesRegex(Error, "was not downloaded"):
                MODULE.verify_assets_by_name(directory, ["absent"], {"absent": "0" * 64})

    def test_installs_a_linux_asset_as_the_plain_binary_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            asset = directory / "breg-v0.33.0-linux-amd64"
            asset.write_bytes(b"binary")
            destination = directory / "bin"
            destination.mkdir()
            MODULE.install_asset(asset, "breg", destination)
            self.assertEqual((destination / "breg").read_bytes(), b"binary")
            self.assertTrue((destination / "breg").stat().st_mode & 0o100)

    def test_installs_only_a_closed_macos_bundle(self) -> None:
        stem = "breg-v0.33.0-macos-arm64"
        library = "libaws_lc_fips_0_14_2_crypto.dylib"
        closed = {stem: b"binary", "THIRD_PARTY_NOTICES": b"notices", library: b"fips"}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            destination = directory / "bin"
            destination.mkdir()
            asset = directory / f"{stem}.tar.gz"
            write_tar(asset, closed)
            MODULE.install_asset(asset, "breg", destination)
            self.assertEqual((destination / "breg").read_bytes(), b"binary")
            self.assertEqual((destination / library).read_bytes(), b"fips")
            self.assertFalse((destination / "THIRD_PARTY_NOTICES").exists())

            refused = {
                "extra member": {**closed, "install.sh": b"#!/bin/sh"},
                "missing notices": {stem: b"binary", library: b"fips"},
                "missing library": {stem: b"binary", "THIRD_PARTY_NOTICES": b"notices"},
                "other executable": {"bregctl": b"binary", "THIRD_PARTY_NOTICES": b"n",
                                     library: b"fips"},
                "path traversal": {stem: b"binary", "THIRD_PARTY_NOTICES": b"n",
                                   f"../{library}": b"fips"},
            }
            for label, members in refused.items():
                with self.subTest(label=label):
                    write_tar(asset, members)
                    with self.assertRaisesRegex(Error, "closed macOS native bundle"):
                        MODULE.install_asset(asset, "breg", destination)

            write_tar(asset, {**closed, library: b"different"})
            with self.assertRaisesRegex(Error, "conflicting"):
                MODULE.install_asset(asset, "breg", destination)


class StateComparisonTest(unittest.TestCase):
    def test_a_table_that_lost_rows_or_vanished_is_a_loss(self) -> None:
        before = {"public.a": 3, "public.b": 2, "public.c": 0}
        after = {"public.a": 3, "public.b": 1, "public.d": 5}
        self.assertEqual(MODULE.row_count_losses(before, after), [
            "public.b dropped from 2 to 1 rows",
            "public.c disappeared (held 0 rows)",
        ])

    def test_growth_and_new_tables_are_not_losses(self) -> None:
        self.assertEqual(MODULE.row_count_losses({"a": 1}, {"a": 4, "b": 0}), [])

    def test_names_every_view_served_differently(self) -> None:
        before = {"records/1": {"etag": "1"}, "records/2": {"etag": "2"}}
        after = {"records/1": {"etag": "changed"}, "records/3": {"etag": "3"}}
        self.assertEqual(MODULE.view_differences(before, after), [
            "records/1 changed across the upgrade",
            "records/2 is no longer served",
            "records/3 was not captured before the upgrade",
        ])
        self.assertEqual(MODULE.view_differences(before, dict(before)), [])


class GateWiringTest(unittest.TestCase):
    def test_workflow_rehearses_from_verified_release_assets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in ("workflow_dispatch:", "pull_request:", "release/manifests/**",
                         "release/scripts/rehearse-upgrade.py",
                         "sigstore/cosign-installer@", "--platform linux-amd64",
                         "--features registry-breg/runtime"):
            self.assertTrue(required in workflow, f"workflow lacks {required!r}")
        for refused in ("--from-bin-dir", "contents: write", "id-token: write"):
            self.assertFalse(refused in workflow, f"workflow carries {refused!r}")

    def test_api_stability_states_the_same_exception(self) -> None:
        page = API_STABILITY.read_text(encoding="utf-8")
        floor = "v{}.{}.{}".format(*MODULE.FORWARD_PATH_FLOOR)
        for required in (floor, "v0.32", "rehearse-upgrade.py"):
            self.assertTrue(required in page, f"api-stability page lacks {required!r}")


if __name__ == "__main__":
    unittest.main()
