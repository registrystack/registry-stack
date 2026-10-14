#!/usr/bin/env python3
from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import socket
import tarfile
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from typing import Any


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

    def test_refuses_a_start_before_the_immediate_predecessor(self) -> None:
        for tag in ("v0.40.0", "v0.39.0", "v0.33.0", "v0.1.0"):
            with self.subTest(tag=tag), self.assertRaisesRegex(Error, "immediate predecessor"):
                MODULE.check_forward_path(tag, "0.42.0")
        MODULE.check_forward_path("v0.41.0", "0.41.0")
        MODULE.check_forward_path("v0.41.0", "0.42.0")

    def test_refuses_a_floor_behind_the_release_before_the_workspace_version(self) -> None:
        released = ["0.9.0", "0.37.0", "0.38.0", "0.39.0"]
        with unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 38, 0)):
            MODULE.check_floor_is_current(released, "0.39.0")
            MODULE.check_floor_is_current(released[:-1], "0.39.0")
            with self.assertRaisesRegex(Error, "FORWARD_PATH_FLOOR is v0.38.0, but .* is v0.39.0"):
                MODULE.check_floor_is_current(released, "0.40.0")
            with self.assertRaisesRegex(Error, "no released manifest"):
                MODULE.check_floor_is_current(released, "0.9.0")

    def test_a_floor_may_start_the_forward_path_at_the_workspace_version(self) -> None:
        released = ["0.38.0", "0.39.0"]
        with unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 40, 0)):
            # Unpublished, published, patched, and succeeded by the next minor
            # line whether or not its publication is recorded yet: the floor
            # stands through all of them without an edit.
            for recorded, version in ((released, "0.40.0"),
                                      ([*released, "0.40.0"], "0.40.0"),
                                      ([*released, "0.40.0"], "0.40.1"),
                                      (released, "0.41.0"),
                                      ([*released, "0.40.0"], "0.41.0")):
                with self.subTest(recorded=recorded, version=version):
                    MODULE.check_floor_is_current(recorded, version)
            with self.assertRaisesRegex(Error, "FORWARD_PATH_FLOOR is v0.40.0, but .* is v0.41.0"):
                MODULE.check_floor_is_current([*released, "0.40.0", "0.41.0"], "0.42.0")

    def test_refuses_a_floor_the_workspace_version_has_not_reached(self) -> None:
        released = ["0.37.0", "0.38.0"]
        with unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 40, 0)):
            for version in ("0.39.0", "0.39.4"):
                with self.subTest(version=version), \
                        self.assertRaisesRegex(Error, "newer than workspace version"):
                    MODULE.check_floor_is_current(released, version)

    def test_a_patch_release_keeps_the_floor_of_its_minor_line(self) -> None:
        released = ["0.37.0", "0.38.0", "0.39.0", "0.39.1"]
        with unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 38, 0)):
            for version in ("0.39.0", "0.39.1", "0.39.2"):
                with self.subTest(version=version):
                    MODULE.check_floor_is_current(released, version)
            for tag in ("v0.38.0", "v0.39.0", "v0.39.1"):
                with self.subTest(tag=tag):
                    MODULE.check_forward_path(tag, "0.39.2")
            with self.assertRaisesRegex(Error, "is v0.39.1"):
                MODULE.check_floor_is_current(released, "0.40.0")

    def test_reads_the_stack_version_of_every_released_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifests = Path(temporary) / "release/manifests"
            manifests.mkdir(parents=True)
            for release, version in (("beta-9", "0.9.0"), ("beta-10", "0.10.0")):
                (manifests / f"registry-stack-{release}.yaml").write_text(
                    f"stack:\n  release: {release}\n  version: {version}\n"
                    f"  source_tag: v{version}\n  status: released\n"
                    f"\nartifacts:\n  version: 9.9.9\n  status: released\n",
                    encoding="utf-8")
            (manifests / "import-map.yaml").write_text("version: 1\n", encoding="utf-8")
            self.assertEqual(sorted(MODULE.released_versions(Path(temporary))),
                             ["0.10.0", "0.9.0"])
            (manifests / "registry-stack-beta-11.yaml").write_text(
                "artifacts:\n  version: 0.11.0\n", encoding="utf-8")
            with self.assertRaisesRegex(Error, "registry-stack-beta-11.yaml"):
                MODULE.released_versions(Path(temporary))

    def test_a_manifest_that_was_never_published_is_not_a_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifests = Path(temporary) / "release/manifests"
            manifests.mkdir(parents=True)
            for release, version, status in (
                ("beta-50", "0.38.0", "  status: released\n"),
                ("beta-51", "0.39.0", "  status: release-candidate\n"),
                ("beta-52", "0.39.1", "\nartifacts:\n  status: released\n"),
            ):
                (manifests / f"registry-stack-{release}.yaml").write_text(
                    f"stack:\n  release: {release}\n  version: {version}\n"
                    f"  source_tag: v{version}\n{status}", encoding="utf-8")
            released = MODULE.released_versions(Path(temporary))
        self.assertEqual(released, ["0.38.0"])
        with unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 38, 0)):
            for version in ("0.39.1", "0.39.2", "0.40.0"):
                with self.subTest(version=version):
                    MODULE.check_floor_is_current(released, version)

    def test_main_refuses_a_stale_floor_before_any_download_or_container(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(stderr), \
                unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 1, 0)):
            work = Path(temporary) / "work"
            status = MODULE.main([
                "--from-tag", "v0.38.0", "--platform", "linux-amd64",
                "--to-bin-dir", temporary, "--work-dir", str(work),
            ])
            self.assertFalse(work.exists())
        self.assertEqual(status, 1)
        self.assertIn("FORWARD_PATH_FLOOR", stderr.getvalue())

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

    def test_main_refuses_an_earlier_start_before_any_download_or_container(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(stderr):
            work = Path(temporary) / "work"
            status = MODULE.main([
                "--from-tag", "v0.37.0", "--platform", "linux-amd64",
                "--to-bin-dir", temporary, "--work-dir", str(work),
            ])
            self.assertFalse(work.exists())
        self.assertEqual(status, 1)
        self.assertIn("immediate predecessor", stderr.getvalue())

    def test_fetch_only_needs_no_binaries_under_test(self) -> None:
        args = MODULE.parse_args(["--fetch-only", "--platform", "linux-amd64",
                                  "--work-dir", "/work"])
        self.assertTrue(args.fetch_only)
        self.assertIsNone(args.to_bin_dir)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--platform", "linux-amd64", "--work-dir", "/work"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--fetch-only", "--from-bin-dir", "/bin", "--platform",
                               "linux-amd64", "--work-dir", "/work"])

    def test_fetch_only_authenticates_the_release_and_starts_nothing(self) -> None:
        def fetch(tag, platform, download, bin_dir, binaries):
            bin_dir.mkdir(mode=0o700)
            for binary in binaries:
                script = bin_dir / binary
                script.write_text(f"#!/bin/sh\necho '{binary} 0.40.0'\n", encoding="utf-8")
                script.chmod(0o755)

        with tempfile.TemporaryDirectory() as temporary, \
                contextlib.redirect_stdout(io.StringIO()), \
                unittest.mock.patch.object(MODULE, "fetch_release", side_effect=fetch) as fetched, \
                unittest.mock.patch.object(MODULE, "Postgres", side_effect=AssertionError("started")), \
                unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 40, 0)), \
                unittest.mock.patch.object(MODULE, "workspace_version", return_value="0.41.0"):
            work = Path(temporary) / "work"
            report = Path(temporary) / "report.json"
            status = MODULE.main(["--fetch-only", "--from-tag", "v0.40.0", "--platform",
                                  "linux-amd64", "--product", "evidence", "--work-dir", str(work),
                                  "--report", str(report)])
            self.assertEqual(status, 0)
            self.assertEqual(fetched.call_args.args[4], ("evidence", "evidencectl"))
            self.assertTrue((work / "from-bin" / "evidencectl").is_file())
            document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(document["fromProvenance"], "cosign and SHA256SUMS verified")
        self.assertEqual(document["fromBinDir"], str(work.resolve() / "from-bin"))
        self.assertNotIn("breg", document)


class UnpublishedFloorTest(unittest.TestCase):
    """While no release from the floor onward is published, this source's
    build stands on both sides. The floor and workspace version are fixed here
    so the tests hold after the floor's release is published."""

    def run_main(self, arguments: list[str], published: list[str], version: str = "0.40.0"
                 ) -> tuple[int, str, str, dict[str, Any]]:
        seen: dict[str, Any] = {"sides": [], "legs": []}

        def binaries(side, expected_version, names):
            seen["sides"].append((side.label, side.bin_dir, expected_version))
            return {name: f"{name} {version}-dev" for name in names}

        def leg(work, keys, tls, old, new, report):
            seen["legs"].append((old.bin_dir, new.bin_dir))

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 40, 0)), \
                unittest.mock.patch.object(MODULE, "workspace_version", return_value=version), \
                unittest.mock.patch.object(MODULE, "released_versions",
                                           return_value=["0.38.0", "0.39.0"]), \
                unittest.mock.patch.object(MODULE, "published_tags", return_value=published), \
                unittest.mock.patch.object(MODULE, "fetch_release") as fetched, \
                unittest.mock.patch.object(MODULE, "check_binaries", side_effect=binaries), \
                unittest.mock.patch.object(MODULE, "Keys"), \
                unittest.mock.patch.object(MODULE, "Postgres"), \
                unittest.mock.patch.object(MODULE, "rehearse_evidence", side_effect=leg):
            status = MODULE.main(arguments)
        seen["fetched"] = fetched.call_args_list
        return status, stdout.getvalue(), stderr.getvalue(), seen

    def test_the_legs_run_from_this_source_s_build_on_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            built = Path(temporary).resolve() / "bin"
            built.mkdir()
            report = Path(temporary) / "report.json"
            status, stdout, _stderr, seen = self.run_main(
                ["--platform", "linux-amd64", "--product", "evidence", "--to-bin-dir",
                 str(built), "--work-dir", str(Path(temporary) / "work"),
                 "--report", str(report)], ["v0.38.0", "v0.39.0"])
            document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual(seen["fetched"], [])
        # A build of this source reports a development version, so neither
        # side is held to the tag.
        self.assertEqual(seen["sides"], [("from", built, None), ("to", built, None)])
        self.assertEqual(seen["legs"], [(built, built)])
        self.assertEqual(document["from"], "v0.40.0")
        self.assertEqual(document["fromProvenance"],
                         "this source's build, no published predecessor")
        self.assertIn("no release from v0.40.0 onward is published", stdout)

    def test_a_product_that_publishes_no_asset_for_the_platform_still_runs(self) -> None:
        with unittest.mock.patch.object(MODULE.release_roster, "MESSAGING_FIRST_RELEASE",
                                        (0, 40, 0)), \
                unittest.mock.patch.object(MODULE, "rehearse_messaging") as leg, \
                tempfile.TemporaryDirectory() as temporary:
            status, _stdout, _stderr, _seen = self.run_main(
                ["--platform", "macos-arm64", "--product", "messaging", "--to-bin-dir",
                 temporary, "--work-dir", str(Path(temporary) / "work")], ["v0.39.0"])
        self.assertEqual(status, 0)
        leg.assert_called_once()

    def test_fetch_only_has_nothing_to_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            status, stdout, _stderr, seen = self.run_main(
                ["--fetch-only", "--platform", "linux-amd64", "--work-dir", str(work)],
                ["v0.39.0"])
            self.assertFalse(work.exists())
        self.assertEqual(status, 0)
        self.assertEqual(seen["fetched"], [])
        self.assertEqual(seen["sides"], [])
        self.assertEqual(stdout.count("\n"), 1)
        self.assertIn("no release from v0.40.0 onward is published", stdout)

    def test_the_floor_s_release_is_downloaded_once_it_is_published(self) -> None:
        for version in ("0.40.0", "0.40.1", "0.41.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary) / "work"
                status, stdout, _stderr, seen = self.run_main(
                    ["--platform", "linux-amd64", "--product", "evidence", "--to-bin-dir",
                     temporary, "--work-dir", str(work)], ["v0.39.0", "v0.40.0"], version)
                self.assertEqual(status, 0)
                (fetched,) = seen["fetched"]
                self.assertEqual(fetched.args[0], "v0.40.0")
                self.assertEqual(seen["sides"][0],
                                 ("from", work.resolve() / "from-bin", "0.40.0"))
                self.assertNotIn("no release from", stdout)

    def test_a_named_or_local_start_before_the_floor_is_still_refused(self) -> None:
        for chosen in (["--from-tag", "v0.39.0"], ["--from-bin-dir", "/previous"]):
            with self.subTest(chosen=chosen), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary) / "work"
                status, _stdout, stderr, seen = self.run_main(
                    [*chosen, "--platform", "linux-amd64", "--to-bin-dir", temporary,
                     "--work-dir", str(work)], ["v0.39.0"])
                self.assertFalse(work.exists())
                self.assertEqual(status, 1)
                self.assertIn("immediate predecessor", stderr)
                self.assertEqual(seen["sides"], [])


class ProductSelectionTest(unittest.TestCase):
    # The tests patch a fixed first release over
    # release_roster.MESSAGING_FIRST_RELEASE, so the Messaging leg is covered
    # without depending on the release that actually first shipped it.
    HYPOTHETICAL_MESSAGING_FIRST_RELEASE = (0, 36, 0)

    def setUp(self) -> None:
        roster_patch = unittest.mock.patch.object(
            MODULE.release_roster,
            "MESSAGING_FIRST_RELEASE",
            self.HYPOTHETICAL_MESSAGING_FIRST_RELEASE,
        )
        roster_patch.start()
        self.addCleanup(roster_patch.stop)

    def test_no_starting_release_holds_messaging_until_the_roster_names_one(self) -> None:
        with unittest.mock.patch.object(
            MODULE.release_roster, "MESSAGING_FIRST_RELEASE", None
        ):
            for tag in ("v0.35.0", "v0.36.0", "v1.0.0"):
                with self.subTest(tag=tag):
                    products, omitted = MODULE.select_products(
                        None, tag, "linux-amd64", True
                    )
                    self.assertEqual(products, ["evidence"])
                    self.assertEqual(list(omitted), ["breg", "casework", "messaging"])
                    self.assertEqual(omitted["casework"], MODULE.CASEWORK_NO_IN_PLACE_UPGRADE)
                    self.assertIn("messaging has not joined a release yet",
                                  omitted["messaging"])
                    for downloading in (True, False):
                        with self.assertRaisesRegex(
                            Error, "messaging has not joined a release yet"
                        ):
                            MODULE.select_products(
                                ["messaging"], tag, "linux-amd64", downloading
                            )

    def test_a_default_run_omits_a_product_the_starting_release_did_not_ship(self) -> None:
        products, omitted = MODULE.select_products(None, "v0.35.0", "linux-amd64", True)
        self.assertEqual(products, ["evidence"])
        self.assertEqual(list(omitted), ["breg", "casework", "messaging"])
        self.assertEqual(omitted["casework"], MODULE.CASEWORK_NO_IN_PLACE_UPGRADE)
        self.assertIn("first shipped in v0.36.0", omitted["messaging"])

    def test_messaging_joins_the_default_run_from_its_first_release(self) -> None:
        for tag in ("v0.36.0", "v0.36.2", "v1.0.0"):
            with self.subTest(tag=tag):
                products, omitted = MODULE.select_products(None, tag, "linux-amd64", True)
                self.assertEqual(products, list(MODULE.PRODUCTS))
                self.assertEqual(omitted, {
                    "breg": MODULE.BREG_NO_IN_PLACE_UPGRADE,
                    "casework": MODULE.CASEWORK_NO_IN_PLACE_UPGRADE,
                })

    def test_a_named_unavailable_product_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, "messaging was first shipped in v0.36.0"):
            MODULE.select_products(["messaging"], "v0.35.0", "linux-amd64", True)
        with self.assertRaisesRegex(Error, "fresh database"):
            MODULE.select_products(["casework"], "v0.35.0", "linux-amd64", True)

    def test_main_refuses_retired_products_before_any_network_or_container(self) -> None:
        for product, guidance in MODULE.RETIRED_PRODUCTS.items():
            with self.subTest(product=product), tempfile.TemporaryDirectory() as temporary:
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), \
                        unittest.mock.patch.object(MODULE, "published_tags", side_effect=AssertionError("network")), \
                        unittest.mock.patch.object(MODULE, "fetch_release", side_effect=AssertionError("download")), \
                        unittest.mock.patch.object(MODULE, "Postgres", side_effect=AssertionError("container")):
                    work = Path(temporary) / "work"
                    status = MODULE.main([
                        "--platform", "linux-amd64", "--product", product,
                        "--to-bin-dir", temporary, "--work-dir", str(work),
                    ])
                self.assertEqual(status, 1)
                self.assertFalse(work.exists())
                self.assertIn(guidance, stderr.getvalue())
                self.assertIn("fresh database", stderr.getvalue())

    def test_messaging_downloads_only_the_platforms_it_publishes(self) -> None:
        products, omitted = MODULE.select_products(None, "v0.36.0", "macos-arm64", True)
        self.assertNotIn("messaging", products)
        self.assertIn("no macos-arm64 asset", omitted["messaging"])
        with self.assertRaisesRegex(Error, "no macos-arm64 asset"):
            MODULE.select_products(["messaging"], "v0.36.0", "macos-arm64", True)
        self.assertEqual(
            MODULE.select_products(["messaging"], "v0.36.0", "macos-arm64", False),
            (["messaging"], {}),
        )

    def test_main_refuses_an_unshipped_product_before_any_download_or_container(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(stderr), \
                unittest.mock.patch.object(MODULE, "workspace_version", return_value="0.41.0"), \
                unittest.mock.patch.object(MODULE, "FORWARD_PATH_FLOOR", (0, 40, 0)), \
                unittest.mock.patch.object(MODULE.release_roster, "MESSAGING_FIRST_RELEASE",
                                           (0, 41, 0)):
            work = Path(temporary) / "work"
            status = MODULE.main([
                "--from-tag", "v0.40.0", "--platform", "linux-amd64",
                "--product", "messaging",
                "--to-bin-dir", temporary, "--work-dir", str(work),
            ])
            self.assertFalse(work.exists())
        self.assertEqual(status, 1)
        self.assertIn("messaging was first shipped in v0.41.0, so v0.40.0 holds no",
                      stderr.getvalue())


class AssetAuthenticationTest(unittest.TestCase):
    def test_names_one_asset_per_rehearsed_binary(self) -> None:
        linux = MODULE.asset_names("v0.33.0", "linux-amd64")
        self.assertEqual(sorted(linux), sorted(MODULE.BINARIES))
        self.assertEqual(linux["evidencectl"], "evidencectl-v0.33.0-linux-amd64")
        macos = MODULE.asset_names("v0.33.0", "macos-arm64")
        self.assertEqual(macos["evidence"], "evidence-v0.33.0-macos-arm64.tar.gz")
        with self.assertRaises(Error):
            MODULE.asset_names("v0.33.0", "windows-amd64")

    def test_parses_sha256sums_strictly(self) -> None:
        digest = "a" * 64
        self.assertEqual(MODULE.parse_sha256sums(f"{digest}  casework\n"), {"casework": digest})
        for text in (
            f"{digest} casework\n",
            f"{digest}  ../casework\n",
            f"{'A' * 64}  casework\n",
            f"{digest}  casework\n{digest}  casework\n",
        ):
            with self.subTest(text=text), self.assertRaises(Error):
                MODULE.parse_sha256sums(text)

    def test_verifies_each_asset_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "casework").write_bytes(b"casework")
            (directory / "other").write_bytes(b"casework")
            digests = {"casework": hashlib.sha256(b"casework").hexdigest()}
            MODULE.verify_assets_by_name(directory, ["casework"], digests)
            with self.assertRaisesRegex(Error, "does not cover other"):
                MODULE.verify_assets_by_name(directory, ["other"], digests)
            (directory / "casework").write_bytes(b"tampered")
            with self.assertRaisesRegex(Error, "does not match"):
                MODULE.verify_assets_by_name(directory, ["casework"], digests)
            with self.assertRaisesRegex(Error, "was not downloaded"):
                MODULE.verify_assets_by_name(directory, ["absent"], {"absent": "0" * 64})

    def test_installs_a_linux_asset_as_the_plain_binary_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            asset = directory / "casework-v0.33.0-linux-amd64"
            asset.write_bytes(b"binary")
            destination = directory / "bin"
            destination.mkdir()
            MODULE.install_asset(asset, "casework", destination)
            self.assertEqual((destination / "casework").read_bytes(), b"binary")
            self.assertTrue((destination / "casework").stat().st_mode & 0o100)

    def test_installs_only_a_closed_macos_bundle(self) -> None:
        stem = "casework-v0.33.0-macos-arm64"
        library = "libaws_lc_fips_0_14_2_crypto.dylib"
        closed = {stem: b"binary", "THIRD_PARTY_NOTICES": b"notices", library: b"fips"}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            destination = directory / "bin"
            destination.mkdir()
            asset = directory / f"{stem}.tar.gz"
            write_tar(asset, closed)
            MODULE.install_asset(asset, "casework", destination)
            self.assertEqual((destination / "casework").read_bytes(), b"binary")
            self.assertEqual((destination / library).read_bytes(), b"fips")
            self.assertFalse((destination / "THIRD_PARTY_NOTICES").exists())

            refused = {
                "extra member": {**closed, "install.sh": b"#!/bin/sh"},
                "missing notices": {stem: b"binary", library: b"fips"},
                "missing library": {stem: b"binary", "THIRD_PARTY_NOTICES": b"notices"},
                "other executable": {"caseworkctl": b"binary", "THIRD_PARTY_NOTICES": b"n",
                                     library: b"fips"},
                "path traversal": {stem: b"binary", "THIRD_PARTY_NOTICES": b"n",
                                   f"../{library}": b"fips"},
            }
            for label, members in refused.items():
                with self.subTest(label=label):
                    write_tar(asset, members)
                    with self.assertRaisesRegex(Error, "closed macOS native bundle"):
                        MODULE.install_asset(asset, "casework", destination)

            write_tar(asset, {**closed, library: b"different"})
            with self.assertRaisesRegex(Error, "conflicting"):
                MODULE.install_asset(asset, "casework", destination)


class SideTest(unittest.TestCase):
    def test_delegating_tools_find_this_side_s_runtime_not_an_ambient_one(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp) / "bin"
            side = MODULE.Side("from", bin_dir, Path(temp) / "ca.pem")
            ambient = {"EVIDENCE_BIN": "/elsewhere/evidence", "PATH": "/usr/bin"}
            with unittest.mock.patch.dict(MODULE.os.environ, ambient):
                env = side.env()
            self.assertEqual(env["EVIDENCE_BIN"], str(bin_dir / "evidence"))
            self.assertEqual(env["PATH"].split(MODULE.os.pathsep)[0], str(bin_dir))

    def test_a_side_never_inherits_a_product_s_ambient_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            side = MODULE.Side("to", Path(temp), Path(temp) / "ca.pem")
            ambient = {prefix + "SETTING": "ambient" for prefix in (
                "BREG_", "CASEWORK_", "MESSAGING_", "REGISTRY_", "DYLD_")}
            with unittest.mock.patch.dict(MODULE.os.environ, ambient):
                env = side.env()
            for name in ambient:
                self.assertNotIn(name, env)

    def test_a_focused_run_needs_only_the_named_products_binaries(self) -> None:
        self.assertEqual(MODULE.product_binaries(["evidence"]), ("evidence", "evidencectl"))
        self.assertEqual(MODULE.product_binaries(["messaging"]), ("messaging", "messagingctl"))
        self.assertEqual(MODULE.product_binaries(list(MODULE.PRODUCTS)), MODULE.BINARIES)
        assets = MODULE.asset_names("v0.33.0", "linux-amd64", ("evidence", "evidencectl"))
        self.assertEqual(sorted(assets), ["evidence", "evidencectl"])
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp)
            for binary in ("evidence", "evidencectl"):
                script = bin_dir / binary
                script.write_text(f"#!/bin/sh\necho '{binary} 0.33.0'\n", encoding="utf-8")
                script.chmod(0o755)
            side = MODULE.Side("from", bin_dir, bin_dir / "ca.pem")
            versions = MODULE.check_binaries(side, "0.33.0", ("evidence", "evidencectl"))
            self.assertEqual(sorted(versions), ["evidence", "evidencectl"])
            with self.assertRaisesRegex(Error, "lack messaging"):
                MODULE.check_binaries(side, "0.33.0", MODULE.BINARIES)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


class MessagingUpgradeTest(unittest.TestCase):
    ACTIVATED = "sha256:" + "a" * 64
    OTHER = "sha256:" + "c" * 64

    def messaging(self, root: Path) -> object:
        messaging = MODULE.Messaging.__new__(MODULE.Messaging)
        messaging.runtime = root / "runtime.yaml"
        return messaging

    def plan(self, change: str, pending: list[int], active: str | None = ACTIVATED,
             package: str | None = ACTIVATED) -> dict[str, Any]:
        return {"packageDigest": package, "activeDigest": active, "change": change,
                "pendingSchemaVersions": pending}

    def upgrade(self, activated: str | None, *plans: dict[str, Any]
                ) -> tuple[list[str], Any, list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            messaging = self.messaging(Path(directory))
            side = unittest.mock.Mock()
            side.run_json.side_effect = list(plans)
            result = messaging.upgrade(side, activated)
            runtime = ["--runtime-config", str(messaging.runtime)]
        plan = unittest.mock.call("messagingctl", "--format", "json", "plan", *runtime)
        self.assertEqual(side.run_json.call_args_list, [plan] * len(plans))
        return result, side, runtime

    def test_pending_schema_versions_are_applied_over_the_previous_activation(self) -> None:
        result, side, runtime = self.upgrade(
            self.ACTIVATED, self.plan("none", [3]), self.plan("none", []))
        self.assertEqual(result, [])
        self.assertEqual(side.run.call_args_list, [
            unittest.mock.call("messagingctl", "check", *runtime),
            unittest.mock.call("messagingctl", "apply", *runtime)])

    def test_an_applied_version_that_empties_nothing_names_no_table(self) -> None:
        result, side, _runtime = self.upgrade(
            self.ACTIVATED, self.plan("none", [4]), self.plan("none", []))
        self.assertEqual(result, [])
        self.assertEqual(side.run.call_count, 2)

    def test_an_upgrade_with_nothing_pending_only_checks_and_plans(self) -> None:
        result, side, runtime = self.upgrade(self.ACTIVATED, self.plan("none", []))
        self.assertEqual(result, [])
        side.run.assert_called_once_with("messagingctl", "check", *runtime)

    def test_a_lost_activation_is_a_difference_and_is_never_applied_over(self) -> None:
        cases = (
            (self.ACTIVATED, self.plan("activate", [3], None)),
            (self.ACTIVATED, self.plan("activate", [3], self.OTHER)),
            (self.ACTIVATED, self.plan("activate", [3], package=self.OTHER)),
            (self.ACTIVATED, self.plan("activate", [3], self.OTHER, self.OTHER)),
            (self.ACTIVATED, self.plan("activate", [3], None, None)),
            (None, self.plan("activate", [3], None, None)),
            (None, self.plan("none", [3])),
        )
        for activated, planned in cases:
            with self.subTest(activated=activated, planned=planned):
                differences, side, runtime = self.upgrade(activated, planned)
                self.assertTrue(differences)
                side.run.assert_called_once_with("messagingctl", "check", *runtime)

    def test_the_plan_after_the_apply_is_the_one_compared(self) -> None:
        differences = self.upgrade(
            self.ACTIVATED, self.plan("none", [3]), self.plan("activate", []))[0]
        self.assertEqual(differences, ["the package ledger still names a change to apply"])


# JSON is YAML, so the runtime document round-trips without PyYAML.




@unittest.mock.patch.object(MODULE, "dump_yaml", dump_json)
@unittest.mock.patch.object(MODULE, "load_yaml", load_json)
class EvidencePackageTest(unittest.TestCase):
    def test_authoring_reuses_the_target_public_key_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = MODULE.Evidence.__new__(MODULE.Evidence)
            evidence.project = root / "project"
            evidence.target = root / "target"
            evidence.candidate = root / "candidate"
            evidence.issuer = "https://issuer.example.test"
            evidence.signing_jwk = {"kid": "synthetic-transit"}
            public_keys = evidence.target / "public-keys"
            public_keys.mkdir(parents=True)
            existing = public_keys / "existing.jwk.json"
            existing.write_text("existing public key")
            dump_json(evidence.target / "target.yaml", {})
            dump_json(evidence.target / "authority.yaml", {"accessProfiles": {}})
            evidence.deployment_target = lambda document: document
            evidence.package = unittest.mock.Mock()
            side = unittest.mock.Mock()
            with unittest.mock.patch.object(MODULE, "evidence_production_target",
                                            return_value={"authority": "authority.yaml"}):
                evidence.author(side)
            self.assertEqual(existing.read_text(), "existing public key")
            self.assertEqual(load_json(public_keys / "synthetic-transit.jwk.json"),
                             evidence.signing_jwk)
            evidence.package.assert_called_once_with(side, evidence.candidate)

    def test_a_sealed_installed_package_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = MODULE.Evidence.__new__(MODULE.Evidence)
            evidence.project = root / "project"
            evidence.target = root / "target"
            evidence.installed = root / "installed"
            evidence.runtime = root / "runtime.yaml"
            evidence.target.mkdir()
            # evidencectl seals every published package directory at 0o500.
            sealed = evidence.installed / "sources"
            sealed.mkdir(parents=True)
            (sealed / "record-status.sql").write_text("select 1;\n")
            (sealed / "record-status.sql").chmod(0o400)
            sealed.chmod(0o500)
            evidence.installed.chmod(0o500)
            candidate = root / "candidate"

            def publish(binary: str, *_args: str) -> None:
                if binary != "evidencectl":
                    return
                candidate.mkdir()
                (candidate / "bundle").mkdir()
                (candidate / "bundle" / "SHA256SUMS").write_text("")
                dump_json(candidate / "runtime.yaml", {"package": {"root": str(evidence.installed / "bundle")}})
                (candidate / "compiled-authority.yaml").write_text("complete authority")

            side = unittest.mock.Mock()
            side.run.side_effect = publish
            evidence.package(side, candidate)
            self.assertEqual(sorted(p.name for p in evidence.installed.iterdir()),
                             ["bundle", "compiled-authority.yaml", "runtime.yaml"])
            self.assertEqual(load_json(evidence.runtime)["package"]["root"], str(evidence.installed / "bundle"))
            side.run.assert_called_with("evidence", "authority", "activate", "--runtime-config",
                                        str(evidence.runtime), "--document",
                                        str(evidence.installed / "compiled-authority.yaml"))
            self.assertFalse(candidate.exists())


class EvidenceGrammarTest(unittest.TestCase):
    def test_tls_trust_input_is_immutable_before_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "evidence"
            work.mkdir()
            (work / "transit-signing.pem").write_text("synthetic placeholder")
            ca_file = root / "ca.pem"
            ca_file.write_text("synthetic certificate placeholder")
            ca_file.chmod(0o644)
            with unittest.mock.patch.object(MODULE, "JwksServer"), \
                    unittest.mock.patch.object(MODULE, "TransitServer"), \
                    unittest.mock.patch.object(MODULE, "run"), \
                    unittest.mock.patch.object(MODULE, "ec_public_jwk"):
                MODULE.Evidence(work, unittest.mock.Mock(), root)
            self.assertEqual(ca_file.stat().st_mode & 0o222, 0)

    def test_project_authoring_uses_the_current_init_command(self) -> None:
        evidence = MODULE.Evidence.__new__(MODULE.Evidence)
        evidence.project = Path("/srv/project")
        side = unittest.mock.Mock()
        side.run.side_effect = Error("stop after project creation")
        with self.assertRaisesRegex(Error, "stop after project creation"):
            evidence.author(side)
        side.run.assert_called_once_with(
            "evidencectl", "init", "--transport", "sqlite-extract", "--profile", "local",
            "/srv/project")

    def test_the_runtime_file_is_named_the_way_each_binary_reads_it(self) -> None:
        runtime = Path("/srv/runtime.yaml")
        self.assertEqual(MODULE.evidence_arguments(runtime, "check"),
                         ["check", "--runtime-config", "/srv/runtime.yaml"])

    def test_a_normalized_local_target_becomes_a_production_target(self) -> None:
        local = {
            "apiVersion": "id.registrystack.org/formats/evidence/target/v1alpha1",
            "kind": "EvidenceTarget", "id": "local", "project": "local-evidence",
            "authority": "authority.yaml", "assuranceProfile": "local",
            "service": {"providerId": "urn:example:provider:local-evidence",
                        "publicOrigin": "http://127.0.0.1:8080"},
            "signer": {"type": "local-jwk", "publicJwkFile": ".generated/secrets/key.json"},
            "authentication": {"oidc": {"issuer": "http://127.0.0.1:8081", "algorithms": ["ES256"]}},
        }
        production = MODULE.evidence_production_target(
            local, "https://127.0.0.1:9443", "public-keys/transit.jwk.json")
        self.assertEqual(production["kind"], "EvidenceTarget")
        self.assertEqual(production["authority"], "authority.yaml")
        self.assertEqual(production["assuranceProfile"], "production")
        self.assertEqual(production["service"]["publicOrigin"], MODULE.EVIDENCE_PUBLIC_ORIGIN)
        self.assertEqual(production["responseFormats"], ["signed-jws"])
        self.assertEqual(production["signer"], {"type": "transit", "algorithm": "ES256",
                         "publicJwkFile": "public-keys/transit.jwk.json"})
        self.assertEqual(production["authentication"]["oidc"]["algorithms"], ["RS256"])
        self.assertEqual(production["authentication"]["oidc"]["jwksSource"], {
            "type": "uri", "uri": "https://127.0.0.1:9443/oauth2/jwks"})
        self.assertEqual(local["assuranceProfile"], "local")

    @unittest.mock.patch.object(MODULE, "http", return_value=(200, {}, {"answer": True}))
    def test_request_uses_the_normalized_selector_and_declared_audience(self, request) -> None:
        evidence = MODULE.Evidence.__new__(MODULE.Evidence)
        evidence.keys = unittest.mock.Mock()
        evidence.keys.mint.return_value = "synthetic-token"
        evidence.issuer = "https://issuer.example.test"
        evidence.port = 8080
        evidence.target_document = {"authentication": {"oidc": {
            "audience": "urn:example:audience:local-evidence", "requiredScopes": ["evidence:request"],
            "requesterTagsClaim": "evidence_tags", "evidenceAudienceClaim": "evidence_audience"}}}
        evidence.authority = {"accessProfiles": {"local-service-1": {"requesterTags": ["local-service"]}}}
        self.assertEqual(evidence.request(), (200, {"answer": True}))
        claims = evidence.keys.mint.call_args.args[2]
        self.assertEqual(claims["evidence_audience"], "urn:example:audience:local-evidence")
        self.assertEqual(claims["evidence_tags"], ["local-service"])
        self.assertEqual(request.call_args.kwargs["body"]["subjects"], [{"role": "subject",
                         "selector": {"profile": "record-reference", "values": {"record-reference": "REC-0001"}}}])


class TransitStubTest(unittest.TestCase):
    def test_a_der_signature_becomes_the_fixed_width_jws_form(self) -> None:
        der = bytes([0x30, 0x45, 0x02, 0x21, 0x00]) + b"\x81" * 32 + bytes([0x02, 0x20]) + b"\x02" * 32
        self.assertEqual(MODULE.ecdsa_der_to_raw(der), b"\x81" * 32 + b"\x02" * 32)
        short = bytes([0x30, 0x24, 0x02, 0x1f]) + b"\x03" * 31 + bytes([0x02, 0x01, 0x04])
        self.assertEqual(MODULE.ecdsa_der_to_raw(short),
                         b"\x00" + b"\x03" * 31 + b"\x00" * 31 + b"\x04")
        with self.assertRaises(Error):
            MODULE.ecdsa_der_to_raw(b"\x31\x00")

    def test_the_stub_signs_a_prehashed_digest_the_public_key_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "transit.pem"
            MODULE.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                        "-out", str(key)])
            jwk = MODULE.ec_public_jwk(key)
            self.assertEqual(sorted(jwk), ["alg", "crv", "kid", "kty", "x", "y"])
            transit = MODULE.TransitServer(key)
            try:
                metadata = transit_call(transit.socket_path, "GET",
                                        "/v1/transit/keys/evidence-signing", None)
                self.assertEqual(metadata["data"]["latest_version"], 1)
                public_pem = metadata["data"]["keys"]["1"]["public_key"]
                digest = hashlib.sha256(b"rehearsal").digest()
                signed = transit_call(transit.socket_path, "POST",
                                      "/v1/transit/sign/evidence-signing/sha2-256",
                                      {"input": base64.b64encode(digest).decode(),
                                       "key_version": 1, "prehashed": True,
                                       "marshaling_algorithm": "jws"})
                refused = transit_call(transit.socket_path, "POST",
                                       "/v1/transit/sign/evidence-signing/sha2-256",
                                       {"input": base64.b64encode(digest).decode(),
                                        "key_version": 1, "prehashed": False,
                                        "marshaling_algorithm": "jws"})
            finally:
                transit.stop()
            self.assertIn("errors", refused)
            self.assertFalse(transit.socket_path.exists())
            prefix, raw = signed["data"]["signature"].rsplit(":", 1)
            self.assertEqual(prefix, "vault:v1")
            raw_bytes = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            self.assertEqual(len(raw_bytes), 64)
            public = Path(directory) / "public.pem"
            public.write_text(public_pem)
            signature = Path(directory) / "signature.der"
            signature.write_bytes(raw_to_der(raw_bytes))
            message = Path(directory) / "digest"
            message.write_bytes(digest)
            MODULE.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public),
                        "-in", str(message), "-sigfile", str(signature)])


def transit_call(socket_path: Path, method: str, path: str, body: Any) -> Any:
    data = json.dumps(body).encode() if body is not None else b""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(socket_path))
        client.sendall(f"{method} {path} HTTP/1.1\r\nHost: transit\r\n"
                       f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode()
                       + data)
        response = b""
        while chunk := client.recv(65536):
            response += chunk
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def raw_to_der(raw: bytes) -> bytes:
    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\0") or b"\0"
        if value[0] & 0x80:
            value = b"\0" + value
        return bytes([0x02, len(value)]) + value
    body = integer(raw[:32]) + integer(raw[32:])
    return bytes([0x30, len(body)]) + body


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

    def test_an_emptied_table_is_a_loss(self) -> None:
        before = {"public.a": 3, "public.b": 2}
        after = {"public.a": 3, "public.b": 0}
        self.assertEqual(MODULE.row_count_losses(before, after),
                         ["public.b dropped from 2 to 0 rows"])

    def test_names_every_view_served_differently(self) -> None:
        before = {"records/1": {"etag": "1"}, "records/2": {"etag": "2"}}
        after = {"records/1": {"etag": "changed"}, "records/3": {"etag": "3"}}
        self.assertEqual(MODULE.view_differences(before, after), [
            "records/1 changed across the upgrade",
            "records/2 is no longer served",
            "records/3 was not captured before the upgrade",
        ])
        self.assertEqual(MODULE.view_differences(before, dict(before)), [])


class AuditUpgradeTest(unittest.TestCase):
    def test_counts_every_segment_of_one_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            audit = Path(temporary)
            for name in ("evidence.jsonl", "evidence.jsonl.00000001"):
                (audit / name).write_text('{"old":true}\n')
            (audit / "other.jsonl").write_text('{"other":true}\n')
            self.assertEqual(MODULE.audit_record_count(audit, "evidence.jsonl"), 2)

    def test_a_stream_must_keep_the_previous_records_and_gain_the_new_ones(self) -> None:
        self.assertEqual(MODULE.audit_stream_losses("Evidence", 2, 4, 2), [])
        self.assertEqual(MODULE.audit_stream_losses("Evidence", 2, 5, 2), [])
        for before, after in ((0, 2), (2, 3), (2, 2), (2, 0)):
            with self.subTest(before=before, after=after):
                self.assertEqual(len(MODULE.audit_stream_losses("Evidence", before, after, 2)), 1)

    def test_the_stream_requires_valid_response_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "evidence.jsonl"
            schema = "registry.evidence.audit/v2"
            for value in ({"old": True}, {"schema": schema, "phase": "response"}):
                path.write_text(json.dumps(value) + "\n")
                with self.assertRaises(Error):
                    MODULE.audit_record_count(root, "evidence.jsonl", schema=schema)
            path.write_text(json.dumps({"schema": schema, "phase": "response",
                "eventId": "event-1", "time": "2026-09-25T00:00:00Z",
                "correlation": "operation-1", "record": {}}) + "\n")
            self.assertEqual(MODULE.audit_record_count(root, "evidence.jsonl", schema=schema), 1)


class MessagingAssertionsTest(unittest.TestCase):
    ACTIVE = "sha256:" + "a" * 64
    OTHER = "sha256:" + "b" * 64

    def plan(self, **members: str | None) -> dict[str, str | None]:
        return {"activeDigest": self.ACTIVE, "packageDigest": self.ACTIVE, "change": "none",
                **members}

    def test_the_plan_must_name_the_previous_activation_with_nothing_to_change(self) -> None:
        self.assertEqual(MODULE.ledger_digest_differences(self.ACTIVE, self.plan()), [])
        for planned, named in (
                (self.plan(activeDigest=self.OTHER), "activeDigest"),
                (self.plan(activeDigest=None), "activeDigest"),
                (self.plan(packageDigest=self.OTHER), "packageDigest"),
                (self.plan(packageDigest=None), "packageDigest"),
                (self.plan(change="activate"), "change to apply"),
                ({}, "activeDigest")):
            with self.subTest(planned=planned):
                differences = MODULE.ledger_digest_differences(self.ACTIVE, planned)
                self.assertTrue(differences)
                self.assertIn(named, differences[0])

    def test_a_ledger_that_named_no_package_before_the_upgrade_is_a_difference(self) -> None:
        for activated in (None, ""):
            with self.subTest(activated=activated):
                (difference,) = MODULE.ledger_digest_differences(activated, self.plan())
                self.assertIn("previous release", difference)

    def test_counts_one_event_across_every_segment_of_the_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            audit = Path(temporary)
            erased = json.dumps({"record": {"event": "messaging.retention.erased"}})
            other = json.dumps({"record": {"event": "messaging.retention.requested"}})
            (audit / "messaging.ndjson").write_text(erased + "\n" + other + "\n")
            (audit / "messaging.ndjson.1").write_text(erased + "\n")
            (audit / "elsewhere.ndjson").write_text(erased + "\n")
            self.assertEqual(MODULE.audit_event_count(
                audit, "messaging.ndjson", "messaging.retention.erased"), 2)
            self.assertEqual(MODULE.audit_event_count(
                audit, "messaging.ndjson", "messaging.retention.requested"), 1)
            self.assertEqual(MODULE.audit_event_count(audit, "messaging.ndjson", "absent"), 0)

    def test_an_entry_without_a_record_event_is_not_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            audit = Path(temporary)
            (audit / "messaging.ndjson").write_text(
                '{"record": {}}\n{"event": "messaging.retention.erased"}\n')
            self.assertEqual(MODULE.audit_event_count(
                audit, "messaging.ndjson", "messaging.retention.erased"), 0)

    def test_the_erase_must_add_its_requested_and_erased_records(self) -> None:
        self.assertEqual(MODULE.retention_audit_losses(0, 0, 1, 1), [])
        self.assertEqual(MODULE.retention_audit_losses(2, 2, 3, 3), [])
        self.assertEqual(len(MODULE.retention_audit_losses(0, 0, 1, 0)), 1)
        self.assertEqual(len(MODULE.retention_audit_losses(0, 0, 0, 1)), 1)
        self.assertEqual(len(MODULE.retention_audit_losses(2, 2, 2, 2)), 2)

    def rehearse(self, *, erase_events: int = 1,
                 ledger_differences: tuple[str, ...] = ()) -> tuple[dict, Any, Any]:
        """Run rehearse_messaging with every process and database faked. The
        erase command writes `erase_events` requested and erased records."""
        old, new = unittest.mock.Mock(), unittest.mock.Mock()
        old.run_json.return_value = {"active": {"packageDigest": self.ACTIVE}}
        messaging = unittest.mock.Mock()
        messaging.submit.return_value = {"id": "m"}
        messaging.views.return_value = {}
        runtime_stream, operator_stream = MODULE.MESSAGING_AUDIT, MODULE.MESSAGING_OPERATOR_AUDIT
        written = {"events": 0, runtime_stream: 9, operator_stream: 2}

        def upgrade(*_arguments):
            written[runtime_stream] += MODULE.MESSAGING_UPGRADED_AUDIT_RECORDS[runtime_stream]
            return list(ledger_differences)

        messaging.upgrade.side_effect = upgrade

        def erase(*arguments, **_):
            if "erase-expired" in arguments:
                written["events"] += erase_events
                written[operator_stream] += 2 * erase_events

        new.run.side_effect = erase
        postgres = unittest.mock.Mock()
        postgres.row_counts.return_value = {"public.messages": 3}
        report: dict[str, Any] = {}
        with tempfile.TemporaryDirectory() as directory, \
                unittest.mock.patch.object(MODULE, "Messaging", return_value=messaging), \
                unittest.mock.patch.object(MODULE, "Service"), \
                unittest.mock.patch.object(
                    MODULE, "audit_record_count",
                    side_effect=lambda _directory, name, **_k: written[name]), \
                unittest.mock.patch.object(
                    MODULE, "audit_event_count",
                    side_effect=lambda *_a, **_k: written["events"]) as events:
            try:
                MODULE.rehearse_messaging(Path(directory), unittest.mock.Mock(), postgres,
                                          old, new, report)
            finally:
                self.report = report
                self.event_streams = {call.args[1] for call in events.call_args_list}
        return report, new, messaging

    def test_the_leg_erases_expired_data_with_the_new_release_and_expects_its_records(
            self) -> None:
        report, new, _messaging = self.rehearse()
        self.assertEqual(report["messaging"]["viewDifferences"], [])
        self.assertEqual(report["messaging"]["rowLosses"], [])
        erase = [call.args for call in new.run.call_args_list
                 if "erase-expired" in call.args]
        self.assertEqual(len(erase), 1)
        self.assertIn("--apply", erase[0])
        self.assertEqual(erase[0][:3], ("messagingctl", "retention", "erase-expired"))
        # `messagingctl` writes the erase records, so the operator stream holds them.
        self.assertEqual(self.event_streams, {MODULE.MESSAGING_OPERATOR_AUDIT})

    def test_the_leg_fails_when_the_erase_leaves_no_audit_record(self) -> None:
        with self.assertRaisesRegex(MODULE.RehearsalError, "retention.erased"):
            self.rehearse(erase_events=0)

    def test_the_leg_upgrades_from_the_digest_the_old_release_activated(self) -> None:
        _report, new, messaging = self.rehearse()
        messaging.upgrade.assert_called_once_with(new, self.ACTIVE)

    def test_the_leg_fails_on_a_ledger_difference_the_upgrade_names(self) -> None:
        with self.assertRaisesRegex(MODULE.RehearsalError, "names another predecessor"):
            self.rehearse(ledger_differences=("the ledger names another predecessor",))

    def test_each_stream_is_held_to_the_records_the_upgrade_writes_to_it(self) -> None:
        self.assertEqual(MODULE.MESSAGING_UPGRADED_AUDIT_RECORDS,
                         {"messaging.ndjson": 7, "messaging.messagingctl.ndjson": 2})
        report, _new, _messaging = self.rehearse()
        self.assertEqual(report["messaging"]["auditRecordsBefore"],
                         {"messaging.ndjson": 9, "messaging.messagingctl.ndjson": 2})
        self.assertEqual(report["messaging"]["auditRecordsAfter"],
                         {"messaging.ndjson": 16, "messaging.messagingctl.ndjson": 4})


class GateWiringTest(unittest.TestCase):
    def test_retired_products_have_no_previous_release_rehearsal_legs(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for product in MODULE.RETIRED_PRODUCTS:
            with self.subTest(product=product):
                self.assertNotIn(product, MODULE.PRODUCTS)
                self.assertNotIn(product, MODULE.BINARIES)
                self.assertNotIn(product + "ctl", MODULE.BINARIES)
                self.assertNotIn("registry-" + product, workflow)
                with self.assertRaisesRegex(Error, "fresh database"):
                    MODULE.select_products([product], "v0.40.0", "linux-amd64", True)

    def test_workflow_rehearses_from_verified_release_assets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in ("workflow_dispatch:", "pull_request:", "release/manifests/**",
                         "release/scripts/rehearse-upgrade.py",
                         "sigstore/cosign-installer@", "--platform linux-amd64",
                         "-p registry-messaging -p registry-messagingctl"):
            self.assertTrue(required in workflow, f"workflow lacks {required!r}")
        for refused in ("--from-bin-dir", "contents: write", "id-token: write"):
            self.assertFalse(refused in workflow, f"workflow carries {refused!r}")
        self.assertNotIn("-p registry-casework", workflow)

    def test_forward_path_floor_is_current_for_the_workspace(self) -> None:
        MODULE.check_floor_is_current(MODULE.released_versions(ROOT),
                                      MODULE.workspace_version(ROOT))

    def test_api_stability_states_the_promise_and_its_rehearsal(self) -> None:
        page = API_STABILITY.read_text(encoding="utf-8")
        floor = "v{}.{}.{}".format(*MODULE.FORWARD_PATH_FLOOR)
        for required in ("immediate predecessor", "rehearse-upgrade.py", floor):
            self.assertTrue(required in page, f"api-stability page lacks {required!r}")


if __name__ == "__main__":
    unittest.main()
