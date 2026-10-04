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
        for tag in ("v0.37.0", "v0.33.0", "v0.1.0"):
            with self.subTest(tag=tag), self.assertRaisesRegex(Error, "immediate predecessor"):
                MODULE.check_forward_path(tag, "0.39.0")
        MODULE.check_forward_path("v0.38.0", "0.38.0")
        MODULE.check_forward_path("v0.38.0", "0.39.0")

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
                script.write_text(f"#!/bin/sh\necho '{binary} 0.38.0'\n", encoding="utf-8")
                script.chmod(0o755)

        with tempfile.TemporaryDirectory() as temporary, \
                contextlib.redirect_stdout(io.StringIO()), \
                unittest.mock.patch.object(MODULE, "fetch_release", side_effect=fetch) as fetched, \
                unittest.mock.patch.object(MODULE, "Postgres", side_effect=AssertionError("started")), \
                unittest.mock.patch.object(MODULE, "workspace_version", return_value="0.39.0"):
            work = Path(temporary) / "work"
            report = Path(temporary) / "report.json"
            status = MODULE.main(["--fetch-only", "--from-tag", "v0.38.0", "--platform",
                                  "linux-amd64", "--product", "breg", "--work-dir", str(work),
                                  "--report", str(report)])
            self.assertEqual(status, 0)
            self.assertEqual(fetched.call_args.args[4], ("breg", "bregctl"))
            self.assertTrue((work / "from-bin" / "bregctl").is_file())
            document = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(document["fromProvenance"], "cosign and SHA256SUMS verified")
        self.assertEqual(document["fromBinDir"], str(work.resolve() / "from-bin"))
        self.assertNotIn("breg", document)


class ProductSelectionTest(unittest.TestCase):
    # Messaging has not joined a release (release_roster.MESSAGING_FIRST_RELEASE
    # is None). The inclusion tests patch a hypothetical first release so the
    # Messaging leg stays covered without any production knob.
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
                    self.assertEqual(products, ["breg", "casework", "evidence"])
                    self.assertEqual(list(omitted), ["messaging"])
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
        self.assertEqual(products, ["breg", "casework", "evidence"])
        self.assertEqual(list(omitted), ["messaging"])
        self.assertIn("first shipped in v0.36.0", omitted["messaging"])

    def test_messaging_joins_the_default_run_from_its_first_release(self) -> None:
        for tag in ("v0.36.0", "v0.36.2", "v1.0.0"):
            with self.subTest(tag=tag):
                products, omitted = MODULE.select_products(None, tag, "linux-amd64", True)
                self.assertEqual(products, list(MODULE.PRODUCTS))
                self.assertEqual(omitted, {})

    def test_a_named_product_the_starting_release_did_not_ship_is_refused(self) -> None:
        with self.assertRaisesRegex(Error, "messaging was first shipped in v0.36.0"):
            MODULE.select_products(["messaging"], "v0.35.0", "linux-amd64", True)
        self.assertEqual(
            MODULE.select_products(["casework"], "v0.35.0", "linux-amd64", True),
            (["casework"], {}),
        )

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
                unittest.mock.patch.object(MODULE.release_roster, "MESSAGING_FIRST_RELEASE",
                                           (0, 39, 0)):
            work = Path(temporary) / "work"
            status = MODULE.main([
                "--from-tag", "v0.38.0", "--platform", "linux-amd64",
                "--product", "messaging",
                "--to-bin-dir", temporary, "--work-dir", str(work),
            ])
            self.assertFalse(work.exists())
        self.assertEqual(status, 1)
        self.assertIn("messaging was first shipped in v0.39.0, so v0.38.0 holds no",
                      stderr.getvalue())


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
            with self.assertRaisesRegex(Error, "lack breg"):
                MODULE.check_binaries(side, "0.33.0", MODULE.BINARIES)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


# JSON is YAML, so the runtime document round-trips without PyYAML, which the
# release-tool CI step does not install.
@unittest.mock.patch.object(MODULE, "dump_yaml", dump_json)
@unittest.mock.patch.object(MODULE, "load_yaml", load_json)
class CaseworkPackageTest(unittest.TestCase):
    def casework(self, root: Path) -> object:
        casework = MODULE.Casework.__new__(MODULE.Casework)
        casework.work = root
        casework.project = root / "project"
        casework.package = root / "package"
        casework.runtime = root / "runtime.yaml"
        casework.package.mkdir()
        dump_json(casework.runtime, {"package": {"root": str(casework.package)}})
        return casework

    def test_a_side_names_the_database_then_plans_and_applies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            casework = self.casework(Path(directory))
            side = unittest.mock.Mock()
            side.run_json.side_effect = [{"changesPending": True},
                                         {"activationId": "activation"}]
            self.assertEqual(casework.activate(side), {"activationId": "activation"})
            self.assertEqual(load_json(casework.runtime)["identity"],
                             {"databaseId": MODULE.CASEWORK_DATABASE_ID})
            runtime = ["--runtime-config", str(casework.runtime)]
            self.assertEqual(side.run_json.call_args_list, [
                unittest.mock.call("caseworkctl", "--format", "json", "plan", *runtime),
                unittest.mock.call("caseworkctl", "--format", "json", "apply", *runtime,
                                   "--operator-reference", MODULE.CASEWORK_OPERATOR_REFERENCE),
            ])
            side.run.assert_not_called()

    def test_a_first_plan_with_nothing_pending_is_refused_before_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            casework = self.casework(Path(directory))
            side = unittest.mock.Mock()
            side.run_json.return_value = {"changesPending": False}
            with self.assertRaisesRegex(MODULE.RehearsalError, "first activation"):
                casework.activate(side)
            self.assertEqual(side.run_json.call_count, 1)

    def already_active(self, activation: str) -> dict[str, Any]:
        return {"changesPending": False, "active": {"activationId": activation},
                "refusals": [{"code": MODULE.CASEWORK_ALREADY_ACTIVE}]}

    def test_an_activated_database_with_nothing_pending_keeps_its_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            casework = self.casework(Path(directory))
            side = unittest.mock.Mock()
            side.run_json.return_value = self.already_active("seeded")
            self.assertEqual(casework.activate(side, "seeded"), {"activationId": "seeded"})
            side.run_json.assert_called_once_with(
                "caseworkctl", "--format", "json", "plan",
                "--runtime-config", str(casework.runtime))

    def test_an_activated_database_with_changes_pending_is_applied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            casework = self.casework(Path(directory))
            side = unittest.mock.Mock()
            side.run_json.side_effect = [{"changesPending": True},
                                         {"activationId": "successor"}]
            self.assertEqual(casework.activate(side, "seeded"), {"activationId": "successor"})
            self.assertEqual(side.run_json.call_args_list[1].args[3], "apply")

    def test_nothing_pending_must_name_the_seeded_activation_as_already_active(self) -> None:
        other = self.already_active("another")
        refused = self.already_active("seeded")
        refused["refusals"].append({"code": "casework.activation.database-id-mismatch"})
        for planned in (other, refused, {"changesPending": False}):
            with self.subTest(planned=planned), tempfile.TemporaryDirectory() as directory:
                casework = self.casework(Path(directory))
                side = unittest.mock.Mock()
                side.run_json.return_value = planned
                with self.assertRaisesRegex(MODULE.RehearsalError, "already active"):
                    casework.activate(side, "seeded")
                self.assertEqual(side.run_json.call_count, 1)


@unittest.mock.patch.object(MODULE, "dump_yaml", dump_json)
@unittest.mock.patch.object(MODULE, "load_yaml", load_json)
class BregLedgerTest(unittest.TestCase):
    DIGEST = "sha256:" + "a" * 64

    def breg(self, root: Path) -> object:
        breg = MODULE.Breg.__new__(MODULE.Breg)
        breg.work = root
        breg.secrets = root / "secrets"
        breg.project = root / "project"
        breg.clients = [MODULE.BREG_CLIENT]
        return breg

    def test_a_ledger_runtime_names_only_the_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.breg(root).write_runtime(root / "runtime.yaml", "registry", root / "pkg",
                                          8000)
            self.assertEqual(load_json(root / "runtime.yaml")["package"],
                             {"root": str(root / "pkg")})

    def test_a_ledger_package_is_tested_and_built_against_its_baseline_unsigned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            breg = self.breg(root)
            breg.create_database = unittest.mock.Mock()
            breg.credentials = unittest.mock.Mock()
            side = unittest.mock.Mock()
            side.run_json.side_effect = [{"ok": True}, {"ok": True, "packageDigest": self.DIGEST}]
            baseline = root / "build-1" / "out" / "package"
            package, digest = breg.package(side, root / "build-2", baseline=baseline)
            self.assertEqual((package, digest), (root / "build-2" / "out" / "package", self.DIGEST))
            breg.create_database.assert_called_once_with("schematest")
            tested, packaged = (call.args for call in side.run_json.call_args_list)
            self.assertEqual(tested[3], "test")
            self.assertEqual(packaged[3], "package")
            for arguments in (tested, packaged):
                self.assertIn("--baseline-package", arguments)
                self.assertEqual(arguments[arguments.index("--baseline-package") + 1],
                                 str(baseline))
                self.assertFalse([flag for flag in arguments if "signature" in flag])
            self.assertEqual(load_json(root / "build-2" / "runtime-test.yaml")["package"],
                             {"root": str(root / "build-2" / "empty-package-root")})

    def test_a_ledger_package_without_a_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            breg = self.breg(Path(directory))
            breg.create_database = unittest.mock.Mock()
            breg.credentials = unittest.mock.Mock()
            side = unittest.mock.Mock()
            side.run_json.side_effect = [{"ok": True}, {"ok": True}]
            with self.assertRaisesRegex(Error, "packageDigest"):
                breg.package(side, Path(directory) / "build")

    def author(self, root: Path, package: dict[str, Any]) -> dict[str, Any]:
        breg = self.breg(root)
        breg.keys = unittest.mock.Mock()
        breg.operator = {}

        def run(binary: str, *arguments: str) -> object:
            if arguments[0] == "init":
                (breg.project / "tests").mkdir(parents=True)
                dump_json(breg.project / "registry.yaml", {"package": dict(package)})
                dump_json(breg.project / "tests" / "journeys.yaml", {"journeys": [
                    {"id": "j", "steps": [{"id": "s", "accessProfile": "operator",
                                           "claims": {"principal": "p"}}]}]})
            return unittest.mock.Mock(stdout="")

        side = unittest.mock.Mock()
        side.run.side_effect = run
        breg.author(side)
        self.assertEqual(breg.operator, {"principal": "p"})
        side.run.assert_called_once_with("bregctl", "init", str(breg.project))
        return load_json(breg.project / "registry.yaml")

    def test_the_starter_project_package_is_left_as_init_wrote_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = self.author(Path(directory), {"sourceRevision": "starter-0.1.0"})
            self.assertEqual(registry["package"], {"sourceRevision": "starter-0.1.0"})

    def test_a_plan_must_name_the_expected_pending_activation(self) -> None:
        plan = {"pending": True, "activation": "successor", "packageDigest": self.DIGEST}
        MODULE.expect_plan(plan, "successor", self.DIGEST)
        for changed in ({"pending": False}, {"activation": "initial"},
                        {"packageDigest": "sha256:" + "b" * 64}):
            with self.subTest(changed=changed), self.assertRaisesRegex(Error, "plan"):
                MODULE.expect_plan({**plan, **changed}, "successor", self.DIGEST)

    def ledger(self) -> dict[str, Any]:
        second = "sha256:" + "b" * 64
        return {"activePackageDigest": second, "activationId": "two",
                "maintenanceStatus": "ready",
                "ledger": [
                    {"applyOrder": 2, "planKind": "successor", "outcome": "applied",
                     "packageDigest": second, "predecessorPackageDigest": self.DIGEST,
                     "activationId": "two"},
                    {"applyOrder": 1, "planKind": "initial", "outcome": "applied",
                     "packageDigest": self.DIGEST, "predecessorPackageDigest": None,
                     "activationId": "one"}]}

    def test_the_ledger_lists_each_activation_in_apply_order(self) -> None:
        status = self.ledger()
        self.assertEqual(MODULE.expect_ledger(status, "sha256:" + "b" * 64),
                         ["initial:applied", "successor:applied"])

    def test_a_ledger_whose_active_package_is_not_the_last_applied_is_refused(self) -> None:
        cases = {
            "another active package": {"activePackageDigest": self.DIGEST},
            "maintenance": {"maintenanceStatus": "failed"},
            "another activation": {"activationId": "one"},
        }
        for name, changed in cases.items():
            with self.subTest(name), self.assertRaisesRegex(Error, "ledger|active"):
                MODULE.expect_ledger({**self.ledger(), **changed}, "sha256:" + "b" * 64)
        unchained = self.ledger()
        unchained["ledger"][0]["predecessorPackageDigest"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(Error, "chain"):
            MODULE.expect_ledger(unchained, "sha256:" + "b" * 64)


@unittest.mock.patch.object(MODULE, "dump_yaml", dump_json)
@unittest.mock.patch.object(MODULE, "load_yaml", load_json)
class EvidencePackageTest(unittest.TestCase):
    def test_a_sealed_installed_package_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = MODULE.Evidence.__new__(MODULE.Evidence)
            evidence.project = root / "project"
            evidence.target = root / "target"
            evidence.installed = root / "installed"
            evidence.runtime = root / "runtime.yaml"
            evidence.target.mkdir()
            dump_json(evidence.target / "runtime.yaml", {"package": {"root": "x"}})
            # evidencectl seals every published package directory at 0o500.
            sealed = evidence.installed / "sources"
            sealed.mkdir(parents=True)
            (sealed / "record-status.sql").write_text("select 1;\n")
            (sealed / "record-status.sql").chmod(0o400)
            sealed.chmod(0o500)
            evidence.installed.chmod(0o500)
            candidate = root / "candidate"

            def publish(*_args: str) -> None:
                candidate.mkdir()
                (candidate / "SHA256SUMS").write_text("")

            side = unittest.mock.Mock()
            side.run.side_effect = publish
            evidence.package(side, candidate)
            self.assertEqual(sorted(p.name for p in evidence.installed.iterdir()),
                             ["SHA256SUMS"])
            self.assertFalse(candidate.exists())


class EvidenceGrammarTest(unittest.TestCase):
    def test_the_runtime_file_is_named_the_way_each_binary_reads_it(self) -> None:
        runtime = Path("/srv/runtime.yaml")
        self.assertEqual(MODULE.evidence_arguments(runtime, "check"),
                         ["check", "--runtime-config", "/srv/runtime.yaml"])
        self.assertEqual(MODULE.breg_arguments(runtime),
                         ["--runtime-config", "/srv/runtime.yaml"])

    def test_a_local_target_becomes_a_production_target(self) -> None:
        local = {
            "assuranceProfile": "local",
            "service": {"providerId": "urn:registrystack:evidence:local:provider",
                        "publicOrigin": "http://127.0.0.1:8080"},
            "publication": {"endpointUrl": "http://127.0.0.1:8080"},
            "responseFormats": [],
            "signing": {"activePublicJwkFile": "public-keys/local.jwk.json"},
            "authorityProfiles": {"local-caller": {"grants": [], "kind": "explicit-request"}},
            "authentication": {"oidc": {"issuer": "http://127.0.0.1:8081"}},
        }
        production = MODULE.evidence_production_governance(
            local, "https://127.0.0.1:9443", "public-keys/transit.jwk.json")
        self.assertEqual(production["assuranceProfile"], "production")
        self.assertEqual(production["service"], {
            "providerId": "urn:example:upgrade-rehearsal:provider",
            "publicOrigin": "https://evidence.example.test"})
        self.assertEqual(production["publication"],
                         {"endpointUrl": "https://evidence.example.test"})
        self.assertEqual(production["responseFormats"], ["signed-jws"])
        self.assertEqual(production["authorityProfiles"]["local-caller"]["grants"], [{
            "requirement": MODULE.EVIDENCE_REQUIREMENT,
            "purpose": MODULE.EVIDENCE_PURPOSE,
            "audienceFrom": "authenticated-requester",
            "responseFormats": ["signed-jws"],
            "subjects": [{"role": "subject", "selectorProfile": "record-reference-v1",
                          "valueOrigin": "request"}]}])
        self.assertEqual(production["signing"],
                         {"activePublicJwkFile": "public-keys/transit.jwk.json"})
        self.assertEqual(production["authentication"], {"oidc": {
            "issuer": "https://127.0.0.1:9443",
            "jwksSource": {"kind": "uri", "uri": "https://127.0.0.1:9443/oauth2/jwks"}}})
        self.assertEqual(local["assuranceProfile"], "local")


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

    def test_the_upgrade_carries_the_instance_claim_over_or_records_one(self) -> None:
        claim = {"systemIdentifier": "7", "databaseOid": 16384, "epoch": 1,
                 "claimedAt": "2026-09-28T00:00:00Z"}
        self.assertEqual(MODULE.claim_differences(claim, dict(claim)), [])
        self.assertEqual(MODULE.claim_differences(None, claim), [])
        self.assertTrue(MODULE.claim_differences(claim, {**claim, "epoch": 2}))
        self.assertTrue(MODULE.claim_differences(claim, None))
        self.assertTrue(MODULE.claim_differences(None, None))

    def test_successor_preserves_record_state_while_etags_change(self) -> None:
        before = {"records/1": {"etag": "old-package", "domainData": {"code": "a"}, "revision": "r1"}}
        after = {"records/1": {"etag": "new-package", "domainData": {"code": "a"}, "revision": "r1"}}
        self.assertEqual(MODULE.breg_view_differences(before, after), [])
        after["records/1"]["domainData"] = {"code": "lost"}
        self.assertTrue(MODULE.breg_view_differences(before, after))

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


class AuditUpgradeTest(unittest.TestCase):
    def test_archives_every_old_segment_before_a_fresh_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            audit = root / "audit"
            audit.mkdir()
            for name in ("evidence.jsonl", "evidence.jsonl.00000001"):
                (audit / name).write_text('{"old":true}\n')
            (audit / "other.jsonl").write_text("keep")
            archive = root / "archive"
            self.assertEqual(MODULE.archive_audit_files(audit, "evidence.jsonl", archive), 2)
            self.assertEqual(MODULE.audit_record_count(archive, "evidence.jsonl"), 2)
            self.assertEqual(sorted(path.name for path in audit.iterdir()), ["other.jsonl"])

    def test_fresh_stream_requires_valid_response_envelopes(self) -> None:
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



class GateWiringTest(unittest.TestCase):
    def test_workflow_rehearses_from_verified_release_assets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in ("workflow_dispatch:", "pull_request:", "release/manifests/**",
                         "release/scripts/rehearse-upgrade.py",
                         "sigstore/cosign-installer@", "--platform linux-amd64",
                         "--features registry-breg/runtime",
                         "-p registry-messaging -p registry-messagingctl"):
            self.assertTrue(required in workflow, f"workflow lacks {required!r}")
        for refused in ("--from-bin-dir", "contents: write", "id-token: write"):
            self.assertFalse(refused in workflow, f"workflow carries {refused!r}")

    def test_api_stability_states_the_same_floor(self) -> None:
        page = API_STABILITY.read_text(encoding="utf-8")
        floor = "v{}.{}.{}".format(*MODULE.FORWARD_PATH_FLOOR)
        for required in (floor, "immediate predecessor", "rehearse-upgrade.py"):
            self.assertTrue(required in page, f"api-stability page lacks {required!r}")


if __name__ == "__main__":
    unittest.main()
