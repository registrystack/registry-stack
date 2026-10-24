# SPDX-License-Identifier: Apache-2.0
"""Preparation freezes exact Cargo outputs without starting product services."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("coordinator_native_preparation", SCRIPTS / "test-real-services.py")
native = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(SCRIPTS))
try:
    spec.loader.exec_module(native)
finally:
    sys.path.pop(0)


class NativePreparationTests(unittest.TestCase):
    def artifacts(self, root):
        target = root / "custom-target"
        target.mkdir()
        messages = []
        for name in (*native.NATIVE_BINARIES, "reviewed-notice-input"):
            path = target / name
            path.write_text("executable " + name)
            messages.append({"reason": "compiler-artifact", "target": {"name": name}, "executable": str(path)})
        return target, messages

    def prepare(self, root, messages, platform="linux", snapshots=None):
        with patch.object(native, "source_snapshot", side_effect=snapshots or [
            {"sourceInventorySha256": "same", "capturedAt": "before"},
            {"sourceInventorySha256": "same", "capturedAt": "after"},
        ]), patch.object(native, "cargo_metadata", return_value={"target_directory": str(root / "custom-target")}) as metadata, \
                patch.object(native, "cargo_build", return_value=messages) as build, \
                patch.object(native.sys, "platform", platform), contextlib.redirect_stdout(io.StringIO()):
            paths = native.prepare_native(root / "prepared", {"CARGO_TARGET_DIR": str(root / "custom-target")})
        return paths, metadata, build

    def test_retained_inventory_is_hashed_as_the_exact_written_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/synthetic/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub fn synthetic() {}")
            shared = root / "scripts/cargo_runtime_library_path.py"
            shared.parent.mkdir()
            shared.write_text("shared resolver source")
            (shared.parent / "unrelated.py").write_text("unrelated tooling")
            inventory = root / "source.inventory.json"
            with patch.object(native, "REPO", root):
                snapshot = native.source_snapshot(inventory)
                source.write_text("pub fn changed() {}")
                changed = native.source_snapshot()
            self.assertEqual(snapshot["sourceInventoryFile"], inventory.name)
            recorded = json.loads(inventory.read_text())
            self.assertIn("scripts/cargo_runtime_library_path.py", recorded)
            self.assertNotIn("scripts/unrelated.py", recorded)
            self.assertEqual(snapshot["sourceInventorySha256"], hashlib.sha256(inventory.read_bytes()).hexdigest())
            self.assertNotEqual(snapshot["sourceInventorySha256"], changed["sourceInventorySha256"])

    def test_freezes_reported_artifacts_and_honors_custom_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, messages = self.artifacts(root)
            (binaries, manifest_path), metadata, build = self.prepare(root, messages)
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(metadata.call_args.args[0]["CARGO_TARGET_DIR"], str(target))
            self.assertEqual(manifest["cargoTargetDirectory"], str(target))
            self.assertEqual(set(manifest["binarySha256"]), set(native.NATIVE_BINARIES))
            self.assertEqual(manifest["helperSha256"], {"reviewed-notice-input": native.file_digest(binaries / "reviewed-notice-input")})
            self.assertEqual(manifest["sourceBeforeBuild"]["capturedAt"], "before")
            self.assertEqual(manifest["sourceAfterBuild"]["capturedAt"], "after")
            command = build.call_args.args[0]
            self.assertIn("--locked", command)
            self.assertIn("registry-scheduling/postgres-test", command[command.index("--features") + 1])
            self.assertIn("registry-messaging/postgres-test", command[command.index("--features") + 1])
            self.assertIn("reviewed-notice-input", command)
            (target / "coordinator").write_text("a later build")
            self.assertEqual(native.file_digest(binaries / "coordinator"), manifest["binarySha256"]["coordinator"])
            self.assertNotEqual(native.file_digest(target / "coordinator"), manifest["binarySha256"]["coordinator"])
            if os.name == "posix":
                self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(binaries.stat().st_mode & 0o777, 0o700)

    def test_source_change_refuses_manifest_but_retains_source_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, messages = self.artifacts(root)
            with self.assertRaisesRegex(SystemExit, "source changed"):
                self.prepare(root, messages, snapshots=[
                    {"sourceInventorySha256": "before"}, {"sourceInventorySha256": "after"}])
            self.assertFalse((root / "prepared/build-manifest.json").exists())
            self.assertEqual(json.loads((root / "prepared/source-after-build.json").read_text())["sourceInventorySha256"], "after")

    def test_missing_helper_refuses_incomplete_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, messages = self.artifacts(root)
            with self.assertRaisesRegex(SystemExit, "reviewed-notice-input"):
                self.prepare(root, messages[:-1])
            self.assertFalse((root / "prepared/build-manifest.json").exists())

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "prepared").mkdir()
            marker = root / "prepared/existing"
            marker.write_text("retained")
            with self.assertRaises(FileExistsError), patch.object(native, "cargo_build") as build:
                native.prepare_native(root / "prepared", {})
            build.assert_not_called()
            self.assertEqual(marker.read_text(), "retained")

    def test_macos_freezes_only_the_exact_linked_fips_library(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, messages = self.artifacts(root)
            artifacts = root / "fips/build/artifacts"
            artifacts.mkdir(parents=True)
            library = artifacts / "libaws_lc_fips_0_14_2_crypto.dylib"
            library.write_bytes(b"linked library")
            (artifacts / "unrelated.dylib").write_bytes(b"unrelated")
            messages.append({"reason": "build-script-executed", "package_id": "registry#aws-lc-fips-sys@0.14.2",
                             "linked_libs": ["dylib=aws_lc_fips_0_14_2_crypto"], "out_dir": str(root / "fips")})
            (_, manifest_path), _, _ = self.prepare(root, messages, platform="darwin")
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(set(manifest["runtimeLibraries"]), {library.name})
            frozen = manifest["runtimeLibraries"][library.name]
            self.assertEqual(Path(frozen["path"]).read_bytes(), b"linked library")
            library.write_bytes(b"changed build cache")
            self.assertEqual(native.file_digest(Path(frozen["path"])), frozen["sha256"])

    def test_failed_cargo_json_build_replays_rendered_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "build.jsonl"
            def failed(command, **kwargs):
                kwargs["stdout"].write(json.dumps({"reason": "compiler-message", "message": {"rendered": "error: synthetic compiler explanation\n"}}) + "\n")
                return SimpleNamespace(returncode=1)
            error = io.StringIO()
            with patch.object(native.subprocess, "run", side_effect=failed), contextlib.redirect_stderr(error), \
                    self.assertRaisesRegex(SystemExit, "native Cargo build failed"):
                native.cargo_build(["cargo", "build"], log, {})
            self.assertIn("error: synthetic compiler explanation", error.getvalue())
            self.assertTrue(log.is_file())

    def test_breg_helper_preserves_diagnostics_before_its_temporary_directory_is_removed(self):
        spec = importlib.util.spec_from_file_location("coordinator_breg_acceptance", SCRIPTS / "test-breg-action.py")
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        error = io.StringIO()
        def failed(command, **kwargs):
            kwargs["stdout"].write(json.dumps({"reason": "compiler-message", "message": {"rendered": "error: synthetic BReg build failure\n"}}) + "\n")
            return SimpleNamespace(returncode=1)
        environment = {"COORDINATOR_TEST_DATABASE_URL": "postgres://localhost/coordinator",
                       "COORDINATOR_MESSAGING_TEST_DATABASE_URL": "postgres://localhost/messaging"}
        with patch.dict(os.environ, environment, clear=True), patch.object(helper, "native_fixture", return_value=native), \
                patch.object(helper.subprocess, "check_output", return_value=b'{"target_directory":"/synthetic-target"}'), \
                patch.object(helper.subprocess, "run", side_effect=failed), contextlib.redirect_stderr(error), \
                self.assertRaises(SystemExit):
            helper.run(None)
        self.assertIn("synthetic BReg build failure", error.getvalue())

    def test_prepare_cli_needs_no_database_and_never_runs_the_journey(self):
        previous_umask = os.umask(0o077)
        try:
            with patch.dict(os.environ, {}, clear=True), patch.object(native.sys, "argv", ["test-real-services.py", "--prepare", "/synthetic-new-output"]), \
                    patch.object(native, "prepare_native") as prepare, patch.object(native, "Journey") as journey:
                native.main()
            prepare.assert_called_once_with(Path("/synthetic-new-output"))
            journey.assert_not_called()
        finally:
            os.umask(previous_umask)

    def test_ordinary_default_uses_cargo_metadata_instead_of_repo_target(self):
        previous_umask = os.umask(0o077)
        try:
            with patch.dict(os.environ, {
                    "COORDINATOR_TEST_DATABASE_URL": "postgres://localhost/coordinator",
                    "COORDINATOR_MESSAGING_TEST_DATABASE_URL": "postgres://localhost/messaging"}, clear=True), \
                    patch.object(native.sys, "argv", ["test-real-services.py"]), \
                    patch.object(native, "cargo_metadata", return_value={"target_directory": "/custom-target"}), \
                    patch.object(native, "Journey") as journey, contextlib.redirect_stdout(io.StringIO()):
                native.main()
            self.assertEqual(journey.call_args.args[1], Path("/custom-target/debug"))
        finally:
            os.umask(previous_umask)

    def test_manifest_rejects_a_changed_reviewed_notice_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, messages = self.artifacts(root)
            (binaries, manifest_path), _, _ = self.prepare(root, messages)
            helper = binaries / "reviewed-notice-input"
            helper.chmod(0o600)
            helper.write_text("unexpected helper")
            journey = root / "journey"
            journey.mkdir()
            with patch.object(native, "source_digest", return_value="same"), \
                    patch.object(native.sys, "platform", "linux"), \
                    self.assertRaisesRegex(AssertionError, "reviewed-notice-input differs"):
                native.Journey(journey, binaries, 30, manifest_path)

    def test_existing_binaries_never_trigger_a_build(self):
        previous_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                    "COORDINATOR_TEST_DATABASE_URL": "postgres://localhost/coordinator",
                    "COORDINATOR_MESSAGING_TEST_DATABASE_URL": "postgres://localhost/messaging"}, clear=True), \
                    patch.object(native.sys, "argv", ["test-real-services.py", "--bin-dir", directory]), \
                    patch.object(native, "prepare_native") as prepare, patch.object(native, "Journey") as journey, \
                    contextlib.redirect_stdout(io.StringIO()):
                native.main()
            prepare.assert_not_called()
            self.assertEqual(journey.call_args.args[1], Path(directory).resolve())
        finally:
            os.umask(previous_umask)


if __name__ == "__main__":
    unittest.main()


class ReleasedArchiveTests(unittest.TestCase):
    def test_released_flat_fips_library_stays_beside_frozen_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = root / "released"
            binaries.mkdir()
            (binaries / "coordinator").write_bytes(b"released executable")
            library = binaries / "libaws_lc_fips_0_14_2_crypto.dylib"
            library.write_bytes(b"released runtime library")
            (binaries / "unrelated.dylib").write_bytes(b"excluded")
            owned = root / "owned"
            owned.mkdir()
            with patch.object(native, "source_digest", return_value="same"), \
                    patch.object(native.sys, "platform", "darwin"):
                journey = native.Journey(owned, binaries, 2,
                    required_binaries=["coordinator"], require_reviewed_notice_starter=False)
            frozen = owned / "native-binaries" / library.name
            self.assertEqual(frozen.read_bytes(), library.read_bytes())
            self.assertEqual(journey.library_digests[library.name], native.file_digest(library))
            self.assertFalse((owned / "native-binaries/unrelated.dylib").exists())
