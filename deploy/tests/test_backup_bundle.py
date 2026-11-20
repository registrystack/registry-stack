import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from state_bundle import (
    BundleError, capture, checked_run, file_hashes, restore_database, verify_archived_manifest, verify_bundle,
    verify_snapshot_age,
)

DIGEST = "sha256:" + "a" * 64


class BackupBundleTest(unittest.TestCase):
    def test_manifest_refuses_missing_modified_and_added_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            payload.mkdir()
            dump = payload / "registry.dump"
            dump.write_bytes(b"dump")
            manifest = {"version": 1, "files": file_hashes(payload)}
            (root / "manifest.json").write_text(json.dumps(manifest))
            self.assertEqual(verify_bundle(root), manifest)
            dump.write_bytes(b"changed")
            with self.assertRaisesRegex(BundleError, "files differ"):
                verify_bundle(root)
            dump.write_bytes(b"dump")
            (payload / "unexpected").write_bytes(b"new")
            with self.assertRaisesRegex(BundleError, "files differ"):
                verify_bundle(root)

    def test_refuses_symlinks_in_operator_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "link").symlink_to("/etc/hosts")
            with self.assertRaisesRegex(BundleError, "symbolic link"):
                file_hashes(root)

    def test_monitor_checks_the_repository_snapshot_timestamp(self):
        now = datetime(2026, 11, 12, 2, tzinfo=timezone.utc)
        max_age = timedelta(hours=26)
        verify_snapshot_age({"time": "2026-11-11T03:00:00Z"}, now, max_age)
        for timestamp in ("2026-11-10T03:00:00Z", "2026-11-13T02:00:00Z", "2026-11-12T01:00:00", "missing"):
            with self.subTest(timestamp=timestamp), self.assertRaises(BundleError):
                verify_snapshot_age({"time": timestamp}, now, max_age)

    def test_new_archive_cannot_make_an_old_recovery_point_fresh(self):
        now = datetime(2026, 11, 12, 2, tzinfo=timezone.utc)
        metadata = {"time": "2026-11-12T01:00:00Z"}
        max_age = timedelta(hours=26)
        verify_snapshot_age(metadata, now, max_age)
        manifest = {"capturedAt": "2026-11-10T03:00:00Z"}
        archive = json.dumps(manifest).encode()
        receipt = {**manifest, "manifestSha256": hashlib.sha256(archive).hexdigest()}
        with self.assertRaisesRegex(BundleError, "capture.*backup window"):
            verify_archived_manifest(archive, receipt, now, max_age)
        with self.assertRaisesRegex(BundleError, "manifest digest"):
            verify_archived_manifest(b"changed", receipt, now, max_age)

    def test_failed_command_reports_its_error_output_but_not_its_input(self):
        script = (
            "import sys\nsys.stdin.buffer.read()\n"
            "for number in range(30):\n    print(f'restore diagnostic {number}', file=sys.stderr)\nsys.exit(2)"
        )
        with tempfile.TemporaryFile() as stdin:
            stdin.write(b"stdin-only-dump")
            stdin.seek(0)
            with self.assertRaises(BundleError) as raised:
                checked_run([sys.executable, "-I", "-c", script], "Synthetic restore", stdin=stdin)
        message = str(raised.exception)
        self.assertIn("Synthetic restore failed with exit 2", message)
        self.assertIn("restore diagnostic 29", message.splitlines())
        self.assertNotIn("restore diagnostic 9", message.splitlines())
        self.assertNotIn("stdin-only-dump", message)


def write_bundle(root, **fields):
    payload = root / "payload" / "databases"
    payload.mkdir(parents=True)
    (payload / "registry_breg.dump").write_bytes(b"synthetic dump")
    manifest = {
        "version": 1, "namespace": "pilot", "release": "directory", "databaseId": "registry-test-db",
        "packageDigest": DIGEST, "activationId": "synthetic-activation",
        "capturedAt": "2026-11-12T01:00:00+00:00", "databases": ["registry_breg"],
        "files": file_hashes(root / "payload"), **fields,
    }
    encoded = json.dumps(manifest, indent=2).encode() + b"\n"
    (root / "manifest.json").write_bytes(encoded)
    receipt = {
        key: manifest[key] for key in ("namespace", "release", "databaseId", "packageDigest", "activationId", "capturedAt")
    }
    return {**receipt, "snapshotId": "c" * 64, "manifestSha256": hashlib.sha256(encoded).hexdigest()}


class ReceiptBindingTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.receipt = write_bundle(self.bundle)
        self.receipt_path = self.root / "receipt.json"
        self.receipt_path.write_text(json.dumps(self.receipt))

    def test_verify_binds_the_bundle_to_its_receipt(self):
        self.assertEqual(verify_bundle(self.bundle, self.receipt)["release"], "directory")
        for change in ({"release": "another"}, {"activationId": "other"}, {"manifestSha256": "e" * 64}):
            with self.subTest(change=change), self.assertRaisesRegex(BundleError, "backup receipt"):
                verify_bundle(self.bundle, {**self.receipt, **change})
        with self.assertRaisesRegex(BundleError, "backup receipt"):
            verify_bundle(self.bundle, [self.receipt])

    def test_consistently_edited_manifest_does_not_match_the_receipt(self):
        manifest = json.loads((self.bundle / "manifest.json").read_text())
        manifest["capturedAt"] = "2026-11-12T02:00:00+00:00"
        (self.bundle / "manifest.json").write_text(json.dumps(manifest))
        self.assertEqual(verify_bundle(self.bundle), manifest)
        with self.assertRaisesRegex(BundleError, "backup receipt"):
            verify_bundle(self.bundle, self.receipt)

    def restore_args(self):
        return SimpleNamespace(
            bundle=self.bundle, receipt=self.receipt_path, database="registry_breg", target="registry_restore",
            kubectl_bin="kubectl", kube_context="test-only", namespace="pilot", pod="registry-postgres-0",
            container="postgres",
        )

    def test_restore_refuses_a_bundle_that_differs_from_its_receipt(self):
        self.receipt_path.write_text(json.dumps({**self.receipt, "databaseId": "another-db"}))
        with patch("state_bundle.checked_run") as run, self.assertRaisesRegex(BundleError, "backup receipt"):
            restore_database(self.restore_args())
        run.assert_not_called()

    def test_restore_proceeds_with_the_matching_receipt(self):
        run = Mock(side_effect=[b"0\n", b""])
        with patch("state_bundle.checked_run", run), redirect_stdout(io.StringIO()):
            restore_database(self.restore_args())
        self.assertIn("pg_restore", run.call_args_list[1].args[0])


class CaptureTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        status = root / "status.json"
        status.write_text(json.dumps({
            "ok": True, "command": "status", "roleMode": "split", "maintenanceStatus": "ready",
            "activePackageDigest": DIGEST, "databaseId": "registry-test-db", "activationId": "synthetic-activation",
        }))
        files = root / "files"
        files.mkdir()
        (files / "values.json").write_text("{}")
        self.args = SimpleNamespace(
            kube_context="test-only", namespace="pilot", pod="registry-postgres-0", container="postgres",
            kubectl_bin="kubectl", release="directory", database=["registry_breg"], status_file=status,
            files=files, output=root / "backup-01",
        )
        self.pod_listings = []
        self.commands = []

    def run_command(self, argv, label, *, stdin=None, stdout=None):
        self.commands.append(argv)
        if "pods" in argv:
            return json.dumps({"items": self.pod_listings.pop(0)}).encode()
        self.assertIn("pg_dump", argv)
        stdout.write(b"synthetic dump")
        return None

    def capture(self):
        output = io.StringIO()
        with patch("state_bundle.checked_run", side_effect=self.run_command), redirect_stdout(output):
            capture(self.args)
        return output.getvalue()

    def test_capture_refuses_while_release_pods_run(self):
        self.pod_listings = [[{"metadata": {"name": "directory-breg-0"}, "status": {"phase": "Running"}}]]
        with self.assertRaisesRegex(BundleError, "stop"):
            self.capture()
        self.assertFalse(self.args.output.exists())
        self.assertEqual(
            self.commands[0],
            ["kubectl", "--context", "test-only", "--namespace", "pilot", "get", "pods",
             "-l", "app.kubernetes.io/instance=directory", "-o", "json"],
        )
        self.assertFalse([argv for argv in self.commands if "pg_dump" in argv])

    def test_capture_states_that_volumes_are_not_included(self):
        self.pod_listings = [[{"status": {"phase": "Succeeded"}}], []]
        printed = self.capture()
        manifest = verify_bundle(self.args.output)
        self.assertIn("persistent volumes", manifest["notIncluded"].lower())
        self.assertIn("persistent volumes", printed.lower())

    def test_capture_refuses_a_release_that_reopened_during_the_dump(self):
        self.pod_listings = [[], [{"status": {"phase": "Pending"}}]]
        with self.assertRaisesRegex(BundleError, "during the capture"):
            self.capture()
        self.assertFalse((self.args.output / "manifest.json").exists())

    def test_capture_requires_a_release_name(self):
        self.args.release = "directory,app=other"
        with self.assertRaisesRegex(BundleError, "release name"):
            self.capture()
        self.assertFalse(self.commands)


if __name__ == "__main__":
    unittest.main()
