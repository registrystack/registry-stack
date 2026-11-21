import hashlib
import io
import json
import subprocess
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
    BundleError, capture, checked_run, file_hashes, require_supported_python, restore_database, snapshot,
    verify_archived_manifest, verify_bundle, verify_snapshot_age,
)

DIGEST = "sha256:" + "a" * 64


class PythonVersionTest(unittest.TestCase):
    def test_older_interpreter_stops_with_a_clear_message(self):
        for version in ((3, 10, 14, "final", 0), (3, 9, 6, "final", 0)):
            with self.subTest(version=version), self.assertRaises(SystemExit) as raised:
                require_supported_python(version)
            self.assertEqual(
                raised.exception.code,
                f"These tools need Python 3.11 or later. This is Python 3.{version[1]}. Run them with a newer python3.",
            )

    def test_supported_interpreters_continue(self):
        for version in ((3, 11, 0, "final", 0), (3, 14, 7, "final", 0), (4, 0, 0, "alpha", 1)):
            with self.subTest(version=version):
                self.assertIsNone(require_supported_python(version))


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

    def test_clean_target_check_ignores_temporary_schemas(self):
        run = Mock(side_effect=[b"0\n", b""])
        with patch("state_bundle.checked_run", run), redirect_stdout(io.StringIO()):
            restore_database(self.restore_args())
        query = run.call_args_list[0].args[0][-1]
        self.assertIn("nspname NOT LIKE 'pg_temp_%'", query)
        self.assertIn("nspname NOT LIKE 'pg_toast_temp_%'", query)


class CaptureTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        status = root / "status.json"
        recorded = {
            "maintenanceStatus": "ready", "activePackageDigest": DIGEST, "databaseId": "registry-test-db",
            "activationId": "synthetic-activation",
        }
        status.write_text(json.dumps({"ok": True, "command": "status", "roleMode": "split", **recorded}))
        files = root / "files"
        files.mkdir()
        (files / "values.json").write_text("{}")
        self.args = SimpleNamespace(
            kube_context="test-only", namespace="pilot", pod="registry-postgres-0", container="postgres",
            kubectl_bin="kubectl", release="directory", database=["registry_breg"], breg_database="registry_breg",
            status_file=status, files=files, output=root / "backup-01",
        )
        self.pod_listings = []
        self.commands = []
        self.breg_state = json.dumps(recorded).encode() + b"\n"
        self.read_back = {}
        self.unreadable = set()

    def run_command(self, argv, label, *, stdin=None, stdout=None):
        self.commands.append(argv)
        if "pods" in argv:
            return json.dumps({"items": self.pod_listings.pop(0)}).encode()
        if "psql" in argv:
            return self.breg_state
        if "pg_restore" in argv:
            database = Path(stdin.name).stem
            self.read_back[database] = stdin.read()
            if database in self.unreadable:
                raise BundleError(f"{label} failed with exit 1.")
            return b""
        self.assertIn("pg_dump", argv)
        database = argv[-1].removeprefix("--dbname=")
        stdout.write(f"synthetic {database} dump".encode())
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

    def test_capture_checks_the_status_file_against_the_breg_database(self):
        self.pod_listings = [[], []]
        self.capture()
        query = next(argv for argv in self.commands if "psql" in argv)
        self.assertEqual(
            query[:-1],
            ["kubectl", "--context", "test-only", "--namespace", "pilot", "exec", "-i", "registry-postgres-0",
             "-c", "postgres", "--", "psql", "-XAt", "--no-password", "--username=postgres",
             "--dbname=registry_breg", "-v", "ON_ERROR_STOP=1", "-c"],
        )
        self.assertTrue(query[-1].startswith("SELECT "))
        self.assertIn("FROM registry_internal.registry_state WHERE singleton", query[-1])
        self.assertLess(self.commands.index(query), next(i for i, argv in enumerate(self.commands) if "pg_dump" in argv))
        self.assertEqual(verify_bundle(self.args.output)["activationId"], "synthetic-activation")

    def test_capture_refuses_a_status_file_for_another_activation_or_database(self):
        recorded = json.loads(self.breg_state)
        for field, value in (
            ("activationId", "later-activation"), ("databaseId", "another-installation-db"),
            ("activePackageDigest", "sha256:" + "b" * 64), ("maintenanceStatus", "failed"),
        ):
            with self.subTest(field=field):
                self.pod_listings, self.commands = [[]], []
                self.breg_state = json.dumps({**recorded, field: value}).encode()
                with self.assertRaisesRegex(BundleError, f"does not describe database registry_breg.*{field}.*status"):
                    self.capture()
                self.assertFalse(self.args.output.exists())
                self.assertFalse([argv for argv in self.commands if "pg_dump" in argv])

    def test_capture_refuses_a_database_without_breg_state(self):
        self.pod_listings, self.breg_state = [[]], b""
        with self.assertRaisesRegex(BundleError, "registry_breg has no BReg state.*--breg-database"):
            self.capture()
        self.assertFalse(self.args.output.exists())

    def test_capture_requires_the_breg_database_among_the_dumps(self):
        self.args.database = ["registry_casework"]
        with self.assertRaisesRegex(BundleError, "--database registry_breg.*--breg-database"):
            self.capture()
        self.assertFalse(self.commands)

    def test_capture_reads_back_each_dump(self):
        self.args.database = ["registry_breg", "registry_casework"]
        self.pod_listings = [[], []]
        self.capture()
        self.assertEqual(self.read_back, {
            "registry_breg": b"synthetic registry_breg dump", "registry_casework": b"synthetic registry_casework dump",
        })
        read_back = [argv for argv in self.commands if "pg_restore" in argv]
        self.assertEqual(read_back[0][-2:], ["pg_restore", "--file=/dev/null"])
        self.assertEqual(len(read_back), 2)

    def test_capture_refuses_an_unreadable_dump(self):
        self.args.database = ["registry_breg", "registry_casework"]
        self.pod_listings, self.unreadable = [[], []], {"registry_breg"}
        with self.assertRaisesRegex(BundleError, "registry_breg dump"):
            self.capture()
        self.assertFalse((self.args.output / "manifest.json").exists())
        self.assertNotIn("--dbname=registry_casework", [arg for argv in self.commands for arg in argv])


class SnapshotTest(unittest.TestCase):
    SNAPSHOT = "d" * 64

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / "backup-01"
        self.bundle.mkdir()
        write_bundle(self.bundle)
        self.args = SimpleNamespace(bundle=self.bundle, receipt=self.root / "receipt.json", restic_bin="restic")
        self.backup = subprocess.CompletedProcess([], 0, json.dumps({
            "message_type": "summary", "snapshot_id": self.SNAPSHOT,
        }).encode() + b"\n", b"")
        self.calls = []

    def restic(self, argv, **_):
        self.calls.append(argv[1])
        if argv[1] == "backup":
            return self.backup
        if argv[1] == "cat":
            return subprocess.CompletedProcess(argv, 0, json.dumps({"paths": [str(self.bundle.resolve())]}).encode(), b"")
        return subprocess.CompletedProcess(argv, 0, (self.bundle / "manifest.json").read_bytes(), b"")

    def snapshot(self):
        self.printed = io.StringIO()
        with patch("state_bundle.subprocess.run", side_effect=self.restic), redirect_stdout(self.printed):
            snapshot(self.args)
        return self.printed.getvalue()

    def test_snapshot_writes_a_receipt_for_the_verified_archive(self):
        printed = self.snapshot()
        receipt = json.loads(self.args.receipt.read_text())
        self.assertEqual(receipt["snapshotId"], self.SNAPSHOT)
        self.assertEqual(verify_bundle(self.bundle, receipt)["release"], "directory")
        self.assertEqual(self.calls, ["backup", "cat", "dump"])
        self.assertIn(f"Verified encrypted snapshot {self.SNAPSHOT}", printed)

    def test_snapshot_refuses_an_existing_receipt_before_archiving(self):
        self.args.receipt.write_text("earlier receipt")
        with self.assertRaisesRegex(BundleError, "already exists"):
            self.snapshot()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.args.receipt.read_text(), "earlier receipt")

    def test_snapshot_refuses_a_receipt_outside_a_directory_before_archiving(self):
        self.args.receipt = self.root / "missing" / "receipt.json"
        with self.assertRaisesRegex(BundleError, "directory"):
            self.snapshot()
        self.assertEqual(self.calls, [])

    def test_failed_restic_backup_writes_no_receipt(self):
        self.backup = subprocess.CompletedProcess([], 1, b"", b"Fatal: unable to open config file\n")
        with self.assertRaises(BundleError) as raised:
            self.snapshot()
        self.assertIn("Write the encrypted snapshot failed with exit 1", str(raised.exception))
        self.assertIn("Fatal: unable to open config file", str(raised.exception))
        self.assertEqual(self.calls, ["backup"])
        self.assertFalse(self.args.receipt.exists())
        self.assertEqual(self.printed.getvalue(), "")

    def test_restic_output_without_one_snapshot_identifier_writes_no_receipt(self):
        summary = {"message_type": "summary", "snapshot_id": self.SNAPSHOT}
        for rows in ([{"message_type": "status"}], [summary, summary], [{**summary, "snapshot_id": "NOT-HEX"}]):
            with self.subTest(rows=rows):
                self.calls = []
                output = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
                self.backup = subprocess.CompletedProcess([], 0, output, b"")
                with self.assertRaisesRegex(BundleError, "one snapshot identifier"):
                    self.snapshot()
                self.assertEqual(self.calls, ["backup"])
                self.assertFalse(self.args.receipt.exists())
                self.assertEqual(self.printed.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
