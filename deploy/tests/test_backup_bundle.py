import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from state_bundle import BundleError, file_hashes, verify_archived_manifest, verify_bundle, verify_snapshot_age


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


if __name__ == "__main__":
    unittest.main()
