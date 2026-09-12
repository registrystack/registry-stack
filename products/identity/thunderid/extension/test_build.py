"""Source preparation must not trust a pre-extracted cache or archive paths."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import subprocess

import build


class SourcePreparationTests(unittest.TestCase):
    def test_applies_patch_inside_an_existing_parent_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            source = root / "target/upstream"
            source.mkdir(parents=True)
            (source / "example").write_text("before\n")
            patch = root / "change.patch"
            patch.write_text("diff --git a/example b/example\n--- a/example\n+++ b/example\n@@ -1 +1 @@\n-before\n+after\n")
            build.apply_source_patch(source, patch)
            self.assertEqual((source / "example").read_text(), "after\n")

    def archive(self, root, name="source/backend/main.go", kind=tarfile.REGTYPE):
        archive = root / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o644
            member.size = 3 if kind == tarfile.REGTYPE else 0
            member.linkname = "../../outside"
            output.addfile(member, io.BytesIO(b"pkg") if member.size else None)
        return archive

    def test_extracts_verified_source_and_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.archive(root)
            destination = root / "out"
            build.extract_source(archive, destination, build.sha256(archive))
            self.assertEqual((destination / "backend/main.go").read_bytes(), b"pkg")
            with self.assertRaises(FileExistsError):
                build.extract_source(archive, destination, build.sha256(archive))

    def test_refuses_checksum_mismatch_before_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.archive(root)
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                build.extract_source(archive, root / "out", "0" * 64)
            self.assertFalse((root / "out").exists())

    def test_refuses_archive_escape_and_links(self):
        for name, kind in [("source/../../outside", tarfile.REGTYPE),
                           ("/absolute", tarfile.REGTYPE),
                           ("source/link", tarfile.SYMTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = self.archive(root, name, kind)
                with self.assertRaisesRegex(ValueError, "unsupported"):
                    build.extract_source(archive, root / "out", build.sha256(archive))
                self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
