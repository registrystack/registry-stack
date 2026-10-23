"""The independent pilot must produce only its authenticated artifact closure."""

from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest.mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import unit_release_pipeline as pipeline


class DiscoveryShardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.shard = self.root / "shard"
        (self.shard / "bin").mkdir(parents=True)
        self.version = "0.44.1"
        self.source = "a" * 40
        self.builder = "rust:fixture@sha256:" + "b" * 64
        self.assets = [
            f"{name}-v{self.version}-linux-amd64"
            for name in ("discovery", "discoveryctl")
        ]
        sums = []
        for asset in self.assets:
            data = asset.encode()
            (self.shard / "bin" / asset).write_bytes(data)
            sums.append(f"{hashlib.sha256(data).hexdigest()}  {asset}\n")
        (self.shard / "bin/SHA256SUMS").write_text("".join(sums))
        (self.shard / "RELEASE_BUILDER_IMAGE").write_text(self.builder + "\n")
        (self.shard / "RELEASE_BINARY_SHARD").write_text(
            f"registry-stack.release-binary-shard.v1\nsource_sha={self.source}\nversion={self.version}\ngroup=discovery\n"
        )

    def merge(self):
        pipeline.merge_unit_shard(
            "discovery",
            self.version,
            self.source,
            self.shard,
            self.root / "dist",
            self.builder,
        )

    def test_merge_preserves_only_discovery_payload_and_image(self):
        self.merge()
        self.assertEqual(
            {p.name for p in (self.root / "dist/bin").iterdir()}, set(self.assets)
        )
        self.assertEqual(
            {p.name for p in (self.root / "dist/image-bin").iterdir()},
            {"discovery", "RELEASE_BUILDER_IMAGE", "SHA256SUMS"},
        )
        self.assertEqual(
            (self.root / "dist/image-bin/discovery").read_bytes(),
            self.assets[0].encode(),
        )

    def test_tampering_refuses_before_creating_output(self):
        (self.shard / "bin" / self.assets[0]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.merge()
        self.assertFalse((self.root / "dist").exists())

    def test_extra_product_refuses_before_creating_output(self):
        (self.shard / "bin/breg-v0.44.1-linux-amd64").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "inventory"):
            self.merge()
        self.assertFalse((self.root / "dist").exists())


class UnitPreparationTest(unittest.TestCase):
    def test_independent_package_versions_and_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("registry-discovery", "registry-discoveryctl"):
                path = root / "crates" / name / "Cargo.toml"
                path.parent.mkdir(parents=True)
                path.write_text(f'[package]\nname = "{name}"\nversion = "1.2.3"\n')
            notes = root / "release/notes/discovery/v1.2.3.md"
            notes.parent.mkdir(parents=True)
            notes.write_text(
                "# Registry Discovery v1.2.3\n\nRelease pilot fixes response handling.\n"
            )
            result = pipeline.prepare_unit(root, "discovery", "1.2.3", "pilot")
            self.assertEqual(result["tag"], "discovery/v1.2.3")
            self.assertEqual(result["binary_groups"], ["discovery"])
            notes.write_text("# Registry Discovery v1.2.2\n\nRelease pilot.\n")
            with self.assertRaisesRegex(ValueError, "wrong title"):
                pipeline.prepare_unit(root, "discovery", "1.2.3", "pilot")
            notes.write_text("# Registry Discovery v1.2.3\n\nFix response handling.\n")
            with self.assertRaisesRegex(ValueError, "do not name pilot"):
                pipeline.prepare_unit(root, "discovery", "1.2.3", "pilot")
            path.write_text('[package]\nversion = "1.2.4"\n')
            with self.assertRaisesRegex(ValueError, "version"):
                pipeline.prepare_unit(root, "discovery", "1.2.3", "pilot")

    def test_staging_requires_exact_binary_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = root / "bin"
            binaries.mkdir()
            (binaries / "breg-v1.2.3-linux-amd64").write_bytes(b"unexpected")
            with self.assertRaisesRegex(ValueError, "inventory"):
                pipeline.stage_payload(
                    root, "discovery", "1.2.3", binaries, root / "out"
                )
            self.assertFalse((root / "out").exists())

    def test_staging_installs_and_checks_the_same_version_binary_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installer = root / "crates/registry-discovery/install.sh"
            installer.parent.mkdir(parents=True)
            shutil.copyfile(
                Path(__file__).resolve().parents[2]
                / "crates/registry-discovery/install.sh",
                installer,
            )
            (root / "THIRD_PARTY_NOTICES").write_text("fixture notices\n")
            binaries = root / "bin"
            binaries.mkdir()
            for binary in ("discovery", "discoveryctl"):
                path = binaries / f"{binary}-v1.2.3-linux-amd64"
                path.write_text(
                    "#!/bin/bash\n"
                    "set -euo pipefail\n"
                    'if [[ "${1:-}" != --version ]]; then exit 2; fi\n'
                    f"printf '%s\\n' '{binary} 1.2.3'\n"
                )
                path.chmod(0o755)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            uname = fake_bin / "uname"
            uname.write_text(
                "#!/bin/bash\n"
                "set -euo pipefail\n"
                'case "${1:-}" in\n'
                "  -s) printf '%s\\n' Linux ;;\n"
                "  -m) printf '%s\\n' x86_64 ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n"
            )
            uname.chmod(0o755)
            getconf = fake_bin / "getconf"
            getconf.write_text(
                "#!/bin/bash\nset -euo pipefail\nprintf 'glibc 2.34\\n'\n"
            )
            getconf.chmod(0o755)
            output = root / "out"
            installer_output = []
            run = subprocess.run

            def quiet_run(*args, **kwargs):
                if "capture_output" not in kwargs:
                    kwargs = {**kwargs, "capture_output": True, "text": True}
                result = run(*args, **kwargs)
                if args[0][0] == "bash":
                    installer_output.append(result.stdout)
                    self.assertNotIn("floor is unchecked", result.stderr)
                return result

            with (
                unittest.mock.patch.dict(
                    os.environ,
                    {"PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"},
                ),
                unittest.mock.patch.object(
                    pipeline.subprocess, "run", side_effect=quiet_run
                ),
            ):
                pipeline.stage_payload(root, "discovery", "1.2.3", binaries, output)

            expected = {
                "THIRD_PARTY_NOTICES",
                "discovery-install.sh",
                "discovery-v1.2.3-install.sh",
                "discovery-v1.2.3-linux-amd64",
                "discoveryctl-v1.2.3-linux-amd64",
            }
            self.assertEqual(expected, {path.name for path in output.iterdir()})
            pinned = (output / "discovery-v1.2.3-install.sh").read_text()
            self.assertIn('default_version="v1.2.3"', pinned)
            self.assertEqual(1, len(installer_output))
            self.assertIn("toolset v1.2.3 installed", installer_output[0])


if __name__ == "__main__":
    unittest.main()
