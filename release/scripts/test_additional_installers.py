"""Additional installers retain the reviewed template and immutable release pin."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import additional_installers  # noqa: E402
import release_roster  # noqa: E402


class AdditionalInstallersTest(unittest.TestCase):
    VERSION = "0.44.0"
    TAG = "v0.44.0"

    def _command(self, mode: str, path: Path, *extra: str) -> list[str]:
        return [
            sys.executable,
            str(Path(additional_installers.__file__)),
            mode,
            str(path),
            "--version",
            self.VERSION,
            "--tag",
            self.TAG,
            *extra,
        ]

    def _package(self, output: Path) -> None:
        result = subprocess.run(
            self._command("--package", output), capture_output=True, text=True
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def _expected_version(self, binary: str) -> str:
        expected = f"{binary} {self.VERSION}"
        if binary != "registry-render":
            return expected
        source = (
            additional_installers.ROOT / "crates/registry-render/src/lib.rs"
        ).read_text()
        match = re.search(
            r'^pub const TYPST_PIN: &str = "([^"]+)";', source, re.MULTILINE
        )
        self.assertIsNotNone(match)
        return f"{expected} (typst {match.group(1)})"

    def _write_linux_payloads(
        self, bundle: Path, wrong_binary: str | None = None
    ) -> None:
        specs = release_roster.additional_installers(
            release_roster.parse_version(self.VERSION)
        )
        for _, _, binaries in specs.values():
            for binary in binaries:
                observed = self._expected_version(binary)
                if binary == wrong_binary:
                    observed = f"{binary} 9.9.9"
                payload = bundle / f"{binary}-{self.TAG}-linux-amd64"
                payload.write_text(f"#!/bin/sh\nprintf '%s\\n' '{observed}'\n")
                payload.chmod(0o755)

    def _linux_environment(self, root: Path) -> dict[str, str]:
        tools = root / "tools"
        tools.mkdir()
        uname = tools / "uname"
        uname.write_text(
            "#!/bin/sh\n"
            'case "${1:-}" in\n'
            "  -s) printf '%s\\n' Linux ;;\n"
            "  -m) printf '%s\\n' x86_64 ;;\n"
            '  *) exec /usr/bin/uname "$@" ;;\n'
            "esac\n"
        )
        uname.chmod(0o755)
        mv = tools / "mv"
        mv.write_text(
            "#!/bin/sh\n"
            'if [ "${1:-}" = -Tf ]; then\n'
            "  shift\n"
            '  exec /bin/mv -f "$@"\n'
            "fi\n"
            'exec /bin/mv "$@"\n'
        )
        mv.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = f"{tools}{os.pathsep}{environment['PATH']}"
        return environment

    def test_generated_sources_match_the_transactional_template(self):
        root = additional_installers.ROOT
        template = (root / "crates/registry-casework/install.sh").read_text()
        for name, (crate, _, binaries) in release_roster.ADDITIONAL_INSTALLERS.items():
            path = root / "crates" / crate / "install.sh"
            with self.subTest(name=name):
                self.assertEqual(
                    additional_installers.render(name, template), path.read_text()
                )
                self.assertIn("binaries=(" + " ".join(binaries) + ")", path.read_text())
                self.assertTrue(os.access(path, os.X_OK))

    def test_packaging_pins_both_names_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            command = [
                sys.executable,
                str(Path(additional_installers.__file__)),
                "--package",
                str(output),
                "--version",
                "0.44.0",
                "--tag",
                "v0.44.0",
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            for name in release_roster.ADDITIONAL_INSTALLERS:
                pinned = output / f"{name}-v0.44.0-install.sh"
                alias = output / f"{name}-install.sh"
                self.assertEqual(pinned.read_bytes(), alias.read_bytes())
                self.assertIn('default_version="v0.44.0"', pinned.read_text())
                if name == "discovery":
                    self.assertIn('release_namespace="stack"', pinned.read_text())
                    self.assertIn('numbered_platforms="all-native"', pinned.read_text())
            refused = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(0, refused.returncode)
            self.assertIn("refusing to overwrite", refused.stderr)

    def test_smoke_installs_all_numbered_additional_installers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            scratch = root / "scratch"
            bundle.mkdir()
            scratch.mkdir()
            self._package(bundle)
            self._write_linux_payloads(bundle)
            before = {path.name: path.read_bytes() for path in bundle.iterdir()}

            result = subprocess.run(
                self._command("--smoke", bundle, "--scratch-root", str(scratch)),
                env=self._linux_environment(root),
                capture_output=True,
                text=True,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("Smoked 7 numbered additional installers", result.stdout)
            self.assertEqual(
                before, {path.name: path.read_bytes() for path in bundle.iterdir()}
            )
            self.assertEqual([], list(scratch.iterdir()))
            self.assertFalse((bundle / "SHA256SUMS").exists())

    def test_stack_carry_forward_excludes_discovery_installers(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            result = subprocess.run(
                self._command(
                    "--package", output, "--exclude-unit", "discovery"
                ),
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            names = {path.name for path in output.iterdir()}
            self.assertFalse(any(name.startswith("discovery") for name in names))
            self.assertTrue(
                any(name.startswith("registry-render") for name in names)
            )

    def test_smoke_rejects_an_installed_binary_with_the_wrong_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            scratch = root / "scratch"
            bundle.mkdir()
            scratch.mkdir()
            self._package(bundle)
            self._write_linux_payloads(bundle, wrong_binary="discoveryctl")
            before = {path.name: path.read_bytes() for path in bundle.iterdir()}

            result = subprocess.run(
                self._command("--smoke", bundle, "--scratch-root", str(scratch)),
                env=self._linux_environment(root),
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(0, result.returncode)
            self.assertIn(
                "discoveryctl binary has an unexpected embedded version",
                result.stderr,
            )
            self.assertEqual(
                before, {path.name: path.read_bytes() for path in bundle.iterdir()}
            )
            self.assertEqual([], list(scratch.iterdir()))

    def test_smoke_rejects_a_missing_payload_without_touching_the_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            scratch = root / "scratch"
            bundle.mkdir()
            scratch.mkdir()
            self._package(bundle)
            self._write_linux_payloads(bundle)
            missing = bundle / f"coordinatorctl-{self.TAG}-linux-amd64"
            missing.unlink()
            before = {path.name: path.read_bytes() for path in bundle.iterdir()}

            result = subprocess.run(
                self._command("--smoke", bundle, "--scratch-root", str(scratch)),
                env=self._linux_environment(root),
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(0, result.returncode)
            self.assertIn(f"missing candidate payload: {missing.name}", result.stderr)
            self.assertEqual(
                before, {path.name: path.read_bytes() for path in bundle.iterdir()}
            )
            self.assertEqual([], list(scratch.iterdir()))
            self.assertFalse((bundle / "SHA256SUMS").exists())
