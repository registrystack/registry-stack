"""The installed package shape, which nothing else in this suite covers.

Every other test imports the compiled extension directly from the bootstrap's
own directory, so it never runs `python/registry_evidence_client/__init__.py`:
the file that turns that directory into a package and re-exports the extension
as its submodule, which is the shape a built wheel installs. Building a wheel
here would require maturin, which this crate's checks deliberately keep out of
CI, so this assembles the same layout by hand from the cdylib the bootstrap
already built, and imports it in a subprocess where nothing else is on the path.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))

import bootstrap  # noqa: E402

bootstrap.ensure_built()

import registry_evidence_client as _extension  # noqa: E402

_PACKAGE_SOURCE = (
    pathlib.Path(__file__).resolve().parents[2] / "python" / "registry_evidence_client"
)

# Runs inside the assembled layout, and prints what it found as JSON. Each
# finding answers one claim `__init__.py` makes about itself.
_PROBE = """
import importlib, json, pathlib, sys
import registry_evidence_client as revc

findings = {
    "imported_file": pathlib.Path(revc.__file__).name,
    "has_client": hasattr(revc, "EvidenceClient"),
    "has_configuration_error": hasattr(revc, "ConfigurationError"),
    "submodule_name_dropped": not hasattr(revc, "registry_evidence_client"),
    "py_typed_beside_init": (
        pathlib.Path(revc.__file__).parent / "py.typed"
    ).is_file(),
}

# The comment on the `pop` claims re-execution stays sound. A reload runs the
# body again against the existing namespace, where the submodule attribute is
# no longer bound.
importlib.reload(revc)
findings["reload_keeps_client"] = hasattr(revc, "EvidenceClient")
findings["reload_keeps_submodule_dropped"] = not hasattr(
    revc, "registry_evidence_client"
)

try:
    revc.EvidenceClient("not-a-url", {"keys": []}, "test-token")
except revc.ConfigurationError as error:
    findings["refusal_kind"] = error.kind

print(json.dumps(findings))
"""


class PackageLayoutTest(unittest.TestCase):
    def test_the_package_layout_a_wheel_installs_imports_and_refuses(self):
        # An extension module always reports the file it was loaded from; a
        # missing one would mean the bootstrap imported something else.
        self.assertIsNotNone(_extension.__file__)
        extension = pathlib.Path(str(_extension.__file__))
        with tempfile.TemporaryDirectory() as root:
            package = pathlib.Path(root) / "registry_evidence_client"
            package.mkdir()
            for name in ("__init__.py", "__init__.pyi", "py.typed"):
                shutil.copyfile(_PACKAGE_SOURCE / name, package / name)
            # The name maturin gives the extension inside the package: the
            # submodule `__init__.py` imports, not a top-level module of the
            # same name as the package.
            shutil.copyfile(extension, package / "registry_evidence_client.so")

            environment = dict(os.environ)
            # Only the assembled layout, so a stray copy elsewhere cannot be
            # what answers the import.
            environment["PYTHONPATH"] = root
            completed = subprocess.run(
                [sys.executable, "-c", _PROBE],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(
            completed.returncode,
            0,
            f"importing the assembled package failed:\n{completed.stderr}",
        )

        findings = json.loads(completed.stdout)
        self.assertEqual(findings["imported_file"], "__init__.py")
        self.assertTrue(findings["has_client"])
        self.assertTrue(findings["has_configuration_error"])
        self.assertTrue(findings["submodule_name_dropped"])
        self.assertTrue(findings["py_typed_beside_init"])
        self.assertTrue(findings["reload_keeps_client"])
        self.assertTrue(findings["reload_keeps_submodule_dropped"])
        self.assertEqual(findings["refusal_kind"], "configuration")


if __name__ == "__main__":
    unittest.main()
