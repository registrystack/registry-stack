#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "scripts" / "smoke-registry-client-package.py"
VERSION = "0.0.0-smoke"
# The namespaces the published wheel carries, with the constructor and error
# class a caller of each one names.
NAMESPACES = {
    "breg": ("BaseRegistryClient", "BaseRegistryClientError"),
    "casework": ("CaseworkClient", "CaseworkClientError"),
    "discovery": ("DiscoveryClient", "DiscoveryClientError"),
    "evidence": ("EvidenceClient", "EvidenceClientError"),
    "relay": ("RelayClient", "RelayClientError"),
}


def published_class(namespace: str, name: str) -> type:
    """One class as the wheel publishes it: constructible, under its namespace."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        return None

    published = type(name, (), {"__init__": __init__})
    published.__module__ = f"registry_client.{namespace}"
    published.__qualname__ = name
    return published


def stub_wheel() -> types.ModuleType:
    package = types.ModuleType("registry_client")
    package.__version__ = VERSION
    for namespace, names in NAMESPACES.items():
        module = types.ModuleType(f"registry_client.{namespace}")
        for name in names:
            setattr(module, name, published_class(namespace, name))
        setattr(package, namespace, module)
    return package


def load_smoke(package: types.ModuleType):
    spec = importlib.util.spec_from_file_location(
        "smoke_registry_client_package", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.version = lambda distribution: VERSION
    return module


class SmokeRegistryClientPackageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.package = stub_wheel()
        self.addCleanup(sys.modules.pop, "registry_client", None)
        self.addCleanup(sys.modules.pop, "smoke_registry_client_package", None)
        sys.modules["registry_client"] = self.package
        for namespace in NAMESPACES:
            name = f"registry_client.{namespace}"
            self.addCleanup(sys.modules.pop, name, None)
            sys.modules[name] = getattr(self.package, namespace)

    def run_smoke(self) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            load_smoke(self.package).main()
        return output.getvalue()

    def test_a_complete_wheel_passes(self) -> None:
        self.assertIn("smoke passed", self.run_smoke())

    def test_every_published_namespace_is_exercised(self) -> None:
        # A wheel missing any one of these names must fail the smoke, whether
        # the smoke refuses it or the missing attribute stops it.
        for namespace, names in NAMESPACES.items():
            for name in names:
                with self.subTest(namespace=namespace, name=name):
                    self.package = stub_wheel()
                    sys.modules["registry_client"] = self.package
                    delattr(getattr(self.package, namespace), name)
                    with self.assertRaises((SystemExit, AttributeError)):
                        self.run_smoke()

    def test_a_casework_namespace_from_another_module_is_refused(self) -> None:
        self.package.casework.CaseworkClientError.__module__ = (
            "registry_casework_client"
        )
        with self.assertRaises(SystemExit):
            self.run_smoke()

    def test_a_casework_extension_that_cannot_load_is_refused(self) -> None:
        # A wheel whose casework directory is present but whose native module
        # fails on construction must not pass the publication smoke.
        def refuse(self: object, *args: object, **kwargs: object) -> None:
            raise RuntimeError("the casework extension module failed to load")

        self.package.casework.CaseworkClient.__init__ = refuse
        with self.assertRaises(RuntimeError):
            self.run_smoke()


if __name__ == "__main__":
    unittest.main()
