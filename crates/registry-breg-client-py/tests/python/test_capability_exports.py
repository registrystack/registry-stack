"""Require every inventoried Python capability on the loaded native class."""

import json
import unittest
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

import registry_breg_client  # noqa: E402
from registry_breg_client import BaseRegistryClient, BRegMetadata  # noqa: E402


class CapabilityExportTests(unittest.TestCase):
    def test_inventoried_client_methods_are_runtime_exports(self) -> None:
        # An entry point is a client method, a metadata method, or a
        # package-level function.
        owners = (BaseRegistryClient, BRegMetadata, registry_breg_client)
        root = Path(__file__).resolve().parents[4]
        inventory = json.loads(
            (root / "products/breg/contracts/client-capabilities.json").read_text()
        )
        missing = sorted(
            {
                method
                for capability in inventory["capabilities"]
                for method in capability["python"]
                if not any(hasattr(owner, method) for owner in owners)
            }
        )
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
