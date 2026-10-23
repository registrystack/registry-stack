"""The neutral namespace preserves the canonical provider class and exports."""
import importlib
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


class AuthFacadeTests(unittest.TestCase):
    def test_public_import_aliases_the_existing_native_provider(self):
        # Native provider effects are exercised by the BReg token-exchange
        # suite; this isolated test checks the public package's import wiring.
        canonical = type("PrivateKeyJwt", (), {})
        modules = {}
        for product in ("breg", "casework", "discovery", "evidence", "messaging", "scheduling", "coordinator", "render"):
            modules[f"registry_client.{product}"] = types.ModuleType(f"registry_client.{product}")
        modules["registry_client.breg"].PrivateKeyJwt = canonical
        source = Path(__file__).resolve().parents[1] / "python"
        with patch.dict(sys.modules, modules), patch.object(sys, "path", [str(source), *sys.path]):
            try:
                client = importlib.import_module("registry_client")
                auth = importlib.import_module("registry_client.auth")
                self.assertIs(auth.PrivateKeyJwt, canonical)
                self.assertIs(auth.PrivateKeyJwt, client.breg.PrivateKeyJwt)
                self.assertIn("auth", client.__all__)
            finally:
                sys.modules.pop("registry_client.auth", None)
                sys.modules.pop("registry_client", None)


if __name__ == "__main__":
    unittest.main()
