import ast
import pathlib
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_coordinator_client import (  # noqa: E402
    CoordinatorClient,
    CoordinatorClientError,
    __version__,
)
from scripted import INSPECTION, STATUS  # noqa: E402

_METHODS = {"start", "workflow", "status", "inspect", "reconcile", "list", "retry_same", "cancel"}
_STUB = (
    pathlib.Path(__file__).resolve().parents[2]
    / "python"
    / "registry_coordinator_client"
    / "__init__.pyi"
)


class CapabilityTests(unittest.TestCase):
    def test_all_canonical_operations_are_exported(self) -> None:
        self.assertEqual({name for name in _METHODS if not hasattr(CoordinatorClient, name)}, set())

    def test_the_stub_declares_exactly_the_exported_operations(self) -> None:
        stub = ast.parse(_STUB.read_text(encoding="utf-8"))
        client = next(
            node for node in stub.body
            if isinstance(node, ast.ClassDef) and node.name == "CoordinatorClient"
        )
        declared = {
            node.name for node in client.body
            if isinstance(node, ast.FunctionDef) and node.name != "__init__"
        }
        self.assertEqual(declared, _METHODS)
        exported = {
            name for name in dir(CoordinatorClient)
            if not name.startswith("_") and callable(getattr(CoordinatorClient, name))
        }
        self.assertEqual(exported, _METHODS)

    def test_the_module_exports_the_version_and_the_error(self) -> None:
        self.assertIsInstance(__version__, str)
        self.assertTrue(issubclass(CoordinatorClientError, Exception))

    def test_the_stub_declares_every_status_member_the_client_returns(self) -> None:
        stub = ast.parse(_STUB.read_text(encoding="utf-8"))
        declared = {
            node.name: {
                field.target.id for field in node.body
                if isinstance(field, ast.AnnAssign) and isinstance(field.target, ast.Name)
            }
            for node in stub.body
            if isinstance(node, ast.ClassDef) and node.name in {"RunStatus", "StepStatus"}
        }
        self.assertEqual(declared["RunStatus"], set(STATUS))
        self.assertEqual(declared["StepStatus"], set(INSPECTION["steps"][0]))

    def test_the_stub_names_the_client_vocabularies(self) -> None:
        stub = _STUB.read_text(encoding="utf-8")
        for member in ("header-bounds", "media-type", "invalid-request", "evaluation-uncertain"):
            self.assertIn(f'"{member}"', stub)
        self.assertNotIn("trace", stub.lower())


if __name__ == "__main__":
    unittest.main()
