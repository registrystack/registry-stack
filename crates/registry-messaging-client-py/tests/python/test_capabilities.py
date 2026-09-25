import ast
import pathlib
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_messaging_client import MessagingClient  # noqa: E402

_METHODS = {"health", "ready", "submit", "message", "cancel", "preview"}
_STUB = (
    pathlib.Path(__file__).resolve().parents[2]
    / "python"
    / "registry_messaging_client"
    / "__init__.pyi"
)


class CapabilityTests(unittest.TestCase):
    def test_all_canonical_operations_are_exported(self) -> None:
        self.assertEqual({name for name in _METHODS if not hasattr(MessagingClient, name)}, set())

    def test_the_stub_declares_exactly_the_exported_operations(self) -> None:
        stub = ast.parse(_STUB.read_text(encoding="utf-8"))
        client = next(
            node for node in stub.body
            if isinstance(node, ast.ClassDef) and node.name == "MessagingClient"
        )
        declared = {
            node.name for node in client.body
            if isinstance(node, ast.FunctionDef) and node.name != "__init__"
        }
        self.assertEqual(declared, _METHODS)
        exported = {
            name for name in dir(MessagingClient)
            if not name.startswith("_") and callable(getattr(MessagingClient, name))
        }
        self.assertEqual(exported, _METHODS)


if __name__ == "__main__":
    unittest.main()
