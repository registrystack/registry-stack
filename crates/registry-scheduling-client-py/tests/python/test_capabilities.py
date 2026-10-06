import ast
import pathlib
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_scheduling_client import SchedulingClient  # noqa: E402

_METHODS = {
    "get_scheduling",
    "list_services",
    "list_offerings",
    "availability",
    "explain",
    "create_hold",
    "release_hold",
    "create_appointment",
    "get_appointment",
    "list_appointments",
    "reschedule_appointment",
    "cancel_appointment",
    "appointment_history",
    "list_resources",
    "list_locations",
}
_STUB = (
    pathlib.Path(__file__).resolve().parents[2]
    / "python"
    / "registry_scheduling_client"
    / "__init__.pyi"
)


class CapabilityTests(unittest.TestCase):
    def test_all_canonical_operations_are_exported(self) -> None:
        self.assertEqual({name for name in _METHODS if not hasattr(SchedulingClient, name)}, set())

    def test_the_stub_declares_exactly_the_exported_operations(self) -> None:
        stub = ast.parse(_STUB.read_text(encoding="utf-8"))
        client = next(
            node for node in stub.body
            if isinstance(node, ast.ClassDef) and node.name == "SchedulingClient"
        )
        declared = {
            node.name for node in client.body
            if isinstance(node, ast.FunctionDef) and node.name != "__init__"
        }
        self.assertEqual(declared, _METHODS)
        exported = {
            name for name in dir(SchedulingClient)
            if not name.startswith("_") and callable(getattr(SchedulingClient, name))
        }
        self.assertEqual(exported, _METHODS)


if __name__ == "__main__":
    unittest.main()
