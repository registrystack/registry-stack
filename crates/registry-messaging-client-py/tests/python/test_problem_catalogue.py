"""The typing stub names the catalogues the Rust client answers with."""

import ast
import pathlib
import unittest

from bootstrap import ensure_built

ensure_built()

import registry_messaging_client  # noqa: E402

_STUB = (
    pathlib.Path(__file__).resolve().parents[2]
    / "python"
    / "registry_messaging_client"
    / "__init__.pyi"
)


def _literal_members(name: str) -> list[str]:
    """Every member of one Literal alias, read from the stub as written."""
    stub = ast.parse(_STUB.read_text(encoding="utf-8"))
    for node in stub.body:
        if not isinstance(node, ast.AnnAssign):
            continue
        if not isinstance(node.target, ast.Name) or node.target.id != name:
            continue
        value = node.value
        if not isinstance(value, ast.Subscript) or getattr(value.value, "id", None) != "Literal":
            raise AssertionError(f"{name} is declared in the stub without a Literal union")
        members = []
        for element in value.slice.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                raise AssertionError(f"{name} carries a member that is not a string: {element}")
            members.append(element.value)
        return members
    raise AssertionError(f"the stub declares no {name} alias")


class ProblemCatalogueTests(unittest.TestCase):
    def test_the_stub_names_every_problem_code_the_client_answers(self) -> None:
        published = _literal_members("MessagingProblemCode")
        self.assertEqual(
            sorted(set(published)),
            sorted(registry_messaging_client.PROBLEM_CODES),
            "the stub and the Rust problem-code catalogue name different codes",
        )
        self.assertEqual(len(published), len(set(published)), "the stub names a code twice")

    def test_an_unregistered_code_is_not_in_the_closed_catalogue(self) -> None:
        self.assertNotIn("message.invented", registry_messaging_client.PROBLEM_CODES)

    def test_the_problem_code_alias_is_closed(self) -> None:
        # The Rust client answers a code outside its catalogue as a protocol
        # failure, so `code` is exactly the closed catalogue.
        stub = _STUB.read_text(encoding="utf-8")
        self.assertIn("code: MessagingProblemCode | None", stub)
        self.assertNotIn("MessagingProblemCode | str", stub)


if __name__ == "__main__":
    unittest.main()
