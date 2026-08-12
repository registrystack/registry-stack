from __future__ import annotations

import ast
import pathlib
import re
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
WORKSPACE = TESTS.parents[3]
PYTHON_STUB = (
    WORKSPACE
    / "crates"
    / "registry-relay-client-py"
    / "python"
    / "registry_relay_client"
    / "__init__.pyi"
)
NODE_DECLARATION = (
    WORKSPACE / "crates" / "registry-relay-client-node" / "client.d.ts"
)
RUST_CLIENT = WORKSPACE / "crates" / "registry-relay-client" / "src" / "client.rs"

RUST_METHODS = {
    "health",
    "ready",
    "openapi",
    "service_metadata",
    "resources",
    "continue_resources",
    "resource",
    "list_records",
    "search_records",
    "continue_collection",
    "read_record",
    "lookup_record",
    "artifact",
    "sdmx_data",
    "sdmx_structure",
}
PYTHON_METHODS = {
    "health",
    "ready",
    "openapi",
    "service_metadata",
    "resources",
    "continue_resources",
    "resource",
    "list_records",
    "continue_list_records",
    "read_record",
    "lookup",
    "search",
    "continue_search",
    "artifact",
    "sdmx_data",
    "sdmx_structure",
}
NODE_METHODS = {
    "health",
    "ready",
    "openapi",
    "serviceMetadata",
    "resources",
    "continueResources",
    "resource",
    "listRecords",
    "continueListRecords",
    "readRecord",
    "lookup",
    "search",
    "continueSearch",
    "artifact",
    "sdmxData",
    "sdmxStructure",
}


def python_client(tree: ast.Module) -> ast.ClassDef:
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RelayClient"
    )


def python_literal_values(tree: ast.Module, name: str) -> set[str]:
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        )
    )
    return {
        node.value
        for node in ast.walk(assignment.value)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


class CrossBindingApiParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.python_source = PYTHON_STUB.read_text(encoding="utf-8")
        cls.python_tree = ast.parse(cls.python_source)
        cls.node_source = NODE_DECLARATION.read_text(encoding="utf-8")
        cls.rust_source = RUST_CLIENT.read_text(encoding="utf-8")

    def test_every_binding_covers_the_canonical_operation_inventory(self):
        rust = set(re.findall(r"pub async fn ([a-z_]+)\(", self.rust_source))
        python = {
            node.name
            for node in python_client(self.python_tree).body
            if isinstance(node, ast.FunctionDef) and node.name != "__init__"
        }
        node_class = re.search(
            r"export declare class RelayClient \{([\s\S]*?)\n\}",
            self.node_source,
        )
        self.assertIsNotNone(node_class)
        node = set(re.findall(r"^  ([A-Za-z][A-Za-z0-9]*)\(", node_class.group(1), re.MULTILINE))
        node.discard("constructor")

        self.assertEqual(rust, RUST_METHODS)
        self.assertEqual(python, PYTHON_METHODS)
        self.assertEqual(node, NODE_METHODS)

    def test_public_input_literal_vocabularies_match(self):
        self.assertEqual(
            python_literal_values(self.python_tree, "RecordFormat"),
            {"json", "json-ld", "geojson", "json-fg"},
        )
        self.assertEqual(
            python_literal_values(self.python_tree, "SdmxStructureKind"),
            {"dataflow", "datastructure"},
        )

        node_record = re.search(
            r"export type RecordFormat = ([^\n]+)", self.node_source
        )
        node_structure = re.search(
            r"export interface SdmxStructureRequest \{([\s\S]*?)\n\}",
            self.node_source,
        )
        self.assertIsNotNone(node_record)
        self.assertIsNotNone(node_structure)
        self.assertEqual(
            set(re.findall(r"'([^']+)'", node_record.group(1))),
            {"json", "json-ld", "geojson", "json-fg"},
        )
        self.assertEqual(
            set(re.findall(r"'([^']+)'", node_structure.group(1))),
            {"dataflow", "datastructure"},
        )

    def test_static_and_private_key_jwt_are_the_two_binding_auth_modes(self):
        python_authorization = next(
            node
            for node in self.python_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "RelayAuthorization"
                for target in node.targets
            )
        )
        self.assertEqual(
            {
                node.id
                for node in ast.walk(python_authorization.value)
                if isinstance(node, ast.Name)
                and node.id.endswith("Authorization")
            },
            {"StaticAuthorization", "PrivateKeyJwtAuthorization"},
        )

        node_authorization = re.search(
            r"export type RelayAuthorization =([\s\S]*?)\n\n",
            self.node_source,
        )
        self.assertIsNotNone(node_authorization)
        self.assertEqual(
            set(re.findall(r"\{ ([A-Za-z][A-Za-z0-9]*):", node_authorization.group(1))),
            {"static", "privateKeyJwt"},
        )


if __name__ == "__main__":
    unittest.main()
