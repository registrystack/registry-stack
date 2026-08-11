"""The committed `__init__.pyi` names exactly the live compiled surface.

PyO3 does not emit a `.pyi` on its own; `__init__.pyi` is hand-written and
nothing forces it to track `src/lib.rs` automatically. This is the Python
analog of `registry-evidence-client-node`'s own `__test__/drift.test.js`:
introspect the built module's real classes and assert the stub names exactly
what exists, in both directions, so an added or removed method/attribute on
either side fails this test rather than silently drifting.

Two different techniques are needed, for two different shapes of drift:

- The eight plain classes (`EvidenceClient`, both prepared request classes,
  both raw response classes, `SdJwtVcBatchResponse`, and both verified result
  classes) expose their methods and
  attributes as ordinary class-level descriptors, visible to `vars(cls)`
  without ever constructing an instance.
- The nine exception classes set their stable attributes (`kind`, `status`,
  ...) per instance, at raise time (`to_py_err`'s `set_attr!` calls in
  `src/lib.rs`), which `vars(cls)` on the class itself cannot see at all.
  Those are checked against a hardcoded reference list instead, drawn
  directly from that same `set_attr!` call list.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import unittest

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
_PACKAGE_DIR = _TESTS_DIR.parent.parent / "python" / "registry_evidence_client"
_STUB_PATH = _PACKAGE_DIR / "__init__.pyi"
sys.path.insert(0, str(_TESTS_DIR))
sys.path.insert(0, str(_TESTS_DIR / "helpers"))

import bootstrap  # noqa: E402

bootstrap.ensure_built()

import registry_evidence_client as revc  # noqa: E402

# Exactly the attributes `to_py_err` sets on every raised exception instance,
# in `crates/registry-evidence-client-py/src/lib.rs`. Update this list only in
# lockstep with that function.
SETTABLE_EXCEPTION_ATTRIBUTES = {
    "kind",
    "status",
    "code",
    "trace_id",
    "retry_after_seconds",
    "transport_kind",
    "token_kind",
}

EXCEPTION_SUBCLASS_NAMES = {
    "ConfigurationError",
    "NonceError",
    "TokenError",
    "TransportError",
    "DeniedError",
    "NotAvailableError",
    "ProtocolError",
    "VerificationError",
}

PLAIN_CLASS_NAMES = {
    "EvidenceClient",
    "PreparedEvidenceRequest",
    "PreparedEvidenceRequestBatch",
    "RawEvidenceResponse",
    "RawEvidenceRequestBatchResponse",
    "SdJwtVcBatchResponse",
    "VerifiedEvidence",
    "VerifiedEvidenceRequestBatch",
}

# The only class whose stub declares a constructor; PyO3 exposes it as
# `__new__`, never `__init__` (confirmed by introspecting the compiled
# `EvidenceClient` class directly: `vars()` has no `__init__` key at all).
CONSTRUCTOR_NAME_MAP = {"__init__": "__new__"}


def _stub_tree() -> ast.Module:
    return ast.parse(_STUB_PATH.read_text(encoding="utf-8"))


def _stub_class_defs(tree: ast.Module) -> dict[str, ast.ClassDef]:
    return {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}


def _stub_member_names(class_def: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for item in class_def.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(item.name)
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            names.add(item.target.id)
    return names


def _stub_base_names(class_def: ast.ClassDef) -> set[str]:
    return {base.id for base in class_def.bases if isinstance(base, ast.Name)}


def _functional_typed_dict_keys(tree: ast.Module, name: str) -> set[str]:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            continue
        if not isinstance(node.value, ast.Call) or len(node.value.args) != 2:
            break
        members = node.value.args[1]
        if not isinstance(members, ast.Dict):
            break
        return {
            key.value
            for key in members.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
    raise AssertionError(f"{name} is not a functional TypedDict in the stub")


def _live_member_names(cls: type) -> set[str]:
    return set(vars(cls)) - {"__doc__", "__module__"}


class DriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = _stub_tree()
        self.stub_classes = _stub_class_defs(self.tree)

    def test_the_stub_declares_exactly_the_live_module_top_level_names(self):
        stub_names = set(self.stub_classes)
        live_names = {name for name in dir(revc) if not name.startswith("_")}
        self.assertEqual(stub_names, live_names)

    def test_every_plain_class_member_matches_in_both_directions(self):
        for name in PLAIN_CLASS_NAMES:
            with self.subTest(cls=name):
                stub_names = _stub_member_names(self.stub_classes[name])
                stub_names = {
                    CONSTRUCTOR_NAME_MAP.get(member, member) for member in stub_names
                }
                live_names = _live_member_names(getattr(revc, name))
                self.assertEqual(
                    stub_names,
                    live_names,
                    f"{name}: stub and compiled surface disagree",
                )

    def test_the_base_exception_declares_exactly_the_settable_attributes(self):
        stub_names = _stub_member_names(self.stub_classes["EvidenceClientError"])
        self.assertEqual(stub_names, SETTABLE_EXCEPTION_ATTRIBUTES)

    def test_holder_key_labels_are_independently_optional_in_the_stub(self):
        required = {"kty", "crv", "x", "y"}
        expected = {
            "HolderPublicKey": required,
            "HolderPublicKeyWithAlgorithm": required | {"alg"},
            "HolderPublicKeyWithKeyId": required | {"kid"},
            "HolderPublicKeyWithLabels": required | {"alg", "kid"},
        }
        self.assertEqual(
            {
                name: _functional_typed_dict_keys(self.tree, name)
                for name in expected
            },
            expected,
        )

    def test_every_exception_subclass_is_declared_and_live_under_the_base(self):
        stub_subclass_names = set(self.stub_classes) & EXCEPTION_SUBCLASS_NAMES
        self.assertEqual(stub_subclass_names, EXCEPTION_SUBCLASS_NAMES)
        for name in EXCEPTION_SUBCLASS_NAMES:
            with self.subTest(cls=name):
                # The stub declares no attributes of its own on the subclass:
                # every stable attribute lives on the shared base only.
                self.assertEqual(_stub_member_names(self.stub_classes[name]), set())
                self.assertEqual(
                    _stub_base_names(self.stub_classes[name]), {"EvidenceClientError"}
                )
                live_cls = getattr(revc, name)
                self.assertTrue(issubclass(live_cls, revc.EvidenceClientError))

    def test_the_package_ships_a_pep_561_marker_beside_the_stub(self):
        # A PEP 561 checker ignores `__init__.pyi` in an installed package that
        # carries no `py.typed`, which reports every client API as `Any` and
        # makes the stub above, and this whole test, invisible to consumers.
        marker = _PACKAGE_DIR / "py.typed"
        self.assertTrue(
            marker.is_file(),
            f"{marker} must exist so the committed stub is honored once installed",
        )

    def test_the_base_exception_is_declared_and_live_as_an_exception(self):
        self.assertEqual(
            _stub_base_names(self.stub_classes["EvidenceClientError"]), {"Exception"}
        )
        self.assertTrue(issubclass(revc.EvidenceClientError, Exception))


if __name__ == "__main__":
    unittest.main()
