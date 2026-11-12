"""The staff workload facade preserves the accepted L4 Casework surface."""

from __future__ import annotations

import ast
import asyncio
import copy
import importlib
import inspect
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[3]
FACADE_SOURCE = ROOT / "crates/registry-stack-client-py/python/registry_client"
NATIVE_STUB = (
    ROOT
    / "crates/registry-casework-client-py/python/registry_casework_client/__init__.pyi"
)
FACADE_RUNTIME = FACADE_SOURCE / "workload_casework.py"
FACADE_STUB = FACADE_SOURCE / "workload_casework.pyi"
L4_METHODS = {
    "description",
    "review_policies",
    "review_policy",
    "review_tasks",
    "review_task",
    "review_task_context",
    "claim_review_task",
    "release_review_task",
    "decide_review_task",
    "own_review_decisions",
    "review_history",
}


def _load_facade():
    package_name = "_registry_client_casework_workload_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(FACADE_SOURCE)]
    sys.modules[package_name] = package
    return importlib.import_module(f"{package_name}.workload_casework")


workload_casework = _load_facade()
CaseworkWorkload = workload_casework.CaseworkWorkload
UnsupportedOperationError = importlib.import_module(
    f"{CaseworkWorkload.__module__.rsplit('.', 1)[0]}.connection"
).UnsupportedOperationError


def _class(path: Path, name: str) -> ast.ClassDef:
    module = ast.parse(path.read_text(encoding="utf-8"))
    return next(
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == name
    )


def _methods(node: ast.ClassDef) -> dict[str, ast.FunctionDef]:
    return {
        member.name: member
        for member in node.body
        if isinstance(member, ast.FunctionDef)
        and member.name not in {"__init__", "__getattr__", "__setattr__"}
    }


class _UnqualifyCasework(ast.NodeTransformer):
    def visit_Attribute(self, node: ast.Attribute):
        node = self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id == "casework":
            return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
        return node


def _signature(node: ast.FunctionDef, *, remove_auth: bool = False) -> tuple[str, str]:
    arguments = copy.deepcopy(node.args)
    if remove_auth:
        self_arg, token_arg, profile_arg, *remaining = arguments.args
        if (
            self_arg.arg != "self"
            or token_arg.arg != "token"
            or profile_arg.arg != "profile"
        ):
            raise AssertionError(
                f"unexpected native authentication prefix on {node.name}"
            )
        arguments.args = [self_arg, *remaining]
    arguments = _UnqualifyCasework().visit(arguments)
    returns = (
        _UnqualifyCasework().visit(copy.deepcopy(node.returns))
        if node.returns is not None
        else None
    )
    return (
        ast.dump(arguments, include_attributes=False),
        ast.dump(returns, include_attributes=False),
    )


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.results: dict[str, object] = {}
        self.failures: dict[str, BaseException] = {}

    def __getattr__(self, name: str):
        def call(*args: object, **kwargs: object):
            self.calls.append((name, args, kwargs))
            if name in self.failures:
                raise self.failures[name]
            return self.results.setdefault(name, object())

        return call


class TokenProviderCanary:
    def __init__(self) -> None:
        self.calls = 0

    def bearer_token(self) -> str:
        self.calls += 1
        return "late-token"


class CaseworkWorkloadTests(unittest.TestCase):
    def test_runtime_and_stub_declare_exactly_the_l4_method_set(self) -> None:
        native = _methods(_class(NATIVE_STUB, "CaseworkClient"))
        runtime = _methods(_class(FACADE_RUNTIME, "CaseworkWorkload"))
        facade = _methods(_class(FACADE_STUB, "CaseworkWorkload"))

        self.assertTrue(L4_METHODS <= set(native))
        self.assertEqual(len(L4_METHODS), 11)
        self.assertEqual(set(runtime), L4_METHODS)
        self.assertEqual(set(facade), L4_METHODS)

    def test_runtime_and_stub_preserve_native_signatures_without_auth(self) -> None:
        native = _methods(_class(NATIVE_STUB, "CaseworkClient"))
        runtime = _methods(_class(FACADE_RUNTIME, "CaseworkWorkload"))
        facade = _methods(_class(FACADE_STUB, "CaseworkWorkload"))

        for name in L4_METHODS:
            with self.subTest(method=name):
                expected = _signature(native[name], remove_auth=True)
                self.assertEqual(_signature(runtime[name]), expected)
                self.assertEqual(_signature(facade[name]), expected)

    def test_every_method_supplies_bound_auth_and_forwards_remaining_arguments(
        self,
    ) -> None:
        native = RecordingClient()
        token = "secret-token-canary"
        profile = "reviewer-profile"
        client = CaseworkWorkload(native, token, profile)

        for name in sorted(L4_METHODS):
            with self.subTest(method=name):
                signature = inspect.signature(getattr(CaseworkWorkload, name))
                positional: list[object] = []
                keywords: dict[str, object] = {}
                for parameter in signature.parameters.values():
                    if parameter.name == "self":
                        continue
                    value = object()
                    if parameter.kind in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    ):
                        positional.append(value)
                    elif parameter.kind == inspect.Parameter.KEYWORD_ONLY:
                        keywords[parameter.name] = value
                    else:
                        self.fail(f"unexpected variadic parameter on {name}")
                expected = native.results.setdefault(name, object())
                actual = getattr(client, name)(*positional, **keywords)
                self.assertIs(actual, expected)
                self.assertEqual(
                    native.calls[-1],
                    (name, (token, profile, *positional), keywords),
                )

    def test_native_errors_pass_through_unchanged(self) -> None:
        native = RecordingClient()
        failure = RuntimeError("native refusal")
        native.failures["description"] = failure

        with self.assertRaises(RuntimeError) as raised:
            CaseworkWorkload(native, "token", "profile").description()

        self.assertIs(raised.exception, failure)

    def test_unknown_operation_uses_the_closed_public_error(self) -> None:
        native = RecordingClient()
        client = CaseworkWorkload(native, "secret-token-canary", "profile")

        with self.assertRaises(UnsupportedOperationError) as raised:
            getattr(client, "create_or_recover_review_request")

        self.assertEqual(raised.exception.code, "client.operation-not-supported")
        self.assertEqual(raised.exception.product, "casework")
        self.assertEqual(raised.exception.operation, "create_or_recover_review_request")
        self.assertEqual(native.calls, [])

    def test_auth_is_a_secret_safe_immutable_snapshot_not_a_callback(self) -> None:
        provider = TokenProviderCanary()
        with self.assertRaisesRegex(TypeError, "token must be a string"):
            CaseworkWorkload(RecordingClient(), provider, "profile")
        self.assertEqual(provider.calls, 0)

        with self.assertRaisesRegex(TypeError, "profile must be a string"):
            CaseworkWorkload(RecordingClient(), "token", object())

        native = RecordingClient()
        client = CaseworkWorkload(native, "secret-token-canary", "profile")
        self.assertNotIn("secret-token-canary", repr(client))
        with self.assertRaisesRegex(AttributeError, "immutable"):
            client._token = "replacement"
        with self.assertRaisesRegex(AttributeError, "immutable"):
            client._profile = "replacement"

        client.description()
        self.assertEqual(
            native.calls[-1],
            ("description", ("secret-token-canary", "profile"), {}),
        )

    def test_direct_event_loop_call_is_refused_before_the_native_client(self) -> None:
        native = RecordingClient()
        client = CaseworkWorkload(native, "token", "profile")

        async def invoke() -> None:
            with self.assertRaisesRegex(RuntimeError, "event-loop thread"):
                client.description()

        asyncio.run(invoke())
        self.assertEqual(native.calls, [])


if __name__ == "__main__":
    unittest.main()
