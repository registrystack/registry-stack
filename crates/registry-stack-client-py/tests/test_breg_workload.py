"""The workload facade preserves the complete native BReg client surface."""

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
    ROOT / "crates/registry-breg-client-py/python/registry_breg_client/__init__.pyi"
)
FACADE_RUNTIME = FACADE_SOURCE / "workload_breg.py"
FACADE_STUB = FACADE_SOURCE / "workload_breg.pyi"


def _load_facade():
    package_name = "_registry_client_breg_workload_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(FACADE_SOURCE)]
    sys.modules[package_name] = package
    return importlib.import_module(f"{package_name}.workload_breg")


workload_breg = _load_facade()
BRegWorkload = workload_breg.BRegWorkload
UnsupportedOperationError = importlib.import_module(
    f"{BRegWorkload.__module__.rsplit('.', 1)[0]}.connection"
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
        and member.name not in {"__init__", "__getattr__"}
    }


class _UnqualifyBReg(ast.NodeTransformer):
    def visit_Attribute(self, node: ast.Attribute):
        node = self.generic_visit(node)
        if isinstance(node.value, ast.Name) and node.value.id == "breg":
            return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
        return node


def _signature(node: ast.FunctionDef) -> tuple[str, str]:
    arguments = _UnqualifyBReg().visit(copy.deepcopy(node.args))
    returns = (
        _UnqualifyBReg().visit(copy.deepcopy(node.returns))
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


class BRegWorkloadTests(unittest.TestCase):
    def test_runtime_and_stub_declare_exactly_the_native_method_set(self) -> None:
        native = _methods(_class(NATIVE_STUB, "BaseRegistryClient"))
        runtime = _methods(_class(FACADE_RUNTIME, "BRegWorkload"))
        facade = _methods(_class(FACADE_STUB, "BRegWorkload"))

        self.assertEqual(len(native), 68)
        self.assertEqual(set(runtime), set(native))
        self.assertEqual(set(facade), set(native))

    def test_runtime_and_stub_preserve_every_native_signature(self) -> None:
        native = _methods(_class(NATIVE_STUB, "BaseRegistryClient"))
        runtime = _methods(_class(FACADE_RUNTIME, "BRegWorkload"))
        facade = _methods(_class(FACADE_STUB, "BRegWorkload"))

        for name, native_method in native.items():
            with self.subTest(method=name):
                expected = _signature(native_method)
                self.assertEqual(_signature(runtime[name]), expected)
                self.assertEqual(_signature(facade[name]), expected)

    def test_every_method_forwards_all_arguments_and_result_identity(self) -> None:
        native = RecordingClient()
        client = BRegWorkload(native)
        method_names = sorted(_methods(_class(NATIVE_STUB, "BaseRegistryClient")))

        for name in method_names:
            with self.subTest(method=name):
                signature = inspect.signature(getattr(BRegWorkload, name))
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
                self.assertEqual(native.calls[-1], (name, tuple(positional), keywords))

    def test_native_errors_pass_through_unchanged(self) -> None:
        native = RecordingClient()
        failure = RuntimeError("native refusal")
        native.failures["health"] = failure

        with self.assertRaises(RuntimeError) as raised:
            BRegWorkload(native).health()

        self.assertIs(raised.exception, failure)

    def test_unknown_operation_uses_the_closed_public_error(self) -> None:
        native = RecordingClient()
        client = BRegWorkload(native)

        with self.assertRaises(UnsupportedOperationError) as raised:
            getattr(client, "bearer_token")

        self.assertEqual(raised.exception.code, "client.operation-not-supported")
        self.assertEqual(raised.exception.product, "breg")
        self.assertEqual(raised.exception.operation, "bearer_token")
        self.assertEqual(native.calls, [])

    def test_direct_event_loop_call_is_refused_before_the_native_client(self) -> None:
        native = RecordingClient()
        client = BRegWorkload(native)

        async def invoke() -> None:
            with self.assertRaisesRegex(RuntimeError, "event-loop thread"):
                client.health()

        asyncio.run(invoke())
        self.assertEqual(native.calls, [])


if __name__ == "__main__":
    unittest.main()
