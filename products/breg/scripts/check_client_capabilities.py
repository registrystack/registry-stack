#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Account for the server surface and the three maintained SDK exports.

This inventory check complements HTTP/runtime tests. It does not establish
behavior from a declaration: the binding tests also load the actual modules.
"""

import json
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INVENTORY = ROOT / "products/breg/contracts/client-capabilities.json"


def enum_variants(source: str, name: str) -> set[str]:
    match = re.search(rf"pub enum {re.escape(name)}\s*\{{(.*?)\n\}}", source, re.S)
    if match is None:
        raise ValueError(f"server enum {name} was not found")
    return set(re.findall(r"^\s+([A-Z]\w*)\s*,", match.group(1), re.M))


def require_accounted(actual: set[str], declared: set[str], label: str) -> list[str]:
    return [f"unaccounted {label}: {name}" for name in sorted(actual - declared)]


def accepted_read_options(source: str) -> set[str]:
    start = source.index("impl QueryBuilder {")
    end = source.index("    fn finish(", start)
    arms = re.findall(r'^            "([^"\n]+)" => \{(.*?)^            \}', source[start:end], re.M | re.S)
    return {name for name, body in arms if "return Err(" not in body}


def braced_body(source: str, marker: str) -> str | None:
    match = re.search(marker, source)
    if match is None:
        return None
    opening = match.end() - 1 if source[match.end() - 1:match.end()] == "{" else source.find("{", match.end())
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    return None


def braced_bodies(source: str, marker: str) -> list[str]:
    bodies = []
    offset = 0
    while match := re.search(marker, source[offset:]):
        start = offset + match.start()
        end = offset + match.end()
        body = braced_body(source[start:], marker)
        if body is None:
            break
        bodies.append(body)
        offset = end
    return bodies


def rust_declaration(source: str, target: str) -> bool:
    parts = target.split(".")
    if len(parts) not in (2, 3):
        return False
    type_name, member = parts[:2]
    bodies = []
    bodies.extend(braced_bodies(source, rf"\bimpl\s+{re.escape(type_name)}\s*\{{"))
    for macro in re.findall(rf"\b(\w+)\s*!\s*\(\s*{re.escape(type_name)}\s*\)\s*;", source):
        body = braced_body(source, rf"macro_rules!\s+{re.escape(macro)}\s*\{{")
        if body is not None:
            bodies.append(body)
    structure = braced_body(source, rf"\bpub\s+struct\s+{re.escape(type_name)}\b")
    if len(parts) == 2:
        field = structure is not None and re.search(rf"^\s*pub\s+{re.escape(member)}\s*:", structure, re.M)
        method = any(re.search(rf"\bpub\s+(?:const\s+)?(?:async\s+)?fn\s+{re.escape(member)}\b", body) for body in bodies)
        return bool(field or method)
    parameter = parts[2]
    for body in bodies:
        signature = re.search(
            rf"\bpub\s+(?:const\s+)?(?:async\s+)?fn\s+{re.escape(member)}\s*(?:<[^>]+>)?\s*\((.*?)\)\s*(?:->.*?)?\{{",
            body,
            re.S,
        )
        if signature is not None and re.search(rf"\b{re.escape(parameter)}\s*:", signature.group(1)):
            return True
    return False


def node_type_body(source: str, type_name: str) -> str | None:
    return braced_body(
        source,
        rf"\bexport\s+(?:declare\s+)?(?:interface|class)\s+{re.escape(type_name)}\b[^\{{]*",
    )


def node_declaration(source: str, target: str) -> bool:
    parts = target.split(".")
    if len(parts) not in (2, 3):
        return False
    type_name, member = parts[:2]
    body = node_type_body(source, type_name)
    if body is None:
        return False
    if len(parts) == 2:
        return re.search(rf"^\s*(?:readonly\s+)?{re.escape(member)}(?:\?|\s)*[:(]", body, re.M) is not None
    signature = re.search(rf"^\s*{re.escape(member)}\s*\((.*?)\)\s*:", body, re.M | re.S)
    return signature is not None and re.search(rf"\b{re.escape(parts[2])}\??\s*:", signature.group(1)) is not None


def python_declarations(source: str) -> dict[tuple[str, str], set[str]]:
    declarations = {}
    for node in ast.parse(source).body:
        if not isinstance(node, ast.ClassDef):
            continue
        for member in node.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = member.args.posonlyargs + member.args.args + member.args.kwonlyargs
                declarations[(node.name, member.name)] = {argument.arg for argument in arguments}
    return declarations


def check_query_option_bindings(
    inventory: dict, rust_source: str, node_types: str, python_types: str
) -> list[str]:
    bindings = inventory.get("queryOptionBindings", {})
    options = set(inventory["queryOptions"])
    errors = require_accounted(options, set(bindings), "client query-option binding")
    errors += [f"unknown client query-option binding: {name}" for name in sorted(set(bindings) - options)]
    python = python_declarations(python_types)
    checkers = {
        "rust": lambda target: rust_declaration(rust_source, target),
        "node": lambda target: node_declaration(node_types, target),
        "python": lambda target: len(target.split(".")) == 3
        and target.split(".")[2] in python.get(tuple(target.split(".")[:2]), set()),
    }
    for option in sorted(options & set(bindings)):
        binding = bindings[option]
        for language, checker in checkers.items():
            targets = binding.get(language, [])
            if not targets:
                errors.append(f"{option}: no {language} query-option binding")
            for target in targets:
                if not checker(target):
                    errors.append(f"{option}: missing {language} query-option declaration {target}")
            for target in binding.get("forbidden", {}).get(language, []):
                if checker(target):
                    errors.append(f"{option}: forbidden {language} query-option declaration {target}")
    return errors


def check(root: Path = ROOT) -> list[str]:
    inventory = json.loads((root / INVENTORY.relative_to(ROOT)).read_text())
    errors = []
    server = root / "crates/registry-breg/src"
    errors += require_accounted(
        enum_variants((server / "contract.rs").read_text(), "Operation"),
        set(inventory["operations"]), "server operation",
    )
    errors += require_accounted(
        enum_variants((server / "model.rs").read_text(), "CompiledQueryKind"),
        set(inventory["queryKinds"]), "server query kind",
    )
    parsed_options = accepted_read_options((server / "query.rs").read_text())
    if not parsed_options:
        errors.append("no accepted server read-query options found")
    errors += require_accounted(parsed_options, set(inventory["queryOptions"]), "server read-query option")

    # These are compiler outputs, reproduced by the existing generated gate.
    # Inspect every committed fixture so a new query or representation cannot
    # be declared supported solely by adding a synthetic client response.
    openapis = sorted((root / "products/breg/generated").glob("*/generated/openapi.json"))
    if not openapis:
        errors.append("no compiled OpenAPI fixtures found")
    for path in openapis:
        document = json.loads(path.read_text())
        for route, methods in document["paths"].items():
            if any(route.startswith(item["prefix"]) for item in inventory["excludedRoutes"]):
                continue
            for operation in methods.values():
                if not isinstance(operation, dict):
                    continue
                parameters = {
                    item["name"] for item in operation.get("parameters", [])
                    if item.get("in") == "query"
                }
                errors += require_accounted(parameters, set(inventory["queryOptions"]), f"query option on {route}")
                media = {
                    media_type for response in operation.get("responses", {}).values()
                    for media_type in response.get("content", {})
                }
                errors += require_accounted(media, set(inventory["representations"]), f"response representation on {route}")

    rust_source = "\n".join(path.read_text() for path in (root / "crates/registry-breg-client/src").glob("*.rs"))
    rust_methods = set(re.findall(r"pub\s+(?:async\s+)?fn\s+(\w+)\s*[<(]", rust_source))
    node_types = (root / "crates/registry-breg-client-node/client.d.ts").read_text()
    node_methods = set(re.findall(r"^\s+(\w+)\s*(?:<[^>]+>)?\(", node_types, re.M))
    python_types = (root / "crates/registry-breg-client-py/python/registry_breg_client/__init__.pyi").read_text()
    errors += check_query_option_bindings(inventory, rust_source, node_types, python_types)
    python_methods = set(re.findall(r"\bdef\s+(\w+)\s*\(", python_types))
    available = {"rust": rust_methods, "node": node_methods, "python": python_methods}
    ids = [row["id"] for row in inventory["capabilities"]]
    if len(ids) != len(set(ids)):
        errors.append("duplicate capability identifiers")
    for row in inventory["capabilities"]:
        for language, methods in available.items():
            declared = set(row[language])
            if not declared:
                errors.append(f"{row['id']} has no {language} entry point")
            for name in sorted(declared - methods):
                errors.append(f"{row['id']}: missing {language} method {name}")
    return errors


if __name__ == "__main__":
    failures = check()
    if failures:
        raise SystemExit("\n".join(failures))
    print("BREG server and client capability inventory passed")
