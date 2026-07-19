#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate Registry Relay security assurance contracts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURITY_DIR = ROOT / "security"

REQUIRED_ENTRY_FIELDS = {
    "service",
    "listener",
    "method",
    "path",
    "feature",
    "audience",
    "auth",
    "scopes",
    "rate_limit",
    "audit",
    "openapi",
    "stability",
    "data_classification",
    "notes",
    "source",
    "enforcement_tests",
    "waiver",
}

LISTENERS = {"public", "admin", "internal", "metrics", "demo", "sidecar"}
AUDIENCES = {"external", "operator", "platform", "internal", "demo", "health"}
AUTHS = {"none", "api_key", "oidc", "api_key_or_oidc", "bearer", "internal", "mTLS"}
AUDIT = {"required", "optional", "not_applicable", "suppressed"}
STABILITY = {"stable", "beta", "experimental", "deprecated", "admin", "demo"}
DATA = {"none", "operational", "metadata", "personal", "credential", "audit", "secret-adjacent"}
SOURCES = {"manual", "generated", "mixed"}

SECRET_COPY_RE = re.compile(
    r"\b(?:COPY|ADD)\b(?=.*(?:\.env|\.pem|\.key|\.p12|jwk|secret|credential))|\"d\"\s*:",
    re.IGNORECASE,
)
CONST_STR_RE = re.compile(r'const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]+)"\s*;')
OPENAPI_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

# Keep this empty unless a static OpenAPI operation is intentionally broader
# than the security exposure manifest. Each entry must explain why the drift is
# acceptable and is reviewed as a narrow exception.
STATIC_OPENAPI_OPERATION_ALLOWLIST: dict[tuple[str, str], str] = {}

# These protected record-read routes are part of Relay's stable core data plane.
# Standards feature-roster changes must not reclassify them with optional adapters.
CORE_STABLE_ROUTE_KEYS = {
    (
        "public",
        "GET",
        "/v1/datasets/{dataset_id}/entities/{entity}/records",
    ),
    (
        "public",
        "GET",
        "/v1/datasets/{dataset_id}/entities/{entity}/records/{id}",
    ),
    (
        "public",
        "GET",
        "/v1/datasets/{dataset_id}/entities/{entity}/records/{id}/relationships/{relationship}",
    ),
}


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {exc}")


def fail(message: str) -> None:
    print(f"security assurance check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def key(entry: dict) -> tuple[str, str, str]:
    return (entry["listener"], entry["method"], entry["path"])


def load_allowlist(path: Path) -> set[tuple[str, str, str]]:
    entries: set[tuple[str, str, str]] = set()
    current: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line == "allowed:":
            continue
        if line.startswith("- "):
            if current:
                add_allowlist_entry(entries, current)
            current = {}
            line = line[2:].strip()
        if ":" in line:
            name, value = line.split(":", 1)
            current[name.strip()] = value.strip().strip('"')
    if current:
        add_allowlist_entry(entries, current)
    return entries


def add_allowlist_entry(
    entries: set[tuple[str, str, str]], current: dict[str, str]
) -> None:
    missing = {"listener", "method", "path"} - current.keys()
    if missing:
        fail(f"auth-none-allowlist.yml entry missing required fields: {sorted(missing)}")
    entries.add((current["listener"], current["method"], current["path"]))


def validate_manifest() -> None:
    manifest = load_json(SECURITY_DIR / "exposure-manifest.json")
    inventory = load_json(SECURITY_DIR / "route-inventory.json")
    allowlist = load_allowlist(SECURITY_DIR / "auth-none-allowlist.yml")

    if not isinstance(manifest, dict) or manifest.get("service") != "registry-relay":
        fail("exposure-manifest.json must describe service registry-relay")
    entries = manifest.get("endpoints")
    if not isinstance(entries, list) or not entries:
        fail("exposure-manifest.json must contain non-empty endpoints list")

    seen: set[tuple[str, str, str]] = set()
    by_key: dict[tuple[str, str, str], dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            fail("endpoint entries must be objects")
        missing = REQUIRED_ENTRY_FIELDS - set(entry)
        if missing:
            fail(f"{entry.get('path', '<unknown>')} missing fields: {sorted(missing)}")
        if entry["service"] != "registry-relay":
            fail(f"{entry['path']} has wrong service {entry['service']}")
        check_value(entry, "listener", LISTENERS)
        check_value(entry, "audience", AUDIENCES)
        check_value(entry, "auth", AUTHS)
        check_value(entry, "audit", AUDIT)
        check_value(entry, "stability", STABILITY)
        check_value(entry, "data_classification", DATA)
        check_value(entry, "source", SOURCES)
        validate_stability(entry)
        if entry["method"] not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            fail(f"{entry['path']} has invalid method {entry['method']}")
        if not isinstance(entry["scopes"], list):
            fail(f"{entry['path']} scopes must be a list")
        if not isinstance(entry["enforcement_tests"], list):
            fail(f"{entry['path']} enforcement_tests must be a list")
        k = key(entry)
        if k in seen:
            fail(f"duplicate endpoint entry {k}")
        seen.add(k)
        by_key[k] = entry

        if entry["auth"] == "none" and entry["audience"] != "health" and k not in allowlist:
            fail(f"{k} is auth:none but missing from auth-none allowlist")
        needs_tests = (
            entry["auth"] != "none"
            or bool(entry["scopes"])
            or entry["audit"] == "required"
            or entry["listener"] == "admin"
            or entry["rate_limit"] is not None
        )
        if needs_tests and not (entry["enforcement_tests"] or entry["waiver"]):
            fail(f"{k} claims security enforcement but has no tests or waiver")
        for test_ref in entry["enforcement_tests"]:
            ensure_test_ref_exists(str(test_ref))

    auth_none_keys = {k for k, entry in by_key.items() if entry["auth"] == "none"}
    stale_allowlist = sorted(allowlist - auth_none_keys)
    if stale_allowlist:
        fail(f"auth-none allowlist contains entries that are not auth:none endpoints: {stale_allowlist}")

    if not isinstance(inventory, dict) or not isinstance(inventory.get("routes"), list):
        fail("route-inventory.json must contain a routes list")
    inventory_keys: set[tuple[str, str, str]] = set()
    for route in inventory["routes"]:
        listener = route["listener"]
        path = route["path"]
        for method in route["methods"]:
            k = (listener, method, path)
            inventory_keys.add(k)
            if k not in by_key:
                fail(f"route inventory entry {k} is missing from exposure manifest")
    stale = sorted(set(by_key) - inventory_keys)
    if stale:
        fail(f"exposure-manifest.json contains endpoints missing from route-inventory.json: {stale}")
    validate_route_sources(inventory)


def validate_stability(entry: dict) -> None:
    if entry["feature"] is not None and entry["stability"] != "experimental":
        fail(
            f"{entry['path']} is feature-gated but has stability "
            f"{entry['stability']}; the 1.0 optional surfaces are experimental"
        )
    if key(entry) in CORE_STABLE_ROUTE_KEYS and entry["stability"] != "stable":
        fail(
            f"{entry['path']} is a core protected record-read route and must remain stable"
        )


def check_value(entry: dict, field: str, allowed: set[str]) -> None:
    if entry[field] not in allowed:
        fail(f"{entry['path']} has invalid {field}: {entry[field]}")


def ensure_test_ref_exists(ref: str) -> None:
    file_part, _, symbol = ref.partition("::")
    if not symbol:
        fail(f"enforcement test reference must include ::test_name: {ref}")
    path = ROOT / file_part
    if not path.exists():
        fail(f"referenced enforcement test file does not exist: {file_part}")
    text = path.read_text(encoding="utf-8")
    if not re.search(rf"\b(?:async\s+)?fn\s+{re.escape(symbol)}\s*\(", text):
        fail(f"referenced enforcement test symbol {symbol} not found in {file_part}")


def validate_route_sources(inventory: object | None = None) -> None:
    if inventory is None:
        inventory = load_json(SECURITY_DIR / "route-inventory.json")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("routes"), list):
        fail("route-inventory.json must contain a routes list")

    inventory_by_source: dict[str, set[tuple[str, str]]] = {}
    source_files = sorted(
        str(path.relative_to(ROOT))
        for path in (ROOT / "src").rglob("*.rs")
        if path.is_file()
    )
    for route in inventory["routes"]:
        source = route.get("source")
        if isinstance(source, str):
            inventory_by_source.setdefault(source, set())
            for method in route["methods"]:
                inventory_by_source[source].add((route["path"], method))
    for source in inventory_by_source:
        if source not in source_files and (ROOT / source).exists():
            source_files.append(source)

    extracted_by_source: dict[str, set[tuple[str, str]]] = {}
    for source in sorted(set(source_files)):
        path = ROOT / source
        if not path.exists():
            fail(f"route inventory references missing source file: {source}")
        routes = extract_axum_routes(path.read_text(encoding="utf-8"))
        if routes:
            extracted_by_source[source] = routes

    for source, routes in extracted_by_source.items():
        missing = sorted(routes - inventory_by_source.get(source, set()))
        if missing:
            fail(f"{source} declares routes missing from route-inventory.json: {missing}")
    for source, routes in inventory_by_source.items():
        missing = sorted(routes - extracted_by_source.get(source, set()))
        if missing:
            fail(f"route-inventory.json lists routes not found in {source}: {missing}")


def extract_axum_routes(text: str) -> set[tuple[str, str]]:
    text = strip_rust_comments(strip_rust_test_module(text))
    consts = dict(CONST_STR_RE.findall(text))
    routes: set[tuple[str, str]] = set()
    cursor = 0
    while True:
        start = text.find(".route(", cursor)
        if start == -1:
            break
        open_paren = start + len(".route(") - 1
        close_paren = matching_paren(text, open_paren)
        if close_paren is None:
            break
        inner = text[open_paren + 1 : close_paren]
        first, second = split_first_top_level_arg(inner)
        route_path = resolve_route_path(first, consts)
        if route_path is not None:
            for method in infer_methods(second):
                routes.add((route_path, method))
        cursor = close_paren + 1
    return routes


def strip_rust_test_module(text: str) -> str:
    return re.split(
        r"\n\s*#\[cfg\(test\)\]\s*mod\s+[A-Za-z0-9_]+\s*\{",
        text,
        maxsplit=1,
    )[0]


def strip_rust_comments(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//")
    )


def matching_paren(text: str, open_paren: int) -> int | None:
    depth = 0
    in_string = False
    escaped = False
    for index in range(open_paren, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def split_first_top_level_arg(args: str) -> tuple[str, str]:
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(args):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            return args[:index].strip(), args[index + 1 :].strip()
    return args.strip(), ""


def resolve_route_path(expr: str, consts: dict[str, str]) -> str | None:
    expr = expr.strip()
    if expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]
    if expr in consts:
        return consts[expr]
    match = re.fullmatch(r'&format!\("([^"]+)"\)', expr, flags=re.S)
    if match:
        template = match.group(1)
        for name, value in consts.items():
            template = template.replace(f"{{{name}}}", value)
        return template.replace("{{", "{").replace("}}", "}")
    return None


def infer_methods(handler_expr: str) -> set[str]:
    methods: set[str] = set()
    if re.search(r"(?<![A-Za-z0-9_])get\s*\(", handler_expr):
        methods.add("GET")
    if re.search(r"(?<![A-Za-z0-9_])post\s*\(|\.post\s*\(", handler_expr):
        methods.add("POST")
    if re.search(r"(?<![A-Za-z0-9_])put\s*\(|\.put\s*\(", handler_expr):
        methods.add("PUT")
    if re.search(r"(?<![A-Za-z0-9_])patch\s*\(|\.patch\s*\(", handler_expr):
        methods.add("PATCH")
    if re.search(r"(?<![A-Za-z0-9_])delete\s*\(|\.delete\s*\(", handler_expr):
        methods.add("DELETE")
    if re.search(r"(?<![A-Za-z0-9_])head\s*\(|\.head\s*\(", handler_expr):
        methods.add("HEAD")
    return methods


def check_dockerfile_secret_patterns() -> None:
    for path in [ROOT / "Dockerfile", ROOT / "Dockerfile.demo"]:
        if not path.is_file():
            fail(f"missing required Dockerfile: {path.relative_to(ROOT)}")
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if SECRET_COPY_RE.search(line):
                fail(f"{path.name}:{lineno} may copy secret or private JWK material")


def check_openapi_strategy() -> None:
    policy = ROOT / "docs" / "security-assurance.md"
    text = policy.read_text(encoding="utf-8")
    required = [
        "OpenAPI comparison strategy",
        "baseline-vs-baseline",
        "generated-vs-curated",
    ]
    for needle in required:
        if needle not in text:
            fail(f"docs/security-assurance.md must document Relay {needle}")
    check_openapi_manifest_coverage(ROOT / "openapi" / "registry-relay.openapi.json")


def check_openapi_manifest_coverage(path: Path) -> None:
    manifest = load_json(SECURITY_DIR / "exposure-manifest.json")
    document = load_json(path)
    if not isinstance(manifest, dict) or not isinstance(document, dict):
        fail("OpenAPI coverage inputs must be JSON objects")
    endpoints = manifest.get("endpoints")
    if not isinstance(endpoints, list):
        fail("exposure-manifest.json must contain endpoints list")
    paths = document.get("paths")
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        fail("OpenAPI paths must be an object")
    openapi_ops = extract_static_openapi_operations(paths)
    openapi_op_keys = {op.key for op in openapi_ops}
    manifest_ops: dict[tuple[str, str], list[dict]] = {}
    manifest_openapi_ops: set[tuple[str, str]] = set()
    for entry in endpoints:
        if not isinstance(entry, dict):
            fail("endpoint entries must be objects")
        op_key = (openapi_path_shape(str(entry.get("path"))), str(entry.get("method")))
        manifest_ops.setdefault(op_key, []).append(entry)
        if entry.get("openapi") is True and is_default_openapi_entry(entry):
            manifest_openapi_ops.add(op_key)

    missing = sorted(
        (entry["method"], entry["path"])
        for entry in endpoints
        if entry.get("openapi")
        and is_default_openapi_entry(entry)
        and (openapi_path_shape(entry["path"]), entry["method"]) not in openapi_op_keys
    )
    if missing:
        fail(f"manifest endpoints marked openapi:true are missing from OpenAPI: {missing}")

    extras: list[tuple[str, str]] = []
    false_contradictions: list[tuple[str, str, list[tuple[str, str, str]]]] = []
    for op in openapi_ops:
        if op.key in manifest_openapi_ops or static_openapi_operation_is_allowlisted(op.key):
            continue
        entries = manifest_ops.get(op.key, [])
        if entries:
            false_contradictions.append(
                (
                    op.method,
                    op.path,
                    sorted(
                        (
                            str(entry.get("listener")),
                            str(entry.get("method")),
                            str(entry.get("path")),
                        )
                        for entry in entries
                        if entry.get("openapi") is not True
                    ),
                )
            )
        else:
            extras.append((op.method, op.path))
    if extras:
        fail(f"OpenAPI operations missing from exposure manifest openapi:true coverage: {sorted(extras)}")
    if false_contradictions:
        fail(
            "OpenAPI operations map to manifest endpoints not marked openapi:true: "
            f"{sorted(false_contradictions)}"
        )


def is_default_openapi_entry(entry: dict) -> bool:
    return entry.get("feature") is None


def openapi_path_shape(path: str) -> str:
    return re.sub(r"\{\*?[^}]+\}", "{}", path)


class StaticOpenapiOperation:
    def __init__(self, method: str, path: str) -> None:
        self.method = method
        self.path = path
        self.key = (openapi_path_shape(path), method)


def extract_static_openapi_operations(paths: dict) -> list[StaticOpenapiOperation]:
    operations: list[StaticOpenapiOperation] = []
    for openapi_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            normalized_method = method.upper()
            if normalized_method in OPENAPI_HTTP_METHODS:
                operations.append(StaticOpenapiOperation(normalized_method, str(openapi_path)))
    return operations


def static_openapi_operation_is_allowlisted(op_key: tuple[str, str]) -> bool:
    comment = STATIC_OPENAPI_OPERATION_ALLOWLIST.get(op_key)
    if comment is None:
        return False
    if not comment.strip():
        fail(f"static OpenAPI allowlist entry {op_key} must include a comment")
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "checks",
        nargs="*",
        choices=[
            "manifest",
            "route-sources",
            "dockerfile-secrets",
            "openapi-strategy",
            "openapi-coverage",
        ],
        default=None,
    )
    args = parser.parse_args()
    checks = args.checks or ["manifest", "dockerfile-secrets", "openapi-strategy"]
    if "manifest" in checks:
        validate_manifest()
    if "route-sources" in checks:
        validate_route_sources()
    if "dockerfile-secrets" in checks:
        check_dockerfile_secret_patterns()
    if "openapi-strategy" in checks:
        check_openapi_strategy()
    if "openapi-coverage" in checks:
        check_openapi_manifest_coverage(ROOT / "openapi" / "registry-relay.openapi.json")


if __name__ == "__main__":
    main()
