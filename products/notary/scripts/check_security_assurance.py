#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate Registry Notary security assurance contracts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
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
AUTHS = {"none", "api_key", "oidc", "api_key_or_oidc", "bearer", "jws", "internal", "mTLS"}
AUDIT = {"required", "optional", "not_applicable", "suppressed"}
STABILITY = {"stable", "beta", "experimental", "admin", "demo"}
DATA = {"none", "operational", "metadata", "personal", "credential", "audit", "secret-adjacent"}
SOURCES = {"manual", "generated", "mixed"}

SECRET_COPY_RE = re.compile(
    r"\b(?:COPY|ADD)\b(?=.*(?:\.env|\.pem|\.key|\.p12|jwk|secret|credential))|\"d\"\s*:",
    re.IGNORECASE,
)
CONST_STR_RE = re.compile(r'const\s+([A-Z][A-Z0-9_]*)\s*:\s*&str\s*=\s*"([^"]+)"\s*;')
IMMUTABLE_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    print(f"security assurance check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"missing required file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {exc}")


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


def key(entry: dict) -> tuple[str, str, str]:
    return (entry["listener"], entry["method"], entry["path"])


def validate_manifest() -> None:
    manifest = load_json(SECURITY_DIR / "exposure-manifest.json")
    inventory = load_json(SECURITY_DIR / "route-inventory.json")
    allowlist = load_allowlist(SECURITY_DIR / "auth-none-allowlist.yml")

    if not isinstance(manifest, dict) or manifest.get("service") != "registry-notary":
        fail("exposure-manifest.json must describe service registry-notary")
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
        if entry["service"] != "registry-notary":
            fail(f"{entry['path']} has wrong service {entry['service']}")
        check_value(entry, "listener", LISTENERS)
        check_value(entry, "audience", AUDIENCES)
        check_value(entry, "auth", AUTHS)
        check_value(entry, "audit", AUDIT)
        check_value(entry, "stability", STABILITY)
        check_value(entry, "data_classification", DATA)
        check_value(entry, "source", SOURCES)
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
            or entry["listener"] in {"admin", "metrics"}
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
        for crate in (ROOT / "crates").glob("*")
        for path in (crate / "src").rglob("*.rs")
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
        r"\n\s*#\[cfg\(test\)\](?:\s*#\[[^\]]+\])*\s*mod\s+[A-Za-z0-9_]+\s*\{",
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
    for path in [ROOT / "Dockerfile", ROOT / "Dockerfile.source-adapter-sidecar"]:
        if not path.is_file():
            fail(f"missing required Dockerfile: {path.relative_to(ROOT)}")
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if SECRET_COPY_RE.search(line):
                fail(f"{path.name}:{lineno} may copy secret or private JWK material")


def check_openapi_baseline() -> None:
    baseline = ROOT / "openapi" / "registry-notary.openapi.json"
    if not baseline.exists():
        fail("missing openapi/registry-notary.openapi.json baseline")
    generated = subprocess.run(
        ["cargo", "run", "-q", "-p", "registry-notary", "--", "openapi"],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if generated.returncode != 0:
        fail(f"OpenAPI generation failed: {generated.stderr.strip()}")
    try:
        expected = json.loads(baseline.read_text(encoding="utf-8"))
        actual = json.loads(generated.stdout)
    except json.JSONDecodeError as exc:
        fail(f"OpenAPI JSON parse failed: {exc}")
    if actual != expected:
        fail("generated OpenAPI differs from committed baseline")
    check_openapi_manifest_coverage(baseline)


def check_openapi_manifest_coverage(path: Path) -> None:
    manifest = load_json(SECURITY_DIR / "exposure-manifest.json")
    document = load_json(path)
    if not isinstance(manifest, dict) or not isinstance(document, dict):
        fail("OpenAPI coverage inputs must be JSON objects")
    paths = document.get("paths")
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        fail("OpenAPI paths must be an object")

    # Index OpenAPI path items by their normalised shape so we can look them up
    # by shape while still checking the extension on the original path item.
    openapi_path_items: dict[tuple[str, str], dict] = {}
    for openapi_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        shape = openapi_path_shape(openapi_path)
        for method in path_item:
            if method.upper() in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                openapi_path_items[(shape, method.upper())] = path_item

    missing = []
    catch_all_mismatch = []
    for entry in manifest.get("endpoints", []):
        if not entry.get("openapi"):
            continue
        entry_path = entry["path"]
        entry_method = entry["method"]
        shape = openapi_path_shape(entry_path)
        key = (shape, entry_method)
        if key not in openapi_path_items:
            missing.append((entry_method, entry_path))
            continue
        path_item = openapi_path_items[key]
        inventory_is_catch_all = is_catch_all_path(entry_path)
        spec_is_catch_all = bool(path_item.get("x-registry-notary-catch-all"))
        if inventory_is_catch_all != spec_is_catch_all:
            catch_all_mismatch.append(
                (entry_method, entry_path, inventory_is_catch_all, spec_is_catch_all)
            )

    if missing:
        fail(f"manifest endpoints marked openapi:true are missing from OpenAPI: {sorted(missing)}")
    if catch_all_mismatch:
        details = "; ".join(
            f"{m} {p}: inventory catch-all={inv} but spec x-registry-notary-catch-all={spec}"
            for m, p, inv, spec in catch_all_mismatch
        )
        fail(
            f"catch-all mismatch between route inventory and OpenAPI spec "
            f"(inventory {{*name}} must map to a spec path item with "
            f"x-registry-notary-catch-all:true, and plain {{name}} must not): {details}"
        )


def is_catch_all_path(path: str) -> bool:
    """Return True if any path segment is an axum-style multi-segment wildcard ({*name})."""
    return bool(re.search(r"\{\*[^}]+\}", path))


def openapi_path_shape(path: str) -> str:
    return re.sub(r"\{\*?[^}]+\}", "{}", path)


def check_workflow_external_refs() -> None:
    workflow_dir = ROOT / ".github" / "workflows"
    if not workflow_dir.is_dir():
        fail("missing .github/workflows directory")
    for path in sorted(workflow_dir.glob("*.yml")):
        rel = path.relative_to(ROOT)
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"^REGISTRY_PLATFORM_REF\s*:\s*(.*)$", line.strip())
            if not match:
                continue
            ref = match.group(1).strip().strip("'\"")
            if not IMMUTABLE_GIT_SHA_RE.fullmatch(ref):
                fail(f"{rel}:{lineno} must pin REGISTRY_PLATFORM_REF to a full commit SHA")


def check_workflow_pull_request_hardening() -> None:
    fuzz = ROOT / ".github" / "workflows" / "fuzz.yml"
    container = ROOT / ".github" / "workflows" / "container.yml"
    for path in [fuzz, container]:
        if not path.is_file():
            fail(f"missing required workflow: {path.relative_to(ROOT)}")
        check_checkout_steps_disable_persisted_credentials(path)

    text = container.read_text(encoding="utf-8")
    pr_job = workflow_job_block(text, "pull-request-images", container)
    if "if: github.event_name == 'pull_request'" not in pr_job:
        fail("container pull-request-images job must be restricted to pull_request")
    for forbidden in ["id-token: write", "packages: write"]:
        if re.search(rf"^\s+{re.escape(forbidden)}\s*$", pr_job, flags=re.M):
            fail(f"container pull-request-images job must not grant {forbidden}")

    image_job = workflow_job_block(text, "images", container)
    if "if: github.event_name != 'pull_request'" not in image_job:
        fail("container images publishing job must be skipped on pull_request")
    for required in ["id-token: write", "packages: write"]:
        if not re.search(rf"^\s+{re.escape(required)}\s*$", image_job, flags=re.M):
            fail(f"container images publishing job must explicitly grant {required}")

    if 'compare/${GITHUB_SHA}...${protected_main_sha}' not in text:
        fail("container release ancestry check must compare tag SHA to protected main SHA")
    if re.search(r"compare/\$\{GITHUB_SHA\}\.\.\.(?:origin/)?main\b", text):
        fail("container release ancestry check must not compare against mutable main")


def check_checkout_steps_disable_persisted_credentials(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if "uses: actions/checkout@" not in line:
            continue
        window = lines[index + 1 : index + 9]
        if not any(re.match(r"^\s+persist-credentials:\s*['\"]?false['\"]?\s*$", item) for item in window):
            fail(
                f"{path.relative_to(ROOT)}:{index + 1} checkout step must set "
                "persist-credentials: false"
            )


def workflow_job_block(text: str, job_name: str, path: Path) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    if not match:
        fail(f"{path.relative_to(ROOT)} missing job {job_name}")
    return match.group("body")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "checks",
        nargs="*",
        choices=[
            "manifest",
            "route-sources",
            "dockerfile-secrets",
            "openapi-baseline",
            "openapi-coverage",
            "workflow-external-refs",
            "workflow-pull-request-hardening",
        ],
        default=None,
    )
    args = parser.parse_args()
    checks = args.checks or [
        "manifest",
        "dockerfile-secrets",
        "openapi-baseline",
        "workflow-external-refs",
        "workflow-pull-request-hardening",
    ]
    if "manifest" in checks:
        validate_manifest()
    if "route-sources" in checks:
        validate_route_sources()
    if "dockerfile-secrets" in checks:
        check_dockerfile_secret_patterns()
    if "openapi-baseline" in checks:
        check_openapi_baseline()
    if "openapi-coverage" in checks:
        check_openapi_manifest_coverage(ROOT / "openapi" / "registry-notary.openapi.json")
    if "workflow-external-refs" in checks:
        check_workflow_external_refs()
    if "workflow-pull-request-hardening" in checks:
        check_workflow_pull_request_hardening()


if __name__ == "__main__":
    main()
