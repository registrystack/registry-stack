#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate Registry Notary security assurance contracts."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECURITY_DIR = ROOT / "security"
# Enforcement test and route-source refs predate (or postdate) the monorepo
# migration and may be written relative to the product tree (ROOT) or to the
# monorepo root; MONOREPO_ROOT is the fallback base for the latter.
MONOREPO_ROOT = ROOT.parents[1]

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

LISTENERS = {"public", "admin", "internal", "metrics", "demo"}
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
MAX_MODULE_FILES = 4096
MAX_MODULE_DEPTH = 64
MODULE_DECL_RE = re.compile(
    r"(?P<attrs>(?:#\s*\[[^\]]*\]\s*)*)"
    r"(?:(?:pub(?:\s*\([^)]*\))?)\s+)?"
    r"mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<delimiter>[;{])",
    re.MULTILINE,
)
PATH_ATTR_RE = re.compile(r'^\s*path\s*=\s*"([^"]+)"\s*$', re.DOTALL)
INCLUDE_RE = re.compile(r'include!\s*\(\s*"([^"]+)"\s*\)')
INCLUDE_START_RE = re.compile(r"\binclude!\s*\(")


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


def resolve_repo_path(rel_part: str) -> Path:
    """Resolve a manifest-relative path against the product tree, falling
    back to the monorepo root for refs written relative to it."""
    path = ROOT / rel_part
    if path.exists():
        return path
    return MONOREPO_ROOT / rel_part


def ensure_test_ref_exists(ref: str) -> None:
    file_part, _, symbol = ref.partition("::")
    if not symbol:
        fail(f"enforcement test reference must include ::test_name: {ref}")
    path = resolve_repo_path(file_part)
    if not path.exists():
        fail(f"referenced enforcement test file does not exist: {file_part}")
    text = path.read_text(encoding="utf-8")
    if not re.search(rf"\b(?:async\s+)?fn\s+{re.escape(symbol)}\s*\(", text):
        fail(f"referenced enforcement test symbol {symbol} not found in {file_part}")


def crates_tree_root() -> Path:
    """The crates/ tree lives at the monorepo root today, but may live under
    the product tree (ROOT) in a future or historical layout; prefer
    whichever actually exists."""
    return ROOT if (ROOT / "crates").is_dir() else MONOREPO_ROOT


def validate_route_sources(inventory: object | None = None) -> None:
    if inventory is None:
        inventory = load_json(SECURITY_DIR / "route-inventory.json")
    if not isinstance(inventory, dict) or not isinstance(inventory.get("routes"), list):
        fail("route-inventory.json must contain a routes list")

    inventory_by_source: dict[str, set[tuple[str, str]]] = {}
    crates_base = crates_tree_root()
    # Only scan registry-notary* crates: the monorepo's crates/ directory also
    # holds other products' and shared platform crates (e.g. the
    # registry-platform-testing mock server), which are out of scope for this
    # product's route inventory.
    source_roots = sorted(
        (crate / "src").resolve()
        for crate in (crates_base / "crates").glob("registry-notary*")
        if (crate / "src").is_dir()
    )
    source_paths: set[Path] = set()
    source_root_by_path: dict[Path, Path] = {}
    for source_root in source_roots:
        for path in sorted(source_root.rglob("*.rs")):
            resolved = checked_source_path(path, source_root, "discovered Rust source")
            source_paths.add(resolved)
            source_root_by_path[resolved] = source_root
    for route in inventory["routes"]:
        source = route.get("source")
        if isinstance(source, str):
            inventory_by_source.setdefault(source, set())
            for method in route["methods"]:
                inventory_by_source[source].add((route["path"], method))
    for source in sorted(inventory_by_source):
        if Path(source).is_absolute() or ".." in Path(source).parts:
            fail(f"route inventory source must be a repository-relative path: {source}")
        path = ROOT.resolve() / source
        if not path.exists():
            path = MONOREPO_ROOT.resolve() / source
        if not path.exists():
            fail(f"route inventory references missing source file: {source}")
        source_root = owning_source_root(path, source_roots)
        if source_root is None:
            fail(f"route inventory source is outside a registry-notary src tree: {source}")
        resolved = checked_source_path(path, source_root, f"route inventory source {source}")
        source_paths.add(resolved)
        source_root_by_path[resolved] = source_root

    source_paths, excluded = classify_test_only_sources(
        source_paths, source_root_by_path
    )

    extracted_by_source: dict[str, set[tuple[str, str]]] = {}
    for path in sorted(source_paths):
        if path in excluded:
            continue
        source = str(path.relative_to(crates_base.resolve()))
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
    text = strip_rust_test_modules(text)
    comments_masked = mask_rust(text, strings=False)
    syntax_masked = mask_rust(text, strings=True)
    consts = {
        match.group(1): match.group(2)
        for match in CONST_STR_RE.finditer(comments_masked)
        if syntax_masked[match.start()] == "c"
    }
    routes: set[tuple[str, str]] = set()
    cursor = 0
    while True:
        start = comments_masked.find(".route(", cursor)
        if start == -1:
            break
        if syntax_masked[start] != ".":
            cursor = start + len(".route(")
            continue
        open_paren = start + len(".route(") - 1
        close_paren = matching_paren(syntax_masked, open_paren)
        if close_paren is None:
            break
        inner = comments_masked[open_paren + 1 : close_paren]
        syntax_inner = syntax_masked[open_paren + 1 : close_paren]
        first, _ = split_first_top_level_arg(inner)
        _, masked_handler = split_first_top_level_arg(syntax_inner)
        route_path = resolve_route_path(first, consts)
        if route_path is not None:
            for method in infer_methods(masked_handler):
                routes.add((route_path, method))
        cursor = close_paren + 1
    return routes


def owning_source_root(path: Path, source_roots: list[Path]) -> Path | None:
    resolved = path.resolve()
    for source_root in source_roots:
        if resolved.is_relative_to(source_root):
            return source_root
    return None


def checked_source_path(path: Path, source_root: Path, context: str) -> Path:
    """Resolve a module source without permitting missing files, escapes, or
    symlink aliases. The route inventory is a repository assurance check, so
    source ownership must be explicit and stable in the checkout."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"{context} cannot be resolved: {path} ({exc})")
    if not resolved.is_file():
        fail(f"{context} is not a file: {path}")
    if not resolved.is_relative_to(source_root):
        fail(f"{context} escapes registry-notary source root {source_root}: {path}")
    # All callers build paths from an already-resolved source root or source
    # file. A mismatch therefore means `..` or a symlink changed ownership.
    if path.absolute() != resolved:
        fail(f"{context} uses a non-canonical or symlinked source path: {path}")
    return resolved


def module_child_dir(file_path: Path) -> Path:
    if file_path.name in {"lib.rs", "main.rs", "mod.rs"}:
        return file_path.parent
    return file_path.parent / file_path.stem


def rust_attributes(attrs: str) -> list[str]:
    return re.findall(r"#\s*\[([^\]]*)\]", attrs, flags=re.DOTALL)


def cfg_requires_test(expression: str) -> bool:
    """Conservatively decide whether a cfg expression implies `test`.

    `all(test, unix)` is test-only; `any(test, feature = \"x\")` is not.
    Unknown or malformed predicates return False so the source remains in the
    production scan.
    """
    tokens = re.findall(
        r'[A-Za-z_][A-Za-z0-9_]*|"(?:\\.|[^"\\])*"|[(),=]', expression
    )
    cursor = 0

    def parse() -> bool:
        nonlocal cursor
        if cursor >= len(tokens) or not re.match(r"[A-Za-z_]", tokens[cursor]):
            raise ValueError
        name = tokens[cursor]
        cursor += 1
        if cursor < len(tokens) and tokens[cursor] == "=":
            cursor += 2
            return False
        if cursor >= len(tokens) or tokens[cursor] != "(":
            return name == "test"
        cursor += 1
        children: list[bool] = []
        while cursor < len(tokens) and tokens[cursor] != ")":
            children.append(parse())
            if cursor < len(tokens) and tokens[cursor] == ",":
                cursor += 1
            elif cursor >= len(tokens) or tokens[cursor] != ")":
                raise ValueError
        if cursor >= len(tokens):
            raise ValueError
        cursor += 1
        if name == "all":
            return any(children)
        if name == "any":
            return bool(children) and all(children)
        return False

    try:
        result = parse()
        return result and cursor == len(tokens)
    except (IndexError, ValueError):
        return False


def attrs_require_test(attrs: str) -> bool:
    for attr in rust_attributes(attrs):
        match = re.fullmatch(r"\s*cfg\s*\((.*)\)\s*", attr, flags=re.DOTALL)
        if match and cfg_requires_test(match.group(1)):
            return True
    return False


def path_attribute(attrs: str) -> str | None:
    for attr in rust_attributes(attrs):
        match = PATH_ATTR_RE.fullmatch(attr)
        if match:
            return match.group(1)
    return None


def mask_rust(text: str, *, strings: bool) -> str:
    """Mask comments, and optionally literals, while preserving offsets."""
    chars = list(text)
    index = 0
    block_depth = 0
    while index < len(text):
        if block_depth:
            if text.startswith("/*", index):
                chars[index : index + 2] = "  "
                block_depth += 1
                index += 2
            elif text.startswith("*/", index):
                chars[index : index + 2] = "  "
                block_depth -= 1
                index += 2
            else:
                if text[index] != "\n":
                    chars[index] = " "
                index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
            chars[index:end] = " " * (end - index)
            index = end
            continue
        if text.startswith("/*", index):
            chars[index : index + 2] = "  "
            block_depth = 1
            index += 2
            continue
        raw_prefix_end = None
        if text[index] == "r":
            raw_prefix_end = index + 1
        elif (
            text[index] in {"b", "c"}
            and index + 1 < len(text)
            and text[index + 1] == "r"
        ):
            raw_prefix_end = index + 2
        if raw_prefix_end is not None:
            quote = raw_prefix_end
            while quote < len(text) and text[quote] == "#":
                quote += 1
            if quote >= len(text) or text[quote] != '"':
                raw_prefix_end = None
        if raw_prefix_end is not None:
            hashes = quote - raw_prefix_end
            marker = '"' + ("#" * hashes)
            end = text.find(marker, quote + 1)
            end = len(text) if end == -1 else end + len(marker)
            if strings:
                for offset in range(index, end):
                    if text[offset] != "\n":
                        chars[offset] = " "
            index = end
            continue
        char_prefix = 1 if text.startswith("b'", index) else 0
        if text[index + char_prefix : index + char_prefix + 1] == "'":
            end = index + char_prefix + 1
            escaped = False
            closed = False
            while end < len(text) and text[end] != "\n":
                char = text[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    closed = True
                    break
            if closed:
                if strings:
                    for offset in range(index, end):
                        chars[offset] = " "
                index = end
                continue
        prefix = 1 if text.startswith(('b"', 'c"'), index) else 0
        if text[index + prefix : index + prefix + 1] == '"':
            end = index + prefix + 1
            escaped = False
            while end < len(text):
                char = text[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            if strings:
                for offset in range(index, end):
                    if text[offset] != "\n":
                        chars[offset] = " "
            index = end
            continue
        index += 1
    return "".join(chars)


def matching_brace(text: str, open_brace: int) -> int | None:
    depth = 0
    for index in range(open_brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def module_declarations(text: str) -> list[re.Match[str]]:
    comments_masked = mask_rust(text, strings=False)
    syntax_masked = mask_rust(text, strings=True)
    return [
        match
        for match in MODULE_DECL_RE.finditer(comments_masked)
        if syntax_masked[match.start("delimiter")] == match.group("delimiter")
    ]


def include_references(text: str) -> tuple[list[re.Match[str]], int]:
    comments_masked = mask_rust(text, strings=False)
    syntax_masked = mask_rust(text, strings=True)
    matches = [
        match
        for match in INCLUDE_RE.finditer(comments_masked)
        if syntax_masked[match.start()] == "i"
    ]
    starts = sum(
        1
        for match in INCLUDE_START_RE.finditer(comments_masked)
        if syntax_masked[match.start()] == "i"
    )
    return matches, starts


def inline_test_modules(text: str) -> list[tuple[int, int, str]]:
    syntax_masked = mask_rust(text, strings=True)
    modules: list[tuple[int, int, str]] = []
    for match in module_declarations(text):
        if match.group("delimiter") != "{" or not attrs_require_test(match.group("attrs")):
            continue
        close = matching_brace(syntax_masked, match.end() - 1)
        if close is None:
            fail(f"unclosed inline cfg(test) module {match.group('name')}")
        modules.append((match.start(), close + 1, match.group("name")))
    return modules


def strip_ranges(text: str, ranges: list[tuple[int, int, str]]) -> str:
    chars = list(text)
    for start, end, _ in ranges:
        for index in range(start, end):
            if chars[index] != "\n":
                chars[index] = " "
    return "".join(chars)


def strip_rust_test_modules(text: str) -> str:
    return strip_ranges(text, inline_test_modules(text))


def resolve_module_file(
    file_path: Path,
    source_root: Path,
    attrs: str,
    name: str,
    child_dir: Path,
    context: str,
) -> Path:
    explicit = path_attribute(attrs)
    if explicit is not None:
        return checked_source_path(file_path.parent / explicit, source_root, context)
    candidates = (child_dir / f"{name}.rs", child_dir / name / "mod.rs")
    existing = [candidate for candidate in candidates if candidate.exists()]
    if len(existing) != 1:
        rendered = ", ".join(str(candidate) for candidate in candidates)
        fail(f"{context} must resolve to exactly one conventional module file: {rendered}")
    return checked_source_path(existing[0], source_root, context)


def source_references(
    text: str,
    file_path: Path,
    source_root: Path,
    *,
    test_context: bool,
) -> tuple[set[Path], set[Path]]:
    """Return (production, test-only) external source references."""
    inline_modules = inline_test_modules(text)
    production_text = text if test_context else strip_ranges(text, inline_modules)
    production: set[Path] = set()
    test_only: set[Path] = set()

    for match in module_declarations(production_text):
        if match.group("delimiter") != ";":
            continue
        is_test = test_context or attrs_require_test(match.group("attrs"))
        target = resolve_module_file(
            file_path,
            source_root,
            match.group("attrs"),
            match.group("name"),
            module_child_dir(file_path),
            f"module {match.group('name')} declared by {file_path}",
        )
        (test_only if is_test else production).add(target)

    include_matches, include_starts = include_references(production_text)
    if len(include_matches) != include_starts:
        fail(f"include! in {file_path} must use a direct string literal")
    for match in include_matches:
        target = checked_source_path(
            file_path.parent / match.group(1),
            source_root,
            f"include! declared by {file_path}",
        )
        (test_only if test_context else production).add(target)

    if not test_context:
        for start, end, module_name in inline_modules:
            body = text[start:end]
            child_dir = module_child_dir(file_path) / module_name
            for match in module_declarations(body):
                if match.group("delimiter") != ";":
                    continue
                test_only.add(
                    resolve_module_file(
                        file_path,
                        source_root,
                        match.group("attrs"),
                        match.group("name"),
                        child_dir,
                        f"module {match.group('name')} declared by inline cfg(test) module in {file_path}",
                    )
                )
            include_matches, include_starts = include_references(body)
            if len(include_matches) != include_starts:
                fail(
                    f"include! in inline cfg(test) module in {file_path} "
                    "must use a direct string literal"
                )
            for match in include_matches:
                test_only.add(
                    checked_source_path(
                        file_path.parent / match.group(1),
                        source_root,
                        f"include! in inline cfg(test) module in {file_path}",
                    )
                )
    return production, test_only


def classify_test_only_sources(
    initial_sources: set[Path], source_root_by_path: dict[Path, Path]
) -> tuple[set[Path], set[Path]]:
    """Exclude only files proven test-only, while retaining any file that also
    has production ownership. Test ancestry and production ownership are both
    expanded transitively with explicit bounds."""
    texts: dict[Path, str] = {}
    reference_cache: dict[
        tuple[Path, bool], tuple[set[Path], set[Path]]
    ] = {}

    def load(path: Path, test_context: bool) -> tuple[set[Path], set[Path]]:
        source_root = source_root_by_path[path]
        if path not in texts:
            try:
                texts[path] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                fail(f"Rust source cannot be read as UTF-8: {path} ({exc})")
        cache_key = (path, test_context)
        # Test-context references differ because every child inherits test-only
        # ownership, so cache them separately.
        if cache_key not in reference_cache:
            reference_cache[cache_key] = source_references(
                texts[path], path, source_root, test_context=test_context
            )
        for target in reference_cache[cache_key][0] | reference_cache[cache_key][1]:
            source_root_by_path.setdefault(target, source_root)
        return reference_cache[cache_key]

    test_candidates: set[Path] = set()
    pending: deque[tuple[Path, int]] = deque()
    for path in sorted(initial_sources):
        _, test_refs = load(path, False)
        for target in sorted(test_refs):
            pending.append((target, 1))
    while pending:
        path, depth = pending.popleft()
        if depth > MAX_MODULE_DEPTH:
            fail(f"cfg(test) source expansion exceeds depth {MAX_MODULE_DEPTH}: {path}")
        if path in test_candidates:
            continue
        test_candidates.add(path)
        if len(test_candidates) > MAX_MODULE_FILES:
            fail(f"cfg(test) source expansion exceeds {MAX_MODULE_FILES} files")
        production_refs, test_refs = load(path, True)
        for target in sorted(production_refs | test_refs):
            pending.append((target, depth + 1))

    all_sources = set(initial_sources) | test_candidates
    production_owned = set(initial_sources - test_candidates)
    pending = deque((path, 0) for path in sorted(production_owned))
    while pending:
        path, depth = pending.popleft()
        if depth > MAX_MODULE_DEPTH:
            fail(f"production source expansion exceeds depth {MAX_MODULE_DEPTH}: {path}")
        production_refs, _ = load(path, False)
        for target in sorted(production_refs):
            all_sources.add(target)
            if target not in production_owned:
                production_owned.add(target)
                if len(production_owned) > MAX_MODULE_FILES:
                    fail(f"production source expansion exceeds {MAX_MODULE_FILES} files")
                pending.append((target, depth + 1))

    excluded = test_candidates - production_owned
    return all_sources, excluded


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
    for path in [ROOT / "Dockerfile"]:
        if not path.is_file():
            fail(f"missing required Dockerfile: {path.relative_to(ROOT)}")
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if SECRET_COPY_RE.search(line):
                fail(f"{path.name}:{lineno} may copy secret or private JWK material")


def check_container_runtime_contract() -> None:
    path = ROOT / "Dockerfile"
    if not path.is_file():
        fail(f"missing required Dockerfile: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    runtime_base = "gcr.io/distroless/cc-debian13:nonroot@sha256:"
    marker = f"FROM {runtime_base}"
    marker_at = text.find(marker)
    if marker_at < 0:
        fail("Dockerfile must use the pinned Distroless Debian 13 nonroot runtime")
    runtime = text[marker_at:]
    first_line = runtime.splitlines()[0]
    if not re.fullmatch(
        r"FROM gcr\.io/distroless/cc-debian13:nonroot@sha256:[0-9a-f]{64} AS runtime",
        first_line,
    ):
        fail("Dockerfile runtime base must use an immutable Distroless image digest")
    required = (
        'ARG REGISTRY_NOTARY_FEATURES="registry-notary-cel,pkcs11"',
        'HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/registry-notary", "healthcheck"]',
        'ENTRYPOINT ["/usr/local/bin/registry-notary"]',
        "COPY --from=builder --chown=65532:65532 /workspace/runtime-root/ /",
        "WORKDIR /var/lib/registry-notary",
        "registry-notary-cel-worker",
    )
    for needle in required:
        if needle not in text:
            fail(f"Dockerfile is missing container runtime contract: {needle}")
    for forbidden in ("\nRUN ", "apt-get", "/bin/sh", "curl ", "wget "):
        if forbidden in runtime:
            fail(f"Dockerfile final runtime contains forbidden dependency: {forbidden.strip()}")
    if re.search(
        r"^\s*(?:COPY|ADD)\b[^\n]*(?:\.so\b|pkcs11[^/\s]*module)",
        text,
        re.IGNORECASE | re.MULTILINE,
    ):
        fail("vendor PKCS#11 modules must remain external read-only mounts")


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "checks",
        nargs="*",
        choices=[
            "manifest",
            "route-sources",
            "dockerfile-secrets",
            "container-runtime",
            "openapi-baseline",
            "openapi-coverage",
        ],
        default=None,
    )
    args = parser.parse_args()
    checks = args.checks or [
        "manifest",
        "dockerfile-secrets",
        "container-runtime",
        "openapi-baseline",
    ]
    if "manifest" in checks:
        validate_manifest()
    if "route-sources" in checks:
        validate_route_sources()
    if "dockerfile-secrets" in checks:
        check_dockerfile_secret_patterns()
    if "container-runtime" in checks:
        check_container_runtime_contract()
    if "openapi-baseline" in checks:
        check_openapi_baseline()
    if "openapi-coverage" in checks:
        check_openapi_manifest_coverage(ROOT / "openapi" / "registry-notary.openapi.json")


if __name__ == "__main__":
    main()
