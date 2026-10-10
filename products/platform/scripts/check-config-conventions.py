#!/usr/bin/env python3
"""Hold every configuration format to the configuration conventions.

The lint reads three files:

- products/platform/CONFIG-CONVENTIONS.md, for the CFG-NAME-5 table of
  refused spellings and the Enforcement summary;
- products/platform/config-formats.yaml, the format registry (CFG-SCHEMA-1);
- products/platform/config-conventions-exceptions.yaml, the exceptions
  register.

It first checks that the registry is accurate: every header constant, reader
function and type, schema path and `$id`, example, and conformance member it
names exists, and every schema in the repository is registered. An
inaccuracy is an error and is never exceptable.

It then reports deviations from the lint-gated rules: the registry-level
envelope, schema, check, and reader rules; the schema rules, over every
registered schema and the shared runtime blocks; and a source lint over each
reader type's closure (CFG-SCHEMA-8, CFG-CHANGE-1, CFG-ID-6). A deviation
recorded in the exceptions register passes; an unrecorded one fails, and so
does a recorded one that no longer deviates. Pending entries are counted per
product and work package, and `--strict` refuses them. CFG-CHANGE-5 compares
the register, entry by entry (rule, format, location), with the merge base of
`origin/main` (or `--base`): an entry may be added only in the
protocol-constant, external-format, and exchange-model classes, or as a
stable-move entry located in a format's first published schema, which records
respellings its correct files already write; no entry changes class, and
deletion is the only other change. A moved entry is a deletion and an
addition. An explicit `--base` whose tree lacks the register fails; without
`--base` that is a note.

`--rule-coverage` checks instead that every rule the convention declares has
one Enforcement summary row and that the gates the row names exist.

Run with PyYAML available:

    uv run --no-project --with PyYAML==6.0.2 python \\
        products/platform/scripts/check-config-conventions.py
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_CONFORMANCE_PATH = Path(__file__).with_name("check-config-conformance.py")
_SPEC = importlib.util.spec_from_file_location("check_config_conformance", _CONFORMANCE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
conformance = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault(_SPEC.name, conformance)
_SPEC.loader.exec_module(conformance)

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = "products/platform/config-formats.yaml"
REGISTER = "products/platform/config-conventions-exceptions.yaml"
CONVENTION = "products/platform/CONFIG-CONVENTIONS.md"
CONFIGURE = "editors/configure.py"
TOOLING_EDITOR = "crates/registry-evidencectl/src/tooling_editor.rs"
LINT_TEST = "products/platform/scripts/test_check_config_conventions.py"
CORPUS = "products/platform/conformance/yaml"

REGISTRY_HEADER = (
    "id.registrystack.org/formats/platform/config-format-registry/v1alpha1",
    "PlatformConfigFormatRegistry",
)
REGISTER_HEADER = (
    "id.registrystack.org/formats/platform/config-conventions-exceptions/v1alpha1",
    "PlatformConfigConventionsExceptions",
)

# Schemas the lint expects to find registered, shared, or declared out of scope.
SCHEMA_GLOBS = (
    "products/*/generated/**/*.schema.json",
    "products/*/contracts/**/*.schema.json",
    "products/*/contracts/**/*.schema.yaml",
    "products/*/schemas/*.schema.json",
    "products/*/profile/schema/*.schema.json",
    "crates/*/schemas/**/*.schema.json",
)

PREFIXES = {
    "breg": "BReg",
    "casework": "Casework",
    "coordinator": "Coordinator",
    "scheduling": "Scheduling",
    "messaging": "Messaging",
    "discovery": "Discovery",
    "render": "Render",
    "evidence": "Evidence",
    "manifest": "Manifest",
    "platform": "Platform",
}
KIND_RE = re.compile(r"^(BReg|Casework|Coordinator|Scheduling|Messaging|Discovery|Render|Evidence|Manifest|Platform)([A-Z][a-z0-9]+)+$")
VERSION_RE = re.compile(r"^v[1-9][0-9]*((alpha|beta)[1-9][0-9]*)?$")
API_VERSION_PREFIX = "id.registrystack.org/formats/"
SCHEMA_ID_PREFIX = "https://id.registrystack.org/schemas/"

FORMAT_FIELDS = (
    "id", "product", "title", "files", "syntax", "audience", "stability", "current",
    "target", "schema", "reader", "check", "example", "conformance", "securityMembers",
    "restrictingMembers",
)
OPTIONAL_FORMAT_FIELDS = ("emittedBy", "exceptionClass", "topLevel", "buildArtifact", "notes")
ENUMS = {
    "syntax": ("yaml", "json", "jsonl", "text"),
    "audience": ("authored", "operator", "generated"),
    "stability": ("promised", "experimental", "unpromised"),
    "topLevel": ("project", "bundle"),
    "exceptionClass": ("external-format", "exchange-model"),
}
SCHEMA_ORIGINS = ("generated", "hand-written", "frozen-contract")
WHEN_OMITTED = ("refused", "open", "closed", "unclassified")
CONFORMANCE_CASES = {"requiredText": str, "optionalText": str, "integer": int, "boolean": bool}
# Optional roles naming a shape the generic corpus cases mutate: a list of
# named items (CFG-ID-5), a set (CFG-ID-6), a reference to a local identifier
# (CFG-ID-4), a relative path to a file beside the example (CFG-VAL-8), and an
# operand another declaration types (CFG-VAL-9).
CONFORMANCE_SHAPES = ("idList", "set", "reference", "relativePath", "operand")
LOCAL_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
# The grammar `$defs/DerivedId` must carry: a dot-separated path of two or more
# local identifiers (CFG-ID-1).
DERIVED_ID_PATTERN = r"^[a-z][a-z0-9_-]{0,63}(\.[a-z][a-z0-9_-]{0,63})+$"

CLASSES = ("protocol-constant", "external-format", "exchange-model", "stable-move", "decision", "pending")
GROWTH_CLASSES = frozenset({"protocol-constant", "external-format", "exchange-model"})
ENTRY_FIELDS = ("rule", "format", "location", "class", "reason", "resolution")
WP_RE = re.compile(r"^WP[0-9]+$")
DATE_RE = re.compile(r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}\b")

SHARED_FORMAT = "platform/runtime-config-blocks"
SHARED_BLOCKS = (
    "ListenerConfig", "PrivateListenerConfig", "DatabaseConfig", "OidcIssuerConfig",
    "OidcClientsConfig", "JwksSource", "AuditKeyConfig", "SecretProvidersConfig",
    "SecretReference", "IdentityConfig", "ProjectIdentity", "Url", "LocalId",
    "ExternalId", "Digest",
)
VALUE_TYPES = ("Url", "Digest", "LocalId", "ExternalId", "SecretReference")
FOREIGN = "x-registry-foreign"
MEMBER_NAMES = "x-registry-member-names"
# A node that passes through a payload its format does not describe or promise
# carries this keyword, whose value is the reason sentence (CFG-SCHEMA-4).
PASSTHROUGH = "x-registry-passthrough"
HEADER_MEMBERS = frozenset(
    {"apiVersion", "kind", "schema", "$schema", "schemaVersion", "schema_version",
     "version", "formatVersion", "fixture"}
)

NAME_1 = re.compile(r"^[a-z][a-z0-9]*([A-Z][a-z0-9]+)*$")
KEBAB_SEGMENT = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
BOUND = re.compile(r"^(max|min)([A-Z].*)$")
DURATION_WORDS = frozenset(
    {"Timeout", "Ttl", "Delay", "Interval", "Lifetime", "Duration", "Leeway", "Grace",
     "Retention", "Window", "Period", "Age"}
)
# A text member whose last word is one of these holds a duration. Period,
# Window, and Age also name labels (a statistical period, a booking window).
DURATION_TEXT_WORDS = frozenset(
    {"Timeout", "Ttl", "Delay", "Interval", "Lifetime", "Duration", "Leeway", "Grace", "Retention"}
)
UNITS = ("Milliseconds", "Seconds", "Minutes", "Hours", "Days", "WorkingDays", "Bytes", "Degrees")
TIME_UNITS = ("Milliseconds", "Seconds", "Minutes", "Hours", "Days")
NONCANONICAL_UNITS = {
    "Ms": "Milliseconds", "Millis": "Milliseconds", "Msec": "Milliseconds",
    "Secs": "Seconds", "Sec": "Seconds", "Mins": "Minutes", "Min": "Minutes",
    "Hrs": "Hours", "Kb": "Bytes", "Mb": "Bytes", "Kib": "Bytes", "Mib": "Bytes",
}
# The largest value of each unsigned integer format, the bound a plain
# unsigned type implies without stating a range of its own.
UNSIGNED_CEILING = {
    "uint8": 2**8 - 1,
    "uint16": 2**16 - 1,
    "uint32": 2**32 - 1,
    "uint64": 2**64 - 1,
    "uint": 2**64 - 1,
}
# Members that hold a URL by name. `format: uri` alone is not enough: Evidence
# types URN identifiers that way, and a `conceptUri` is an identifier too, so
# only the exact `uri` member counts among the URI spellings.
URL_NAME = re.compile(r"^(?:url|uri|issuer)$|.*(?:Url|Origin|Issuer)$")
SECRET_FILE = re.compile(r"(?:[Kk]ey|[Ss]ecret|[Pp]assword|[Tt]oken|[Cc]redential)s?(?:File|Path)$")
INLINE_SECRET = re.compile(
    r"^(?:secret|password|passphrase|token|credentials?|apiKey|privateKey|clientSecret)$"
    r"|(?:Secret|Password|Passphrase|ApiKey|PrivateKey|Token|Credentials?)$"
)
SECRET_REFERENCE_TARGET = re.compile(r"(?:/|^)(?:SecretReference|secret-ref)$")
EMBED_NAME = re.compile(r"^(?:schema|openapi|jsonSchema|[a-z][A-Za-z0-9]*Schema)$")
SET_TYPES = re.compile(r"\b(?:BTreeSet|HashSet|IndexSet)\b")
DIRECT_LINT_PHRASES = ("check-config-conventions.py", "convention lint", "source lint")


class UsageError(Exception):
    pass


@dataclass
class Finding:
    rule: str
    format: str
    file: str
    pointer: str
    message: str
    fix: str
    status: str = "unrecorded"
    cls: str | None = None

    @property
    def location(self) -> str:
        return f"{self.file}#{self.pointer}"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.rule, self.format, self.location)


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stale: list[dict] = field(default_factory=list)
    pending: Counter = field(default_factory=Counter)
    pending_entries: list[dict] = field(default_factory=list)
    change5: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    strict: bool = False

    @property
    def unrecorded(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.status == "unrecorded"]

    @property
    def failed(self) -> bool:
        return bool(
            self.errors or self.unrecorded or self.stale or self.change5
            or (self.strict and self.pending_entries)
        )


# --------------------------------------------------------------------------
# Small helpers


def escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def pointer(tokens: tuple[str, ...]) -> str:
    return "".join(f"/{escape(token)}" for token in tokens)


def split_pointer(text: str) -> list[str]:
    if text in ("", "/"):
        return []
    return [unescape(token) for token in text.lstrip("/").split("/")]


def words(name: str) -> list[str]:
    return re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+", name)


def capitalize(text: str) -> str:
    return text[:1].upper() + text[1:]


def def_context(name: str) -> str:
    """Name a definition as a member would be named, for parent context."""

    if name.startswith("Raw") and name[3:4].isupper():
        name = name[3:]
    if name.endswith("Config") and len(name) > len("Config"):
        name = name[: -len("Config")]
    return name[:1].lower() + name[1:]


def shared_stem(name: str) -> str:
    if name.startswith("Raw") and name[3:4].isupper():
        name = name[3:]
    if name.endswith("Config") and len(name) > len("Config"):
        name = name[: -len("Config")]
    return name


SHARED_STEMS = {shared_stem(name): name for name in SHARED_BLOCKS}


def glob_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        elif pattern[index] == "{" and "}" in pattern[index:]:
            end = pattern.index("}", index)
            choices = pattern[index + 1 : end].split(",")
            out.append("(?:" + "|".join(re.escape(choice) for choice in choices) + ")")
            index = end + 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out) + r"\Z")


def matches_tail(pattern: str, path: str) -> bool:
    regex = glob_regex(pattern)
    parts = path.split("/")
    return any(regex.match("/".join(parts[index:])) for index in range(len(parts)))


def covers(mapped: str, registered: str) -> bool:
    """Whether an editor pattern maps every file a registered pattern names.

    A registered pattern names the tail of a path. An editor pattern is
    relative to the project directory, so it may name directories above that
    tail; `{document}` is the one file the adopter names at setup.
    """

    if mapped == "{document}":
        return True
    wide, narrow = mapped.split("/"), registered.split("/")
    if len(wide) < len(narrow):
        return False
    return all(
        theirs == ours
        or theirs in ("*", "**")
        or (not any(mark in ours for mark in "*?{") and glob_regex(theirs).fullmatch(ours) is not None)
        for theirs, ours in zip(reversed(wide), reversed(narrow))
    )


def load_document(path: Path) -> object:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return yaml.safe_load(text)


def git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, text=True, check=False
    )


def same_value(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right if isinstance(left, bool) or isinstance(right, bool) else left == right


# --------------------------------------------------------------------------
# The convention page


@dataclass
class Name5Item:
    parent: str | None
    regex: re.Pattern[str]
    text: str
    context: tuple[str, str] | None


@dataclass
class Name5Row:
    concept: str
    allowed: list[Name5Item]
    refused: list[Name5Item]


@dataclass
class Convention:
    rules: dict[str, str]
    name5: list[Name5Row]
    summary: list[tuple[str, list[str], str]]


RULE_DECLARATION = re.compile(r"\*\*(CFG-[A-Z]+-[0-9]+) \((MUST|SHOULD)\)")
CODE_ITEM = re.compile(r"`([^`]+)`(?:\s+(outside|under)\s+`([^`]+)`)?")


def name5_item(text: str, context: tuple[str, str] | None) -> Name5Item:
    parent = None
    if "." in text:
        parent, text = text.split(".", 1)
    regex = ""
    for part in re.split(r"(<thing>|<Thing>)", text):
        if part == "<thing>":
            regex += "(?P<thing>[a-z][A-Za-z0-9]*)"
        elif part == "<Thing>":
            regex += "(?P<Thing>[A-Z][A-Za-z0-9]*)"
        else:
            regex += re.escape(part)
    return Name5Item(parent, re.compile(f"^{regex}$"), text, context)


def parse_name5(text: str) -> list[Name5Row] | None:
    start = text.find("**CFG-NAME-5")
    if start == -1:
        return None
    lines = text[start:].splitlines()
    rows: list[Name5Row] = []
    header = None
    for line in lines[1:]:
        if line.startswith("**CFG-"):
            break
        if not line.startswith("|"):
            if header is not None and rows:
                break
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if header is None:
            header = cells
            if "Refused spellings (lint)" not in header or "Key" not in header:
                return None
            continue
        if set(line.replace("|", "").strip()) <= {"-", " "}:
            continue
        key_cell = cells[header.index("Key")]
        refused_cell = cells[header.index("Refused spellings (lint)")]

        def items(cell: str) -> list[Name5Item]:
            return [
                name5_item(match.group(1), (match.group(2), match.group(3)) if match.group(2) else None)
                for match in CODE_ITEM.finditer(cell)
            ]

        rows.append(Name5Row(cells[0], items(key_cell), items(refused_cell)))
    return rows if header is not None else None


def expand_rules(cell: str) -> list[str]:
    rules: list[str] = []
    for group in cell.replace("(SHOULD)", "").split(";"):
        match = re.match(r"\s*CFG-([A-Z]+)-(.*)$", group.strip())
        if not match:
            continue
        for part in match.group(2).split(","):
            part = part.strip()
            span = re.match(r"^([0-9]+)\s+to\s+([0-9]+)$", part)
            if span:
                numbers = range(int(span.group(1)), int(span.group(2)) + 1)
            elif part.isdigit():
                numbers = [int(part)]
            else:
                continue
            rules += [f"CFG-{match.group(1)}-{number}" for number in numbers]
    return rules


def parse_summary(text: str) -> list[tuple[str, list[str], str]] | None:
    start = text.find("## Enforcement summary")
    if start == -1:
        return None
    rows = []
    for line in text[start:].splitlines()[1:]:
        if line.startswith("## "):
            break
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or cells[0] == "Rules" or set(cells[0]) <= {"-"}:
            continue
        rows.append((cells[0], expand_rules(cells[0]), cells[1]))
    return rows


def load_convention(root: Path, report: Report) -> Convention | None:
    path = root / CONVENTION
    if not path.is_file():
        report.errors.append(f"{CONVENTION} does not exist")
        return None
    text = path.read_text(encoding="utf-8")
    rules = {match.group(1): match.group(2) for match in RULE_DECLARATION.finditer(text)}
    name5 = parse_name5(text)
    if name5 is None:
        report.errors.append(
            f"{CONVENTION}: the CFG-NAME-5 table with a 'Refused spellings (lint)' column is missing"
        )
        name5 = []
    summary = parse_summary(text)
    if summary is None:
        report.errors.append(f"{CONVENTION}: the Enforcement summary is missing")
        summary = []
    return Convention(rules, name5, summary)


# --------------------------------------------------------------------------
# Rust sources


def crate_index(root: Path) -> dict[str, tuple[Path, dict]]:
    crates: dict[str, tuple[Path, dict]] = {}
    for manifest in sorted(root.glob("crates/*/Cargo.toml")):
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            continue
        name = data.get("package", {}).get("name")
        if isinstance(name, str):
            crates[name] = (manifest.parent, data)
        crates.setdefault(manifest.parent.name, (manifest.parent, data))
    return crates


def production_dependencies(data: dict) -> list[str]:
    tables = [data.get("dependencies", {})]
    tables += [target.get("dependencies", {}) for target in data.get("target", {}).values()]
    names: list[str] = []
    for table in tables:
        for name, value in table.items():
            if isinstance(value, dict) and isinstance(value.get("package"), str):
                name = value["package"]
            if name.startswith("registry-") and name not in names:
                names.append(name)
    return names


@dataclass
class RustItem:
    kind: str
    name: str
    crate: str
    path: Path
    attributes: str
    raw_attributes: str
    body: str
    offset: int


def skip_back(code: str, index: int) -> int:
    while index > 0 and code[index - 1].isspace():
        index -= 1
    return index


def attributes_start(code: str, start: int) -> int:
    index = skip_back(code, start)
    visibility = re.search(r"pub(?:\s*\([^)]*\))?\s*$", code[max(0, index - 40) : index])
    if visibility:
        index = max(0, index - 40) + visibility.start()
    while True:
        end = skip_back(code, index)
        if end == 0 or code[end - 1] != "]":
            return index
        depth = 0
        cursor = end - 1
        while cursor >= 0:
            if code[cursor] == "]":
                depth += 1
            elif code[cursor] == "[":
                depth -= 1
                if depth == 0:
                    break
            cursor -= 1
        if cursor > 0 and code[cursor - 1] == "#":
            index = cursor - 1
            continue
        return index


def matching(code: str, opening: int, pair: str) -> int:
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == pair[0]:
            depth += 1
        elif code[index] == pair[1]:
            depth -= 1
            if depth == 0:
                return index
    return len(code) - 1


ITEM = re.compile(r"\b(struct|enum|type)\s+([A-Z]\w*)")


def parse_items(crate: str, path: Path, code: str, text: str) -> list[RustItem]:
    items: list[RustItem] = []
    for match in ITEM.finditer(code):
        start = attributes_start(code, match.start())
        index = match.end()
        if index < len(code) and code[index] == "<":
            depth = 0
            while index < len(code):
                if code[index] == "<":
                    depth += 1
                elif code[index] == ">":
                    depth -= 1
                    if depth == 0:
                        index += 1
                        break
                index += 1
        rest = re.match(r"\s*(?:where[^{;(]*)?", code[index:])
        index += rest.end() if rest else 0
        if index >= len(code):
            continue
        opener = code[index]
        if match.group(1) == "type":
            if opener != "=":
                continue
            end = code.find(";", index)
            body = code[index + 1 : end]
        elif opener == "{":
            body = code[index + 1 : matching(code, index, "{}")]
        elif opener == "(" and match.group(1) == "struct":
            body = "(" + code[index + 1 : matching(code, index, "()")] + ")"
        elif opener == ";":
            body = ""
        else:
            continue
        items.append(
            RustItem(
                match.group(1), match.group(2), crate, path,
                code[start : match.start()], text[start : match.start()], body, match.start(),
            )
        )
    return items


def split_top(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current = ""
    for character in text:
        if character in "([{<":
            depth += 1
        elif character in ")]}>":
            depth -= 1
        if character == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += character
    if current.strip():
        parts.append(current)
    return parts


def leading_attributes(entry: str) -> tuple[str, str]:
    index = 0
    entry_length = len(entry)
    while True:
        while index < entry_length and entry[index].isspace():
            index += 1
        if entry.startswith("#[", index):
            index = matching(entry, index + 1, "[]") + 1
            continue
        return entry[:index], entry[index:].strip()


def serde_attributes(attributes: str) -> str:
    return " ".join(re.findall(r"serde\s*\(([^\]]*)\)\s*\]", attributes))


class RustIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.crates = crate_index(root)
        self.items: dict[str, list[RustItem]] = {}
        self.code: dict[Path, str] = {}
        self.closures: dict[str, list[str]] = {}

    def closure(self, crate: str) -> list[str]:
        if crate not in self.closures:
            order: list[str] = []
            queue = [crate]
            while queue:
                name = queue.pop(0)
                if name in order or name not in self.crates:
                    continue
                order.append(name)
                queue += production_dependencies(self.crates[name][1])
            self.closures[crate] = order
        return self.closures[crate]

    def crate_items(self, crate: str) -> list[RustItem]:
        if crate not in self.items:
            directory = self.crates[crate][0] / "src"
            paths = sorted(directory.rglob("*.rs")) if directory.is_dir() else []
            items: list[RustItem] = []
            for path, code in conformance.production_code(paths).items():
                self.code[path] = code
                items += parse_items(crate, path, code, path.read_text(encoding="utf-8"))
            self.items[crate] = items
        return self.items[crate]

    def lookup(self, crate: str, name: str, near: RustItem | None = None,
               crate_hint: str | None = None) -> RustItem | None:
        candidates = [
            item for member in self.closure(crate) for item in self.crate_items(member)
            if item.name == name
        ]
        if not candidates:
            return None
        if crate_hint is not None:
            hinted = [item for item in candidates if item.crate.replace("-", "_") == crate_hint]
            if hinted:
                return hinted[0]
        if near is not None:
            for same in (lambda item: item.path == near.path, lambda item: item.crate == near.crate):
                matched = [item for item in candidates if same(item)]
                if matched:
                    return matched[0]
        return candidates[0]


# --------------------------------------------------------------------------
# Schemas


def resolve_ref(root: object, reference: str) -> object | None:
    if not reference.startswith("#"):
        return None
    node = root
    for token in split_pointer(reference[1:]):
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            return None
    return node


def ref_names(node: object) -> list[str]:
    """Return the `$ref` targets a member is typed with, through allOf and nullable unions."""

    if not isinstance(node, dict):
        return []
    found = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
    for keyword in ("allOf", "anyOf", "oneOf"):
        for branch in node.get(keyword, []) or []:
            if isinstance(branch, dict) and branch.get("type") != "null":
                found += ref_names(branch)
    return found


def refs_to(node: object, name: str) -> bool:
    return any(reference.rsplit("/", 1)[-1] == name for reference in ref_names(node))


def typed_as_derived_id(node: object, document: dict) -> bool:
    """Whether a member references `$defs/DerivedId` and the schema defines it with the derived grammar."""

    definitions = document.get("$defs")
    definition = definitions.get("DerivedId") if isinstance(definitions, dict) else None
    return (
        refs_to(node, "DerivedId")
        and isinstance(definition, dict)
        and definition.get("type") == "string"
        and definition.get("pattern") == DERIVED_ID_PATTERN
    )


def types_of(node: object) -> set[str]:
    if not isinstance(node, dict):
        return set()
    declared = node.get("type")
    if isinstance(declared, str):
        return {declared}
    if isinstance(declared, list):
        return {item for item in declared if isinstance(item, str)}
    found: set[str] = set()
    for keyword in ("anyOf", "oneOf"):
        for branch in node.get(keyword, []) or []:
            found |= types_of(branch)
    return found


def expand(root: object, node: object, depth: int = 0) -> list[dict]:
    """The node and everything `$ref` and `allOf` make it, without alternatives."""

    if not isinstance(node, dict) or depth > 12:
        return []
    nodes = [node]
    if isinstance(node.get("$ref"), str):
        nodes += expand(root, resolve_ref(root, node["$ref"]), depth + 1)
    for branch in node.get("allOf", []) or []:
        nodes += expand(root, branch, depth + 1)
    return nodes


def alternatives(root: object, node: object) -> list[list[list[dict]]]:
    groups = []
    for part in expand(root, node):
        for keyword in ("anyOf", "oneOf"):
            if isinstance(part.get(keyword), list):
                groups.append([sub for branch in part[keyword] for sub in [expand(root, branch)] if sub])
    return groups


def object_view(root: object, node: object) -> tuple[dict, set[str]]:
    properties: dict = {}
    required: set[str] = set()
    for part in expand(root, node):
        if isinstance(part.get("properties"), dict):
            properties.update(part["properties"])
        required |= {name for name in part.get("required", []) or [] if isinstance(name, str)}
    return properties, required


def schema_children(root: object, node: object, token: str) -> list[tuple[str, dict, bool]]:
    """Children of a schema node for one document pointer token.

    Each child carries its schema pointer suffix and whether the token is
    required at this step.
    """

    parts = expand(root, node)
    groups = alternatives(root, node)
    flat = parts + [part for group in groups for branch in group for part in branch]
    required = any(token in (part.get("required") or []) for part in parts) or any(
        group and all(any(token in (part.get("required") or []) for part in branch) for branch in group)
        for group in groups
    )
    children: list[tuple[str, dict, bool]] = []
    for part in flat:
        if token == "*" or token.isdigit():
            items = part.get("items")
            if isinstance(items, dict):
                children.append(("items", items, required))
            prefix = part.get("prefixItems")
            if token.isdigit() and isinstance(prefix, list) and int(token) < len(prefix):
                children.append((f"prefixItems/{token}", prefix[int(token)], required))
            if token == "*":
                extra = part.get("additionalProperties")
                if isinstance(extra, dict):
                    children.append(("additionalProperties", extra, required))
                for pattern, sub in (part.get("patternProperties") or {}).items():
                    children.append((f"patternProperties/{escape(pattern)}", sub, required))
            continue
        properties = part.get("properties") or {}
        if token in properties and isinstance(properties[token], (dict, bool)):
            sub = properties[token] if isinstance(properties[token], dict) else {}
            children.append((f"properties/{escape(token)}", sub, required))
            continue
        for pattern, sub in (part.get("patternProperties") or {}).items():
            try:
                if re.search(pattern, token):
                    children.append((f"patternProperties/{escape(pattern)}", sub, required))
            except re.error:
                continue
        extra = part.get("additionalProperties")
        if isinstance(extra, dict) and not properties:
            children.append(("additionalProperties", extra, required))
    return children


def node_pointer(root: object, node: dict) -> str | None:
    """Find the schema pointer of a node by identity."""

    stack: list[tuple[object, tuple[str, ...]]] = [(root, ())]
    while stack:
        current, tokens = stack.pop()
        if current is node:
            return pointer(tokens)
        if isinstance(current, dict):
            stack += [(value, tokens + (key,)) for key, value in current.items() if isinstance(value, (dict, list))]
        elif isinstance(current, list):
            stack += [(value, tokens + (str(index),)) for index, value in enumerate(current)]
    return None


def resolve_member(root: object, member: str) -> list[tuple[dict, list[bool]]] | None:
    """Resolve a document pointer to the schema nodes that describe it."""

    current: list[tuple[dict, list[bool]]] = [(root, [])] if isinstance(root, dict) else []
    for token in split_pointer(member):
        following: list[tuple[dict, list[bool]]] = []
        for node, steps in current:
            for _, child, required in schema_children(root, node, token):
                named = not (token == "*" or token.isdigit())
                following.append((child, steps + ([required] if named else [])))
        if not following:
            return None
        current = following
    return current


@dataclass
class Visit:
    tokens: tuple[str, ...]
    node: dict
    names: tuple[str, ...]
    member: str | None
    parent: dict | None
    # Under a keyword that constrains what its schema already describes: the
    # closure rule exempts the node (CFG-SCHEMA-4).
    conditional: bool = False
    # The node constrains a value the constrained schema declares elsewhere,
    # where every rule reads it; no rule reads it here.
    constraint: bool = False


# A subschema that constrains the value its schema already describes. Each
# value of `dependentSchemas` is one more.
CONDITIONAL_SCHEMAS = ("if", "then", "else", "not")


def same_value_schemas(root: object, nodes: list[dict]) -> list[dict]:
    """The nodes and every schema `$ref`, `allOf`, `anyOf`, and `oneOf` apply to the same value."""

    found: list[dict] = []
    seen: set[int] = set()
    stack: list[object] = list(reversed(nodes))
    while stack:
        node = stack.pop()
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        found.append(node)
        if isinstance(node.get("$ref"), str):
            stack.append(resolve_ref(root, node["$ref"]))
        for keyword in ("allOf", "anyOf", "oneOf"):
            stack += node.get(keyword) or []
    return found


def declared_member(root: object, nodes: list[dict], key: str) -> list[dict]:
    """The schemas the nodes declare for one member, empty when they declare none."""

    found: list[dict] = []
    for part in same_value_schemas(root, nodes):
        properties = part.get("properties") or {}
        if key in properties:
            found.append(properties[key] if isinstance(properties[key], dict) else {})
            continue
        for pattern, sub in (part.get("patternProperties") or {}).items():
            try:
                if re.search(pattern, key):
                    found.append(sub if isinstance(sub, dict) else {})
            except re.error:
                continue
        if isinstance(part.get("additionalProperties"), dict):
            found.append(part["additionalProperties"])
    return found


def declared_values(root: object, nodes: list[dict]) -> list[dict]:
    """The schemas the nodes declare for the items of a list or the values of a mapping."""

    found: list[dict] = []
    for part in same_value_schemas(root, nodes):
        items = part.get("items")
        subs = [items] if isinstance(items, dict) else list(items) if isinstance(items, list) else []
        subs += part.get("prefixItems") or []
        subs += list((part.get("patternProperties") or {}).values())
        subs.append(part.get("additionalProperties"))
        found += [sub for sub in subs if isinstance(sub, dict)]
    return found


def walk(schema: object, canonical: dict) -> list[Visit]:
    """Every subschema of a schema, each marked with how the rules read it.

    A subschema under `if`, `then`, `else`, `not`, or `dependentSchemas`
    constrains the value its schema already describes. A member it names that
    the constrained schema declares is a constraint, and so is everything it
    says about that member; a member the constrained schema does not declare
    is declared here, and the rules read it as they read any other member.
    """

    visits: list[Visit] = []

    def visit(node: object, tokens: tuple[str, ...], names: tuple[str, ...],
              member: str | None, parent: dict | None, conditional: bool,
              declared: list[dict] | None, anchor: dict | None) -> None:
        # `declared` holds the constrained schema's own schemas for this value
        # when the node is a constraint. `anchor` is the schema that describes
        # the value an applicator branch shares with it.
        if node is True:
            node = {}
        if not isinstance(node, dict) or FOREIGN in node:
            return
        if anchor is None:
            anchor = node
        visits.append(Visit(tokens, node, names, member, parent, conditional, declared is not None))

        def below(sub: object, step: tuple[str, ...], below_names: tuple[str, ...],
                  below_member: str | None, known: list[dict] | None) -> None:
            # A value the constrained schema does not declare is declared by
            # the conditional subschema itself.
            visit(sub, tokens + step, below_names, below_member, node, conditional, known or None, None)

        def values() -> list[dict] | None:
            return None if declared is None else declared_values(schema, declared)

        for key, sub in (node.get("properties") or {}).items():
            known = None if declared is None else declared_member(schema, declared, key)
            below(sub, ("properties", key), names + (key,), key, known)
        for key, sub in (node.get("patternProperties") or {}).items():
            below(sub, ("patternProperties", key), names, None, values())
        for keyword in ("$defs", "definitions"):
            for key, sub in (node.get(keyword) or {}).items():
                if not tokens and key in canonical and sub == canonical[key]:
                    continue
                visit(sub, tokens + (keyword, key), names + (def_context(key),), None, node, False, None, None)
        if isinstance(node.get("additionalProperties"), dict):
            below(node["additionalProperties"], ("additionalProperties",), names, None, values())
        items = node.get("items")
        if isinstance(items, dict):
            below(items, ("items",), names, None, values())
        elif isinstance(items, list):
            for index, sub in enumerate(items):
                below(sub, ("items", str(index)), names, None, values())
        for index, sub in enumerate(node.get("prefixItems") or []):
            below(sub, ("prefixItems", str(index)), names, None, values())
        for keyword in ("allOf", "anyOf", "oneOf"):
            for index, sub in enumerate(node.get(keyword) or []):
                visit(sub, tokens + (keyword, str(index)), names, None, node, conditional, declared, anchor)
        constrained = declared if declared is not None else [anchor]
        for keyword in CONDITIONAL_SCHEMAS:
            if isinstance(node.get(keyword), dict):
                visit(node[keyword], tokens + (keyword,), names, None, node, True, constrained, anchor)
        dependents = node.get("dependentSchemas")
        for key, sub in (dependents.items() if isinstance(dependents, dict) else ()):
            if isinstance(sub, dict):
                visit(sub, tokens + ("dependentSchemas", key), names, None, node, True, constrained, anchor)

    visit(schema, (), (), None, None, False, None, None)
    return visits


def json_type_ok(value: object, kind: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(kind, True)


def valid(value: object, node: object, root: object, depth: int = 0) -> bool:
    """A small JSON Schema validator, enough to check declared defaults."""

    if depth > 20 or node is True or node is None:
        return True
    if node is False:
        return False
    if not isinstance(node, dict):
        return True
    if isinstance(node.get("$ref"), str):
        target = resolve_ref(root, node["$ref"])
        if target is not None and not valid(value, target, root, depth + 1):
            return False
    if not all(valid(value, sub, root, depth + 1) for sub in node.get("allOf", []) or []):
        return False
    if node.get("anyOf") and not any(valid(value, sub, root, depth + 1) for sub in node["anyOf"]):
        return False
    if node.get("oneOf") and sum(valid(value, sub, root, depth + 1) for sub in node["oneOf"]) != 1:
        return False
    declared = node.get("type")
    if declared is not None:
        kinds = declared if isinstance(declared, list) else [declared]
        if not any(json_type_ok(value, kind) for kind in kinds):
            return False
    if "enum" in node and not any(same_value(value, option) for option in node["enum"]):
        return False
    if "const" in node and not same_value(value, node["const"]):
        return False
    if isinstance(value, str):
        if len(value) < node.get("minLength", 0) or len(value) > node.get("maxLength", len(value)):
            return False
        if isinstance(node.get("pattern"), str):
            try:
                if re.search(node["pattern"], value) is None:
                    return False
            except re.error:
                pass
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in node and value < node["minimum"]:
            return False
        if "maximum" in node and value > node["maximum"]:
            return False
        if "exclusiveMinimum" in node and value <= node["exclusiveMinimum"]:
            return False
        if "exclusiveMaximum" in node and value >= node["exclusiveMaximum"]:
            return False
    if isinstance(value, list):
        if len(value) < node.get("minItems", 0) or len(value) > node.get("maxItems", len(value)):
            return False
        if node.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            return False
        if isinstance(node.get("items"), dict) and not all(valid(item, node["items"], root, depth + 1) for item in value):
            return False
    if isinstance(value, dict):
        if any(name not in value for name in node.get("required", []) or []):
            return False
        if len(value) < node.get("minProperties", 0):
            return False
        properties = node.get("properties") or {}
        patterns = node.get("patternProperties") or {}
        for key, item in value.items():
            if key in properties:
                if not valid(item, properties[key], root, depth + 1):
                    return False
                continue
            if any(re.search(pattern, key) for pattern in patterns):
                continue
            extra = node.get("additionalProperties")
            if extra is False:
                return False
            if isinstance(extra, dict) and not valid(item, extra, root, depth + 1):
                return False
    return True


# --------------------------------------------------------------------------
# The lint


class Lint:
    def __init__(self, root: Path, report: Report) -> None:
        self.root = root
        self.report = report
        self.findings: dict[tuple[str, str, str], Finding] = {}
        self.rust = RustIndex(root)
        self.schemas: dict[str, object] = {}
        self.canonical: dict = {}
        self.convention: Convention | None = None
        self.formats: list[dict] = []
        self.by_id: dict[str, dict] = {}
        self.quantities: list[tuple[str, str, str, str, str]] = []

    # Findings and errors -------------------------------------------------

    def error(self, message: str) -> None:
        if message not in self.report.errors:
            self.report.errors.append(message)

    def find(self, rule: str, format_id: str, file: str, at: str, message: str, fix: str) -> None:
        finding = Finding(rule, format_id, file, at, message, fix)
        self.findings.setdefault(finding.key, finding)

    def applies(self, entry: dict, rule: str) -> bool:
        # A build artifact is written and read back by its own product's build,
        # never edited by people, so no authoring rule reaches it; the registry
        # accuracy checks still hold it to the code.
        if entry.get("buildArtifact") is True:
            return False
        exception = entry.get("exceptionClass")
        if exception == "external-format":
            return False
        if exception == "exchange-model":
            return rule in ("CFG-YAML-1", "CFG-CHECK-1", "CFG-SEC-1") or rule.startswith("CFG-SCHEMA-")
        if entry.get("audience") == "generated":
            exempt = {"CFG-SCHEMA-2", "CFG-SCHEMA-6"}
            if entry.get("reader") == "none":
                exempt |= {"CFG-YAML-1", "CFG-CHECK-1"}
            return rule not in exempt
        return True

    # Files ----------------------------------------------------------------

    def schema(self, path: str) -> object | None:
        if path not in self.schemas:
            try:
                self.schemas[path] = load_document(self.root / path)
            except (OSError, ValueError, yaml.YAMLError) as problem:
                self.error(f"{path} does not parse: {problem}")
                self.schemas[path] = None
        return self.schemas[path]

    def rust_text(self, relative: str) -> str | None:
        path = self.root / relative
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8")

    # Registry accuracy ------------------------------------------------------

    def load_registry(self) -> dict | None:
        path = self.root / REGISTRY
        if not path.is_file():
            self.error(f"{REGISTRY} does not exist")
            return None
        try:
            registry = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as problem:
            self.error(f"{REGISTRY} does not parse: {problem}")
            return None
        if not isinstance(registry, dict):
            self.error(f"{REGISTRY} is not a mapping")
            return None
        if (registry.get("apiVersion"), registry.get("kind")) != REGISTRY_HEADER:
            self.error(f"{REGISTRY}: the header is not {REGISTRY_HEADER[0]} {REGISTRY_HEADER[1]}")
        return registry

    def check_symbol(self, fid: str, label: str, reference: object) -> str | None:
        if reference == "none":
            return None
        if not isinstance(reference, dict) or not {"file", "symbol"} <= set(reference):
            self.error(f"{fid}: {label} is neither none nor a file and symbol")
            return None
        text = self.rust_text(reference["file"])
        if text is None:
            self.error(f"{fid}: {label} file {reference['file']} does not exist")
            return None
        code = conformance.code_only(text)
        if not re.search(rf"\b(?:const|static|fn)\s+{re.escape(str(reference['symbol']))}\b", code):
            self.error(f"{fid}: {label} {reference['file']} does not define {reference['symbol']}")
            return None
        return text

    def check_current(self, fid: str, entry: dict) -> None:
        current = entry["current"]
        if not isinstance(current, dict) or not {"apiVersion", "kind", "checkedBy"} <= set(current):
            self.error(f"{fid}: current needs apiVersion, kind, and checkedBy")
            return
        values = [current["apiVersion"], current["kind"]]
        other = current.get("otherHeader")
        if other is not None:
            if not isinstance(other, str) or ": " not in other:
                self.error(f"{fid}: current.otherHeader is not 'key: value'")
            else:
                values.append(other.split(": ", 1)[1])
        values = [value for value in values if isinstance(value, str) and value != "none"
                  and "<" not in value and not value.isdigit()]
        text = self.check_symbol(fid, "checkedBy", current["checkedBy"])
        if text is None or not values:
            return
        if not any(f'"{value}"' in text for value in values):
            self.error(
                f"{fid}: checkedBy {current['checkedBy']['file']} does not contain the current header "
                f"({', '.join(values)}) as a literal"
            )
        symbol = re.escape(str(current["checkedBy"]["symbol"]))
        literal = re.search(rf"\b(?:const|static)\s+{symbol}\s*:[^=]*=\s*\"([^\"]*)\"\s*;", text)
        if literal and literal.group(1) not in values:
            self.error(f"{fid}: checkedBy {current['checkedBy']['symbol']} is {literal.group(1)!r}, not a current header value")

    def check_target(self, fid: str, entry: dict, kinds: dict[str, list[str]]) -> None:
        target = entry["target"]
        if target == "none":
            if not entry.get("exceptionClass") and entry.get("buildArtifact") is not True:
                self.error(f"{fid}: target none needs an exceptionClass or generated buildArtifact")
            return
        if not isinstance(target, dict) or not {"apiVersion", "kind"} <= set(target):
            self.error(f"{fid}: target needs apiVersion and kind")
            return
        kind = str(target["kind"])
        kinds[kind].append(fid)
        prefix = PREFIXES.get(entry["product"], "")
        if not KIND_RE.match(kind) or not kind.startswith(prefix):
            self.error(f"{fid}: target kind {kind} does not match the kind pattern with prefix {prefix}")
        else:
            derived = derive_format(kind, prefix)
            if f"{entry['product']}/{derived}" != fid:
                self.error(f"{fid}: target kind {kind} derives format {derived}, not {fid.split('/', 1)[-1]}")
        api_version = str(target["apiVersion"])
        expected = f"{API_VERSION_PREFIX}{fid}/"
        if not api_version.startswith(expected):
            self.error(f"{fid}: target apiVersion {api_version} is not {expected}<version>")
        else:
            version = api_version[len(expected):]
            if not VERSION_RE.match(version):
                self.error(f"{fid}: target version {version} does not match {VERSION_RE.pattern}")
        top = entry.get("topLevel")
        if top in ("project", "bundle"):
            wanted = f"{prefix}{capitalize(top)}"
            if kind != wanted:
                self.error(f"{fid}: a topLevel {top} format targets kind {wanted} (CFG-ENV-6), not {kind}")

    def check_schema_entry(self, fid: str, entry: dict) -> None:
        schema = entry["schema"]
        if schema == "none":
            return
        if not isinstance(schema, dict) or not {"path", "id", "origin"} <= set(schema):
            self.error(f"{fid}: schema needs path, id, and origin")
            return
        if schema["origin"] not in SCHEMA_ORIGINS:
            self.error(f"{fid}: schema origin {schema['origin']!r} is not one of {', '.join(SCHEMA_ORIGINS)}")
        needed = ("generator", "driftCheck") if schema["origin"] == "generated" else ("differentialTest",)
        for name in needed:
            if name not in schema:
                self.error(f"{fid}: a {schema['origin']} schema needs {name}")
        path = str(schema["path"])
        if not (self.root / path).is_file():
            self.error(f"{fid}: schema {path} does not exist")
            return
        document = self.schema(path)
        if not isinstance(document, dict):
            return
        actual = document.get("$id", "none")
        if actual != schema["id"]:
            self.error(f"{fid}: schema {path} $id is {actual}, the registry records {schema['id']}")
        for name in ("driftCheck", "differentialTest"):
            self.check_names_schema(fid, name, schema.get(name), path)

    def check_names_schema(self, fid: str, label: str, checker: object, path: str) -> None:
        if checker in (None, "none"):
            return
        file = self.root / str(checker)
        if not file.is_file():
            self.error(f"{fid}: {label} {checker} does not exist")
            return
        text = file.read_text(encoding="utf-8")
        directory = str(Path(path).parent)
        names = (path, Path(path).name, directory, "/".join(Path(path).parent.parts[-2:]))
        if not any(name in text for name in names):
            self.error(f"{fid}: {label} {checker} does not name {path} or its directory")

    def check_reader(self, fid: str, entry: dict) -> None:
        reader = entry["reader"]
        if reader == "none":
            if entry["audience"] != "generated" and entry.get("exceptionClass") != "external-format":
                self.error(f"{fid}: reader none is only for a generated or external-format format")
            return
        if not isinstance(reader, dict) or not {"crate", "file", "function", "type"} <= set(reader):
            self.error(f"{fid}: reader needs crate, file, function, and type")
            return
        text = self.rust_text(reader["file"])
        if text is None:
            self.error(f"{fid}: reader file {reader['file']} does not exist")
            return
        if not re.search(rf"\bfn\s+{re.escape(str(reader['function']))}\b", conformance.code_only(text)):
            self.error(f"{fid}: reader {reader['file']} does not define fn {reader['function']}")
        if reader["crate"] not in self.rust.crates:
            self.error(f"{fid}: reader crate {reader['crate']} does not exist")
            return
        if reader["type"] != "untyped" and self.rust.lookup(reader["crate"], str(reader["type"])) is None:
            self.error(
                f"{fid}: reader type {reader['type']} is not defined in {reader['crate']} "
                "or its registry dependencies"
            )

    def check_example(self, fid: str, entry: dict) -> object:
        example = entry["example"]
        if example == "none":
            if isinstance(entry["conformance"], dict) and any(
                value != "none" for value in entry["conformance"].values()
            ):
                self.error(f"{fid}: conformance members need an example")
            return None
        path = self.root / str(example)
        if not path.is_file():
            self.error(f"{fid}: example {example} does not exist")
            return None
        files = entry["files"]
        if files and not any(matches_tail(pattern, str(example)) for pattern in files):
            self.error(f"{fid}: example {example} does not match files {', '.join(files)}")
        if entry["syntax"] == "text":
            return None
        try:
            return load_document(path)
        except (ValueError, yaml.YAMLError) as problem:
            self.error(f"{fid}: example {example} does not parse: {problem}")
            return None

    def check_conformance(self, fid: str, entry: dict, document: object, schema: object) -> None:
        cases = entry["conformance"]
        if cases == "none":
            return
        if (
            not isinstance(cases, dict)
            or not set(CONFORMANCE_CASES) <= set(cases)
            or set(cases) - set(CONFORMANCE_CASES) - set(CONFORMANCE_SHAPES)
        ):
            self.error(
                f"{fid}: conformance needs {', '.join(CONFORMANCE_CASES)}, may add "
                f"{', '.join(CONFORMANCE_SHAPES)}, or is none"
            )
            return
        for shape in CONFORMANCE_SHAPES:
            if shape in cases and cases[shape] != "none" and document is not None:
                self.check_conformance_shape(fid, entry, shape, str(cases[shape]), document, schema)
        for case, expected in CONFORMANCE_CASES.items():
            member = cases[case]
            if member == "none" or document is None:
                continue
            value: object = document
            for token in split_pointer(str(member)):
                if isinstance(value, dict) and token in value:
                    value = value[token]
                elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
                    value = value[int(token)]
                else:
                    self.error(f"{fid}: conformance {case} {member} does not resolve in the example")
                    break
            else:
                wrong = isinstance(value, bool) != (expected is bool) or not isinstance(value, expected)
                if wrong:
                    self.error(f"{fid}: conformance {case} {member} is a {type(value).__name__} in the example")
                    continue
            if not isinstance(schema, dict) or case not in ("requiredText", "optionalText"):
                continue
            resolved = resolve_member(schema, str(member))
            if resolved is None:
                self.error(f"{fid}: conformance {case} {member} does not resolve in the schema")
                continue
            steps = resolved[0][1]
            if case == "requiredText" and not all(steps):
                self.error(f"{fid}: conformance requiredText {member} is not required by the schema")
            if case == "optionalText" and steps and steps[-1]:
                self.error(f"{fid}: conformance optionalText {member} is required by the schema")

    def check_conformance_shape(
        self, fid: str, entry: dict, shape: str, member: str, document: object, schema: object
    ) -> None:
        value: object = document
        for token in split_pointer(member):
            if isinstance(value, dict) and token in value:
                value = value[token]
            elif isinstance(value, list) and token.isdigit() and int(token) < len(value):
                value = value[int(token)]
            else:
                self.error(f"{fid}: conformance {shape} {member} does not resolve in the example")
                return
        problem = None
        if shape == "idList" and not (
            isinstance(value, list) and value
            and all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in value)
        ):
            problem = "is not a list of mappings with an `id` in the example"
        elif shape == "set" and not (
            isinstance(value, list) and value
            and all(item is not None and not isinstance(item, (list, dict)) for item in value)
        ):
            problem = "is not a list of scalars in the example"
        elif shape == "reference" and not (isinstance(value, str) and LOCAL_ID_RE.match(value)):
            problem = "is not an identifier in the example"
        elif shape == "operand" and not isinstance(value, (int, float)):
            problem = "is not a number or boolean in the example"
        elif shape == "relativePath":
            directory = (self.root / str(entry["example"])).parent
            relative = Path(value) if isinstance(value, str) else None
            if (
                relative is None or relative.is_absolute() or ".." in relative.parts
                or not (directory / relative).is_file()
            ):
                problem = "does not name a file in the example's directory"
        if problem:
            self.error(f"{fid}: conformance {shape} {member} {problem}")
            return
        if isinstance(schema, dict) and resolve_member(schema, member) is None:
            self.error(f"{fid}: conformance {shape} {member} does not resolve in the schema")

    def check_members(self, fid: str, entry: dict, schema: object) -> None:
        security = entry["securityMembers"]
        if not isinstance(security, list):
            self.error(f"{fid}: securityMembers is not a list")
            security = []
        restricting = entry["restrictingMembers"]
        if not isinstance(restricting, list):
            self.error(f"{fid}: restrictingMembers is not a list")
            restricting = []
        for item in security:
            if not isinstance(item, dict) or set(item) != {"pointer", "whenOmitted"}:
                self.error(f"{fid}: a securityMembers item needs pointer and whenOmitted")
                continue
            if item["whenOmitted"] not in WHEN_OMITTED:
                self.error(f"{fid}: securityMembers {item['pointer']} whenOmitted {item['whenOmitted']!r} is not one of {', '.join(WHEN_OMITTED)}")
            if isinstance(schema, dict) and resolve_member(schema, str(item["pointer"])) is None:
                self.error(f"{fid}: securityMembers {item['pointer']} does not resolve in the schema")
        for member in restricting:
            if isinstance(schema, dict) and resolve_member(schema, str(member)) is None:
                self.error(f"{fid}: restrictingMembers {member} does not resolve in the schema")

    def check_registry(self, registry: dict) -> None:
        shared = registry.get("sharedSchemas")
        if not isinstance(shared, list):
            self.error(f"{REGISTRY}: sharedSchemas is not a list")
            shared = []
        self.shared = [item for item in shared if isinstance(item, dict)]
        for item in self.shared:
            path = str(item.get("path"))
            if not (self.root / path).is_file():
                self.error(f"{REGISTRY}: shared schema {path} does not exist")
                continue
            self.check_names_schema(str(item.get("id")), "driftCheck", item.get("driftCheck"), path)
            document = self.schema(path)
            if item.get("id") == SHARED_FORMAT and isinstance(document, dict):
                self.canonical = document.get("$defs") or {}
        formats = registry.get("formats")
        if not isinstance(formats, list):
            self.error(f"{REGISTRY}: formats is not a list")
            return
        kinds: dict[str, list[str]] = defaultdict(list)
        for index, entry in enumerate(formats):
            if not isinstance(entry, dict):
                self.error(f"{REGISTRY}: formats/{index} is not a mapping")
                continue
            fid = str(entry.get("id", f"formats/{index}"))
            missing = [name for name in FORMAT_FIELDS if name not in entry]
            for name in missing:
                self.error(f"{fid}: missing field {name}")
            for name in entry:
                if name not in FORMAT_FIELDS and name not in OPTIONAL_FORMAT_FIELDS:
                    self.error(f"{fid}: unknown field {name}")
            if missing:
                continue
            if fid in self.by_id:
                self.error(f"{fid}: the id is not unique")
                continue
            for name, allowed in ENUMS.items():
                if name in entry and entry[name] not in allowed:
                    self.error(f"{fid}: {name} {entry[name]!r} is not one of {', '.join(allowed)}")
            if "buildArtifact" in entry:
                if entry["buildArtifact"] is not True:
                    self.error(f"{fid}: buildArtifact is true or absent; set it to true or remove it")
                elif entry["audience"] != "generated":
                    self.error(f"{fid}: buildArtifact is only for a generated format; set audience: generated or remove buildArtifact")
            if entry["product"] not in PREFIXES or not fid.startswith(f"{entry['product']}/"):
                self.error(f"{fid}: the id does not start with a known product")
                continue
            if not isinstance(entry["files"], list):
                self.error(f"{fid}: files is not a list")
                entry["files"] = []
            self.by_id[fid] = entry
            self.formats.append(entry)
            self.check_current(fid, entry)
            self.check_target(fid, entry, kinds)
            self.check_schema_entry(fid, entry)
            self.check_reader(fid, entry)
            if "emittedBy" in entry:
                self.check_symbol(fid, "emittedBy", entry["emittedBy"])
            document = self.check_example(fid, entry)
            entry["_example"] = document
            schema = self.format_schema(entry)
            self.check_conformance(fid, entry, document, schema)
            self.check_members(fid, entry, schema)
        for kind, ids in kinds.items():
            if len(ids) > 1:
                self.error(f"target kind {kind} is not unique: {', '.join(ids)}")
        self.check_scope(registry)

    def format_schema(self, entry: dict) -> object:
        schema = entry["schema"]
        if not isinstance(schema, dict) or not (self.root / str(schema.get("path"))).is_file():
            return None
        return self.schema(str(schema["path"]))

    def check_scope(self, registry: dict) -> None:
        scope = registry.get("outOfScope", [])
        if not isinstance(scope, list) or not all(
            isinstance(item, dict) and {"files", "reason"} <= set(item) for item in scope
        ):
            self.error(f"{REGISTRY}: every outOfScope item needs files and reason")
            scope = []
        patterns = [str(item["files"]) for item in scope if isinstance(item, dict) and "files" in item]
        known = {str(entry["schema"]["path"]) for entry in self.formats if isinstance(entry["schema"], dict)}
        known |= {str(item.get("path")) for item in self.shared}
        for pattern in patterns:
            regex = glob_regex(pattern)
            for path in sorted(known):
                if regex.match(path):
                    self.error(f"outOfScope {pattern} matches registered schema {path}")
        regexes = [glob_regex(pattern) for pattern in patterns]
        scanned: set[str] = set()
        for pattern in SCHEMA_GLOBS:
            for path in self.root.glob(pattern):
                relative = path.relative_to(self.root).as_posix()
                if "/target/" in relative or "/node_modules/" in relative:
                    continue
                scanned.add(relative)
        for relative in sorted(scanned - known):
            if not any(regex.match(relative) for regex in regexes):
                self.error(f"{relative} is not registered, shared, or out of scope")

    # Registry-level rules ---------------------------------------------------

    def registry_rules(self, entry: dict, configure: dict[str, set[str]], tooling: dict[str, set[str]]) -> None:
        fid = entry["id"]
        current = entry["current"]
        target = entry["target"] if isinstance(entry["target"], dict) else {}
        product = entry["product"]

        def rule(name: str, at: str, message: str, fix: str) -> None:
            if self.applies(entry, name):
                self.find(name, fid, REGISTRY, at, message, fix)

        for member in ("apiVersion", "kind"):
            if current.get(member) == "none":
                rule("CFG-ENV-1", f"/current/{member}", f"the format carries no {member}",
                     f"Write and check {member}: {target.get(member, '<target>')}")
        if target and current.get("apiVersion") not in ("none", None) and current["apiVersion"] != target["apiVersion"]:
            rule("CFG-ENV-2", "/current/apiVersion", f"apiVersion is {current['apiVersion']}",
                 f"Read and write {target['apiVersion']}; refuse the old value with config.retired-api-version")
        if target and current.get("kind") not in ("none", None) and current["kind"] != target["kind"]:
            rule("CFG-ENV-3", "/current/kind", f"kind is {current['kind']}", f"Rename the kind to {target['kind']}")
        top = entry.get("topLevel")
        if top in ("project", "bundle"):
            wanted = f"{PREFIXES[product]}{capitalize(top)}"
            if current.get("kind") != wanted:
                rule("CFG-ENV-6", "/current/kind", f"the top-level {top} file's kind is {current.get('kind')}",
                     f"Name the kind {wanted}")
            if top == "project" and not self.has_project_block(entry):
                rule("CFG-ENV-6", "/topLevel", "no top-level project block holding id and version",
                     "Name the project in a top-level project block with the shared ProjectIdentity members")
        if entry["example"] == "none":
            rule("CFG-SCHEMA-1", "/example", "the format registers no minimal valid example",
                 "Register a minimal valid example")
        schema = entry["schema"]
        if entry["audience"] in ("authored", "operator") or entry.get("exceptionClass"):
            if schema == "none":
                rule("CFG-SCHEMA-2", "/schema", "the format ships no JSON Schema",
                     "Generate a schema from the reader types and hold it with a drift check")
            elif schema.get("origin") == "hand-written":
                rule("CFG-SCHEMA-2", "/schema", "the schema is written by hand",
                     "Generate the schema from the reader types")
            elif schema.get("origin") == "frozen-contract" and schema.get("differentialTest") == "none":
                rule("CFG-SCHEMA-2", "/schema", "the frozen contract has no differential test",
                     "Add a differential test holding the reader to the contract")
            elif schema.get("origin") == "generated" and schema.get("driftCheck") == "none":
                rule("CFG-SCHEMA-2", "/schema", "the generated schema has no drift check",
                     "Add a drift check that runs on every pull request touching the product")
        if isinstance(schema, dict) and target:
            document = self.schema(str(schema["path"])) if (self.root / str(schema["path"])).is_file() else None
            fmt = fid.split("/", 1)[1]
            version = str(target["apiVersion"]).rsplit("/", 1)[-1]
            expected = f"{SCHEMA_ID_PREFIX}{product}/{fmt}/{fmt}.{version}.schema.json"
            if isinstance(document, dict) and document.get("$id") != expected:
                rule("CFG-SCHEMA-3", "", f"$id is {document.get('$id', 'absent')}", f"Set $id to {expected}")
                key = ("CFG-SCHEMA-3", fid, f"{REGISTRY}#")
                finding = self.findings.pop(key, None)
                if finding is not None:
                    finding.file, finding.pointer = str(schema["path"]), "/$id"
                    self.findings.setdefault(finding.key, finding)
        if entry["audience"] in ("authored", "operator"):
            mapped = isinstance(schema, dict) and (
                str(schema["path"]) in configure or Path(str(schema["path"])).name in tooling
            )
            if not mapped:
                if self.applies(entry, "CFG-SCHEMA-6"):
                    self.find("CFG-SCHEMA-6", fid, CONFIGURE, f"/SCHEMAS/{product}",
                              "the format is not mapped for editors",
                              f"Map {schema['path'] if isinstance(schema, dict) else 'its schema'} in editors/configure.py")
            else:
                patterns = configure.get(str(schema["path"]), set()) | tooling.get(Path(str(schema["path"])).name, set())
                for index, pattern in enumerate(entry["files"]):
                    if not any(covers(theirs, str(pattern)) for theirs in patterns):
                        rule("CFG-SCHEMA-6", f"/files/{index}", f"no editor mapping covers the file pattern {pattern}",
                             f"Map {pattern} to {schema['path']} in editors/configure.py, or register the pattern editors map")
        if entry["check"] == "none":
            rule("CFG-CHECK-1", "/check", "a read format with no offline check command",
                 "Add an offline check command")
        reader = entry["reader"]
        if isinstance(reader, dict) and entry["syntax"] in ("yaml", "json") and self.applies(entry, "CFG-YAML-1"):
            text = self.rust_text(str(reader["file"])) or ""
            if "registry_platform_yaml" not in text and "RuntimeConfigLoader" not in text:
                self.find("CFG-YAML-1", fid, str(reader["file"]), f"{reader['function']}()",
                          "the reader does not read through registry-platform-yaml",
                          "Read through registry-platform-yaml")

    def has_project_block(self, entry: dict) -> bool:
        schema = self.format_schema(entry)
        if isinstance(schema, dict):
            properties, required = object_view(schema, schema)
            block = properties.get("project")
            if block is None or "project" not in required:
                return False
            members, _ = object_view(schema, block)
            return {"id", "version"} <= set(members)
        example = entry.get("_example")
        block = example.get("project") if isinstance(example, dict) else None
        return isinstance(block, dict) and {"id", "version"} <= set(block)

    # Schema rules -------------------------------------------------------------

    def name5_match(self, key: str, names: tuple[str, ...]) -> tuple[Name5Row, Name5Item, re.Match[str]] | None:
        if self.convention is None:
            return None
        ancestors = [name.lower() for name in names[:-1]]
        parent = names[-2] if len(names) > 1 else ""

        def fits(item: Name5Item) -> re.Match[str] | None:
            if item.parent is not None and item.parent.lower() != parent.lower():
                return None
            match = item.regex.match(key)
            if match is None:
                return None
            if item.context is not None:
                relation, scope = item.context
                inside = any(scope.lower() in name for name in ancestors)
                if (relation == "outside") == inside:
                    return None
            return match

        # A size inside a pool counts the pool's members (connections or
        # workers), never bytes, so a row whose key counts bytes does not
        # claim it; CFG-NAME-3 still asks for the maximum spelling.
        pooled = any("pool" in name for name in ancestors)
        for row in self.convention.name5:
            if any(fits(item) for item in row.allowed):
                continue
            if pooled and row.allowed and all(item.text.endswith("Bytes") for item in row.allowed):
                continue
            for item in row.refused:
                match = fits(item)
                if match:
                    return row, item, match
        return None

    def schema_rules(self, fid: str, entry: dict | None, path: str, document: dict) -> None:
        def applies(rule: str) -> bool:
            return entry is None or self.applies(entry, rule)

        def find(rule: str, visit: Visit, message: str, fix: str, suffix: tuple[str, ...] = ()) -> None:
            if applies(rule):
                self.find(rule, fid, path, pointer(visit.tokens + suffix), message, fix)

        for visit in walk(document, self.canonical if entry is not None else {}):
            if visit.constraint:
                continue
            node, key = visit.node, visit.member
            exempt_value = len(visit.tokens) == 2 and visit.tokens[0] in ("$defs", "definitions") and visit.tokens[1] in VALUE_TYPES
            numeric = bool(types_of(node) & {"integer", "number"})
            stringy = "string" in types_of(node) and "enum" not in node and "const" not in node and "$ref" not in node
            embedded = False
            name5 = self.name5_match(key, visit.names) if key is not None else None
            if key is not None:
                if visit.parent is None or "propertyNames" not in visit.parent:
                    if not NAME_1.match(key):
                        find("CFG-NAME-1", visit, f"key {key} is not camelCase ASCII", "Spell the key in camelCase, acronyms as words")
                if name5 is not None:
                    row, item, match = name5
                    thing = match.groupdict().get("thing") or match.groupdict().get("Thing")
                    allowed = []
                    for option in row.allowed:
                        text = option.text
                        if thing:
                            text = text.replace("<thing>", thing[:1].lower() + thing[1:])
                            text = text.replace("<Thing>", capitalize(thing))
                        allowed.append(text)
                    find("CFG-NAME-5", visit, f"{key} is a refused spelling of '{row.concept}'",
                         f"Rename to {' or '.join(dict.fromkeys(allowed))}")
                bound = BOUND.match(key)
                if name5 is None and (bound or key.endswith("Limit")):
                    rest = bound.group(2) if bound else capitalize(key[: -len("Limit")])
                    word = "minimum" if bound and bound.group(1) == "min" else "maximum"
                    find("CFG-NAME-3", visit, f"{key} spells a bound with max, min, or Limit", f"Rename to {word}{rest}")
                parts = words(key)
                last = parts[-1] if parts else ""
                if numeric and (last in NONCANONICAL_UNITS or (
                    any(part in DURATION_WORDS for part in parts) and not any(key.endswith(unit) for unit in UNITS)
                )):
                    if last in NONCANONICAL_UNITS:
                        fix = f"Rename to {key[: -len(last)]}{NONCANONICAL_UNITS[last]}"
                    else:
                        fix = f"Put the unit last: {key}Seconds, or the unit the reader uses"
                    find("CFG-NAME-4", visit, f"{key} does not end in a spelled-out unit", fix)
                if stringy and (
                    node.get("format") == "duration"
                    or "PT" in str(node.get("pattern", ""))
                    or re.search(r"\((?:\?:)?[a-z|]*\b(?:ms|s|m|h|d)\b[a-z|]*\)", str(node.get("pattern", "")))
                    or last in DURATION_TEXT_WORDS
                    or "ISO 8601 duration" in str(node.get("description", ""))
                    or (last in TIME_UNITS and key.endswith(last))
                ):
                    find("CFG-QTY-1", visit, f"{key} holds a duration as text", "Write an integer with the unit as the last word of the key")
                if numeric and name5 is None:
                    for unit in TIME_UNITS:
                        if key.endswith(unit) and not key.endswith("WorkingDays") and len(key) > len(unit):
                            self.quantities.append((key[: -len(unit)], unit, fid, path, pointer(visit.tokens)))
                            break
                if (last == "Bytes" or "Size" in parts) and not (types_of(node) & {"integer"}) and not (
                    "$ref" in node or "const" in node or "enum" in node
                ):
                    find("CFG-QTY-3", visit, f"{key} is a size that is not an integer number of bytes", "Write an integer number of bytes; put Bytes last in the key")
                if not exempt_value:
                    if key == "id" and not (refs_to(node, "LocalId") or typed_as_derived_id(node, document)):
                        find(
                            "CFG-ID-1",
                            visit,
                            "id is not typed as $defs/LocalId or $defs/DerivedId",
                            "Type the member with $ref: #/$defs/LocalId, or #/$defs/DerivedId for an identifier the product derives",
                        )
                    if (key == "digest" or key.endswith("Digest")) and not refs_to(node, "Digest"):
                        find("CFG-VAL-6", visit, f"{key} is not typed as $defs/Digest", "Type the member with $ref: #/$defs/Digest")
                    textual = not (types_of(node) and types_of(node) <= {"object", "array", "null"}) and not any(
                        word in node for word in ("enum", "const")
                    ) and not (node.get("$ref") and not refs_to(node, "Url"))
                    if URL_NAME.match(key) and textual and not refs_to(node, "Url"):
                        find("CFG-VAL-7", visit, f"{key} is not typed as $defs/Url", "Type the member with $ref: #/$defs/Url")
                secret_typed = any(SECRET_REFERENCE_TARGET.search(reference) for reference in ref_names(node))
                items_secret = any(SECRET_REFERENCE_TARGET.search(reference) for reference in ref_names(node.get("items")))
                frozen = any(reference.endswith("/secret-ref") for reference in ref_names(node) + ref_names(node.get("items")))
                if key.endswith("Ref") and not secret_typed:
                    find("CFG-SEC-1", visit, f"{key} ends in Ref but is not a SecretReference", "Type the member as $defs/SecretReference, or drop the Ref suffix")
                elif key.endswith("Refs") and not items_secret:
                    find("CFG-SEC-1", visit, f"{key} ends in Refs but is not a list of SecretReference", "Type the items as $defs/SecretReference, or drop the Refs suffix")
                elif (key.endswith("Ref") or key.endswith("Refs")) and frozen:
                    find("CFG-SEC-1", visit, f"{key} is typed through Evidence's frozen $defs/secret-ref", "Type the member as $defs/SecretReference")
                elif SECRET_FILE.search(key):
                    # A report a command only writes may name a file the command generated;
                    # the refusal is for a format something reads as configuration.
                    if entry is None or entry.get("reader") != "none":
                        find("CFG-SEC-1", visit, f"{key} is a bare path to a key or secret file", "Replace it with a <name>Ref member holding a SecretReference")
                elif (secret_typed or items_secret) and not (key.endswith("Ref") or key.endswith("Refs")):
                    find("CFG-SEC-1", visit, f"{key} holds a secret reference but does not end in Ref or Refs", f"Rename to {key}Ref")
                elif INLINE_SECRET.search(key) and stringy:
                    find("CFG-SEC-1", visit, f"{key} holds a secret inline", f"Replace it with {key}Ref holding a SecretReference")
                if EMBED_NAME.match(key) and unconstrained(node):
                    embedded = True
                    find("CFG-EMBED-2", visit, f"{key} embeds a foreign document without the marker",
                         "Mark the member with x-registry-foreign: json-schema-2020-12 or openapi-3.1")
            names = node.get("propertyNames")
            if isinstance(names, dict) and isinstance(names.get("enum"), list):
                for value in names["enum"]:
                    if isinstance(value, str) and not NAME_1.match(value):
                        find("CFG-NAME-1", visit, f"key {value} is not camelCase ASCII", "Spell the key in camelCase", ("propertyNames", "enum", value))
            marked = node.get(MEMBER_NAMES) is True or (visit.parent is not None and visit.parent.get(MEMBER_NAMES) is True and visit.tokens[-1:] == ("items",))
            header = bool(visit.names) and visit.names[-1] in HEADER_MEMBERS
            command = bool(visit.names) and visit.names[-1] == "command"
            if not marked and not header:
                values = [("enum", value) for value in node.get("enum", []) or []]
                if "const" in node:
                    values.append(("const", node["const"]))
                for keyword, value in values:
                    # A sentence is prose for people, not a code (three words or more).
                    if not isinstance(value, str) or len(value.split()) >= 3:
                        continue
                    # A value that names a command is written as the command is typed (`source add`).
                    if command and all(KEBAB_SEGMENT.match(word) for word in value.split(" ")):
                        continue
                    if not all(KEBAB_SEGMENT.match(segment) for segment in re.split(r"[./]", value) if segment):
                        find("CFG-NAME-2", visit, f"value {value} is not lowercase kebab-case", "Spell the value in kebab-case, or mark a member-name enum", (keyword, value))
            if not exempt_value:
                is_map = isinstance(node.get("additionalProperties"), dict) or bool(node.get("patternProperties"))
                if is_map and not (refs_to(node.get("propertyNames"), "LocalId") or refs_to(node.get("propertyNames"), "ExternalId")):
                    find("CFG-ID-1", visit, "a mapping whose keys are not typed", "Declare propertyNames: {$ref: #/$defs/LocalId} or ExternalId")
                items = node.get("items")
                if isinstance(items, dict) and not node.get("uniqueItems"):
                    target = items
                    if isinstance(items.get("$ref"), str):
                        resolved = resolve_ref(document, items["$ref"])
                        target = resolved if isinstance(resolved, dict) else items
                    set_like = (isinstance(target.get("enum"), list) and all(isinstance(value, str) for value in target["enum"])) \
                        or refs_to(items, "LocalId") or refs_to(items, "ExternalId")
                    if set_like:
                        find("CFG-ID-6", visit, "a list of values or identifiers that accepts duplicates", "Declare uniqueItems: true and read it with UniqueList")
            union = self.union_problem(document, node)
            if union:
                find("CFG-ID-7", visit, union, "Tag the variants with a type member, or use single-key mappings")
            sentinel = self.sentinel_problem(document, node)
            if sentinel:
                find("CFG-EMPTY-2", visit, sentinel, "Declare minItems: 1 (or minProperties: 1) beside the unrestricted sentinel")
            if refs_to(node, "DataLiteral"):
                # The one place null is a value; the register records it until
                # the format states unset values explicitly.
                find("CFG-EMPTY-1", visit, "accepts null as a record value through $defs/DataLiteral",
                     "State unset values explicitly; until then record a stable-move entry")
            if "default" in node:
                if node["default"] is None:
                    find("CFG-EMPTY-4", visit, "default: null", "Remove the default and describe what omitting the member means")
                elif not valid(node["default"], {k: v for k, v in node.items() if k != "default"}, document):
                    find("CFG-EMPTY-4", visit, f"the default {json.dumps(node['default'])[:60]} does not validate against the member's schema",
                         "Declare the default the reader uses, valid under the member's schema")
            if "integer" in types_of(node) and isinstance(node.get("type"), (str, list)) and "const" not in node and "enum" not in node:
                # A bounded integer type states minimum 0 beside a maximum below its
                # format's own ceiling; a plain unsigned type only implies it.
                implicit = str(node.get("format", "")).startswith("uint") and node.get("minimum") == 0 \
                    and node.get("maximum", UNSIGNED_CEILING.get(node.get("format"))) == UNSIGNED_CEILING.get(node.get("format"))
                has_minimum = ("minimum" in node and not implicit) or "exclusiveMinimum" in node
                has_maximum = "maximum" in node or "exclusiveMaximum" in node
                if not (has_minimum and has_maximum):
                    missing = [bound for bound, present in (("minimum", has_minimum), ("maximum", has_maximum)) if not present]
                    detail = " (minimum 0 is the unsigned type's implicit bound)" if implicit else ""
                    find("CFG-QTY-4", visit, f"an integer without a stated {' and '.join(missing)}{detail}",
                         "Read it with BoundedU32/BoundedU64 and state both bounds")
            closing = None if visit.conditional else self.closing_problem(document, visit)
            passthrough = self.passthrough_problem(entry, node)
            if passthrough:
                find("CFG-SCHEMA-4", visit, passthrough[0], passthrough[1])
            elif closing and not embedded and PASSTHROUGH not in node:
                find("CFG-SCHEMA-4", visit, closing, "Close the object (additionalProperties or unevaluatedProperties: false)")
        if entry is not None:
            self.schema5(fid, entry, path, document)
            self.envelope_schema(fid, entry, path, document)

    def union_problem(self, root: dict, node: dict) -> str | None:
        for keyword in ("oneOf", "anyOf"):
            branches = node.get(keyword)
            if not isinstance(branches, list):
                continue
            # anyOf branches that only require members may all hold at once:
            # they state "at least one of these members", not a choice of variant.
            if keyword == "anyOf" and all(isinstance(branch, dict) and set(branch) == {"required"} for branch in branches):
                continue
            resolved = []
            for branch in branches:
                parts = expand(root, branch)
                if not parts or types_of(parts[0]) == {"null"} or parts[0].get("type") == "null":
                    continue
                resolved.append(parts)
            if len(resolved) < 2:
                continue
            kinds = [branch_kind(root, parts) for parts in resolved]
            if all(kind == "unit" for kind in kinds):
                continue
            objects = [parts for parts, kind in zip(resolved, kinds) if kind == "object"]
            units = [parts for parts, kind in zip(resolved, kinds) if kind == "unit"]
            tags = discriminators(root, objects)
            single = bool(objects) and all(single_key(root, parts[0]) for parts in objects)
            if objects and tags:
                if "type" not in tags and not ok_envelope(root, objects, tags):
                    return f"a union tagged by {', '.join(sorted(tags))}, not type"
            # `unrestricted` (CFG-EMPTY-2) is a sentinel beside any mapping;
            # `none` (CFG-EMPTY-6) is one beside an untagged single-key
            # mapping, such as `target: none` or `target: {elapsedMinutes: N}`.
            sentinels = [{"unrestricted"}] + ([] if tags else [{"none"}])
            sentinel_units = [parts for parts in units if unit_values(parts) in sentinels]
            if units and objects and (tags or single) and len(sentinel_units) < len(units):
                return "a union mixing unit variants with mapping variants"
            if len(objects) >= 2 and not tags and not single:
                return "mapping variants that no constant member tells apart"
            if kinds.count("array") >= 2:
                return "two list variants told apart by their items"
        return None

    def sentinel_problem(self, root: dict, node: dict) -> str | None:
        for keyword in ("anyOf", "oneOf"):
            branches = node.get(keyword)
            if not isinstance(branches, list):
                continue
            expanded = [expand(root, branch) for branch in branches]
            if not any(unit_values(parts) and "unrestricted" in unit_values(parts) for parts in expanded):
                continue
            for parts in expanded:
                problem = empty_form(parts)
                if problem:
                    return f"the unrestricted sentinel sits beside {problem}"
        return None

    def passthrough_problem(self, entry: dict | None, node: dict) -> tuple[str, str] | None:
        if PASSTHROUGH not in node:
            return None
        reason = node[PASSTHROUGH]
        if not isinstance(reason, str) or not reason.strip():
            return (f"an {PASSTHROUGH} annotation with no reason",
                    f"Give {PASSTHROUGH} a sentence saying why the node passes its payload through")
        # A promised format its product reads refuses unknown members in the
        # same position (CFG-SCHEMA-8), so it has no payload to pass through.
        if entry is not None and entry.get("stability") == "promised" and entry.get("reader") != "none":
            return (f"an {PASSTHROUGH} annotation in a promised format its product reads",
                    f"Describe and close the object, and remove {PASSTHROUGH}")
        return None

    def closing_problem(self, root: dict, visit: Visit) -> str | None:
        node = visit.node
        if node.get("additionalProperties") is True or node.get("unevaluatedProperties") is True:
            return "the object accepts unknown members"
        own = node.get("properties") or {}
        closed_additional = node.get("additionalProperties") is False
        closed_unevaluated = node.get("unevaluatedProperties") is False
        branch = len(visit.tokens) >= 2 and visit.tokens[-2] in ("allOf", "anyOf", "oneOf")
        sources: list[set[str]] = []
        if isinstance(node.get("$ref"), str):
            sources.append(set(object_view(root, resolve_ref(root, node["$ref"]))[0]))
        for keyword in ("allOf", "anyOf", "oneOf"):
            for sub in node.get(keyword) or []:
                sources.append(set(object_view(root, sub)[0]))
        spread = set().union(*sources) - set(own) if sources else set()
        if own and not (closed_additional or closed_unevaluated):
            if branch and ("type" not in node or (visit.parent or {}).get("unevaluatedProperties") is False):
                return None
            return "the object declares members without closing them"
        if own and closed_additional and spread:
            return f"additionalProperties: false refuses members spread across its subschemas ({', '.join(sorted(spread)[:4])})"
        allof_sources = [set(object_view(root, sub)[0]) for sub in node.get("allOf") or []]
        if not own and not closed_unevaluated and sum(1 for names in allof_sources if names) >= 2:
            return "members spread across allOf without unevaluatedProperties: false"
        if (
            "object" in types_of(node) and not own and not node.get("patternProperties")
            and "additionalProperties" not in node and not closed_unevaluated
            and not any(keyword in node for keyword in ("$ref", "allOf", "anyOf", "oneOf", "propertyNames"))
        ):
            return "an object schema with no members accepts any member"
        return None

    def schema5(self, fid: str, entry: dict, path: str, document: dict) -> None:
        if not self.applies(entry, "CFG-SCHEMA-5"):
            return
        covered = {row.runtime_schema for row in conformance.ROWS if isinstance(row.runtime_schema, str)}
        covered |= {hand.path for row in conformance.ROWS for hand in row.hand_schemas}
        for keyword in ("$defs", "definitions"):
            for name, sub in (document.get(keyword) or {}).items():
                stem = shared_stem(name)
                at = f"/{keyword}/{escape(name)}"
                if stem in SHARED_STEMS and name != SHARED_STEMS[stem]:
                    self.find("CFG-SCHEMA-5", fid, path, at,
                              f"{name} redeclares the shared block {SHARED_STEMS[stem]}",
                              f"Embed {SHARED_STEMS[stem]} unchanged from the platform schema")
                elif name in SHARED_BLOCKS and name in self.canonical and sub != self.canonical[name] and path not in covered:
                    self.find("CFG-SCHEMA-5", fid, path, at,
                              f"{name} differs from the platform definition",
                              f"Embed {name} unchanged from the platform schema")

    def envelope_schema(self, fid: str, entry: dict, path: str, document: dict) -> None:
        if not self.applies(entry, "CFG-ENV-1"):
            return
        parts = expand(document, document)
        _, required = object_view(document, document)
        for member in ("apiVersion", "kind"):
            value = entry["current"].get(member)
            if value in (None, "none"):
                continue
            holder = next((part for part in parts if member in (part.get("properties") or {})), None)
            if holder is None:
                self.find("CFG-ENV-1", fid, path, "/properties", f"the schema does not declare {member}",
                          f"Declare {member} with const {value}")
                continue
            if member not in required:
                self.find("CFG-ENV-1", fid, path, "/required", f"the schema does not require {member}",
                          f"List {member} in required")
            sub = holder["properties"][member]
            values = [sub.get("const")] if isinstance(sub, dict) and "const" in sub else (
                sub.get("enum") if isinstance(sub, dict) and isinstance(sub.get("enum"), list) and len(sub["enum"]) == 1 else []
            )
            if value not in values:
                at = node_pointer(document, holder) or ""
                self.find("CFG-ENV-1", fid, path, f"{at}/properties/{member}",
                          f"{member} is not a const equal to {value}", f"Declare {member} with const {value}")

    def restricting(self, entry: dict, path: str, document: dict) -> None:
        for member in entry["restrictingMembers"]:
            resolved = resolve_member(document, str(member))
            if not resolved:
                continue
            node = resolved[0][0]
            at = node_pointer(document, node)
            if at is None:
                continue
            parts = expand(document, node)
            problem = empty_form(parts)
            for group in alternatives(document, node):
                for branch in group:
                    problem = problem or empty_form(branch)
            if problem and self.applies(entry, "CFG-EMPTY-2"):
                self.find("CFG-EMPTY-2", entry["id"], path, at, f"the restricting member {member} accepts {problem}",
                          "Refuse empty: declare minItems: 1 (or minProperties: 1) and no empty default")

    def quantity_units(self) -> None:
        stems: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
        seen = set()
        for stem, unit, fid, path, at in self.quantities:
            if (path, at, fid) in seen:
                continue
            seen.add((path, at, fid))
            stems[stem[:1].lower() + stem[1:]].append((unit, fid, path, at))
        for stem, uses in sorted(stems.items()):
            counts = Counter(unit for unit, _, _, _ in uses)
            if len(counts) < 2:
                continue
            majority = sorted(counts, key=lambda unit: (-counts[unit], TIME_UNITS.index(unit)))[0]
            for unit, fid, path, at in uses:
                if unit != majority:
                    entry = self.by_id.get(fid)
                    if entry is None or self.applies(entry, "CFG-QTY-2"):
                        self.find("CFG-QTY-2", fid, path, at,
                                  f"stem {stem} uses {unit} here and {majority} in {counts[majority]} other places",
                                  f"Rename to {stem}{majority}, or move every use of the stem to one unit")

    # Source lint ----------------------------------------------------------------

    def source_rules(self) -> None:
        seen: set[tuple[Path, str]] = set()
        for entry in self.formats:
            reader = entry["reader"]
            if not isinstance(reader, dict) or reader.get("type") in (None, "untyped"):
                continue
            if reader.get("crate") not in self.rust.crates or entry.get("exceptionClass") == "external-format":
                continue
            start = self.rust.lookup(reader["crate"], str(reader["type"]))
            queue = [start] if start else []
            while queue:
                item = queue.pop(0)
                if (item.path, item.name) in seen:
                    continue
                seen.add((item.path, item.name))
                queue += self.lint_item(entry, item)

    def follow(self, entry: dict, item: RustItem, text: str) -> list[RustItem]:
        found = []
        for match in re.finditer(r"((?:\w+::)*)([A-Z]\w*)", text):
            path = match.group(1).split("::")[0] if match.group(1) else None
            target = self.rust.lookup(entry["reader"]["crate"], match.group(2), item, path)
            if target is not None:
                found.append(target)
        return found

    def lint_item(self, entry: dict, item: RustItem) -> list[RustItem]:
        fid = entry["id"]
        file = item.path.relative_to(self.root).as_posix()
        if item.kind == "type":
            if SET_TYPES.search(item.body) and self.applies(entry, "CFG-ID-6"):
                self.find("CFG-ID-6", fid, file, item.name, f"{item.name} is an alias of a set type that collapses duplicates",
                          "Use UniqueList<T> from registry-platform-yaml")
            return self.follow(entry, item, item.body)
        following: list[RustItem] = []
        for match in re.finditer(r"\b(?:try_from|from)\s*=\s*\"([^\"]+)\"", item.raw_attributes):
            following += self.follow(entry, item, match.group(1))
        if not re.search(r"\bDeserialize\b", item.attributes):
            return following

        def rule(name: str, at: str, message: str, fix: str) -> None:
            if self.applies(entry, name):
                self.find(name, fid, file, at, message, fix)

        container = serde_attributes(item.attributes)
        untagged = re.search(r"\buntagged\b", container) is not None
        tagged = re.search(r"\btag\s*=", container) is not None
        if untagged:
            rule("CFG-SCHEMA-8", item.name, f"{item.name} derives an untagged union",
                 "Decode it with the shared reader's union helper, with variants that differ by node kind")
        if tagged:
            rule("CFG-SCHEMA-8", item.name, f"{item.name} derives serde's tag",
                 "Decode it with the shared reader's union helper")
        if item.kind == "struct":
            following += self.lint_fields(entry, item, file, item.name, item.body)
            return following
        variants = [leading_attributes(part) for part in split_top(item.body)]
        shapes = []
        for attributes, rest in variants:
            name_match = re.match(r"([A-Z]\w*)\s*(.*)$", rest, re.DOTALL)
            if not name_match:
                continue
            name, payload = name_match.group(1), name_match.group(2).strip()
            shape = "unit" if not payload or payload.startswith("=") else ("struct" if payload.startswith("{") else "tuple")
            shapes.append((attributes, name, payload, shape))
        mixed = not untagged and any(shape == "unit" for *_, shape in shapes) and any(shape != "unit" for *_, shape in shapes)
        for attributes, name, payload, shape in shapes:
            at = f"{item.name}/{name}"
            if re.search(r"\balias\s*=", serde_attributes(attributes)):
                rule("CFG-CHANGE-1", at, f"{at} accepts an alias", "Accept one spelling; refuse the old one with config.removed-key")
            if shape == "unit" and (tagged or mixed):
                rule("CFG-SCHEMA-8", at, f"{at} is a unit variant of a tagged union", f"Make it a struct variant ({name} {{}})")
            if shape == "struct":
                following += self.lint_fields(entry, item, file, at, payload[1 : payload.rfind("}")])
            elif shape == "tuple":
                inner = payload[1 : payload.rfind(")")]
                if SET_TYPES.search(inner):
                    rule("CFG-ID-6", at, f"{at} decodes a set type that collapses duplicates", "Use UniqueList<T> from registry-platform-yaml")
                following += self.follow(entry, item, inner)
        return following

    def lint_fields(self, entry: dict, item: RustItem, file: str, owner: str, body: str) -> list[RustItem]:
        following: list[RustItem] = []
        fid = entry["id"]

        def rule(name: str, at: str, message: str, fix: str) -> None:
            if self.applies(entry, name):
                self.find(name, fid, file, at, message, fix)

        tuple_struct = body.startswith("(")
        if tuple_struct:
            body = body[1:-1]
        for index, part in enumerate(split_top(body)):
            attributes, rest = leading_attributes(part)
            if tuple_struct:
                name, field_type = str(index), re.sub(r"^pub(?:\([^)]*\))?\s+", "", rest)
            else:
                field_match = re.match(r"(?:pub(?:\s*\([^)]*\))?\s+)?(\w+)\s*:\s*(.*)$", rest, re.DOTALL)
                if not field_match:
                    continue
                name, field_type = field_match.group(1), field_match.group(2)
            at = f"{owner}/{name}"
            serde = serde_attributes(attributes)
            if re.search(r"\bflatten\b", serde):
                plain = re.sub(r"\s+", "", field_type)
                last = plain.rsplit("::", 1)[-1]
                hint = plain.split("::")[0] if "::" in plain else None
                target = self.rust.lookup(entry["reader"]["crate"], last, item, hint) if re.fullmatch(r"[A-Z]\w*", last) else None
                shared = target is not None and (target.crate.startswith("registry-platform-") or last in SHARED_BLOCKS)
                if not shared:
                    rule("CFG-SCHEMA-8", at, f"{at} flattens {plain}", "Inline the members, or flatten only a platform shared block")
            if re.search(r"\balias\s*=", serde):
                rule("CFG-CHANGE-1", at, f"{at} accepts an alias", "Accept one spelling; refuse the old one with config.removed-key")
            if SET_TYPES.search(field_type):
                rule("CFG-ID-6", at, f"{at} decodes a set type that collapses duplicates", "Use UniqueList<T> from registry-platform-yaml")
            following += self.follow(entry, item, field_type)
        return following

    # Register --------------------------------------------------------------------

    def load_register(self) -> list[dict]:
        path = self.root / REGISTER
        if not path.is_file():
            self.error(f"{REGISTER} does not exist")
            return []
        try:
            register = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as problem:
            self.error(f"{REGISTER} does not parse: {problem}")
            return []
        if not isinstance(register, dict) or (register.get("apiVersion"), register.get("kind")) != REGISTER_HEADER:
            self.error(f"{REGISTER}: the header is not {REGISTER_HEADER[0]} {REGISTER_HEADER[1]}")
            return []
        entries = register.get("exceptions") or []
        if not isinstance(entries, list):
            self.error(f"{REGISTER}: exceptions is not a list")
            return []
        valid_entries: list[dict] = []
        keys: set[tuple] = set()
        for index, entry in enumerate(entries):
            label = f"{REGISTER}: exceptions/{index}"
            if not isinstance(entry, dict):
                self.error(f"{label} is not a mapping")
                continue
            label = f"{label} ({entry.get('rule')} {entry.get('format')} {entry.get('location')})"
            missing = [name for name in ENTRY_FIELDS if not entry.get(name)]
            if missing:
                self.error(f"{label}: missing {', '.join(missing)}")
                continue
            unknown = set(entry) - set(ENTRY_FIELDS) - {"wp"}
            if unknown:
                self.error(f"{label}: unknown field {', '.join(sorted(unknown))}")
            cls = entry["class"]
            if cls not in CLASSES:
                self.error(f"{label}: class {cls!r} is not one of {', '.join(CLASSES)}")
                continue
            if cls == "pending" and not WP_RE.match(str(entry.get("wp", ""))):
                self.error(f"{label}: a pending entry needs wp (WP<n>)")
            if cls != "pending" and "wp" in entry:
                self.error(f"{label}: only a pending entry names a wp")
            owner = self.by_id.get(entry["format"])
            if owner is None and entry["format"] != SHARED_FORMAT:
                self.error(f"{label}: format {entry['format']} is not registered")
            stability = owner["stability"] if owner else "promised"
            if cls == "stable-move" and stability != "promised":
                self.error(f"{label}: stable-move applies only to a promised format")
            if cls == "decision" and not DATE_RE.search(str(entry["resolution"])):
                self.error(f"{label}: a decision entry names a dated decision (YYYY-MM-DD) in its resolution")
            key = (entry["rule"], entry["format"], entry["location"])
            if key in keys:
                self.error(f"{label}: duplicate entry")
                continue
            keys.add(key)
            valid_entries.append(entry)
        return valid_entries

    def reconcile(self, entries: list[dict], strict: bool) -> None:
        recorded = {(entry["rule"], entry["format"], entry["location"]): entry for entry in entries}
        for finding in self.findings.values():
            entry = recorded.pop(finding.key, None)
            if entry is not None:
                finding.status, finding.cls = "recorded", entry["class"]
                if entry["class"] == "pending":
                    owner = self.by_id.get(entry["format"])
                    product = owner["product"] if owner else "platform"
                    self.report.pending[(product, str(entry.get("wp")))] += 1
                    self.report.pending_entries.append(entry)
        self.report.stale = list(recorded.values())
        self.report.findings = sorted(self.findings.values(), key=lambda item: (item.format, item.rule, item.location))
        self.report.strict = strict

    def ratchet(self, entries: list[dict], base: str | None) -> None:
        """CFG-CHANGE-5: compare entries by (rule, format, location) with the base.

        An entry outside the growth classes may not appear, except a
        stable-move entry located in a format's first published schema, and no
        entry may change class; deleting an entry is the only other change the
        register takes. A moved entry is a deletion and an addition, so it is
        refused like any other new one.
        """
        explicit = base is not None
        if base is None:
            merge = git(self.root, "merge-base", "HEAD", "origin/main")
            if merge.returncode != 0:
                self.report.notes.append("CFG-CHANGE-5 not checked: no merge base with origin/main; pass --base")
                return
            base = merge.stdout.strip()
        elif git(self.root, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}").returncode != 0:
            raise UsageError(f"--base {base} does not name a commit")

        def unchecked(reason: str) -> None:
            message = f"CFG-CHANGE-5 not checked: {reason}"
            if explicit:
                self.report.change5.append(f"{message}; pass a --base that carries the register")
            else:
                self.report.notes.append(message)

        shown = git(self.root, "show", f"{base}:{REGISTER}")
        if shown.returncode != 0:
            unchecked(f"{base} has no {REGISTER}")
            return
        try:
            document = yaml.safe_load(shown.stdout) or {}
        except yaml.YAMLError:
            unchecked(f"{REGISTER} at {base} does not parse")
            return
        before = document.get("exceptions") if isinstance(document, dict) else None
        if not isinstance(before, list):
            unchecked(f"{REGISTER} at {base} has no exceptions list")
            return

        def keyed(items: list) -> dict[tuple, str | None]:
            return {
                (item.get("rule"), item.get("format"), item.get("location")): item.get("class")
                for item in items if isinstance(item, dict)
            }

        revealed = self.first_schemas(base)

        def addable(format_id: str | None, location: str | None, entry_class: str | None) -> bool:
            if entry_class in GROWTH_CLASSES:
                return True
            schema = revealed.get(format_id)
            return (
                schema is not None
                and entry_class == "stable-move"
                and str(location or "").startswith(f"{schema}#")
            )

        then, now = keyed(before), keyed(entries)
        for key in sorted(now, key=str):
            rule, format_id, location = key
            if key not in then:
                if not addable(format_id, location, now[key]):
                    self.report.change5.append(
                        f"CFG-CHANGE-5 {rule} {format_id} {location}: a new {now[key]} entry; only "
                        f"{', '.join(sorted(GROWTH_CLASSES))} entries, and stable-move entries in a "
                        "format's first published schema, may be added, so fix the deviation "
                        "instead of recording it"
                    )
            elif now[key] != then[key]:
                self.report.change5.append(
                    f"CFG-CHANGE-5 {rule} {format_id} {location}: the class changed from {then[key]} to "
                    f"{now[key]}; an existing entry may only be deleted"
                )

    def first_schemas(self, base: str) -> dict[str, str]:
        """The schema path of each format registered at `base` without a schema
        that registers one now: its first schema records deviations a correct
        file already wrote, which no earlier register could locate."""
        shown = git(self.root, "show", f"{base}:{REGISTRY}")
        if shown.returncode != 0:
            return {}
        try:
            formats = (yaml.safe_load(shown.stdout) or {}).get("formats") or []
        except yaml.YAMLError:
            return {}
        unpublished = {
            entry.get("id") for entry in formats
            if isinstance(entry, dict) and not isinstance(entry.get("schema"), dict)
        }
        return {
            format_id: entry["schema"]["path"]
            for format_id, entry in self.by_id.items()
            if format_id in unpublished
            and isinstance(entry.get("schema"), dict)
            and isinstance(entry["schema"].get("path"), str)
        }


def unconstrained(node: dict) -> bool:
    constraining = ("properties", "patternProperties", "items", "prefixItems", "$ref", "enum", "const",
                    "allOf", "anyOf", "oneOf", "propertyNames")
    if any(keyword in node for keyword in constraining):
        return False
    if isinstance(node.get("additionalProperties"), dict) or node.get("additionalProperties") is False:
        return False
    return not (types_of(node) & {"string", "integer", "number", "boolean", "array", "null"})


def discriminators(root: dict, objects: list[list[dict]]) -> set[str]:
    """Members every mapping variant fixes to a constant, different in each."""

    seen: dict[str, list[str]] = {}
    for parts in objects:
        properties, _ = object_view(root, parts[0])
        for name, sub in properties.items():
            if not isinstance(sub, dict):
                continue
            if "const" in sub:
                value = sub["const"]
            elif isinstance(sub.get("enum"), list) and len(sub["enum"]) == 1:
                value = sub["enum"][0]
            else:
                continue
            if isinstance(value, (str, bool)):
                seen.setdefault(name, []).append(json.dumps(value))
    return {
        name for name, values in seen.items()
        if len(values) == len(objects) and len(set(values)) == len(values)
    }


def ok_envelope(root: dict, objects: list[list[dict]], tags: set[str]) -> bool:
    """The shared command report envelope, two variants told apart by `ok: true` and `ok: false`."""

    if "ok" not in tags or len(objects) != 2:
        return False
    values = []
    for parts in objects:
        properties, _ = object_view(root, parts[0])
        sub = properties["ok"]
        values.append(sub["const"] if "const" in sub else sub["enum"][0])
    return sorted(values) == [False, True] and all(isinstance(value, bool) for value in values)


def single_key(root: dict, node: dict) -> bool:
    """A mapping variant with exactly one member, which it requires.

    A branch that declares no member and requires exactly one counts too: it
    states "exactly one of these members" over members its parent object
    declares, so the member's presence tells the branches apart.
    """

    properties, required = object_view(root, node)
    if not properties:
        return len(required) == 1
    return len(properties) == 1 and set(properties) <= required


def own_types(part: dict) -> set[str]:
    declared = part.get("type")
    if isinstance(declared, str):
        return {declared}
    if isinstance(declared, list):
        return {item for item in declared if isinstance(item, str)}
    return set()


def unit_values(parts: list[dict]) -> set[str]:
    values: set[str] = set()
    for part in parts:
        if isinstance(part.get("const"), str):
            values.add(part["const"])
        if isinstance(part.get("enum"), list):
            values |= {value for value in part["enum"] if isinstance(value, str)}
    return values


def branch_kind(root: dict, parts: list[dict]) -> str:
    kinds: set[str] = set()
    for part in parts:
        kinds |= types_of(part)
        if part.get("properties") or part.get("required") or isinstance(part.get("additionalProperties"), (dict, bool)):
            kinds.add("object")
        if "items" in part:
            kinds.add("array")
    if unit_values(parts) and not kinds - {"string"}:
        return "unit"
    if "object" in kinds:
        return "object"
    if "array" in kinds:
        return "array"
    return "scalar"


def empty_form(parts: list[dict]) -> str | None:
    for part in parts:
        if part.get("default") in ([], {}):
            return f"an empty default ({json.dumps(part['default'])})"
    arrays = [part for part in parts if "array" in own_types(part) or "items" in part]
    if arrays and not any(int(part.get("minItems", 0) or 0) >= 1 for part in parts):
        return "an empty list"
    maps = [part for part in parts if isinstance(part.get("additionalProperties"), dict) or part.get("patternProperties")]
    if maps and not any(int(part.get("minProperties", 0) or 0) >= 1 for part in parts):
        return "an empty mapping"
    return None


def derive_format(kind: str, prefix: str) -> str:
    stem = kind[len(prefix):] if kind.startswith(prefix) else kind
    if stem.endswith("Config") and len(stem) > len("Config"):
        stem = stem[: -len("Config")]
    return "-".join(part.lower() for part in re.findall(r"[A-Z][a-z0-9]*", stem))


def editor_mappings(root: Path, lint: Lint) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """The file patterns each schema is mapped to, by `editors/configure.py` and by `evidencectl tooling editor`.

    The first is keyed by schema path, the second by schema file name.
    """

    configured: dict[str, set[str]] = {}
    path = root / CONFIGURE
    if not path.is_file():
        lint.error(f"{CONFIGURE} does not exist")
    else:
        try:
            module = ast.parse(path.read_text(encoding="utf-8"))
            for statement in module.body:
                targets = statement.targets if isinstance(statement, ast.Assign) else (
                    [statement.target] if isinstance(statement, ast.AnnAssign) else []
                )
                if any(isinstance(target, ast.Name) and target.id == "SCHEMAS" for target in targets):
                    schemas = ast.literal_eval(statement.value)
                    for pairs in schemas.values():
                        for pair in pairs:
                            configured.setdefault(str(pair[0]), set()).add(str(pair[1]))
        except (SyntaxError, ValueError) as problem:
            lint.error(f"{CONFIGURE}: SCHEMAS does not parse as a literal: {problem}")
    tooling: dict[str, set[str]] = {}
    editor = root / TOOLING_EDITOR
    if editor.is_file():
        text = editor.read_text(encoding="utf-8")
        for name in re.findall(r"include_str!\(\s*\"([^\"]+)\"\s*\)", text):
            tooling.setdefault(Path(name).name, set())
        for glob, name in re.findall(
            r"file_glob:\s*\"([^\"]+)\"\s*,\s*document:\s*include_str!\(\s*\"([^\"]+)\"\s*\)", text
        ):
            tooling[Path(name).name].add(glob)
    return configured, tooling


def run(root: Path, base: str | None = None, strict: bool = False) -> Report:
    root = Path(root)
    report = Report()
    lint = Lint(root, report)
    lint.convention = load_convention(root, report)
    registry = lint.load_registry()
    if registry is None:
        return report
    lint.check_registry(registry)
    configured, tooling = editor_mappings(root, lint)
    for entry in lint.formats:
        lint.registry_rules(entry, configured, tooling)
        schema = entry["schema"]
        if entry.get("exceptionClass") == "external-format" or not isinstance(schema, dict):
            continue
        document = lint.format_schema(entry)
        if isinstance(document, dict):
            lint.schema_rules(entry["id"], entry, str(schema["path"]), document)
            lint.restricting(entry, str(schema["path"]), document)
    for item in lint.shared:
        document = lint.schema(str(item.get("path"))) if (root / str(item.get("path"))).is_file() else None
        if isinstance(document, dict):
            lint.schema_rules(str(item.get("id")), None, str(item.get("path")), document)
    lint.quantity_units()
    lint.source_rules()
    entries = lint.load_register()
    lint.reconcile(entries, strict)
    lint.ratchet(entries, base)
    return report


# --------------------------------------------------------------------------
# Rule coverage


def rule_coverage(root: Path) -> list[str]:
    report = Report()
    convention = load_convention(root, report)
    gaps = list(report.errors)
    if convention is None:
        return gaps
    rows_by_rule: dict[str, list[int]] = defaultdict(list)
    for index, (_, rules, _) in enumerate(convention.summary):
        for rule in rules:
            rows_by_rule[rule].append(index)
    rust_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(root.glob("crates/**/*.rs")) if "/target/" not in path.as_posix()
    )
    corpus = root / CORPUS
    corpus_text = "\n".join(
        f"{path.relative_to(root).as_posix()}\n{path.read_text(encoding='utf-8', errors='replace')}"
        for path in sorted(corpus.rglob("*")) if path.is_file()
    ) if corpus.is_dir() else ""
    test = root / LINT_TEST
    test_text = test.read_text(encoding="utf-8") if test.is_file() else ""
    for rule, level in sorted(convention.rules.items(), key=lambda item: rule_order(item[0])):
        rows = rows_by_rule.get(rule, [])
        if not rows:
            gaps.append(f"{rule}: no Enforcement summary row")
            continue
        if len(rows) > 1:
            gaps.append(f"{rule}: listed in {len(rows)} Enforcement summary rows")
        for index in rows:
            cell, _, gate = convention.summary[index]
            should_row = "(SHOULD)" in cell
            if level == "SHOULD" and not should_row:
                gaps.append(f"{rule}: a SHOULD rule outside the SHOULD row")
            if level == "MUST" and should_row:
                gaps.append(f"{rule}: a MUST rule in the SHOULD row")
            for duty in gate_duties(rule, gate):
                group, number = rule.split("-")[1:]
                snake = f"cfg_{group.lower()}_{number}"
                if duty == "reader unit tests" and not re.search(rf"\bfn\s+\w*{snake}(?![0-9])\w*\s*\(", rust_text):
                    gaps.append(f"{rule}: reader unit tests (no Rust test named {snake}_*)")
                if duty == "conformance corpus" and not re.search(
                    rf"{re.escape(rule)}(?![0-9])|cfg-{group.lower()}-{number}(?![0-9])", corpus_text
                ):
                    gaps.append(f"{rule}: conformance corpus (no case under {CORPUS} cites it)")
                if duty == "lint test" and not re.search(rf"\bdef\s+test_{snake}(?![0-9])\w*\s*\(", test_text):
                    gaps.append(f"{rule}: check-config-conventions.py (no test_{snake}_* in {LINT_TEST})")
    for rule in sorted(rows_by_rule, key=rule_order):
        if rule not in convention.rules:
            gaps.append(f"{rule}: in the Enforcement summary but not declared")
    return gaps


def rule_order(rule: str) -> tuple[str, int]:
    _, group, number = rule.split("-")
    return group, int(number)


def gate_duties(rule: str, gate: str) -> list[str]:
    duties: list[str] = []
    for clause in gate.split(";"):
        clause = clause.strip()
        scoped = re.match(r"^for\s+(CFG-[A-Z]+-[0-9]+(?:\s*(?:,|and)\s*CFG-[A-Z]+-[0-9]+)*)\s+(.*)$", clause)
        if scoped:
            if rule not in re.findall(r"CFG-[A-Z]+-[0-9]+", scoped.group(1)):
                continue
            clause = scoped.group(2)
        lowered = clause.lower()
        if "reader unit tests" in lowered or "parser tests" in lowered:
            duties.append("reader unit tests")
        if "corpus" in lowered:
            duties.append("conformance corpus")
        if any(phrase in lowered for phrase in DIRECT_LINT_PHRASES):
            duties.append("lint test")
    return list(dict.fromkeys(duties))


# --------------------------------------------------------------------------
# Output


def as_json(report: Report) -> dict:
    return {
        "errors": report.errors,
        "findings": [
            {
                "rule": finding.rule, "format": finding.format, "file": finding.file,
                "pointer": finding.pointer, "location": finding.location, "message": finding.message,
                "fix": finding.fix, "status": finding.status, "class": finding.cls,
            }
            for finding in report.findings
        ],
        "stale": report.stale,
        "pending": [
            {"product": product, "wp": wp, "count": count}
            for (product, wp), count in sorted(report.pending.items())
        ],
        "change5": report.change5,
        "notes": report.notes,
    }


def print_text(report: Report, listing: bool) -> None:
    for error in report.errors:
        print(f"error: {error}")
    for finding in report.findings:
        if finding.status == "unrecorded" or listing:
            label = finding.status if finding.status == "unrecorded" else finding.cls
            print(f"{finding.rule} {label} {finding.location} [{finding.format}] {finding.message}; fix: {finding.fix}")
    for entry in report.stale:
        print(f"{entry['rule']} stale {entry['location']} [{entry['format']}] ({entry['class']}): "
              "the location no longer deviates; remove the entry")
    for line in report.change5:
        print(line)
    if report.strict:
        for entry in report.pending_entries:
            print(f"{entry['rule']} pending {entry['location']} [{entry['format']}] {entry.get('wp')}: "
                  "--strict refuses pending entries")
    for note in report.notes:
        print(f"note: {note}")
    for (product, wp), count in sorted(report.pending.items()):
        print(f"pending {product} {wp}: {count}")
    recorded = sum(1 for finding in report.findings if finding.status == "recorded")
    print(
        f"{len(report.findings)} findings ({len(report.unrecorded)} unrecorded, {recorded} recorded), "
        f"{len(report.stale)} stale, {len(report.errors)} errors"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--strict", action="store_true", help="refuse pending exceptions")
    parser.add_argument("--list", action="store_true", help="print recorded findings too")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--base", help="compare the exceptions register with this commit (CFG-CHANGE-5)")
    parser.add_argument("--rule-coverage", action="store_true",
                        help="check that every rule has one Enforcement summary row and its gates exist")
    arguments = parser.parse_args(argv)
    root = arguments.root.resolve()
    if arguments.rule_coverage:
        gaps = rule_coverage(root)
        for gap in gaps:
            print(gap)
        print(f"{len(gaps)} rule coverage gaps")
        return 1 if gaps else 0
    try:
        report = run(root, base=arguments.base, strict=arguments.strict)
    except UsageError as problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    if arguments.format == "json":
        print(json.dumps(as_json(report), indent=2))
    else:
        print_text(report, arguments.list)
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
