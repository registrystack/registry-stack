#!/usr/bin/env python3
"""Check the source half of the YAML reader boundary (CFG-YAML-1).

YAML is read only through `registry-platform-yaml`. Clippy refuses every
direct read through the `disallowed-methods` entries each `clippy.toml`
carries; this checker proves the things clippy cannot see from inside one
package:

- every tracked `clippy.toml` carries every entry, each with a reason that
  names the fix, because a nearer file replaces the workspace one;
- a reader crate that has left the dependency graph is banned in `deny.toml`,
  because clippy is silent about entries for a crate it never loads;
- no source suppression of the lint covers a direct read, except in test code
  that gives a reason, or in production code whose reason names a format
  registered with `exceptionClass: external-format`;
- no crate reaches a reader under another name, where the audit above could
  not see it, and no manifest or Cargo configuration turns the lint off.

`check-yaml-reader-boundary.sh` runs this, then proves with real probes that
every entry still resolves and refuses. With `--plan DIR` it writes the
configurations and the locked reader crates the probes need.

Standard library only: CI runs it before any dependency is installed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path, PurePosixPath

READERS = ("serde_norway", "serde_yaml_ng")
# Other YAML parsers the workspace must never gain a direct use of, each with
# the only crates deny.toml may let bring it in.
OTHER_PARSER_BANS = {
    "saphyr-parser": ("registry-platform-yaml",),
    "serde_yaml": ("hayagriva", "typst-library"),
    "yaml-rust": ("syntect",),
    "serde_yml": (),
    "yaml-rust2": (),
    "saphyr": (),
}
ENTRY_POINTS = (
    "from_str",
    "from_slice",
    "from_reader",
    "from_value",
    "Deserializer::from_str",
    "Deserializer::from_slice",
    "Deserializer::from_reader",
)
FIX = "registry_platform_yaml"
REASON = (
    "read configuration through registry_platform_yaml::Document::decode or "
    "RuntimeConfigLoader (CFG-YAML-1)"
)
SHARED_READER = "crates/registry-platform-yaml/"
REGISTER = "products/platform/config-formats.yaml"
TEST_DIRECTORIES = frozenset({"tests", "benches", "examples"})

READER_NAME = re.compile(r"\b(?:serde_norway|serde_yaml_ng)\b")
SILENCED_LINT = re.compile(
    r"\bclippy\s*::\s*(?:disallowed_methods|style|all)\b|(?<![\w:])warnings\b"
)
LITERAL_START = re.compile(
    r"(?P<raw>(?<!\w)b?r(?P<hashes>#*)\")|(?P<line>//)|(?P<block>/\*)|(?P<string>\")|(?P<char>')"
)
BLOCK_DELIMITER = re.compile(r"/\*|\*/")
STRING_END = re.compile(r'(?:[^"\\]|\\.)*"', re.DOTALL)
ATTRIBUTE_START = re.compile(r"#\s*(?P<inner>!)?\s*\[")
SUPPRESSION_HEAD = re.compile(r"\[\s*(?:allow|expect|cfg_attr)\s*\(")
CFG_ATTR_SUPPRESSION = re.compile(r"\b(?:allow|expect)\s*\(")
CFG_TEST = re.compile(r"\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\b")
PATH_ATTRIBUTE = re.compile(r'\[\s*path\s*=\s*"([^"]*)"')
REASON_TEXT = re.compile(r'\breason\s*=\s*"((?:[^"\\]|\\.)*)"', re.DOTALL)
MODULE_DECLARATION = re.compile(
    r"(?<![\w:])(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?P<name>\w+)\s*(?P<body>[;{])"
)
REEXPORT = re.compile(
    r"\bpub\b(?:\s*\([^)]*\))?\s+use\b[^;]*\b(?:serde_norway|serde_yaml_ng)\b"
)
EXTERN_CRATE = re.compile(r"\bextern\s+crate\s+(?:serde_norway|serde_yaml_ng)\b")
SILENCING_FLAGS = re.compile(
    r"--cap-lints|(?:-A|--allow)[\s=]*(?:clippy::(?:disallowed_methods|style|all)|warnings)\b"
)
SILENCEABLE = {
    "clippy": frozenset({"disallowed_methods", "style", "all"}),
    "rust": frozenset({"warnings"}),
}


def required_paths() -> list[str]:
    return [f"{reader}::{entry}" for reader in READERS for entry in ENTRY_POINTS]


def entry_snippet(path: str) -> str:
    return f'{{ path = "{path}", reason = "{REASON}" }}'


def configuration_problems(name: str, text: str) -> list[str]:
    """Problems with one clippy configuration's YAML reader entries."""

    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [f"{name} does not parse as TOML ({error}), so clippy refuses nothing from it."]
    entries = document.get("disallowed-methods", [])
    by_path: dict[str, object] = {}
    for entry in entries if isinstance(entries, list) else []:
        path = entry if isinstance(entry, str) else entry.get("path") if isinstance(entry, dict) else None
        if isinstance(path, str):
            by_path[path] = entry

    problems = []
    for path in required_paths():
        entry = by_path.get(path)
        if entry is None:
            problems.append(
                f"{name} does not refuse {path}. A nearer clippy.toml replaces the "
                f"workspace one, so add {entry_snippet(path)} to its disallowed-methods."
            )
        elif not isinstance(entry, dict) or FIX not in str(entry.get("reason", "")):
            problems.append(
                f"{name} refuses {path} without naming the fix. Spell the entry "
                f"{entry_snippet(path)}."
            )
        elif entry.get("allow-invalid"):
            problems.append(
                f"{name} sets allow-invalid on {path}, which hides the warning that it "
                "stopped resolving. Remove allow-invalid."
            )
    return problems


def banned_crates(deny_text: str) -> dict[str, dict[str, object]]:
    """The [bans] deny entries of deny.toml, by crate name."""

    bans = tomllib.loads(deny_text).get("bans", {}).get("deny", [])
    banned: dict[str, dict[str, object]] = {}
    for entry in bans:
        if isinstance(entry, str):
            banned[entry.split("@")[0]] = {}
        elif isinstance(entry, dict):
            name = entry.get("crate", entry.get("name", ""))
            banned[str(name).split("@")[0]] = entry
    return banned


def other_parser_ban_problems(deny_text: str) -> list[str]:
    """Problems with the deny.toml bans on every other YAML parser."""

    banned = banned_crates(deny_text)
    problems = []
    for name, allowed in OTHER_PARSER_BANS.items():
        entry = banned.get(name)
        if entry is None:
            problems.append(
                f'deny.toml does not ban {name}. Add {{ crate = "{name}", reason = "..." }} '
                "to [bans] deny, so no crate can read YAML around registry_platform_yaml."
            )
            continue
        extra = sorted(set(entry.get("wrappers", [])) - set(allowed))
        if extra:
            problems.append(
                f"deny.toml lets {', '.join(extra)} bring in {name}. Only "
                f"{', '.join(allowed) or 'no crate'} may."
            )
    return problems


def ban_problems(deny_text: str, absent: set[str] | frozenset[str]) -> list[str]:
    """Problems with the deny.toml bans that stand in for dormant entries."""

    banned = banned_crates(deny_text)
    problems = []
    for reader in sorted(absent):
        entry = banned.get(reader)
        if entry is None:
            problems.append(
                f"{reader} is out of the dependency graph, so clippy is silent about its "
                f"disallowed-methods entries and refuses nothing. Add "
                f'{{ crate = "{reader}", reason = "{REASON}" }} to [bans] deny in deny.toml, '
                "so it cannot come back."
            )
        elif entry.get("wrappers"):
            problems.append(
                f"deny.toml bans {reader} with wrappers, which lets those crates bring it "
                "back. Remove the wrappers."
            )
    return problems


def external_formats(register_text: str) -> frozenset[str]:
    """Format ids the register marks `exceptionClass: external-format`.

    The register is read by line, as the CI classifier reads its manifests,
    because this checker runs without PyYAML; the conventions lint validates
    the register's shape with a full parse.
    """

    found = set()
    current = None
    for line in register_text.splitlines():
        if item := re.match(r"^  - id:\s*['\"]?([^'\"\s]+)['\"]?\s*$", line):
            current = item.group(1)
        elif re.match(r"^\S", line):
            current = None
        elif current and re.match(r"^    exceptionClass:\s*['\"]?external-format['\"]?\s*$", line):
            found.add(current)
    return frozenset(found)


def blank(source: str) -> str:
    """Return the source with comments and literals blanked in place.

    Offsets and line numbers are preserved, so a position found in the blanked
    text names the same place in the original. Lifetimes are kept.
    """

    pieces = []
    position = 0
    length = len(source)
    while (start := LITERAL_START.search(source, position)) is not None:
        begin = start.start()
        kind = start.lastgroup if start.group("raw") is None else "raw"
        if kind == "raw":
            close = source.find('"' + start.group("hashes"), start.end())
            end = length if close < 0 else close + 1 + len(start.group("hashes"))
        elif kind == "line":
            close = source.find("\n", begin)
            end = length if close < 0 else close
        elif kind == "block":
            depth, cursor = 0, begin
            for delimiter in BLOCK_DELIMITER.finditer(source, begin):
                depth += 1 if delimiter.group() == "/*" else -1
                cursor = delimiter.end()
                if depth == 0:
                    break
            end = cursor if depth == 0 else length
        elif kind == "string":
            close = STRING_END.match(source, begin + 1)
            end = length if close is None else close.end()
        elif begin + 1 < length and source[begin + 1] == "\\":
            close = source.find("'", begin + 3)
            end = length if close < 0 else close + 1
        elif begin + 2 < length and source[begin + 2] == "'":
            end = begin + 3
        else:
            pieces.append(source[position : begin + 1])
            position = begin + 1
            continue
        pieces.append(source[position:begin])
        pieces.append(re.sub(r"[^\n]", " ", source[begin:end]))
        position = end
    pieces.append(source[position:])
    return "".join(pieces)


def matching(text: str, start: int, opening: str, closing: str) -> int:
    """Index just past the delimiter closing the one at `start`."""

    depth = 0
    for index in range(start, len(text)):
        character = text[index]
        if character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return index + 1
    return len(text)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


@dataclass
class Attribute:
    start: int
    end: int
    inner: bool
    code: str
    original: str
    item: int = 0


@dataclass
class SourceFile:
    path: str
    text: str

    @cached_property
    def code(self) -> str:
        return blank(self.text)

    @cached_property
    def attributes(self) -> list[Attribute]:
        found = []
        for start in ATTRIBUTE_START.finditer(self.code):
            bracket = start.end() - 1
            end = matching(self.code, bracket, "[", "]")
            found.append(
                Attribute(
                    start.start(),
                    end,
                    start.group("inner") is not None,
                    self.code[bracket:end],
                    self.text[bracket:end],
                )
            )
        # An outer attribute applies to the item after it and after any
        # attributes that follow it.
        item = len(self.code)
        for attribute in reversed(found):
            following = len(self.code[attribute.end :]) - len(self.code[attribute.end :].lstrip())
            if attribute.end + following < item and not self.code.startswith("#", attribute.end + following):
                item = attribute.end + following
            attribute.item = item
            if attribute.inner:
                item = len(self.code)
            else:
                item = attribute.start
        return found

    @cached_property
    def names_a_reader(self) -> bool:
        return READER_NAME.search(self.text) is not None and READER_NAME.search(self.code) is not None

    def module_directory(self) -> PurePosixPath:
        path = PurePosixPath(self.path)
        if path.name in {"mod.rs", "lib.rs", "main.rs", "build.rs"} or path.parent.name in TEST_DIRECTORIES | {"bin"}:
            return path.parent
        return path.parent / path.stem

    def declarations(self) -> list[tuple[int, str, str, list[Attribute]]]:
        """Each `mod` item: its offset, name, body opener, and attributes."""

        by_item: dict[int, list[Attribute]] = {}
        for attribute in self.attributes:
            if not attribute.inner:
                by_item.setdefault(attribute.item, []).append(attribute)
        found = []
        for declaration in MODULE_DECLARATION.finditer(self.code):
            found.append(
                (
                    declaration.start(),
                    declaration.group("name"),
                    declaration.group("body"),
                    by_item.get(declaration.start(), []),
                )
            )
        return found

    @cached_property
    def test_ranges(self) -> list[tuple[int, int]]:
        ranges = []
        for attribute in self.attributes:
            if attribute.inner and CFG_TEST.match(attribute.code):
                ranges.append((0, len(self.code)))
        for offset, _, body, attributes in self.declarations():
            if body == "{" and any(CFG_TEST.match(attribute.code) for attribute in attributes):
                opening = self.code.index("{", offset)
                ranges.append((offset, matching(self.code, opening, "{", "}")))
        return ranges


@dataclass
class Tree:
    files: dict[str, SourceFile] = field(default_factory=dict)

    @classmethod
    def of(cls, sources: dict[str, str]) -> Tree:
        return cls({path: SourceFile(path, text) for path, text in sources.items()})

    def resolve(self, parent: SourceFile, name: str, attributes: list[Attribute]) -> str | None:
        for attribute in attributes:
            if explicit := PATH_ATTRIBUTE.match(attribute.original):
                candidate = PurePosixPath(parent.path).parent / explicit.group(1)
                parts: list[str] = []
                for part in candidate.parts:
                    if part == "..":
                        parts.pop() if parts else None
                    elif part != ".":
                        parts.append(part)
                path = "/".join(parts)
                return path if path in self.files else None
        directory = parent.module_directory()
        for candidate in (directory / f"{name}.rs", directory / name / "mod.rs"):
            if str(candidate) in self.files:
                return str(candidate)
        return None

    def children(self, file: SourceFile, *, only_test: bool = False) -> list[str]:
        found = []
        for _, name, body, attributes in file.declarations():
            if body != ";":
                continue
            if only_test and not any(CFG_TEST.match(attribute.code) for attribute in attributes):
                continue
            if (child := self.resolve(file, name, attributes)) is not None:
                found.append(child)
        return found

    def closure(self, roots: list[str]) -> set[str]:
        seen: set[str] = set()
        pending = list(roots)
        while pending:
            path = pending.pop()
            if path in seen or path not in self.files:
                continue
            seen.add(path)
            if "mod" in self.files[path].text:
                pending.extend(self.children(self.files[path]))
        return seen

    @cached_property
    def test_files(self) -> set[str]:
        roots = []
        for path, file in self.files.items():
            parts = PurePosixPath(path).parts
            name = parts[-1]
            if TEST_DIRECTORIES.intersection(parts[:-1]) or name == "tests.rs" or name.endswith("_tests.rs"):
                roots.append(path)
            elif "test" in file.text and "cfg" in file.text:
                if any(start == 0 and end == len(file.code) for start, end in file.test_ranges):
                    roots.append(path)
                roots.extend(self.children(file, only_test=True))
        return self.closure(roots)

    def in_test_code(self, file: SourceFile, offset: int) -> bool:
        if file.path in self.test_files:
            return True
        return any(start <= offset < end for start, end in file.test_ranges)

    def scope(self, file: SourceFile, attribute: Attribute) -> set[str]:
        """The files whose code a suppression covers."""

        if attribute.inner:
            return self.closure([file.path])
        for offset, name, body, attributes in file.declarations():
            if offset == attribute.item and body == ";":
                child = self.resolve(file, name, attributes)
                return {file.path} | (self.closure([child]) if child else set())
        return {file.path}


def is_suppression(attribute: Attribute) -> bool:
    if not SUPPRESSION_HEAD.match(attribute.code):
        return False
    if attribute.code.lstrip("[ \t\n").startswith("cfg_attr") and not CFG_ATTR_SUPPRESSION.search(
        attribute.code
    ):
        return False
    return SILENCED_LINT.search(attribute.code) is not None


def suppression_problems(
    sources: dict[str, str], external: frozenset[str]
) -> tuple[list[str], list[str]]:
    """Suppressions of the reader lint that cover a direct YAML read.

    Returns the problems and the accepted production suppressions, each named
    with the external format its reason gives.
    """

    tree = Tree.of(sources)
    problems: list[str] = []
    accepted: list[str] = []
    for path, file in sorted(tree.files.items()):
        if path.startswith(SHARED_READER) or not SILENCED_LINT.search(file.text):
            continue
        for attribute in file.attributes:
            if not is_suppression(attribute):
                continue
            covered = tree.scope(file, attribute)
            if not any(tree.files[member].names_a_reader for member in covered):
                continue
            location = f"{path}:{line_of(file.code, attribute.start)}"
            reason = REASON_TEXT.search(attribute.original)
            if reason is None:
                problems.append(
                    f"{location}: this suppression covers a direct YAML read and gives no "
                    "reason. Read through registry_platform_yaml::Document::decode or "
                    'RuntimeConfigLoader, or, in test code reading a tool\'s own output, add reason = "...".'
                )
                continue
            if tree.in_test_code(file, attribute.start):
                continue
            named = sorted(format_id for format_id in external if format_id in reason.group(1))
            if named:
                accepted.append(f"{location} ({', '.join(named)})")
                continue
            problems.append(
                f"{location}: production code reads YAML directly under this suppression. "
                "Read through registry_platform_yaml::Document::decode or RuntimeConfigLoader. "
                f"Only a format {REGISTER} registers with exceptionClass: external-format may "
                "be read directly, and the reason must name its id."
            )
    return problems, accepted


def alias_problems(sources: dict[str, str]) -> list[str]:
    """A reader reachable under another name, where the audit cannot see it."""

    problems = []
    for path, text in sorted(sources.items()):
        if READER_NAME.search(text) is None:
            continue
        code = blank(text)
        for pattern in (REEXPORT, EXTERN_CRATE):
            for found in pattern.finditer(code):
                problems.append(
                    f"{path}:{line_of(code, found.start())}: this makes a YAML reader "
                    "reachable under another name, where the suppression audit cannot see "
                    "it. Import it privately in the file that uses it, or read through "
                    "registry_platform_yaml."
                )
    return problems


def silenced_lints(table: object) -> list[str]:
    found = []
    if not isinstance(table, dict):
        return found
    for tool, names in SILENCEABLE.items():
        lints = table.get(tool, {})
        for name in sorted(names & set(lints) if isinstance(lints, dict) else ()):
            level = lints[name]
            level = level.get("level") if isinstance(level, dict) else level
            if level == "allow":
                found.append(f"{tool}::{name}")
    return found


def rustflags(document: dict[str, object]) -> list[str]:
    tables = [document.get("build", {})]
    targets = document.get("target", {})
    if isinstance(targets, dict):
        tables.extend(targets.values())
    flags = []
    for table in tables:
        value = table.get("rustflags") if isinstance(table, dict) else None
        if isinstance(value, str):
            flags.append(value)
        elif isinstance(value, list):
            flags.append(" ".join(str(flag) for flag in value))
    return flags


def manifest_problems(manifests: dict[str, str]) -> list[str]:
    """Manifests and Cargo configuration that rename a reader or turn the lint off."""

    problems = []
    for path, text in sorted(manifests.items()):
        try:
            document = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            problems.append(f"{path} does not parse as TOML ({error}).")
            continue
        if PurePosixPath(path).name == "Cargo.toml":
            for found in re.finditer(r'\bpackage\s*=\s*"(serde_norway|serde_yaml_ng)"', text):
                problems.append(
                    f"{path}:{line_of(text, found.start())}: this renames {found.group(1)}, so "
                    "its calls never name it. Depend on it under its own name."
                )
            workspace = document.get("workspace", {})
            for table in (document.get("lints"), workspace.get("lints") if isinstance(workspace, dict) else None):
                for lint in silenced_lints(table):
                    problems.append(
                        f"{path}: [lints] allows {lint}, which silences the YAML reader lint "
                        "for every crate it reaches. Remove it."
                    )
        else:
            for flags in rustflags(document):
                if SILENCING_FLAGS.search(flags):
                    problems.append(
                        f"{path}: rustflags {flags!r} silence the YAML reader lint. Remove them."
                    )
    return problems


def tracked(root: Path, *patterns: str) -> list[str]:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", *patterns],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return sorted(path for path in listed.split("\0") if path)


def tracked_configurations(root: Path) -> list[str]:
    return [
        path
        for path in tracked(root, "*clippy.toml")
        if PurePosixPath(path).name in {"clippy.toml", ".clippy.toml"}
    ]


def read(root: Path, paths: list[str]) -> dict[str, str]:
    return {path: (root / path).read_text(encoding="utf-8") for path in paths}


def tracked_sources(root: Path) -> dict[str, str]:
    return read(root, tracked(root, "*.rs"))


def tracked_manifests(root: Path) -> dict[str, str]:
    return read(
        root,
        [
            path
            for path in tracked(root, "*Cargo.toml", "*.cargo/config", "*.cargo/config.toml")
            if PurePosixPath(path).name == "Cargo.toml"
            or re.search(r"(^|/)\.cargo/config(\.toml)?$", path)
        ],
    )


def locked_readers(root: Path) -> list[str]:
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    names = {package.get("name") for package in lock.get("package", [])}
    return [reader for reader in READERS if reader in names]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, help="write the probe plan into this directory")
    arguments = parser.parse_args(argv)
    root = arguments.root

    configurations = tracked_configurations(root)
    readers = locked_readers(root)
    absent = frozenset(READERS) - set(readers)
    external = external_formats((root / REGISTER).read_text(encoding="utf-8"))
    sources = tracked_sources(root)

    problems = []
    for name in configurations:
        problems.extend(configuration_problems(name, (root / name).read_text(encoding="utf-8")))
    deny_text = (root / "deny.toml").read_text(encoding="utf-8")
    problems.extend(ban_problems(deny_text, absent))
    problems.extend(other_parser_ban_problems(deny_text))
    suppressions, accepted = suppression_problems(sources, external)
    problems.extend(suppressions)
    problems.extend(alias_problems(sources))
    problems.extend(manifest_problems(tracked_manifests(root)))

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1

    print(f"Every clippy.toml carries the {len(required_paths())} YAML reader entries:")
    for name in configurations:
        print(f"  {name}")
    for reader in sorted(absent):
        print(f"{reader} is out of the dependency graph, and deny.toml bans it.")
    print("Production suppressions accepted for registered external formats:")
    for location in accepted:
        print(f"  {location}")
    if not accepted:
        print("  none")
    if arguments.plan is not None:
        arguments.plan.mkdir(parents=True, exist_ok=True)
        (arguments.plan / "configurations").write_text(
            "".join(f"{name}\n" for name in configurations), encoding="utf-8"
        )
        (arguments.plan / "readers").write_text(
            "".join(f"{reader}\n" for reader in readers), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
