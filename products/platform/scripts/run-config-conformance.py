#!/usr/bin/env python3
"""Run the configuration conformance corpus against the products' check commands.

The corpus under products/platform/conformance/yaml holds one case per reader
rule of products/platform/CONFIG-CONVENTIONS.md. A case is a small mutation of
a format's registered minimal valid example (the `example` of its entry in
products/platform/config-formats.yaml), so one case applies to every format
without a per-format copy. For every registered format with a `check` command
and an example, the runner first checks the unmutated example (the `baseline`
case: exit 0, no diagnostics), then applies each case that applies to the
format, runs the check command with `--format json` against a temporary copy
of the example's project, and asserts the exit status, every diagnostic's
code, path, line, and column, the diagnostic shape, and that the planted
marker value appears nowhere in the output.

A case file (`cases/<id>.yaml`) has these members:

  id          the file name without `.yaml`
  rules       the convention rule IDs the case proves
  summary     one sentence
  appliesTo   optional: `audiences` (list), `envelope: true` (formats whose
              target has a kind), `formats` (list of format ids)
  mutation    optional, one operation:
                append: text              added after the example
                prepend: text             added before it
                replace: text             the whole file
                member: {role, value}     the scalar at the format's
                                          registered `conformance` pointer for
                                          `role` (requiredText, optionalText,
                                          integer, boolean) becomes `value`
                envelope: {apiVersion, kind}
                                          each member's value replaced, or
                                          `remove`; an absent member is added
                removedKeys: {value}      every removed key the harness
                                          declares for the format, inserted
                                          into its parent mapping
                retiredApiVersion: {}     one run per retired apiVersion the
                                          harness declares
                spelling: {role}          the member's key in the other
                                          spelling (camelCase or snake_case),
                                          beside it, with the same value
                duplicateItem: {role}     the first item of the list at the
                                          `idList` or `set` pointer, copied
                                          after its last item
                pathOutside: {role, via}  the file the `relativePath` pointer
                                          names, moved outside the work
                                          directory's project and reached
                                          through `../` segments
                                          (`via: parent`) or through a
                                          symbolic link left in its place
                                          (`via: link`)
                boundaries: {}            one run per integer member of the
                                          example whose schema (the registry's
                                          `schema.path`) bounds it on both
                                          sides: its maximum plus one, then
                                          its minimum minus one
  run         optional, `init`: run the harness's `init` command for the
              format instead of its check, and assert that the file it writes
              starts with a `# yaml-language-server: $schema=` modeline naming
              the format's schema `$id` (or a local copy of that schema); such
              a case takes `expect: {exit: 0, report: false}` and nothing else
  encoding    optional: byteOrderMark, lineEndings (crlf), appendBytes (hex),
              size (pad with comment lines to this many bytes)
  args        optional extra arguments for the check command
  expect      exit; report (default true: stdout is one JSON report); and
              diagnostics, each with code (`any` matches every code; for a
              rule that fixes the place but not the code), path, optional
              severity (default error), at ({line, column} relative to an
              anchor of the mutation, or `file`), optional from (the anchor:
              start, value, key, root, apiVersion, kind, item, itemId, first,
              firstId), optional suggestedAction, message, and related
              ({path, at, from} each)
  human       optional: also run without `--format json` and find each
              diagnostic in the human output

Text in a case expands `{marker}` (the planted value that must never be
printed), `{repeat:N:text}`, and the values of the mutated site: `{pointer}`,
`{key}`, `{numberOfUnit}`, and for `duplicateItem` the copy's `{index}`.

A role pointer that does not resolve in the example is a harness error that
names the registry entry to update, so a moved example member fails loudly
instead of making a case silently inapplicable.

`formats.yaml` beside the cases says how to stage a format whose check needs
more than a copy of the example's directory: `project` (the directory to
copy, default the example's directory), `copies` ({name: {from, set}}, each
available as `{name}` to the check command), `set` ({pointer: template} on
the example), `write` ({path: text} in the project copy), `values`
({name: template}), `prepare` (commands run in order in the work directory
before the check, each program taken from the binary directory, such as one
that generates disposable key material), `digests` (a SHA256SUMS file in the
project copy to refresh), `removedKeys`, `retiredApiVersions`, and `init`
({command, file}: the command that starts a project in `{directory}`, and the
file of this format it writes there, relative to that directory). A format
with an `init` command gets its `run: init` cells even when its check is not
reached.

`expected-failures.yaml` lists the cells that fail because a product has not
yet converged on the conventions, each with a digest of its sorted problem
list, the formats with a check command that are not reached, and the cases
that apply to no format. A failing cell outside it fails the run, and so does
a listed cell whose problems no longer match the digest, or whose problems
include a marker leak, a signal, an exit status above 3, or a timeout: those
are never expected failures. When a format's baseline fails, its other check
cells are `blocked` (not run), so the baseline entry is the format's one
entry. With `--strict`, an entry that no longer holds (a cell that now
passes, a format now reached, a case that now applies) fails the run too, as
does an unlisted unreached format or inapplicable case.
`--write-expected-failures` rewrites the file from the current results; it
is the only writer, and it records no cell that leaks, crashes, or times out.

Run through products/platform/scripts/run-config-conformance.sh, which
provides PyYAML.
"""

from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import importlib.util
import json
import math
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = "products/platform/config-formats.yaml"
CORPUS = "products/platform/conformance/yaml"

MARKER = "CONFORMANCE-MARKER-Q7ZK2W"
# The check command runs with VARIABLE set to the marker and UNSET_VARIABLE
# removed, so a substitution case can name either.
VARIABLE = "REGISTRY_CONFORMANCE_VALUE"
UNSET_VARIABLE = "REGISTRY_CONFORMANCE_UNSET"
BASELINE = "baseline"
TIMEOUT_SECONDS = 120

CODE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$")
RULE = re.compile(r"^CFG-[A-Z]+-[0-9]+$")
PLACEHOLDER = re.compile(r"\{(marker|repeat:(\d+):([^}]*)|[A-Za-z][A-Za-z0-9]*)\}")
LEFTOVER = re.compile(r"\{[A-Za-z][A-Za-z0-9]*\}")

OPERATIONS = (
    "append",
    "prepend",
    "replace",
    "member",
    "envelope",
    "removedKeys",
    "retiredApiVersion",
    "spelling",
    "duplicateItem",
    "pathOutside",
    "boundaries",
)
DEFAULT_FROM = {
    None: "start",
    "append": "start",
    "prepend": "start",
    "replace": "start",
    "member": "value",
    "removedKeys": "key",
    "spelling": "key",
    "retiredApiVersion": "apiVersion",
    "duplicateItem": "item",
    "pathOutside": "value",
    "boundaries": "value",
}
ENVELOPE = ("apiVersion", "kind")
STATUSES = ("pass", "expected failure", "fail", "stale", "blocked", "not applicable")
# An expected diagnostic whose code is ANY_CODE matches a diagnostic of any
# code at its path and position.
ANY_CODE = "any"
OUTSIDE = "conformance-outside"
MODELINE = "# yaml-language-server: $schema="
LEAK = "the output repeats the planted marker value (CFG-SEC-3)"
UNMASKABLE = re.compile(
    r"(?:^|: )(?:killed by signal \d+|the command did not finish within \d+ seconds|exit status (\d+), expected \d+)"
)


class NotApplicable(Exception):
    """The case does not apply to the format; the message says why."""


class HarnessError(Exception):
    """The corpus, harness, or registry is wrong, not the product."""


# --------------------------------------------------------------------------
# Text helpers


def expand(text: str, values: dict[str, str]) -> str:
    """Expand `{marker}`, `{repeat:N:text}`, and named values; leave the rest."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name == "marker":
            return MARKER
        if match.group(2) is not None:
            return match.group(3) * int(match.group(2))
        if name in values:
            return str(values[name])
        return match.group(0)

    return PLACEHOLDER.sub(replace, text)


# The unit words of registry-platform-yaml's messages, in its order.
UNITS = (
    ("WorkingDays", "working days"),
    ("Milliseconds", "milliseconds"),
    ("Seconds", "seconds"),
    ("Minutes", "minutes"),
    ("Hours", "hours"),
    ("Days", "days"),
    ("Bytes", "bytes"),
    ("Degrees", "degrees"),
)


def unit_word(key: str | None) -> str | None:
    """The unit a member's key implies, as the reader's messages name it."""
    if not key:
        return None
    for suffix, word in UNITS:
        alone = suffix[0].lower() + suffix[1:]
        if key.endswith(suffix) or key == alone:
            return word
    return None


def number_of_unit(key: str | None) -> str:
    unit = unit_word(key)
    return f"number of {unit}" if unit else "number"


def spelling_variant(key: str) -> str | None:
    """The other spelling of a key of two or more words, or None."""
    if "_" in key:
        head, *rest = key.split("_")
        return head + "".join(part[:1].upper() + part[1:] for part in rest)
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()
    return snake if "_" in snake else None


def position(text: str, index: int) -> tuple[int, int]:
    """1-based line and column (in characters) of a character index."""
    line = text.count("\n", 0, index) + 1
    column = index - (text.rfind("\n", 0, index) + 1) + 1
    return line, column


def mark(node_mark: yaml.Mark) -> tuple[int, int]:
    return node_mark.line + 1, node_mark.column + 1


# --------------------------------------------------------------------------
# Data


@dataclass
class Site:
    """Where a mutation happened: named positions and expansion values."""

    anchors: dict[str, tuple[int, int]]
    values: dict[str, str] = field(default_factory=dict)


@dataclass
class Variant:
    text: str
    sites: list[Site]
    # Called once the project is staged, with the text and the staging; it
    # returns the text to write and may change the staged files.
    finish: Callable[[str, "Staged"], str] | None = None


@dataclass(frozen=True)
class Format:
    id: str
    syntax: str
    audience: str
    check: str | None
    example: str | None
    kind: str | None
    roles: dict[str, str | None]
    harness: dict[str, Any]
    schema: str | None = None
    schema_id: str | None = None

    def with_harness(self, harness: dict[str, Any]) -> "Format":
        return dataclasses.replace(self, harness=dict(harness))


CASE_KEYS = {"id", "rules", "summary", "appliesTo", "mutation", "encoding", "args", "expect", "human", "run"}
RUN_MODES = ("init",)
APPLIES_KEYS = {"audiences", "envelope", "formats"}
ENCODING_KEYS = {"byteOrderMark", "lineEndings", "appendBytes", "size"}
EXPECT_KEYS = {"exit", "report", "diagnostics"}
DIAGNOSTIC_KEYS = {"severity", "code", "path", "at", "from", "suggestedAction", "message", "related"}
RELATED_KEYS = {"path", "at", "from"}


@dataclass
class Case:
    id: str
    rules: list[str]
    summary: str
    applies_to: dict[str, Any]
    mutation: dict[str, Any] | None
    encoding: dict[str, Any]
    args: list[str]
    expect: dict[str, Any]
    human: bool
    run: str | None = None

    @property
    def operation(self) -> str | None:
        return next(iter(self.mutation)) if self.mutation else None

    @classmethod
    def from_document(cls, doc: Any, stem: str) -> "Case":
        def fail(problem: str) -> HarnessError:
            return HarnessError(f"case {stem}: {problem}")

        if not isinstance(doc, dict):
            raise fail("the file is not a mapping")
        unknown = sorted(set(doc) - CASE_KEYS)
        if unknown:
            raise fail(f"unknown member `{unknown[0]}`")
        if doc.get("id") != stem:
            raise fail("`id` is not the file name")
        rules = doc.get("rules")
        if not isinstance(rules, list) or not rules or not all(isinstance(r, str) and RULE.match(r) for r in rules):
            raise fail("`rules` is not a non-empty list of rule IDs")
        summary = doc.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise fail("`summary` is missing")
        applies = doc.get("appliesTo") or {}
        if not isinstance(applies, dict) or set(applies) - APPLIES_KEYS:
            raise fail("`appliesTo` has an unknown member")
        mutation = doc.get("mutation")
        if mutation is not None:
            if not isinstance(mutation, dict) or len(mutation) != 1 or next(iter(mutation)) not in OPERATIONS:
                raise fail(f"`mutation` is not one of {', '.join(OPERATIONS)}")
        encoding = doc.get("encoding") or {}
        if not isinstance(encoding, dict) or set(encoding) - ENCODING_KEYS:
            raise fail("`encoding` has an unknown member")
        args = doc.get("args") or []
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise fail("`args` is not a list of text")
        expect = doc.get("expect")
        if not isinstance(expect, dict) or set(expect) - EXPECT_KEYS:
            raise fail("`expect` is missing or has an unknown member")
        if not isinstance(expect.get("exit"), int) or expect["exit"] not in (0, 1, 2, 3):
            raise fail("`expect.exit` is not 0, 1, 2, or 3")
        if expect.get("report", True):
            diagnostics = expect.get("diagnostics")
            if not isinstance(diagnostics, list):
                raise fail("`expect.diagnostics` is not a list")
            for item in diagnostics:
                check_expected_diagnostic(item, fail)
        human = doc.get("human", False)
        if not isinstance(human, bool):
            raise fail("`human` is not true or false")
        run = doc.get("run")
        if run is not None:
            if run not in RUN_MODES:
                raise fail(f"`run` is not one of {', '.join(RUN_MODES)}")
            if expect != {"exit": 0, "report": False}:
                raise fail("a `run: init` case expects `{exit: 0, report: false}`")
            extra = sorted({"mutation", "encoding", "args", "human"} & set(doc))
            if extra:
                raise fail(f"a `run: init` case takes no `{extra[0]}`")
        return cls(
            id=stem,
            rules=list(rules),
            summary=summary,
            applies_to=dict(applies),
            mutation=mutation,
            encoding=dict(encoding),
            args=list(args),
            expect=dict(expect),
            human=human,
            run=run,
        )


def check_expected_diagnostic(item: Any, fail) -> None:
    if not isinstance(item, dict) or set(item) - DIAGNOSTIC_KEYS:
        raise fail("an expected diagnostic has an unknown member")
    if not isinstance(item.get("code"), str) or not isinstance(item.get("path"), str):
        raise fail("an expected diagnostic needs `code` and `path`")
    check_at(item.get("at"), fail)
    for related in item.get("related") or []:
        if not isinstance(related, dict) or set(related) - RELATED_KEYS or not isinstance(related.get("path"), str):
            raise fail("a related location needs `path` and `at` only")
        check_at(related.get("at"), fail)


def check_at(at: Any, fail) -> None:
    if at == "file":
        return
    if not isinstance(at, dict) or set(at) != {"line", "column"}:
        raise fail("`at` is not `file` or {line, column}")


# --------------------------------------------------------------------------
# Mutation


def compose(text: str) -> yaml.Node | None:
    try:
        return yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as error:
        raise HarnessError(f"the example text does not parse as YAML: {error}") from error


def segments(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise HarnessError(f"`{pointer}` is not a JSON pointer")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def child(node: yaml.Node | None, segment: str) -> tuple[yaml.Node | None, yaml.Node | None]:
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            if isinstance(key, yaml.ScalarNode) and key.value == segment:
                return key, value
    if isinstance(node, yaml.SequenceNode) and segment.isdigit() and int(segment) < len(node.value):
        return None, node.value[int(segment)]
    return None, None


def find(root: yaml.Node | None, pointer: str) -> tuple[yaml.Node | None, yaml.Node | None]:
    """The key node (None for a list item) and value node at a pointer."""
    key, node = None, root
    for segment in segments(pointer):
        key, node = child(node, segment)
        if node is None:
            return None, None
    return key, node


def find_inserted(root: yaml.Node | None, pointer: str) -> tuple[yaml.Node, yaml.Node]:
    """The key and value at a pointer the mutation itself just wrote."""
    key, node = find(root, pointer)
    if key is None or node is None:
        raise HarnessError(f"the mutated example has no `{pointer}`")
    return key, node


def last_line(node: yaml.Node) -> int:
    """The 0-based line of the last character a node's source covers."""
    if isinstance(node, yaml.MappingNode) and not node.flow_style and node.value:
        return last_line(node.value[-1][1])
    if isinstance(node, yaml.SequenceNode) and not node.flow_style and node.value:
        return last_line(node.value[-1])
    end = node.end_mark
    if end.column == 0 and end.line > node.start_mark.line:
        return end.line - 1
    return end.line


def line_start(text: str, line: int) -> tuple[str, int]:
    """The index where 0-based `line` starts, completing a missing final newline."""
    lines = text.splitlines(keepends=True)
    if line >= len(lines):
        if text and not text.endswith("\n"):
            text += "\n"
        return text, len(text)
    return text, sum(len(item) for item in lines[:line])


def insert_member(text: str, parent: yaml.Node, key: str, value: str) -> str:
    """Add `key: value` as the last member of a mapping node."""
    if not isinstance(parent, yaml.MappingNode):
        raise HarnessError(f"cannot add `{key}` to a node that is not a mapping")
    if parent.flow_style:
        if parent.value:
            index = parent.value[-1][1].end_mark.index
            return text[:index] + f", {key}: {value}" + text[index:]
        index = parent.start_mark.index + 1
        return text[:index] + f"{key}: {value}" + text[index:]
    indent = parent.value[0][0].start_mark.column if parent.value else 0
    text, index = line_start(text, last_line(parent) + 1)
    return text[:index] + " " * indent + f"{key}: {value}\n" + text[index:]


def replace_span(text: str, node: yaml.Node, source: str) -> tuple[str, int]:
    start, end = node.start_mark.index, node.end_mark.index
    return text[:start] + source + text[end:], start


def role_pointer(fmt: Format, role: str) -> str:
    pointer = fmt.roles.get(role)
    if pointer is None:
        raise NotApplicable(f"the format registers no {role} member")
    return pointer


def missing_pointer(fmt: Format, role: str, pointer: str) -> HarnessError:
    return HarnessError(
        f"{fmt.id}: the conformance {role} pointer {pointer} does not resolve in the example;"
        f" update the format's conformance block in {REGISTRY}"
    )


def scalar_at(
    root: yaml.Node | None, pointer: str, fmt: Format, role: str | None = None
) -> tuple[yaml.Node | None, yaml.Node]:
    key, node = find(root, pointer)
    if node is None:
        if role is not None:
            raise missing_pointer(fmt, role, pointer)
        raise HarnessError(f"{fmt.id}: the example has no member at {pointer}")
    if not isinstance(node, yaml.ScalarNode):
        raise HarnessError(f"{fmt.id}: the member at {pointer} is not a scalar")
    return key, node


def site_values(pointer: str) -> dict[str, str]:
    last = segments(pointer)[-1] if pointer else ""
    key = None if last.isdigit() else last
    return {"pointer": pointer, "key": key or "", "numberOfUnit": number_of_unit(key)}


def mutate_member(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    role = str(spec.get("role"))
    pointer = role_pointer(fmt, role)
    key, node = scalar_at(compose(text), pointer, fmt, role)
    text, start = replace_span(text, node, expand(str(spec.get("value", "")), {}))
    anchors = {"start": (1, 1), "value": position(text, start)}
    if key is not None:
        anchors["key"] = mark(key.start_mark)
    return [Variant(text, [Site(anchors, site_values(pointer))])]


def edit_envelope(text: str, spec: dict[str, Any]) -> str:
    for member in ENVELOPE:
        if member not in spec:
            continue
        root = compose(text)
        if root is not None and not isinstance(root, yaml.MappingNode):
            raise HarnessError("the example is not a mapping")
        key, node = child(root, member)
        wanted = spec[member]
        if wanted == "remove":
            if key is not None and node is not None:
                lines = text.splitlines(keepends=True)
                del lines[key.start_mark.line : last_line(node) + 1]
                text = "".join(lines)
            continue
        value = expand(str(wanted), {})
        if node is not None:
            text, _ = replace_span(text, node, value)
            continue
        others = [k for k, _ in (root.value if root is not None else []) if k.value not in ENVELOPE]
        if others:
            index = others[0].start_mark.index - others[0].start_mark.column
            indent = " " * others[0].start_mark.column
        else:
            text, index = line_start(text, last_line(root) + 1 if root is not None else len(text.splitlines()))
            indent = ""
        text = text[:index] + f"{indent}{member}: {value}\n" + text[index:]
    return text


def envelope_anchors(text: str) -> dict[str, tuple[int, int]]:
    anchors = {"start": (1, 1), "root": (1, 1)}
    root = compose(text)
    if isinstance(root, yaml.MappingNode):
        if root.value:
            anchors["root"] = mark(root.value[0][0].start_mark)
        for member in ENVELOPE:
            _, node = child(root, member)
            if node is not None:
                anchors[member] = mark(node.start_mark)
    return anchors


def mutate_envelope(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    if not isinstance(spec, dict) or not spec or set(spec) - set(ENVELOPE):
        raise HarnessError("`envelope` takes apiVersion and kind")
    text = edit_envelope(text, spec)
    return [Variant(text, [Site(envelope_anchors(text))])]


def mutate_removed_keys(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    pointers = fmt.harness.get("removedKeys") or []
    if not pointers:
        raise NotApplicable("the format declares no removed key")
    value = expand(str(spec.get("value", "")), {})
    inserted = []
    for pointer in pointers:
        parts = segments(pointer)
        parent_pointer = "".join("/" + part.replace("~", "~0").replace("/", "~1") for part in parts[:-1])
        root = compose(text)
        _, parent = find(root, parent_pointer)
        if not isinstance(parent, yaml.MappingNode) or child(parent, parts[-1])[1] is not None:
            continue
        text = insert_member(text, parent, parts[-1], value)
        inserted.append(pointer)
    if not inserted:
        raise NotApplicable("the example has no mapping that would hold a removed key")
    root = compose(text)
    sites = []
    for pointer in inserted:
        key, node = find_inserted(root, pointer)
        anchors = {"start": (1, 1), "key": mark(key.start_mark), "value": mark(node.start_mark)}
        sites.append(Site(anchors, site_values(pointer)))
    return [Variant(text, sites)]


def mutate_retired(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    versions = fmt.harness.get("retiredApiVersions") or []
    if not versions:
        raise NotApplicable("the format declares no retired apiVersion")
    variants = []
    for version in versions:
        changed = edit_envelope(text, {"apiVersion": version})
        variants.append(Variant(changed, [Site(envelope_anchors(changed))]))
    return variants


def mutate_spelling(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    role = str(spec.get("role"))
    pointer = role_pointer(fmt, role)
    parts = segments(pointer)
    other = spelling_variant(parts[-1]) if parts else None
    if other is None:
        raise NotApplicable(f"the {role} member's key is one word")
    parent_pointer = pointer[: pointer.rfind("/")]
    root = compose(text)
    _, node = scalar_at(root, pointer, fmt, role)
    _, parent = find(root, parent_pointer)
    if not isinstance(parent, yaml.MappingNode):
        raise NotApplicable(f"the {role} member is not in a mapping")
    if child(parent, other)[1] is not None:
        raise NotApplicable(f"the example already writes `{other}`")
    source = text[node.start_mark.index : node.end_mark.index]
    text = insert_member(text, parent, other, source)
    other_pointer = f"{parent_pointer}/{other}"
    key, value = find_inserted(compose(text), other_pointer)
    anchors = {"start": (1, 1), "key": mark(key.start_mark), "value": mark(value.start_mark)}
    return [Variant(text, [Site(anchors, site_values(other_pointer))])]


def mutate_duplicate_item(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    role = str(spec.get("role"))
    pointer = role_pointer(fmt, role)
    _, node = find(compose(text), pointer)
    if node is None:
        raise missing_pointer(fmt, role, pointer)
    if not isinstance(node, yaml.SequenceNode) or not node.value:
        raise HarnessError(f"{fmt.id}: the {role} member at {pointer} is not a list with an item")
    first, count = node.value[0], len(node.value)
    if node.flow_style:
        source = text[first.start_mark.index : first.end_mark.index]
        index = node.value[-1].end_mark.index
        text = text[:index] + ", " + source + text[index:]
    else:
        dash = text.rfind("-", 0, first.start_mark.index)
        begin = text.rfind("\n", 0, dash) + 1
        if dash < 0 or text[begin:dash].strip() or text[dash + 1 : first.start_mark.index].strip():
            raise HarnessError(f"{fmt.id}: the first item of {pointer} does not start its own `-` line")
        text, end = line_start(text, last_line(first) + 1)
        copy = text[begin:end]
        text, index = line_start(text, last_line(node) + 1)
        text = text[:index] + copy + text[index:]
    _, node = find(compose(text), pointer)
    assert isinstance(node, yaml.SequenceNode)
    anchors = {"start": (1, 1), "item": mark(node.value[count].start_mark), "first": mark(node.value[0].start_mark)}
    for name, item in (("itemId", node.value[count]), ("firstId", node.value[0])):
        _, identifier = child(item, "id")
        if identifier is not None:
            anchors[name] = mark(identifier.start_mark)
    return [Variant(text, [Site(anchors, dict(site_values(pointer), index=str(count)))])]


def mutate_path_outside(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    role = str(spec.get("role"))
    via = spec.get("via")
    if via not in ("parent", "link"):
        raise HarnessError("`pathOutside` takes `via: parent` or `via: link`")
    pointer = role_pointer(fmt, role)
    key, node = scalar_at(compose(text), pointer, fmt, role)
    named = node.value
    name = Path(named).name

    def move_outside(staged: Staged) -> None:
        original = staged.target.parent / named
        if not original.is_file():
            raise HarnessError(f"{fmt.id}: the {role} member names {named}, which the staged project lacks")
        outside = staged.work / OUTSIDE / name
        outside.parent.mkdir(exist_ok=True)
        shutil.copyfile(original, outside)
        original.unlink()
        if via == "link":
            original.symlink_to(os.path.relpath(outside, original.parent))
            return
        # The project is left as if it never held the file: no directory the
        # move emptied, and no digests line naming it.
        if fmt.harness.get("digests"):
            forget_digest(staged, fmt.harness["digests"], original)
        directory = original.parent
        while directory != staged.project and under(directory, staged.project) is not None:
            if any(directory.iterdir()):
                break
            directory.rmdir()
            directory = directory.parent

    start = node.start_mark.index
    if via == "parent":
        text, start = replace_span(text, node, json.dumps(f"../{OUTSIDE}/{name}"))
        length = len(json.dumps(f"../{OUTSIDE}/{name}"))

        def finish(current: str, staged: Staged) -> str:
            move_outside(staged)
            depth = len(staged.target.parent.relative_to(staged.work).parts)
            value = json.dumps("../" * depth + f"{OUTSIDE}/{name}")
            return current[:start] + value + current[start + length :]
    else:

        def finish(current: str, staged: Staged) -> str:
            move_outside(staged)
            return current

    anchors = {"start": (1, 1), "value": position(text, start)}
    if key is not None:
        anchors["key"] = mark(key.start_mark)
    return [Variant(text, [Site(anchors, site_values(pointer))], finish)]


@functools.cache
def lint_module() -> Any:
    """check-config-conventions.py, whose schema helpers read a format's bounds."""
    path = Path(__file__).with_name("check-config-conventions.py")
    spec = importlib.util.spec_from_file_location("check_config_conventions", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


@functools.cache
def load_schema(path: str) -> Any:
    try:
        return lint_module().load_document(Path(path))
    except (OSError, ValueError, yaml.YAMLError) as error:
        raise HarnessError(f"cannot read the schema {path}: {error}") from error


def integer_bound(part: dict, keyword: str) -> int | None:
    value = part.get(keyword)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return {
        "minimum": math.ceil(value),
        "exclusiveMinimum": math.floor(value) + 1,
        "maximum": math.floor(value),
        "exclusiveMaximum": math.ceil(value) - 1,
    }[keyword]


def integer_bounds(schema: Any, pointer: str) -> tuple[int, int] | None:
    """The one (minimum, maximum) pair the schema gives an integer member, or None."""
    lint = lint_module()
    candidates = lint.resolve_member(schema, pointer)
    if not candidates:
        return None
    found = set()
    for node, _ in candidates:
        parts = list(lint.expand(schema, node))
        for group in lint.alternatives(schema, node):
            integers = [branch for branch in group if "integer" in set().union(*(lint.types_of(p) for p in branch))]
            if len(integers) > 1:
                return None
            parts += integers[0] if integers else []
        if "integer" not in set().union(*(lint.types_of(part) for part in parts)):
            return None
        lows = [b for p in parts for k in ("minimum", "exclusiveMinimum") if (b := integer_bound(p, k)) is not None]
        highs = [b for p in parts for k in ("maximum", "exclusiveMaximum") if (b := integer_bound(p, k)) is not None]
        if not lows or not highs:
            return None
        found.add((max(lows), min(highs)))
    return found.pop() if len(found) == 1 else None


def integer_scalars(node: yaml.Node | None, pointer: str = "") -> list[tuple[str, yaml.Node | None, yaml.Node]]:
    """Each plain integer scalar of a composed document, in document order, with its pointer and key."""
    found = []
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            if isinstance(key, yaml.ScalarNode):
                inner = f"{pointer}/{key.value.replace('~', '~0').replace('/', '~1')}"
                if isinstance(value, yaml.ScalarNode):
                    if value.tag == "tag:yaml.org,2002:int" and value.style is None:
                        found.append((inner, key, value))
                else:
                    found += integer_scalars(value, inner)
    elif isinstance(node, yaml.SequenceNode):
        for index, value in enumerate(node.value):
            if isinstance(value, yaml.ScalarNode):
                if value.tag == "tag:yaml.org,2002:int" and value.style is None:
                    found.append((f"{pointer}/{index}", None, value))
            else:
                found += integer_scalars(value, f"{pointer}/{index}")
    return found


def mutate_boundaries(text: str, spec: dict[str, Any], fmt: Format) -> list[Variant]:
    if not fmt.schema:
        raise NotApplicable("the format registers no schema to read bounds from")
    schema = load_schema(fmt.schema)
    variants = []
    for pointer, key, node in integer_scalars(compose(text)):
        bounds = integer_bounds(schema, pointer)
        if bounds is None:
            continue
        for value in (bounds[1] + 1, bounds[0] - 1):
            changed, start = replace_span(text, node, str(value))
            anchors = {"start": (1, 1), "value": position(changed, start)}
            if key is not None:
                anchors["key"] = mark(key.start_mark)
            variants.append(Variant(changed, [Site(anchors, site_values(pointer))]))
    if not variants:
        raise NotApplicable("the example has no integer member its schema bounds on both sides")
    return variants


def mutate(text: str, mutation: dict[str, Any] | None, fmt: Format) -> list[Variant]:
    """The texts one mutation produces from an example, with their anchors."""
    if not mutation:
        return [Variant(text, [Site({"start": (1, 1)})])]
    if len(mutation) != 1:
        raise HarnessError("a mutation has exactly one operation")
    operation, spec = next(iter(mutation.items()))
    if operation in ("append", "prepend", "replace"):
        snippet = expand(str(spec), {})
        if operation == "prepend":
            return [Variant(snippet + text, [Site({"start": (1, 1)})])]
        if operation == "replace":
            return [Variant(snippet, [Site({"start": (1, 1)})])]
        if text and not text.endswith("\n"):
            text += "\n"
        start = (text.count("\n") + 1, 1)
        return [Variant(text + snippet, [Site({"start": start})])]
    handlers = {
        "member": mutate_member,
        "envelope": mutate_envelope,
        "removedKeys": mutate_removed_keys,
        "retiredApiVersion": mutate_retired,
        "spelling": mutate_spelling,
        "duplicateItem": mutate_duplicate_item,
        "pathOutside": mutate_path_outside,
        "boundaries": mutate_boundaries,
    }
    if operation not in handlers:
        raise HarnessError(f"unknown mutation `{operation}`")
    return handlers[operation](text, spec or {}, fmt)


def encode(text: str, encoding: dict[str, Any] | None) -> bytes:
    """The bytes written for a mutated text."""
    encoding = encoding or {}
    if encoding.get("lineEndings") == "crlf":
        text = text.replace("\n", "\r\n")
    data = text.encode("utf-8")
    if encoding.get("byteOrderMark"):
        data = b"\xef\xbb\xbf" + data
    if "appendBytes" in encoding:
        data += bytes.fromhex(str(encoding["appendBytes"]))
    if "size" in encoding:
        need = int(encoding["size"]) - len(data)
        if need < 0:
            raise HarnessError(f"the text is already longer than {encoding['size']} bytes")
        if need and not data.endswith(b"\n"):
            data += b"\n"
            need -= 1
        while need >= 2:
            length = min(need, 1024)
            data += b"#" + b"-" * (length - 2) + b"\n"
            need -= length
        if need == 1:
            data += b"\n"
    return data


# --------------------------------------------------------------------------
# Expectations


def relative(anchor: tuple[int, int], at: dict[str, int]) -> tuple[int, int]:
    """A position stated relative to an anchor: line 1 is the anchor's line."""
    line = anchor[0] + at["line"] - 1
    column = anchor[1] + at["column"] - 1 if at["line"] == 1 else at["column"]
    return line, column


def resolve_position(spec: dict[str, Any], operation: str | None, site: Site) -> tuple[int | None, int | None]:
    at = spec["at"]
    if at == "file":
        return None, None
    name = spec.get("from")
    if name is None:
        if operation not in DEFAULT_FROM:
            raise HarnessError(f"a `{operation}` expectation must say which anchor it is `from`")
        name = DEFAULT_FROM[operation]
    if name not in site.anchors:
        raise HarnessError(f"the mutation has no `{name}` anchor")
    return relative(site.anchors[name], at)


def resolve_expected(
    expect: dict[str, Any], operation: str | None, variant: Variant, target_file: str
) -> list[dict[str, Any]]:
    """The diagnostics a conforming check reports, one per site per entry."""
    resolved = []
    for site in variant.sites:
        for spec in expect.get("diagnostics") or []:
            line, column = resolve_position(spec, operation, site)
            entry: dict[str, Any] = {
                "severity": spec.get("severity", "error"),
                "code": spec["code"],
                "path": expand(spec["path"], site.values),
                "file": target_file,
                "line": line,
                "column": column,
            }
            for member in ("suggestedAction", "message"):
                if member in spec:
                    entry[member] = expand(str(spec[member]), site.values)
            entry["related"] = []
            for related in spec.get("related") or []:
                related_line, related_column = resolve_position(related, operation, site)
                entry["related"].append(
                    {
                        "file": target_file,
                        "line": related_line,
                        "column": related_column,
                        "path": expand(related["path"], site.values),
                    }
                )
            resolved.append(entry)
    return resolved


# --------------------------------------------------------------------------
# Reports


def parse_report(stdout: str) -> tuple[list[Any] | None, list[str]]:
    text = stdout.strip()
    if not text:
        return None, ["the command printed no JSON report"]
    try:
        value = json.loads(text)
    except ValueError:
        return None, ["the output is not one JSON document"]
    if not isinstance(value, dict):
        return None, ["the report is not a JSON object"]
    diagnostics = value.get("diagnostics")
    if not isinstance(diagnostics, list):
        return None, ["the report has no `diagnostics` list"]
    return diagnostics, []


REQUIRED_MEMBERS = ("severity", "code", "path", "message", "suggestedAction")
ALLOWED_MEMBERS = REQUIRED_MEMBERS + ("artifact", "source", "related")
RELATED_MEMBERS = ("file", "line", "column", "path", "message")


def positive(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def shape_problems(diag: Any, kind: str | None) -> list[str]:
    """How a reported diagnostic departs from the one diagnostic shape."""
    if not isinstance(diag, dict):
        return ["the diagnostic is not a JSON object"]
    problems = [f"missing member `{m}`" for m in REQUIRED_MEMBERS if m not in diag]
    problems += [f"unknown member `{m}`" for m in diag if m not in ALLOWED_MEMBERS]
    if "severity" in diag and diag["severity"] not in ("error", "warning"):
        problems.append("severity is not error or warning")
    if "code" in diag and not (isinstance(diag["code"], str) and CODE.match(diag["code"])):
        problems.append("code is not dotted lowercase kebab-case")
    if "path" in diag:
        path = diag["path"]
        if not isinstance(path, str) or (path and not path.startswith("/")):
            problems.append("path is not a JSON pointer")
    for member in ("message", "suggestedAction"):
        if member in diag and not (isinstance(diag[member], str) and diag[member].strip()):
            problems.append(f"{member} is empty")
    if "artifact" in diag:
        if not isinstance(diag["artifact"], str):
            problems.append("artifact is not text")
        elif kind is not None and diag["artifact"] != kind:
            problems.append(f"artifact is not {kind}")
    if "source" in diag:
        problems += source_problems(diag["source"])
    if "related" in diag:
        related = diag["related"]
        if not isinstance(related, list):
            problems.append("related is not a list")
        elif not related:
            problems.append("related is empty")
        else:
            for index, entry in enumerate(related):
                if not isinstance(entry, dict):
                    problems.append(f"related[{index}] is not an object")
                    continue
                problems += [f"related[{index}] has no {m}" for m in RELATED_MEMBERS if m not in entry]
                problems += [f"related[{index}] has unknown member `{m}`" for m in entry if m not in RELATED_MEMBERS]
    return problems


def source_problems(source: Any) -> list[str]:
    if not isinstance(source, dict):
        return ["source is not an object"]
    problems = [f"source has unknown member `{m}`" for m in source if m not in ("file", "line", "column")]
    if not (isinstance(source.get("file"), str) and source["file"]):
        problems.append("source has no file")
    if "line" in source and not positive(source["line"]):
        problems.append("source.line is not a positive integer")
    if "column" in source:
        if "line" not in source:
            problems.append("source.column without source.line")
        elif not positive(source["column"]):
            problems.append("source.column is not a positive integer")
    return problems


def normalized(file: Any) -> str | None:
    return os.path.normpath(file) if isinstance(file, str) and file else None


def describe(code: Any, path: Any, line: Any, column: Any) -> str:
    where = path or "the root"
    if code == ANY_CODE:
        code = "a diagnostic of any code"
    if line is None:
        return f"{code} at {where} (file)"
    return f"{code} at {where} {line}:{column}"


def actual_record(diag: dict[str, Any]) -> dict[str, Any]:
    source = diag.get("source")
    source = source if isinstance(source, dict) else {}
    related = diag.get("related")
    related = related if isinstance(related, list) else []
    return {
        "severity": diag.get("severity"),
        "code": diag.get("code"),
        "path": diag.get("path"),
        "file": normalized(source.get("file")),
        "line": source.get("line"),
        "column": source.get("column"),
        "suggestedAction": diag.get("suggestedAction"),
        "message": diag.get("message"),
        "related": sorted(
            (
                (normalized(r.get("file")), r.get("line"), r.get("column"), r.get("path"))
                for r in related
                if isinstance(r, dict)
            ),
            key=repr,
        ),
    }


def matches(want: dict[str, Any], got: dict[str, Any]) -> bool:
    for member in ("severity", "code", "path", "line", "column"):
        if want[member] != got[member] and not (member == "code" and want[member] == ANY_CODE):
            return False
    if normalized(want["file"]) != got["file"]:
        return False
    for member in ("suggestedAction", "message"):
        if member in want and want[member] != got[member]:
            return False
    if want.get("related"):
        stated = sorted(
            ((normalized(r["file"]), r["line"], r["column"], r["path"]) for r in want["related"]),
            key=repr,
        )
        if stated != got["related"]:
            return False
    return True


def match_problems(expected: list[dict[str, Any]], actual: list[Any]) -> list[str]:
    """Missing and unexpected diagnostics; the match is exact and counted."""
    records = [actual_record(d) for d in actual if isinstance(d, dict)]
    used = [False] * len(records)
    missing = []
    for want in expected:
        for index, got in enumerate(records):
            if not used[index] and matches(want, got):
                used[index] = True
                break
        else:
            missing.append(f"missing {describe(want['code'], want['path'], want['line'], want['column'])}")
    unexpected = [
        f"unexpected {describe(got['code'], got['path'], got['line'], got['column'])}"
        for index, got in enumerate(records)
        if not used[index]
    ]
    return missing + unexpected


def same_file(printed: str, wanted: str) -> bool:
    if os.path.normpath(printed) == os.path.normpath(wanted):
        return True
    return not os.path.isabs(printed) and os.path.normpath(wanted).endswith("/" + os.path.normpath(printed))


def location_matches(location: str, file: str, line: int | None, column: int | None) -> bool:
    if line is None:
        return same_file(location, file)
    suffix = f":{line}:{column}"
    return location.endswith(suffix) and same_file(location[: -len(suffix)], file)


def plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def human_problems(expected: list[dict[str, Any]], output: str) -> list[str]:
    """Expected diagnostics the human output does not show position first."""
    lines = output.splitlines()
    problems = []
    for item in expected:
        code = r"[a-z0-9.-]+" if item["code"] == ANY_CODE else re.escape(item["code"])
        header = re.compile(rf"{re.escape(item['severity'])}\[{code}\] ")
        found = False
        for line in lines:
            if not (start := header.match(line)):
                continue
            location, _, path = line[start.end() :].partition(" ")
            if path == item["path"] and location_matches(location, item["file"], item["line"], item["column"]):
                found = True
                break
        if not found:
            problems.append(
                f"human output has no line for {describe(item['code'], item['path'], item['line'], item['column'])}"
            )
            continue
        for related in item.get("related") or []:
            if not any(note_matches(line, related) for line in lines):
                problems.append(f"human output has no note for {related['path']} {related['line']}:{related['column']}")
    errors = sum(1 for item in expected if item["severity"] == "error")
    warnings = sum(1 for item in expected if item["severity"] == "warning")
    summary = f"{plural(errors, 'error')}, {plural(warnings, 'warning')}"
    if not any(line.startswith(summary) for line in lines):
        problems.append(f"human output has no summary line starting `{summary}`")
    return problems


def note_matches(line: str, related: dict[str, Any]) -> bool:
    _, marker, rest = line.partition("note: ")
    if not marker:
        return False
    location, _, remainder = rest.partition(" ")
    path = related["path"]
    return location_matches(location, related["file"], related["line"], related["column"]) and (
        remainder == path or remainder.startswith(path + " ")
    )


def marker_problems(stdout: bytes, stderr: bytes) -> list[str]:
    if MARKER.encode() in stdout or MARKER.encode() in stderr:
        return [LEAK]
    return []


def sanitize(text: str, work: str) -> str:
    return text.replace(work, "<work>").replace(MARKER, "<marker>")


# --------------------------------------------------------------------------
# Plan


def not_applicable(case: Case, fmt: Format) -> str | None:
    """Why a case does not apply to a format, or None when it does."""
    audiences = case.applies_to.get("audiences")
    if audiences and fmt.audience not in audiences:
        return f"the case applies to {' and '.join(audiences)} files"
    if case.applies_to.get("envelope") and fmt.kind is None:
        return "the format has no envelope"
    formats = case.applies_to.get("formats")
    if formats and fmt.id not in formats:
        return f"the case applies to {', '.join(formats)}"
    if case.run == "init" and not fmt.harness.get("init"):
        return "the harness declares no init command"
    return None


def partition_formats(formats: list[Format]) -> tuple[list[Format], dict[str, str]]:
    reached, skipped = [], {}
    for fmt in formats:
        if not fmt.check:
            skipped[fmt.id] = "no check command"
        elif not fmt.example:
            skipped[fmt.id] = "no example"
        elif fmt.syntax != "yaml":
            skipped[fmt.id] = f"syntax {fmt.syntax}; the corpus mutates YAML text"
        else:
            reached.append(fmt)
    return reached, skipped


def inapplicable_reason(case: Case, reasons: list[str]) -> str:
    audiences = case.applies_to.get("audiences")
    if audiences and all(r.startswith("the case applies to") and r.endswith(" files") for r in reasons):
        words = " or ".join(audiences)
        article = "an" if words[:1] in "aeiou" else "a"
        return f"no reached format is {article} {words} file"
    return "; ".join(sorted(set(reasons))) or "no format is reached"


# --------------------------------------------------------------------------
# Expected failures


@dataclass(frozen=True)
class Listed:
    """An expected failure: why the cell fails, and a digest of its problems."""

    reason: str
    digest: str


@dataclass
class ExpectedFailures:
    failures: dict[tuple[str, str], Listed]
    unreached: dict[str, str]
    inapplicable: dict[str, str]


def digest(problems: list[str]) -> str:
    """A short digest of a cell's problems, independent of their order."""
    return hashlib.sha256("\n".join(sorted(problems)).encode("utf-8")).hexdigest()[:12]


def unmaskable(problem: str) -> bool:
    """A leak, a crash, or a hang: never an expected failure."""
    if problem.endswith(LEAK):
        return True
    match = UNMASKABLE.search(problem)
    return match is not None and (match.group(1) is None or int(match.group(1)) > 3)


def unmasked(problems: list[str], listed: Listed) -> str | None:
    """Why a listed cell's problems still fail the run, or None when the entry covers them."""
    if any(unmaskable(problem) for problem in problems):
        return "a leak, a crash, or a timeout is never an expected failure"
    if digest(problems) != listed.digest:
        return (
            f"its problems changed since expected-failures.yaml recorded digest {listed.digest};"
            " rerun with --write-expected-failures if the change is intended"
        )
    return None


def statuses(
    results: dict[tuple[str, str], list[str]], expected: ExpectedFailures
) -> dict[tuple[str, str], str]:
    status = {}
    for cell, problems in results.items():
        listed = expected.failures.get(cell)
        if problems:
            status[cell] = "expected failure" if listed and unmasked(problems, listed) is None else "fail"
        else:
            status[cell] = "stale" if listed else "pass"
    return status


def reason(problems: list[str]) -> str:
    """The first two problems, which name the exit status and the diagnostics that did not match."""
    shown = "; ".join(problems[:2])
    rest = len(problems) - 2
    if rest <= 0:
        return shown
    return f"{shown} (and {rest} more problem{'' if rest == 1 else 's'})"


EXPECTED_HEADER = """\
# Configuration conformance cells that fail today, and why.
#
# Written by `products/platform/scripts/run-config-conformance.sh
# --write-expected-failures` against binaries built from this tree. A failing
# cell is a format whose reader has not yet converged on the conventions in
# products/platform/CONFIG-CONVENTIONS.md, not a reason to weaken a case:
# remove the entry when the product conforms. Each entry's digest covers the
# cell's sorted problems, so a listed cell whose problems change fails the run;
# a leak, a crash, or a timeout is never listed. A format whose baseline fails
# has only its baseline entry: its other cells do not run. The runner fails on
# a failing cell missing here, and with --strict on an entry that no longer
# holds.
"""


def write_expected_failures(path: Path, value: ExpectedFailures, case_order: list[str]) -> None:
    order = {case: index for index, case in enumerate(case_order)}
    document = {
        "expectedFailures": [
            {"format": fmt, "case": case, "reason": listed.reason, "digest": listed.digest}
            for (fmt, case), listed in sorted(
                value.failures.items(), key=lambda item: (item[0][0], order.get(item[0][1], len(order)), item[0][1])
            )
        ],
        "unreachedFormats": [{"format": fmt, "reason": text} for fmt, text in sorted(value.unreached.items())],
        "inapplicableCases": [
            {"case": case, "reason": text}
            for case, text in sorted(value.inapplicable.items(), key=lambda item: (order.get(item[0], len(order)), item[0]))
        ],
    }
    body = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=4096)
    path.write_text(EXPECTED_HEADER + "\n" + body, encoding="utf-8")


EXPECTED_SECTIONS = {
    "expectedFailures": ("format", "case", "reason", "digest"),
    "unreachedFormats": ("format", "reason"),
    "inapplicableCases": ("case", "reason"),
}


def load_expected_failures(path: Path) -> ExpectedFailures:
    value = ExpectedFailures({}, {}, {})
    if not path.is_file():
        return value
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(document, dict):
        raise HarnessError(f"{path.name} is not a mapping")
    for section in document:
        if section not in EXPECTED_SECTIONS:
            raise HarnessError(f"{path.name}: unknown member `{section}`")
    targets = {
        "expectedFailures": value.failures,
        "unreachedFormats": value.unreached,
        "inapplicableCases": value.inapplicable,
    }
    for section, members in EXPECTED_SECTIONS.items():
        entries = document.get(section) or []
        if not isinstance(entries, list):
            raise HarnessError(f"{path.name}: `{section}` is not a list")
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != set(members):
                raise HarnessError(f"{path.name}: a `{section}` entry needs exactly {', '.join(members)}")
            if not all(isinstance(entry[m], str) and entry[m] for m in members):
                raise HarnessError(f"{path.name}: a `{section}` entry has an empty member")
            if "digest" in entry and not re.fullmatch(r"[0-9a-f]{12}", entry["digest"]):
                raise HarnessError(f"{path.name}: a `{section}` digest is not 12 lowercase hexadecimal digits")
            names = [m for m in members if m not in ("reason", "digest")]
            values = tuple(entry[m] for m in names)
            key = values[0] if len(names) == 1 else values
            if key in targets[section]:
                raise HarnessError(f"{path.name}: `{section}` lists {key} twice")
            targets[section][key] = Listed(entry["reason"], entry["digest"]) if "digest" in entry else entry["reason"]
    return value


# --------------------------------------------------------------------------
# Loading


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise HarnessError(f"cannot read {path}: {error}") from error


def load_cases(directory: Path) -> list[Case]:
    cases = [Case.from_document(load_yaml(path), path.stem) for path in sorted(directory.glob("*.yaml"))]
    return sorted(cases, key=lambda case: (case.id != BASELINE, case.id))


def none(value: Any) -> Any:
    return None if value in (None, "none") else value


def load_registry(path: Path) -> list[Format]:
    document = load_yaml(path)
    if not isinstance(document, dict) or not isinstance(document.get("formats"), list):
        raise HarnessError(f"{path} has no `formats` list")
    root = path.parents[2]
    formats = []
    for entry in document["formats"]:
        target = entry.get("target")
        roles = entry.get("conformance")
        schema = entry.get("schema") if isinstance(entry.get("schema"), dict) else {}
        formats.append(
            Format(
                id=entry["id"],
                syntax=entry.get("syntax", "yaml"),
                audience=entry.get("audience", "authored"),
                check=none(entry.get("check")),
                example=none(entry.get("example")),
                kind=target.get("kind") if isinstance(target, dict) else None,
                roles={role: none(pointer) for role, pointer in roles.items()} if isinstance(roles, dict) else {},
                harness={},
                schema=str(root / schema["path"]) if isinstance(schema.get("path"), str) else None,
                schema_id=schema["id"] if isinstance(schema.get("id"), str) else None,
            )
        )
    return formats


HARNESS_KEYS = {
    "project", "copies", "set", "write", "values", "prepare", "digests", "removedKeys", "retiredApiVersions", "init"
}


def load_harness(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    document = load_yaml(path) or {}
    formats = document.get("formats") if isinstance(document, dict) else None
    if not isinstance(formats, dict) or set(document) != {"formats"}:
        raise HarnessError(f"{path.name} needs one member, `formats`, a mapping")
    for format_id, harness in formats.items():
        if not isinstance(harness, dict) or set(harness) - HARNESS_KEYS:
            raise HarnessError(f"{path.name}: {format_id} has an unknown member")
        prepare = harness.get("prepare", [])
        if not isinstance(prepare, list) or not all(isinstance(command, str) for command in prepare):
            raise HarnessError(f"{path.name}: {format_id}: `prepare` is not a list of commands")
        init = harness.get("init")
        if init is not None and not (
            isinstance(init, dict) and set(init) == {"command", "file"} and all(isinstance(v, str) for v in init.values())
        ):
            raise HarnessError(f"{path.name}: {format_id}: `init` needs exactly `command` and `file`, both text")
    return formats


def set_members(text: str, members: dict[str, str], values: dict[str, str], fmt: Format) -> str:
    for pointer, template in members.items():
        _, node = scalar_at(compose(text), pointer, fmt)
        text, _ = replace_span(text, node, json.dumps(expand(template, values)))
    return text


def prepare_example(text: str, fmt: Format, values: dict[str, str]) -> str:
    """The example as the harness stages it, before any mutation."""
    return set_members(text, fmt.harness.get("set") or {}, values, fmt)


# --------------------------------------------------------------------------
# Running


@dataclass
class Staged:
    work: Path
    target: Path
    project: Path
    values: dict[str, str]


def under(path: Path, directory: Path) -> Path | None:
    try:
        return path.relative_to(directory)
    except ValueError:
        return None


def copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copyfile)


def stage(root: Path, fmt: Format) -> Staged:
    """Copy what the check command reads into a fresh work directory."""
    harness = fmt.harness
    example = root / str(fmt.example)
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="config-conformance.")))
    project_source = root / harness["project"] if "project" in harness else example.parent
    project = work / "project"
    copy_tree(project_source, project)
    values = {"work": str(work), "project": str(project), "directory": str(project)}
    target = project / inside if (inside := under(example, project_source)) is not None else None
    copied_files = {}
    for name, spec in (harness.get("copies") or {}).items():
        source = root / spec["from"]
        if source.is_dir():
            destination = work / name
            copy_tree(source, destination)
            if (inside := under(example, source)) is not None:
                target = destination / inside
        else:
            destination = work / name / source.name
            destination.parent.mkdir()
            shutil.copyfile(source, destination)
            copied_files[name] = destination
        values[name] = str(destination)
    if target is None:
        raise HarnessError(f"{fmt.id}: the example is in neither the project nor a copy")
    values["file"] = str(target)
    for name, template in (harness.get("values") or {}).items():
        values[name] = expand(template, values)
    for relative_path, content in (harness.get("write") or {}).items():
        path = project / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(expand(content, values), encoding="utf-8")
    for name, spec in (harness.get("copies") or {}).items():
        if spec.get("set"):
            path = copied_files.get(name)
            if path is None:
                raise HarnessError(f"{fmt.id}: copy {name} is a directory; `set` needs a file")
            path.write_text(set_members(path.read_text(encoding="utf-8"), spec["set"], values, fmt), encoding="utf-8")
    return Staged(work, target, project, values)


def refresh_digests(staged: Staged, digests: str) -> None:
    sums = staged.project / digests
    directory = sums.parent
    name = under(staged.target, directory)
    if name is None:
        raise HarnessError(f"{digests} does not cover the example")
    lines = sums.read_text(encoding="utf-8").splitlines(keepends=True)
    digest = hashlib.sha256(staged.target.read_bytes()).hexdigest()
    for index, line in enumerate(lines):
        if line.rstrip("\n").split("  ", 1)[-1] == name.as_posix():
            lines[index] = f"{digest}  {name.as_posix()}\n"
            break
    else:
        raise HarnessError(f"{digests} has no line for {name.as_posix()}")
    sums.write_text("".join(lines), encoding="utf-8")


def forget_digest(staged: Staged, digests: str, path: Path) -> None:
    """Drop the digests line for a file the project no longer holds."""
    sums = staged.project / digests
    name = under(path, sums.parent)
    if name is None:
        # The digests file does not cover the path, so it names nothing to drop.
        return
    lines = sums.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [line for line in lines if line.rstrip("\n").split("  ", 1)[-1] != name.as_posix()]
    sums.write_text("".join(kept), encoding="utf-8")


def remove_tree(path: Path) -> None:
    for directory, _, files in os.walk(path):
        os.chmod(directory, os.stat(directory).st_mode | stat.S_IRWXU)
        for name in files:
            file = os.path.join(directory, name)
            if not os.path.islink(file):
                os.chmod(file, os.stat(file).st_mode | stat.S_IWUSR)
    shutil.rmtree(path)


def command_argv(
    command: str, fmt: Format, values: dict[str, str], bin_dir: Path
) -> tuple[list[str] | None, str | None]:
    """A command template's arguments, its program taken from the binary directory."""
    argv = [expand(part, values) for part in shlex.split(command)]
    for part in argv:
        leftover = LEFTOVER.search(part)
        if leftover:
            raise HarnessError(f"{fmt.id}: no value for {leftover.group(0)} in `{command}`")
    program = bin_dir / argv[0]
    if not (program.is_file() and os.access(program, os.X_OK)):
        return None, f"{argv[0]} is not in the binary directory"
    return [str(program), *argv[1:]], None


def check_argv(fmt: Format, values: dict[str, str], bin_dir: Path) -> tuple[list[str] | None, str | None]:
    return command_argv(str(fmt.check), fmt, values, bin_dir)


def prepare_problems(fmt: Format, staged: "Staged", env: dict[str, str], bin_dir: Path) -> list[str]:
    """Run the harness's `prepare` commands in order; the first one's problems."""
    for command in fmt.harness.get("prepare") or []:
        prefix = f"preparing with `{command}`: "
        argv, missing = command_argv(command, fmt, staged.values, bin_dir)
        if argv is None:
            return [prefix + str(missing)]
        code, _, stderr = run_command(argv, staged.work, env)
        problems = exit_problem(code, 0, stderr, prefix)
        if problems:
            return problems
    return []


def check_environment(bin_dir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    env["NO_COLOR"] = "1"
    env[VARIABLE] = MARKER
    env.pop(UNSET_VARIABLE, None)
    return env


def run_command(argv: list[str], work: Path, env: dict[str, str]) -> tuple[int | None, bytes, bytes]:
    try:
        process = subprocess.run(
            argv, cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired as error:
        return None, error.stdout or b"", error.stderr or b""
    return process.returncode, process.stdout, process.stderr


def exit_problem(code: int | None, wanted: int, stderr: bytes, prefix: str = "") -> list[str]:
    if code is None:
        return [f"{prefix}the command did not finish within {TIMEOUT_SECONDS} seconds"]
    if code == wanted:
        return []
    if code < 0:
        return [f"{prefix}killed by signal {-code}"]
    first = next((line.strip() for line in stderr.decode("utf-8", "replace").splitlines() if line.strip()), "")
    return [f"{prefix}exit status {code}, expected {wanted}" + (f": {first}" if first else "")]


def absolute(diag: Any, work: Path) -> Any:
    """A diagnostic whose relative files are joined to the command's directory."""
    if not isinstance(diag, dict):
        return diag
    diag = dict(diag)
    source = diag.get("source")
    if isinstance(source, dict) and isinstance(source.get("file"), str) and not os.path.isabs(source["file"]):
        diag["source"] = dict(source, file=str(work / source["file"]))
    if isinstance(diag.get("related"), list):
        diag["related"] = [
            dict(r, file=str(work / r["file"]))
            if isinstance(r, dict) and isinstance(r.get("file"), str) and not os.path.isabs(r["file"])
            else r
            for r in diag["related"]
        ]
    return diag


def check_variant(
    fmt: Format, case: Case, argv: list[str], staged: Staged, env: dict[str, str], expected: list[dict[str, Any]]
) -> list[str]:
    wanted = case.expect["exit"]
    code, stdout, stderr = run_command([*argv, "--format", "json", *case.args], staged.work, env)
    problems = exit_problem(code, wanted, stderr)
    problems += marker_problems(stdout, stderr)
    if case.expect.get("report", True):
        diagnostics, report = parse_report(stdout.decode("utf-8", "replace"))
        problems += report
        if diagnostics is not None:
            problems += match_problems(expected, [absolute(d, staged.work) for d in diagnostics])
            for index, diag in enumerate(diagnostics):
                problems += [f"diagnostic {index}: {p}" for p in shape_problems(diag, fmt.kind)]
    if case.human:
        code, stdout, stderr = run_command([*argv, *case.args], staged.work, env)
        problems += exit_problem(code, wanted, stderr, "human run: ")
        problems += marker_problems(stdout, stderr)
        output = stdout.decode("utf-8", "replace") + "\n" + stderr.decode("utf-8", "replace")
        problems += human_problems(expected, output)
    return problems


def modeline_problems(path: Path, name: str, schema_id: str | None) -> list[str]:
    """How the first line of a file init wrote departs from the schema modeline (CFG-SCHEMA-7)."""
    if schema_id is None:
        return ["the format registers no schema `$id` for the modeline to name"]
    if not path.is_file():
        return [f"init wrote no {name}"]
    first = path.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0].rstrip("\r")
    if not first.startswith(MODELINE):
        return [f"the first line of {name} is not a `{MODELINE}` modeline"]
    named = first[len(MODELINE) :].strip()
    if named == schema_id:
        return []
    local = path.parent / named
    if "://" not in named and local.is_file():
        try:
            document = json.loads(local.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            document = None
        if isinstance(document, dict) and document.get("$id") == schema_id:
            return []
    return [f"the modeline in {name} names neither the format's schema `$id` nor a local copy of that schema"]


def run_init_cell(fmt: Format, bin_dir: Path) -> list[str]:
    """Run the format's init command in a fresh directory and check the modeline of the file it writes."""
    init = fmt.harness["init"]
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="config-conformance.")))
    try:
        values = {"work": str(work), "directory": str(work / "init")}
        argv, missing = command_argv(init["command"], fmt, values, bin_dir)
        if argv is None:
            return [str(missing)]
        code, stdout, stderr = run_command(argv, work, check_environment(bin_dir))
        problems = exit_problem(code, 0, stderr, "init: ") + marker_problems(stdout, stderr)
        if code == 0:
            problems += modeline_problems(work / "init" / init["file"], init["file"], fmt.schema_id)
        return list(dict.fromkeys(sanitize(problem, str(work)) for problem in problems))
    finally:
        remove_tree(work)


def run_cell(root: Path, fmt: Format, case: Case, bin_dir: Path) -> list[str]:
    """Run one case against one format; the problems found, sanitized."""
    if case.run == "init":
        return run_init_cell(fmt, bin_dir)
    staged = stage(root, fmt)
    try:
        argv, missing = check_argv(fmt, staged.values, bin_dir)
        if argv is None:
            return [str(missing)]
        env = check_environment(bin_dir)
        problems = prepare_problems(fmt, staged, env, bin_dir)
        if problems:
            return [sanitize(problem, str(staged.work)) for problem in problems]
        text = prepare_example(staged.target.read_text(encoding="utf-8"), fmt, staged.values)
        for variant in mutate(text, case.mutation, fmt):
            if staged.target.is_symlink():
                staged.target.unlink()
            written = variant.finish(variant.text, staged) if variant.finish else variant.text
            staged.target.write_bytes(encode(written, case.encoding))
            if fmt.harness.get("digests"):
                refresh_digests(staged, fmt.harness["digests"])
            expected = resolve_expected(case.expect, case.operation, variant, str(staged.target))
            problems += check_variant(fmt, case, argv, staged, env, expected)
        return list(dict.fromkeys(sanitize(problem, str(staged.work)) for problem in problems))
    finally:
        remove_tree(staged.work)


def run_cells(
    root: Path, cells: list[tuple[Format, Case]], bin_dir: Path, jobs: int
) -> dict[tuple[str, str], list[str]]:
    def run(cell: tuple[Format, Case]) -> tuple[tuple[str, str], list[str]]:
        fmt, case = cell
        return (fmt.id, case.id), run_cell(root, fmt, case, bin_dir)

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        return dict(pool.map(run, cells))


# --------------------------------------------------------------------------
# Command line


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    parser.add_argument("--bin-dir", type=Path, help="directory of built binaries (default: <root>/target/debug)")
    parser.add_argument("--strict", action="store_true", help="also fail on stale or unacknowledged entries")
    parser.add_argument("--matrix", action="store_true", help="print one `format<TAB>case<TAB>status` line per cell")
    parser.add_argument("--verbose", action="store_true", help="also print expected failures and inapplicable cells")
    parser.add_argument(
        "--write-expected-failures", action="store_true", help="rewrite expected-failures.yaml from this run"
    )
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1), help="cells run at once")
    parser.add_argument("--only-format", action="append", default=[], help="run only this format (repeatable)")
    parser.add_argument("--only-case", action="append", default=[], help="run only this case (repeatable)")
    return parser.parse_args(argv)


@dataclass
class Plan:
    reached: list[Format]
    skipped: dict[str, str]
    cases: list[Case]
    cells: list[tuple[Format, Case]]
    inapplicable: dict[tuple[str, str], str]
    # Formats whose check is not reached but whose harness declares `init`:
    # they get the `run: init` cells only.
    init_only: list[Format] = field(default_factory=list)


def plan(root: Path, formats: list[Format], cases: list[Case], harness: dict[str, dict[str, Any]]) -> Plan:
    reached, skipped = partition_formats(formats)
    reached = [fmt.with_harness(harness.get(fmt.id, {})) for fmt in reached]
    init_only = [
        fmt.with_harness(harness[fmt.id]) for fmt in formats if fmt.id in skipped and harness.get(fmt.id, {}).get("init")
    ]
    cells, inapplicable = [], {}
    for fmt in reached:
        text = prepare_example((root / str(fmt.example)).read_text(encoding="utf-8"), fmt, {})
        for case in cases:
            why = not_applicable(case, fmt)
            if why is None and case.run is None:
                try:
                    mutate(text, case.mutation, fmt)
                except NotApplicable as error:
                    why = str(error)
            if why is None:
                cells.append((fmt, case))
            else:
                inapplicable[(fmt.id, case.id)] = why
    for fmt in init_only:
        for case in cases:
            if case.run is not None:
                why = not_applicable(case, fmt)
                if why is None:
                    cells.append((fmt, case))
                else:
                    inapplicable[(fmt.id, case.id)] = why
    return Plan(reached, skipped, cases, cells, inapplicable, init_only)


def validate_ids(expected: ExpectedFailures, formats: list[Format], cases: list[Case], harness: dict[str, Any]) -> None:
    format_ids = {fmt.id for fmt in formats}
    case_ids = {case.id for case in cases}
    for format_id in harness:
        if format_id not in format_ids:
            raise HarnessError(f"formats.yaml names {format_id}, which the registry does not")
    for format_id, case_id in expected.failures:
        if format_id not in format_ids:
            raise HarnessError(f"expected-failures.yaml names format {format_id}, which the registry does not")
        if case_id not in case_ids:
            raise HarnessError(f"expected-failures.yaml names case {case_id}, which the corpus does not")
    for format_id in expected.unreached:
        if format_id not in format_ids:
            raise HarnessError(f"expected-failures.yaml names format {format_id}, which the registry does not")
    for case_id in expected.inapplicable:
        if case_id not in case_ids:
            raise HarnessError(f"expected-failures.yaml names case {case_id}, which the corpus does not")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if (args.only_format or args.only_case) and (args.strict or args.write_expected_failures):
        print("run-config-conformance: error: --only-format and --only-case run part of the matrix;"
              " they cannot be combined with --strict or --write-expected-failures", file=sys.stderr)
        return 2
    root = Path(os.path.realpath(args.root))
    bin_dir = Path(os.path.realpath(args.bin_dir or root / "target/debug"))
    corpus = root / CORPUS
    expected_path = corpus / "expected-failures.yaml"
    try:
        formats = load_registry(root / REGISTRY)
        cases = load_cases(corpus / "cases")
        harness = load_harness(corpus / "formats.yaml")
        expected = load_expected_failures(expected_path)
        validate_ids(expected, formats, cases, harness)
        if not any(case.id == BASELINE for case in cases):
            raise HarnessError(f"the corpus has no `{BASELINE}` case")
        selected = [f for f in formats if not args.only_format or f.id in args.only_format]
        chosen = [c for c in cases if not args.only_case or c.id in args.only_case or c.id == BASELINE]
        work = plan(root, selected, chosen, harness)
        baselines = [(fmt, case) for fmt, case in work.cells if case.id == BASELINE]
        results = run_cells(root, baselines, bin_dir, args.jobs)
        # A format whose baseline fails gets no other check cell: its one
        # expected failure is the baseline's. An init cell does not read the
        # example, so it runs regardless.
        others, blocked = [], []
        for fmt, case in work.cells:
            if case.id == BASELINE:
                continue
            if case.run is None and results[(fmt.id, BASELINE)]:
                blocked.append((fmt.id, case.id))
            else:
                others.append((fmt, case))
        results.update(run_cells(root, others, bin_dir, args.jobs))
    except HarnessError as error:
        print(f"run-config-conformance: error: {error}", file=sys.stderr)
        return 1
    return report(args, work, results, expected, expected_path, blocked)


def report(
    args: argparse.Namespace,
    work: Plan,
    results: dict[tuple[str, str], list[str]],
    expected: ExpectedFailures,
    expected_path: Path,
    blocked: list[tuple[str, str]] | None = None,
) -> int:
    status = statuses(results, expected)
    for cell in blocked or []:
        status[cell] = "blocked"
    for cell in work.inapplicable:
        status[cell] = "not applicable"
    partial = bool(args.only_format or args.only_case)
    for format_id, why in work.skipped.items():
        print(f"skipped {format_id}: {why}")
    unreached = {f: why for f, why in work.skipped.items() if why != "no check command"}
    applies = Counter(case.id for _, case in work.cells)
    inapplicable = {}
    for case in work.cases:
        if not applies[case.id]:
            reasons = [why for (_, case_id), why in work.inapplicable.items() if case_id == case.id]
            inapplicable[case.id] = inapplicable_reason(case, reasons)

    if args.write_expected_failures:
        failures, refused = {}, []
        for cell, problems in results.items():
            if any(unmaskable(problem) for problem in problems):
                refused.append(cell)
            elif problems:
                failures[cell] = Listed(reason(problems), digest(problems))
        value = ExpectedFailures(failures, unreached, inapplicable)
        write_expected_failures(expected_path, value, [case.id for case in work.cases])
        for format_id, case_id in refused:
            print(f"FAIL {format_id} {case_id}")
            print("  not recorded: a leak, a crash, or a timeout is never an expected failure")
            for problem in results[(format_id, case_id)]:
                print(f"  {problem}")
        print(
            f"wrote {expected_path.name}: {plural(len(failures), 'expected failure')}, "
            f"{plural(len(unreached), 'unreached format')}, {plural(len(inapplicable), 'inapplicable case')}"
        )
        return 1 if refused else 0

    if args.matrix:
        for fmt in work.reached + work.init_only:
            for case in work.cases:
                if (fmt.id, case.id) in status:
                    print(f"{fmt.id}\t{case.id}\t{status[(fmt.id, case.id)]}")
    for (format_id, case_id), problems in results.items():
        cell_status = status[(format_id, case_id)]
        if cell_status == "fail" or (cell_status == "expected failure" and args.verbose):
            print(f"{cell_status.upper()} {format_id} {case_id}")
            listed = expected.failures.get((format_id, case_id))
            if cell_status == "fail" and listed is not None:
                print(f"  listed in expected-failures.yaml, but {unmasked(problems, listed)}")
            for problem in problems:
                print(f"  {problem}")
    if args.verbose:
        for (format_id, case_id), why in work.inapplicable.items():
            print(f"not applicable {format_id} {case_id}: {why}")

    stale = [f"stale: {f} {c} now passes" for (f, c), s in status.items() if s == "stale"]
    stale += [f"stale: {f} {c} is blocked by its failing baseline" for (f, c) in expected.failures if status.get((f, c)) == "blocked"]
    strict_problems = []
    if not partial:
        stale += [f"stale: {f} {c} no longer runs" for (f, c) in expected.failures if (f, c) not in status]
        stale += [f"stale: {f} is now reached" for f in expected.unreached if f not in unreached]
        stale += [f"stale: case {c} now applies" for c in expected.inapplicable if c not in inapplicable]
        strict_problems += [
            f"{f} has a check command but is not reached: {why}" for f, why in unreached.items() if f not in expected.unreached
        ]
        strict_problems += [
            f"case {c} applies to no format: {why}" for c, why in inapplicable.items() if c not in expected.inapplicable
        ]
    for line in stale + strict_problems:
        print(line)

    counts = Counter(status.values())
    print(
        f"{plural(len(status), 'cell')}: {counts['pass']} pass, {plural(counts['expected failure'], 'expected failure')}, "
        f"{counts['fail']} fail, {counts['stale']} stale, {counts['blocked']} blocked, "
        f"{counts['not applicable']} not applicable"
    )
    if counts["fail"]:
        return 1
    if args.strict and (stale or strict_problems):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
