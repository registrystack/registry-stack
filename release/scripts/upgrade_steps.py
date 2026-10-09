"""Upgrade steps: the operator's documented edits, shared with the rehearsal.

A BREAKING item in a release-note fragment under
release/notes/config-conventions/ tells an operator which files to edit to
carry state from the previous release forward. The steps catalog beside the
fragments holds those edits as data. The fragment cites the step ids in an
HTML comment on the line after the heading, and the rehearsal applies the
same steps to the files the previous release's binaries wrote. One catalog
therefore feeds both the note and the rehearsal, and check_fragment ties
them: a heading whose marker is absent, malformed, or names no catalog entry
is refused.

A catalog entry is one of three kinds:

  edit     a list of edits the engine applies to every file the entry's
           `file` glob matches under its root (`project` or `target`).
  manual   an operator action the engine cannot apply (regenerate a file,
           stop a service). The instruction is reported, never applied.
  unknown  a BREAKING item whose edit is not derivable from the fragment and
           the code. The entry names the file and the diagnostic the new
           reader gives, and applying it fails.

The edits are envelope, set, delete, rename, and replace-value. A path is
dot separated; `*` matches every member of a mapping or item of a list, and
`**` matches any depth. An edit that matches nothing is refused unless it is
marked `optional`, so a step written for a shape the file does not have
fails visibly instead of passing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[2]
FRAGMENTS = ROOT / "release/notes/config-conventions"
CATALOG = FRAGMENTS / "upgrade-steps.yaml"
CATALOG_API_VERSION = "id.registrystack.org/formats/release/upgrade-steps/v1alpha1"
CATALOG_KIND = "ReleaseUpgradeSteps"

# Marker words that stand in for step ids. `already-wrong` marks an item that
# refuses only a file that was already outside the documented grammar;
# `no-file` marks an item that changes behavior or output, not a file an
# operator edits.
RESERVED = ("already-wrong", "no-file")
ROOTS = ("project", "target", "runtime")
STEP_ID = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
MARKER = re.compile(r"^<!-- upgrade: (.*) -->$")

EDIT_MEMBERS = {
    "envelope": ({"apiVersion", "kind"}, set()),
    "set": ({"path", "value"}, {"ifAbsent", "optional"}),
    "delete": ({"path"}, {"optional"}),
    "rename": ({"path", "to"}, {"multiplyBy", "optional"}),
    "replace-value": ({"path", "from", "to"}, {"optional"}),
}
STEP_MEMBERS = {
    "edit": ({"edits"}, set()),
    "manual": ({"instruction"}, set()),
    "unknown": ({"diagnostic"}, set()),
}


class StepError(RuntimeError):
    """An upgrade step, its catalog, or a fragment marker is wrong."""


class _EditFailure(Exception):
    """An edit cannot apply; the caller adds the step and file context."""


# ---------------------------------------------------------------------------
# Documents.


def _yaml() -> Any:
    try:
        import yaml  # PyYAML; the rehearsal runs through `uv run --with PyYAML`.
    except ImportError as error:
        raise StepError("PyYAML is required to read and write YAML upgrade files") from error
    return yaml


def _no_alias_dumper() -> Any:
    yaml = _yaml()

    class NoAliasDumper(yaml.SafeDumper):
        # An alias in an old file is expanded in full, as the fragments tell an
        # operator to do, so a shared mapping is written out at each use.
        def ignore_aliases(self, _data: Any) -> bool:
            return True

    return NoAliasDumper


def load_document(path: Path) -> Any:
    suffix = path.suffix.lower()
    try:
        text = path.read_text(encoding="utf-8")
        if suffix in (".yaml", ".yml"):
            document = _yaml().safe_load(text)
        elif suffix == ".json":
            document = json.loads(text)
        else:
            raise StepError(f"{path}: expected a YAML or JSON file")
    except StepError:
        raise
    except (OSError, ValueError, _yaml().YAMLError) as error:
        raise StepError(f"{path}: cannot be read as a document: {error}") from error
    if document is None:
        raise StepError(f"{path}: the document is empty")
    return document


def dump_document(path: Path, document: Any) -> None:
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        text = _yaml().dump(document, Dumper=_no_alias_dumper(), sort_keys=False,
                            allow_unicode=True, default_flow_style=False)
    elif suffix == ".json":
        text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    else:
        raise StepError(f"{path}: expected a YAML or JSON file")
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Edits.


def _children(node: Any) -> Iterator[Any]:
    if isinstance(node, dict):
        yield from node.values()
    elif isinstance(node, list):
        yield from node


def _descendants(node: Any) -> Iterator[Any]:
    yield node
    for child in _children(node):
        yield from _descendants(child)


def _containers(document: Any, segments: list[str]) -> list[dict[str, Any]]:
    """Every mapping the path's parent segments lead to, each once."""

    nodes = [document]
    for segment in segments:
        if segment == "*":
            nodes = [child for node in nodes for child in _children(node)]
        elif segment == "**":
            nodes = [inner for node in nodes for inner in _descendants(node)]
        else:
            nodes = [node[segment] for node in nodes
                     if isinstance(node, dict) and segment in node]
    seen: set[int] = set()
    unique = []
    for node in nodes:
        if isinstance(node, dict) and id(node) not in seen:
            seen.add(id(node))
            unique.append(node)
    return unique


def _split(path: str) -> tuple[list[str], str]:
    *parents, last = path.split(".")
    if last in ("*", "**"):
        raise _EditFailure(f"path '{path}' must end in a member name")
    return parents, last


def _nothing(path: str) -> _EditFailure:
    return _EditFailure(f"path '{path}' matches nothing")


def _apply(document: Any, edit: dict[str, Any]) -> Any:
    op = edit["op"]
    optional = bool(edit.get("optional"))
    if op == "envelope":
        if not isinstance(document, dict):
            raise _EditFailure("the document is not a mapping")
        rest = {k: v for k, v in document.items() if k not in ("apiVersion", "kind")}
        return {"apiVersion": edit["apiVersion"], "kind": edit["kind"], **rest}

    parents, last = _split(edit["path"])
    containers = _containers(document, parents)
    if op == "set":
        if not containers and not optional:
            raise _nothing(edit["path"])
        for container in containers:
            if edit.get("ifAbsent") and last in container:
                continue
            container[last] = edit["value"]
        return document

    holders = [container for container in containers if last in container]
    if not holders and not optional:
        raise _nothing(edit["path"])
    for holder in holders:
        if op == "delete":
            del holder[last]
        elif op == "rename":
            new = edit["to"]
            if new in holder:
                raise _EditFailure(f"a mapping at '{edit['path']}' already has '{new}'")
            value = holder[last]
            if "multiplyBy" in edit:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise _EditFailure(f"the value at '{edit['path']}' is not a number")
                value = value * edit["multiplyBy"]
            items = [(new if key == last else key, value if key == last else item)
                     for key, item in holder.items()]
            holder.clear()
            holder.update(items)
        elif op == "replace-value" and holder[last] == edit["from"]:
            holder[last] = edit["to"]
    return document


def validate_edit(edit: Any, step_id: str) -> None:
    if not isinstance(edit, dict) or "op" not in edit:
        raise StepError(f"{step_id}: an edit must be a mapping with an 'op'")
    op = edit["op"]
    if op not in EDIT_MEMBERS:
        raise StepError(f"{step_id}: unknown edit '{op}'")
    required, allowed = EDIT_MEMBERS[op]
    members = set(edit) - {"op"}
    if missing := sorted(required - members):
        raise StepError(f"{step_id}: edit '{op}' needs {', '.join(missing)}")
    if extra := sorted(members - required - allowed):
        raise StepError(f"{step_id}: edit '{op}' takes no {', '.join(extra)}")


def apply_edit(document: Any, edit: dict[str, Any], step_id: str) -> Any:
    """Apply one edit to a parsed document; return the edited document."""

    validate_edit(edit, step_id)
    try:
        return _apply(document, edit)
    except _EditFailure as failure:
        raise StepError(f"{step_id}: {failure}") from failure


# ---------------------------------------------------------------------------
# Catalog.


def _check_file(step_id: str, file: Any) -> None:
    parts = Path(str(file)).parts
    if not isinstance(file, str) or not file or Path(file).is_absolute() or ".." in parts:
        raise StepError(f"{step_id}: file '{file}' is outside its root")


def _validate_step(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
        raise StepError("every step needs an 'id'")
    step_id = entry["id"]
    if not STEP_ID.match(step_id) or step_id in RESERVED:
        raise StepError(f"{step_id}: a step id is kebab case and not a reserved word")
    kind = entry.get("kind")
    if kind not in STEP_MEMBERS:
        raise StepError(f"{step_id}: kind '{kind}' is not edit, manual, or unknown")
    required, _ = STEP_MEMBERS[kind]
    common = {"id", "product", "kind", "file", "root"}
    if missing := sorted((required | {"product", "file"}) - set(entry)):
        raise StepError(f"{step_id}: a {kind} step needs {', '.join(missing)}")
    if extra := sorted(set(entry) - common - required):
        raise StepError(f"{step_id}: a {kind} step takes no {', '.join(extra)}")
    root = entry.get("root", "project")
    if root not in ROOTS:
        raise StepError(f"{step_id}: root '{root}' is not project, target or runtime")
    _check_file(step_id, entry["file"])
    if kind == "edit":
        if not isinstance(entry["edits"], list) or not entry["edits"]:
            raise StepError(f"{step_id}: a step needs a non-empty list of edits")
        for edit in entry["edits"]:
            validate_edit(edit, step_id)
    return {**entry, "root": root}


def load_catalog(path: Path = CATALOG) -> dict[str, dict[str, Any]]:
    document = load_document(path)
    if (not isinstance(document, dict)
            or document.get("apiVersion") != CATALOG_API_VERSION
            or document.get("kind") != CATALOG_KIND):
        raise StepError(f"{path}: expected apiVersion {CATALOG_API_VERSION} "
                        f"and kind {CATALOG_KIND}")
    steps = document.get("steps")
    if not isinstance(steps, list):
        raise StepError(f"{path}: 'steps' must be a list")
    catalog: dict[str, dict[str, Any]] = {}
    for entry in steps:
        step = _validate_step(entry)
        if step["id"] in catalog:
            raise StepError(f"{path}: repeats the id '{step['id']}'")
        catalog[step["id"]] = step
    return catalog


def apply_steps(ids: list[str], roots: dict[str, Path],
                catalog: dict[str, dict[str, Any]] | None = None) -> list[str]:
    """Apply the named steps in order; return the manual instructions.

    Every edit step must match a file under its root. A manual step is
    returned for the caller to report, and an unknown step fails.
    """

    catalog = load_catalog() if catalog is None else catalog
    manual = []
    for step_id in ids:
        step = catalog.get(step_id)
        if step is None:
            raise StepError(f"unknown upgrade step id '{step_id}'")
        if step["kind"] == "unknown":
            raise StepError(f"{step_id}: step unknown; {step['file']} has no documented edit "
                            f"(diagnostic: {step['diagnostic']})")
        if step["kind"] == "manual":
            manual.append(f"{step_id} ({step['file']}): {step['instruction']}")
            continue
        _check_file(step_id, step["file"])
        root = roots.get(step["root"])
        if root is None:
            raise StepError(f"{step_id}: root '{step['root']}' is not available")
        files = sorted(path for path in root.glob(step["file"]) if path.is_file())
        if not files:
            raise StepError(f"{step_id}: no file matches {step['file']} under the "
                            f"{step['root']} root {root}")
        for file in files:
            _edit_file(step_id, step, file)
    return manual


def _edit_file(step_id: str, step: dict[str, Any], file: Path) -> None:
    document = load_document(file)
    for edit in step["edits"]:
        validate_edit(edit, step_id)
        try:
            document = _apply(document, edit)
        except _EditFailure as failure:
            raise StepError(f"{step_id}: {file}: {failure}") from failure
    dump_document(file, document)


def apply_step_to_file(step_id: str, file: Path,
                       catalog: dict[str, dict[str, Any]] | None = None) -> None:
    """Apply one `edit` step to a single file, whatever its name."""

    catalog = load_catalog() if catalog is None else catalog
    step = catalog.get(step_id)
    if step is None:
        raise StepError(f"unknown upgrade step id '{step_id}'")
    if step["kind"] != "edit":
        raise StepError(f"{step_id}: only an edit step applies to a file")
    _edit_file(step_id, step, file)


# ---------------------------------------------------------------------------
# Fragments.


@dataclass(frozen=True)
class Item:
    """A BREAKING item and the step ids its marker names."""

    line: int
    number: int | None
    ids: tuple[str, ...]


def _ids(text: str, where: str, catalog: dict[str, dict[str, Any]]) -> tuple[str, ...]:
    tokens = [token.strip() for token in text.split(",")]
    if not all(re.fullmatch(r"[a-z][a-z0-9-]*", token) for token in tokens):
        raise StepError(f"{where}: unparseable upgrade marker '{text}'")
    for token in tokens:
        if token not in RESERVED and token not in catalog:
            raise StepError(f"{where}: unknown upgrade step id '{token}'")
    if len(tokens) > 1 and any(token in RESERVED for token in tokens):
        raise StepError(f"{where}: '{[t for t in tokens if t in RESERVED][0]}' stands alone")
    return tuple(tokens)


def check_fragment(path: Path, catalog: dict[str, dict[str, Any]]) -> list[Item]:
    """Return every BREAKING item of a fragment with its step ids.

    Each `BREAKING` heading carries `<!-- upgrade: id, id -->` on the next
    line. The `BREAKING changes` heading of a numbered list carries
    `<!-- upgrade: 1=id,id; 2=no-file -->`, one entry per numbered item.
    """

    lines = path.read_text(encoding="utf-8").splitlines()
    items: list[Item] = []
    for index, text in enumerate(lines):
        heading = re.match(r"^#{2,3} (BREAKING.*)$", text)
        if not heading:
            continue
        where = f"{path}:{index + 1}"
        marker = lines[index + 1] if index + 1 < len(lines) else ""
        if not marker.startswith("<!-- upgrade"):
            raise StepError(f"{where}: BREAKING heading has no upgrade marker on the next line")
        match = MARKER.match(marker)
        if not match:
            raise StepError(f"{where}: unparseable upgrade marker '{marker}'")
        body = match.group(1)
        if heading.group(1) != "BREAKING changes":
            items.append(Item(index + 1, None, _ids(body, where, catalog)))
            continue
        numbered = _numbered_items(lines, index)
        marked: dict[int, tuple[str, ...]] = {}
        for part in body.split(";"):
            number, separator, ids = part.strip().partition("=")
            if not separator or not number.isdigit():
                raise StepError(f"{where}: a numbered BREAKING list is marked N=ids per "
                                f"item, and item {numbered[0] if numbered else 1} has no marker")
            marked[int(number)] = _ids(ids, where, catalog)
        for number in numbered:
            if number not in marked:
                raise StepError(f"{where}: BREAKING item {number} has no marker")
        for number in marked:
            if number not in numbered:
                raise StepError(f"{where}: marker names item {number}: no such item")
        items.extend(Item(index + 1, number, marked[number]) for number in numbered)
    if not items:
        raise StepError(f"{path}: no BREAKING heading found")
    return items


def _numbered_items(lines: list[str], heading: int) -> list[int]:
    numbers = []
    for text in lines[heading + 1:]:
        if re.match(r"^#{1,6} ", text):
            break
        item = re.match(r"^(\d+)\. ", text)
        if item:
            numbers.append(int(item.group(1)))
    return numbers
