#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hold every Evidence configuration reference in parity with its schema.

A schema states which keys a document may carry. A CONFIG.md is the prose that
explains them. This check makes each pair inseparable: every key path in a
schema must appear in that schema's delimited key-path block in the reference
it feeds, and every documented path must exist in the schema. Prose outside the
block stays free-form.

Two kinds of schema are held to that rule, and they are not the same promise.
`bundle.schema.yaml` and `runtime.schema.yaml` are the normative, frozen
Version 1 configuration grammar. The authoring-form schemas under
`crates/registry-evidencectl/schemas/authoring/` are adopter tooling: generated
from the `registry-evidence-authoring` model, outside the frozen Version 1
contract set, and free to change with the tooling that generates them. Parity
is a documentation rule here, not a freeze.

Run the check:

    products/evidence/scripts/check-config-key-paths.sh

After changing a schema, rewrite the blocks and review the diff:

    products/evidence/scripts/check-config-key-paths.sh --write
"""

import argparse
import sys
from pathlib import Path
from typing import NamedTuple


class Contract(NamedTuple):
    """One schema, and the delimited block in the prose that documents it.

    Both paths are repository-relative and complete, so a schema is free to
    live wherever it is generated and to document into whichever reference
    explains it.
    """

    schema: str
    reference: str
    marker: str


# The prose explaining the frozen Version 1 deployment grammar.
DEPLOYMENT_REFERENCE = (
    "products/evidence/reference/request-adapter/deployment-projects/CONFIG.md"
)

# The prose explaining the authoring form, which is adopter tooling.
AUTHORING_REFERENCE = "products/evidence/reference/authoring-projects/CONFIG.md"

CONTRACTS = {
    "bundle": Contract(
        schema="products/evidence/contracts/bundle.schema.yaml",
        reference=DEPLOYMENT_REFERENCE,
        marker="evidence-bundle-key-paths",
    ),
    "runtime": Contract(
        schema="products/evidence/contracts/runtime.schema.yaml",
        reference=DEPLOYMENT_REFERENCE,
        marker="evidence-runtime-key-paths",
    ),
    "authoring-question": Contract(
        schema="crates/registry-evidencectl/schemas/authoring/question.schema.json",
        reference=AUTHORING_REFERENCE,
        marker="evidence-authoring-question-key-paths",
    ),
    "authoring-project-marker": Contract(
        schema=(
            "crates/registry-evidencectl/schemas/authoring/project-marker.schema.json"
        ),
        reference=AUTHORING_REFERENCE,
        marker="evidence-authoring-project-marker-key-paths",
    ),
}

FENCE = "```"


class ContractError(Exception):
    """A contract, or the reference documenting it, is not readable as expected."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_schema(path: Path) -> object:
    """Read one schema document. JSON is YAML, so one loader reads both forms."""
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on the host
        raise ContractError("PyYAML is required to read the Evidence schemas") from exc
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ContractError(f"{path} does not parse: {exc}") from exc


def resolve(document: dict, reference: str) -> dict:
    """Resolve a local `#/...` reference, which is the only form the contracts use."""
    if not reference.startswith("#/"):
        raise ContractError(f"only local schema references are supported: {reference}")
    node: object = document
    for part in reference[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            raise ContractError(f"unresolved schema reference {reference}")
        node = node[part]
    if not isinstance(node, dict):
        raise ContractError(f"schema reference {reference} is not a schema object")
    return node


def _walk(
    document: dict,
    schema: object,
    prefix: str,
    found: set,
    reference_stack: frozenset,
) -> None:
    if not isinstance(schema, dict):
        return

    if "$ref" in schema:
        reference = schema["$ref"]
        # A recursive definition contributes its shape once; re-entry would not
        # terminate and adds no key the reader has not already seen.
        if reference in reference_stack:
            return
        _walk(
            document,
            resolve(document, reference),
            prefix,
            found,
            reference_stack | {reference},
        )
        return

    for combinator in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            for branch in branches:
                _walk(document, branch, prefix, found, reference_stack)

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            child_prefix = f"{prefix}.{name}" if prefix else name
            found.add(child_prefix)
            _walk(document, child, child_prefix, found, reference_stack)

    items = schema.get("items")
    if isinstance(items, dict):
        item_prefix = f"{prefix}[]"
        found.add(item_prefix)
        _walk(document, items, item_prefix, found, reference_stack)

    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        value_prefix = f"{prefix}.*" if prefix else "*"
        found.add(value_prefix)
        _walk(document, additional, value_prefix, found, reference_stack)


def key_paths(document: object) -> set:
    """Every key path a deployment may write, in the notation Relay's check uses.

    `name` is a property, `name[]` an array item, and `name.*` a map value. The
    governance blocks the contracts carry beside the schema (`ownership`,
    `startup`, `platform`) are not schema keywords and contribute no paths.
    """
    if not isinstance(document, dict):
        raise ContractError("a schema must be a mapping")
    found: set = set()
    _walk(document, document, "", found, frozenset())
    return found


def documented_key_paths(text: str, marker: str) -> set:
    """Read the sorted key-path block CONFIG.md delimits with HTML comments."""
    start = f"<!-- {marker}:start -->"
    end = f"<!-- {marker}:end -->"
    _, separator, tail = text.partition(start)
    if not separator:
        raise ContractError(f"CONFIG.md is missing the {start} marker")
    block, separator, _ = tail.partition(end)
    if not separator:
        raise ContractError(f"CONFIG.md is missing the {end} marker")

    paths = [
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith(FENCE)
    ]
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    if duplicates:
        raise ContractError(
            f"{marker} lists duplicate key paths: {', '.join(duplicates)}"
        )
    if paths != sorted(paths):
        raise ContractError(f"{marker} key paths must be sorted")
    return set(paths)


def compare(
    schema_paths: set, documented_paths: set, label: str, reference: str
) -> list:
    """Report both directions of drift, so neither artifact can lead silently.

    More than one reference carries blocks, so a problem names the file that
    should have carried the path as well as the schema that decided it.
    """
    problems = []
    for path in sorted(schema_paths - documented_paths):
        problems.append(f"{label}: key path is not documented in {reference}: {path}")
    for path in sorted(documented_paths - schema_paths):
        problems.append(
            f"{label}: {reference} documents a key path that {label} does not "
            f"define: {path}"
        )
    return problems


def rewrite_block(text: str, marker: str, paths: set) -> str:
    """Replace one delimited block with the current key paths."""
    start = f"<!-- {marker}:start -->"
    end = f"<!-- {marker}:end -->"
    head, separator, tail = text.partition(start)
    if not separator:
        raise ContractError(f"CONFIG.md is missing the {start} marker")
    _, separator, rest = tail.partition(end)
    if not separator:
        raise ContractError(f"CONFIG.md is missing the {end} marker")
    body = "\n".join(sorted(paths))
    return f"{head}{start}\n{FENCE}text\n{body}\n{FENCE}\n{end}{rest}"


def references() -> dict:
    """Every reference, with the contracts whose blocks it carries, in order."""
    grouped: dict = {}
    for contract in CONTRACTS.values():
        grouped.setdefault(contract.reference, []).append(contract)
    return grouped


def write_all(root: Path) -> bool:
    """Regenerate every block in place. Returns whether any reference changed.

    Every reference is read and rewritten in memory before any file is
    written, so a schema that fails to parse or a reference missing a marker
    raises before a single byte reaches disk: a failed run leaves the
    committed references exactly as they were, matching the generated-output
    rule that a regeneration is reproduced whole or not at all. This does not
    make the final write step atomic; a `write_text` failure partway through
    that step (a permissions error, a full disk) can still leave some
    references updated and others not.
    """
    updates = {}
    for reference, contracts in references().items():
        path = root / reference
        original = path.read_text(encoding="utf-8")
        updated = original
        for contract in contracts:
            paths = key_paths(load_schema(root / contract.schema))
            updated = rewrite_block(updated, contract.marker, paths)
        if updated != original:
            updates[path] = updated

    for path, updated in updates.items():
        path.write_text(updated, encoding="utf-8")

    return bool(updates)


def check_all(root: Path) -> list:
    documents = {
        reference: (root / reference).read_text(encoding="utf-8")
        for reference in references()
    }
    problems = []
    for contract in CONTRACTS.values():
        schema_paths = key_paths(load_schema(root / contract.schema))
        try:
            documented = documented_key_paths(
                documents[contract.reference], contract.marker
            )
        except ContractError as error:
            problems.append(f"{contract.schema}: {error}")
            continue
        problems.extend(
            compare(schema_paths, documented, contract.schema, contract.reference)
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check every Evidence configuration reference against its schema."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the CONFIG.md key-path blocks from the schemas",
    )
    arguments = parser.parse_args()
    root = repository_root()

    try:
        if arguments.write:
            if write_all(root):
                print("Updated the CONFIG.md key-path blocks; review the diff.")
            else:
                print("CONFIG.md key-path blocks are already current.")
            return 0

        problems = check_all(root)
    except ContractError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            "\nAn Evidence configuration reference is out of parity with its "
            "schema.\nRun this check with --write, then document every new key in "
            "the prose above the blocks.",
            file=sys.stderr,
        )
        return 1

    print("Evidence configuration key paths match the committed reference.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
