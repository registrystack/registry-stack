#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hold the Evidence configuration reference in parity with the frozen contracts.

`bundle.schema.yaml` and `runtime.schema.yaml` are the normative Version 1
configuration grammar. CONFIG.md is the prose that explains it. This check makes
the pair inseparable: every key path in a contract must appear in that contract's
delimited key-path block in CONFIG.md, and every documented path must exist in
the contract. Prose outside the block stays free-form.

Run the check:

    products/evidence/scripts/check-config-key-paths.sh

After changing a contract, rewrite the blocks and review the diff:

    products/evidence/scripts/check-config-key-paths.sh --write
"""

import argparse
import sys
from pathlib import Path

CONTRACT_DIRECTORY = Path("products/evidence/contracts")
REFERENCE_PATH = Path(
    "products/evidence/reference/request-adapter/deployment-projects/CONFIG.md"
)

# Contract file -> the CONFIG.md marker naming its key-path block.
CONTRACTS = {
    "bundle": ("bundle.schema.yaml", "evidence-bundle-key-paths"),
    "runtime": ("runtime.schema.yaml", "evidence-runtime-key-paths"),
}

FENCE = "```"


class ContractError(Exception):
    """A contract, or the reference documenting it, is not readable as expected."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_yaml(path: Path) -> object:
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on the host
        raise ContractError("PyYAML is required to read the Evidence contracts") from exc
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ContractError(f"invalid YAML in {path}: {exc}") from exc


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
        raise ContractError("a contract must be a mapping")
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


def compare(schema_paths: set, documented_paths: set, label: str) -> list:
    """Report both directions of drift, so neither artifact can lead silently."""
    problems = []
    for path in sorted(schema_paths - documented_paths):
        problems.append(f"{label}: key path is not documented in CONFIG.md: {path}")
    for path in sorted(documented_paths - schema_paths):
        problems.append(f"{label}: CONFIG.md documents a key path that {label} does not define: {path}")
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


def write_all(root: Path) -> bool:
    """Regenerate every block in place. Returns whether the reference changed."""
    reference_path = root / REFERENCE_PATH
    original = reference_path.read_text(encoding="utf-8")
    updated = original
    for filename, marker in CONTRACTS.values():
        paths = key_paths(load_yaml(root / CONTRACT_DIRECTORY / filename))
        updated = rewrite_block(updated, marker, paths)
    if updated != original:
        reference_path.write_text(updated, encoding="utf-8")
    return updated != original


def check_all(root: Path) -> list:
    reference = (root / REFERENCE_PATH).read_text(encoding="utf-8")
    problems = []
    for filename, marker in CONTRACTS.values():
        contract = root / CONTRACT_DIRECTORY / filename
        schema_paths = key_paths(load_yaml(contract))
        try:
            documented = documented_key_paths(reference, marker)
        except ContractError as error:
            problems.append(f"{filename}: {error}")
            continue
        problems.extend(compare(schema_paths, documented, filename))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the Evidence configuration reference against the frozen contracts."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the CONFIG.md key-path blocks from the contracts",
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
            "\nEvidence configuration reference is out of parity with the frozen "
            "contracts.\nRun this check with --write, then document every new key in "
            "the prose above the blocks.",
            file=sys.stderr,
        )
        return 1

    print("Evidence configuration key paths match the committed reference.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
