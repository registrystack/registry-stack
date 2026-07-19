#!/usr/bin/env python3
"""Remove roster-declared unstable formats from Relay OpenAPI compatibility inputs."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any


class RosterError(ValueError):
    """The Relay support roster cannot safely drive compatibility filtering."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RosterError(f"{path} is not valid JSON: {error}") from error


def index_roster(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise RosterError("Relay support roster must be a non-empty list")
    result: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(value):
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise RosterError(f"Relay support roster entry {index} has no string id")
        entry_id = entry["id"]
        if entry_id in result:
            raise RosterError(f"duplicate Relay support roster id: {entry_id}")
        result[entry_id] = entry
    return result


def compare_rosters(
    base_value: Any, current_value: Any
) -> list[str]:
    """Reject a downgrade of a surface that the base roster promised as stable."""
    base = index_roster(base_value)
    current = index_roster(current_value)
    errors: list[str] = []
    for entry_id, old in sorted(base.items()):
        if old.get("stability_tier") != "stable":
            continue
        new = current.get(entry_id)
        if new is None:
            errors.append(f"stable Relay roster surface removed: {entry_id}")
            continue
        if new.get("stability_tier") != "stable" or new.get("canonical_release") is not True:
            errors.append(f"stable Relay roster surface downgraded: {entry_id}")
        if old.get("openapi_policy") == "included" and new.get("openapi_policy") != "included":
            errors.append(f"stable Relay OpenAPI surface excluded: {entry_id}")
    return errors


def unstable_aggregate_selectors(roster_value: Any) -> tuple[set[str], set[str]]:
    """Read selectors only from authoritative included-unstable roster entries."""
    tokens: set[str] = set()
    media_types: set[str] = set()
    roster = index_roster(roster_value)
    stable_tokens = {
        entry_id.removesuffix("-aggregate-output")
        for entry_id, entry in roster.items()
        if entry.get("category") == "aggregate_output"
        and entry.get("stability_tier") == "stable"
        and entry.get("canonical_release") is True
        and entry.get("openapi_policy") == "included"
        and entry_id.endswith("-aggregate-output")
    }
    for entry_id, entry in roster.items():
        if entry.get("openapi_policy") != "included_unstable":
            continue
        if (
            entry.get("category") != "aggregate_output"
            or entry.get("stability_tier") != "experimental"
            or entry.get("feature_frozen") is not True
            or entry.get("canonical_release") is not False
        ):
            raise RosterError(
                f"included-unstable Relay surface {entry_id} must be a frozen, "
                "non-canonical experimental aggregate output"
            )
        selectors = entry.get("openapi_selectors")
        if not isinstance(selectors, dict) or set(selectors) != {
            "format_tokens",
            "media_types",
        }:
            raise RosterError(
                f"included-unstable Relay surface {entry_id} needs exact OpenAPI selectors"
            )
        entry_tokens = selectors["format_tokens"]
        entry_media_types = selectors["media_types"]
        if (
            not isinstance(entry_tokens, list)
            or not entry_tokens
            or any(not isinstance(item, str) or not item for item in entry_tokens)
            or not isinstance(entry_media_types, list)
            or not entry_media_types
            or any(not isinstance(item, str) or not item for item in entry_media_types)
        ):
            raise RosterError(
                f"included-unstable Relay surface {entry_id} has empty or invalid selectors"
            )
        tokens.update(entry_tokens)
        media_types.update(entry_media_types)
    token_collisions = stable_tokens & tokens
    media_type_collisions = {
        media_type
        for media_type in media_types
        if media_type.partition(";")[0].partition("/")[2] in stable_tokens
    }
    if token_collisions or media_type_collisions:
        collisions = sorted(token_collisions | media_type_collisions)
        raise RosterError(
            "included-unstable selectors overlap a stable aggregate representation: "
            + ", ".join(collisions)
        )
    return tokens, media_types


def _filter_operation(value: Any, tokens: set[str], media_types: set[str]) -> None:
    if isinstance(value, dict):
        enum = value.get("enum")
        if isinstance(enum, list):
            value["enum"] = [item for item in enum if item not in tokens]
        content = value.get("content")
        if isinstance(content, dict):
            for media_type in media_types:
                content.pop(media_type, None)
        for nested in value.values():
            _filter_operation(nested, tokens, media_types)
    elif isinstance(value, list):
        for nested in value:
            _filter_operation(nested, tokens, media_types)


def filter_openapi(document: Any, roster_value: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise RosterError("Relay OpenAPI document has no paths object")
    tokens, media_types = unstable_aggregate_selectors(roster_value)
    filtered = copy.deepcopy(document)
    for path, path_item in filtered["paths"].items():
        if "aggregates" not in path.split("/"):
            continue
        _filter_operation(path_item, tokens, media_types)
    return filtered


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current-roster", required=True, type=Path)
    parser.add_argument("--base-roster", type=Path)
    parser.add_argument("--base-openapi", required=True, type=Path)
    parser.add_argument("--current-openapi", required=True, type=Path)
    parser.add_argument("--filtered-base", required=True, type=Path)
    parser.add_argument("--filtered-current", required=True, type=Path)
    args = parser.parse_args()
    try:
        current_roster = load_json(args.current_roster)
        if args.base_roster is None:
            base_roster = current_roster
        else:
            base_roster = load_json(args.base_roster)
            errors = compare_rosters(base_roster, current_roster)
            if errors:
                raise RosterError("; ".join(errors))
        write_json(
            args.filtered_base,
            filter_openapi(load_json(args.base_openapi), base_roster),
        )
        write_json(
            args.filtered_current,
            filter_openapi(load_json(args.current_openapi), current_roster),
        )
    except (OSError, RosterError) as error:
        print(f"Relay OpenAPI stability filter failed: {error}", file=sys.stderr)
        return 1
    print("Relay OpenAPI stability filter passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
