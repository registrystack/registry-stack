#!/usr/bin/env python3
"""Verify tutorial query results and persist two inert exact selections."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


EVIDENCE_TYPE = "urn:example:evidence-type:adult-status"
RELAY_CLASS = "urn:example:class:person"
RELAY_FAMILY = "urn:example:operation:lookup"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"expected a JSON object in {path}")
    return value


def one_item(response: dict[str, Any], kind: str) -> dict[str, Any]:
    items = response.get("items")
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise SystemExit(f"expected exactly one {kind} result")
    item = items[0]
    if item.get("serviceKind") != kind:
        raise SystemExit(f"the selected result is not a {kind} service")
    return item


def required_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise SystemExit(f"expected a non-empty {name}")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolution", type=Path, required=True)
    parser.add_argument("--evidence-search", type=Path, required=True)
    parser.add_argument("--relay-search", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    resolution = read_object(args.resolution)
    alternatives = resolution.get("alternatives")
    if not isinstance(alternatives, list) or len(alternatives) != 1:
        raise SystemExit("expected exactly one evidence-type alternative")
    alternative = alternatives[0]
    if not isinstance(alternative, dict) or alternative.get("evidenceTypeIds") != [EVIDENCE_TYPE]:
        raise SystemExit("the resolved evidence type does not match the authored mapping")
    mapping_revision = required_string(resolution.get("mappingRevision"), "mapping revision")
    if DIGEST.fullmatch(mapping_revision) is None:
        raise SystemExit("the mapping revision is not a SHA-256 digest")

    evidence_search = read_object(args.evidence_search)
    evidence = one_item(evidence_search, "evidence")
    if evidence.get("evidenceTypeIds") != [EVIDENCE_TYPE]:
        raise SystemExit("the Evidence result does not carry the resolved evidence type")
    catalog_revision = required_string(evidence_search.get("catalogRevision"), "catalog revision")
    if DIGEST.fullmatch(catalog_revision) is None:
        raise SystemExit("the catalog revision is not a SHA-256 digest")
    evidence_record_id = required_string(evidence.get("recordId"), "Evidence record ID")
    evidence_binding_id = required_string(evidence.get("bindingId"), "Evidence binding ID")

    relay_search = read_object(args.relay_search)
    relay = one_item(relay_search, "relay")
    if relay.get("semanticClassIds") != [RELAY_CLASS]:
        raise SystemExit("the Relay result does not carry the searched semantic class")
    if relay.get("operationFamilyIds") != [RELAY_FAMILY]:
        raise SystemExit("the Relay result does not carry the searched operation family")
    if relay_search.get("catalogRevision") != catalog_revision:
        raise SystemExit("the Evidence and Relay searches do not share one catalog revision")
    relay_record_id = required_string(relay.get("recordId"), "Relay record ID")
    relay_binding_id = required_string(relay.get("bindingId"), "Relay binding ID")

    selection = {
        "catalogRevision": catalog_revision,
        "mappingRevision": mapping_revision,
        "evidence": {
            "recordId": evidence_record_id,
            "bindingId": evidence_binding_id,
            "matchedCapability": {"kind": "evidence-type", "id": EVIDENCE_TYPE},
        },
        "relay": {
            "recordId": relay_record_id,
            "bindingId": relay_binding_id,
            "matchedCapability": {"kind": "operation-family", "id": RELAY_FAMILY},
        },
    }
    args.output.write_text(
        json.dumps(selection, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"resolved evidenceType={EVIDENCE_TYPE} alternatives=1")
    print(f"selected evidence recordId={evidence_record_id}")
    print(f"selected relay recordId={relay_record_id}")


if __name__ == "__main__":
    main()
