from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE_URI = "https://id.registrystack.org/profiles/registry-record/v1"
SCHEMA_URI = "https://id.registrystack.org/schemas/registry-record/v1"
CONTEXT_URI = "https://id.registrystack.org/contexts/registry-record/v1"
VOCABULARY_URI = "https://id.registrystack.org/vocab/registry-record/"
IDENTIFIER_TERMS = (
    "registryIdentifier",
    "datasetIdentifier",
    "entityTypeIdentifier",
    "recordIdentifier",
    "revisionIdentifier",
)
INFRASTRUCTURE_MEMBERS = {
    "data",
    "items",
    "pageInfo",
    "meta",
    "registryIdentifier",
    "datasetIdentifier",
    "entityTypeIdentifier",
    "recordIdentifier",
    "revisionIdentifier",
    "nextCursor",
}
RECORD_FORBIDDEN_MEMBERS = INFRASTRUCTURE_MEMBERS - {
    "recordIdentifier",
    "revisionIdentifier",
    "domainData",
}
SINGLE_FORBIDDEN_MEMBERS = INFRASTRUCTURE_MEMBERS - {"data", "meta"}
COLLECTION_FORBIDDEN_MEMBERS = INFRASTRUCTURE_MEMBERS - {
    "items",
    "pageInfo",
    "meta",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def require_identifier(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an opaque non-empty string")


def reject_nested_context(value: Any, path: str) -> None:
    if isinstance(value, dict):
        for key, member in value.items():
            if key == "@context":
                raise ValueError(f"{path} contains an inline or nested @context")
            reject_nested_context(member, f"{path}.{key}")
    elif isinstance(value, list):
        for index, member in enumerate(value):
            reject_nested_context(member, f"{path}[{index}]")


def validate_record(record: Any, path: str) -> None:
    if not isinstance(record, dict):
        raise ValueError(f"{path} must be an object")
    members = RECORD_FORBIDDEN_MEMBERS.intersection(record)
    if members:
        raise ValueError(f"{path} contains misplaced infrastructure member")
    for field in ("recordIdentifier", "revisionIdentifier"):
        if field not in record:
            raise ValueError(f"{path}.{field} is required")
        require_identifier(record[field], f"{path}.{field}")
    domain_data = record.get("domainData")
    if not isinstance(domain_data, dict):
        raise ValueError(f"{path}.domainData must be an object")
    members = INFRASTRUCTURE_MEMBERS.intersection(domain_data)
    if members:
        raise ValueError(f"{path}.domainData contains infrastructure member")


def validate_meta(meta: Any) -> None:
    if not isinstance(meta, dict):
        raise ValueError("meta must be an object")
    for field in IDENTIFIER_TERMS[:3]:
        if field not in meta:
            raise ValueError(f"meta.{field} is required")
        require_identifier(meta[field], f"meta.{field}")


def validate_response(document: Any, *, jsonld: bool) -> None:
    if not isinstance(document, dict):
        raise ValueError("response must be an object")
    context = document.get("@context")
    if jsonld:
        if context != CONTEXT_URI:
            raise ValueError("JSON-LD response must use the governed @context")
    elif "@context" in document:
        raise ValueError("JSON response must not include @context")
    if "@context" in document:
        document = {key: value for key, value in document.items() if key != "@context"}
    reject_nested_context(document, "response")
    is_single = "data" in document
    is_collection = "items" in document or "pageInfo" in document
    if is_single == is_collection:
        raise ValueError("response must use exactly one v1 envelope")
    validate_meta(document.get("meta"))
    if is_single:
        members = SINGLE_FORBIDDEN_MEMBERS.intersection(document)
        if members:
            raise ValueError("single response contains misplaced infrastructure member")
        validate_record(document["data"], "data")
        return
    members = COLLECTION_FORBIDDEN_MEMBERS.intersection(document)
    if members:
        raise ValueError("collection response contains misplaced infrastructure member")
    items = document.get("items")
    if not isinstance(items, list):
        raise ValueError("items must be an array")
    for index, item in enumerate(items):
        validate_record(item, f"items[{index}]")
    page_info = document.get("pageInfo")
    if not isinstance(page_info, dict) or "nextCursor" not in page_info:
        raise ValueError("pageInfo.nextCursor is required")
    next_cursor = page_info["nextCursor"]
    if next_cursor is not None:
        require_identifier(next_cursor, "pageInfo.nextCursor")


class RegistryRecordContractTest(unittest.TestCase):
    def test_normative_artifacts_use_stable_identifiers(self) -> None:
        profile = (ROOT / "profile/registry-record-v1.md").read_text(encoding="utf-8")
        self.assertIn(PROFILE_URI, profile)
        self.assertIn(SCHEMA_URI, profile)
        self.assertIn(CONTEXT_URI, profile)
        schema = load_json(ROOT / "schema/registry-record-v1.schema.json")
        self.assertEqual(schema["$id"], SCHEMA_URI)
        self.assertEqual(schema["properties"]["@context"]["const"], CONTEXT_URI)

    def test_schema_keeps_required_v1_member_placement_open_to_extensions(self) -> None:
        schema = load_json(ROOT / "schema/registry-record-v1.schema.json")
        definitions = schema["$defs"]
        self.assertEqual(
            definitions["singleResponse"]["required"], ["data", "meta"]
        )
        self.assertEqual(
            definitions["collectionResponse"]["required"],
            ["items", "pageInfo", "meta"],
        )
        self.assertEqual(
            definitions["record"]["required"],
            ["recordIdentifier", "revisionIdentifier", "domainData"],
        )
        self.assertEqual(
            definitions["responseMeta"]["required"],
            ["registryIdentifier", "datasetIdentifier", "entityTypeIdentifier"],
        )
        self.assertIn("not", definitions["singleResponse"])
        self.assertIn("not", definitions["collectionResponse"])
        self.assertIn("not", definitions["record"])
        self.assertEqual(
            definitions["domainData"]["propertyNames"]["not"]["const"],
            "@context",
        )
        self.assertTrue(definitions["singleResponse"]["additionalProperties"])
        self.assertTrue(definitions["collectionResponse"]["additionalProperties"])
        self.assertTrue(definitions["record"]["additionalProperties"])

    def test_context_preserves_all_opaque_identifiers_as_strings(self) -> None:
        context = load_json(ROOT / "context/registry-record-v1.jsonld")["@context"]
        for term in IDENTIFIER_TERMS:
            with self.subTest(term=term):
                mapping = context[term]
                self.assertEqual(mapping["@id"], f"{VOCABULARY_URI}{term}")
                self.assertEqual(
                    mapping["@type"], "http://www.w3.org/2001/XMLSchema#string"
                )
                self.assertNotEqual(mapping["@type"], "@id")

    def test_positive_fixtures_conform_in_json_and_jsonld(self) -> None:
        for path in sorted((ROOT / "fixtures/positive").iterdir()):
            with self.subTest(path=path.name):
                document = load_json(path)
                validate_response(document, jsonld=path.suffix == ".jsonld")

    def test_negative_fixtures_are_rejected(self) -> None:
        for path in sorted((ROOT / "fixtures/negative").iterdir()):
            with self.subTest(path=path.name):
                with self.assertRaises(ValueError):
                    validate_response(load_json(path), jsonld=path.suffix == ".jsonld")


if __name__ == "__main__":
    unittest.main()
