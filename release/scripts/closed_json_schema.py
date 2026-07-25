#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate the closed JSON Schema subset used by release evidence tools."""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
from typing import Any


class SchemaValidationError(ValueError):
    """A value does not satisfy the supported closed schema."""


def resolve_ref(schema: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise SchemaValidationError(
            f"unsupported external schema reference: {reference}"
        )
    value: Any = schema
    try:
        for component in reference[2:].split("/"):
            value = value[component]
    except (KeyError, TypeError):
        raise SchemaValidationError(
            f"schema reference does not resolve: {reference}"
        ) from None
    if not isinstance(value, dict):
        raise SchemaValidationError(
            f"schema reference does not resolve to an object: {reference}"
        )
    return value


def json_value_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON values without Python's bool-as-int equivalence."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return (
            isinstance(actual, bool)
            and isinstance(expected, bool)
            and actual == expected
        )
    if actual is None or expected is None:
        return actual is expected
    if isinstance(actual, list) or isinstance(expected, list):
        return (
            isinstance(actual, list)
            and isinstance(expected, list)
            and len(actual) == len(expected)
            and all(
                json_value_equal(left, right)
                for left, right in zip(actual, expected)
            )
        )
    if isinstance(actual, dict) or isinstance(expected, dict):
        return (
            isinstance(actual, dict)
            and isinstance(expected, dict)
            and set(actual) == set(expected)
            and all(json_value_equal(actual[key], expected[key]) for key in actual)
        )
    return actual == expected


def validate_against_schema(
    value: Any,
    rule: dict[str, Any],
    schema: dict[str, Any],
    label: str = "result",
) -> None:
    """Validate the const/enum/closed-object/array/scalar subset used here."""
    if "$ref" in rule:
        validate_against_schema(
            value,
            resolve_ref(schema, rule["$ref"]),
            schema,
            label,
        )
        return
    if "const" in rule and not json_value_equal(value, rule["const"]):
        raise SchemaValidationError(f"{label} must equal {rule['const']!r}")
    if "enum" in rule and not any(
        json_value_equal(value, allowed) for allowed in rule["enum"]
    ):
        raise SchemaValidationError(f"{label} is outside the closed allowed set")

    kind = rule.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise SchemaValidationError(f"{label} must be an object")
        required = set(rule.get("required", []))
        missing = required - set(value)
        if missing:
            raise SchemaValidationError(
                f"{label} is missing {', '.join(sorted(missing))}"
            )
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False:
            unknown = set(value) - set(properties)
            if unknown:
                raise SchemaValidationError(
                    f"{label} has unknown fields: {', '.join(sorted(unknown))}"
                )
        for name, item in value.items():
            if name in properties:
                validate_against_schema(
                    item,
                    properties[name],
                    schema,
                    f"{label}.{name}",
                )
    elif kind == "array":
        if not isinstance(value, list):
            raise SchemaValidationError(f"{label} must be an array")
        if len(value) < rule.get("minItems", 0) or len(value) > rule.get(
            "maxItems", sys.maxsize
        ):
            raise SchemaValidationError(f"{label} has an invalid item count")
        if rule.get("uniqueItems") and len(
            {json.dumps(item, sort_keys=True) for item in value}
        ) != len(value):
            raise SchemaValidationError(f"{label} must contain unique values")
        for index, item in enumerate(value):
            validate_against_schema(
                item,
                rule.get("items", {}),
                schema,
                f"{label}[{index}]",
            )
    elif kind == "string":
        if not isinstance(value, str):
            raise SchemaValidationError(f"{label} must be a string")
        if len(value) < rule.get("minLength", 0) or len(value) > rule.get(
            "maxLength", sys.maxsize
        ):
            raise SchemaValidationError(f"{label} has an invalid length")
        if "pattern" in rule and re.fullmatch(rule["pattern"], value) is None:
            raise SchemaValidationError(f"{label} has an invalid or unsafe value")
        if rule.get("format") == "uri":
            try:
                parsed = urllib.parse.urlsplit(value)
                parsed.port
            except ValueError:
                raise SchemaValidationError(
                    f"{label} has an invalid URI"
                ) from None
            if not parsed.scheme or not parsed.netloc:
                raise SchemaValidationError(f"{label} has an invalid URI")
    elif kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise SchemaValidationError(f"{label} must be an integer")
        if value < rule.get("minimum", value) or value > rule.get("maximum", value):
            raise SchemaValidationError(f"{label} is outside its allowed range")
    elif kind == "boolean" and not isinstance(value, bool):
        raise SchemaValidationError(f"{label} must be a boolean")
    elif kind == "null" and value is not None:
        raise SchemaValidationError(f"{label} must be null")
