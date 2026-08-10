#!/usr/bin/env python3
"""Focused tests for the aligned SDMX profile validator."""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from unittest import mock
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-sdmx-profile.py")
SPEC = importlib.util.spec_from_file_location("validate_sdmx_profile", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import environment
    raise RuntimeError("could not load validate-sdmx-profile.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class SdmxProfileValidatorTests(unittest.TestCase):
    def test_official_schema_validator_receives_its_format_checker(self) -> None:
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "oneOf": [
                {"type": "string", "format": "date"},
                {"type": "string", "format": "date-time"},
            ],
        }
        format_checker = object()

        class FakeValidator:
            FORMAT_CHECKER = format_checker
            checked_schema = None

            @classmethod
            def check_schema(cls, checked):
                cls.checked_schema = checked

            def __init__(self, validated_schema, *, format_checker):
                self.schema = validated_schema
                self.format_checker = format_checker

        fake_jsonschema = types.SimpleNamespace(
            validators=types.SimpleNamespace(validator_for=lambda _: FakeValidator)
        )
        with mock.patch.dict(sys.modules, {"jsonschema": fake_jsonschema}):
            validator = VALIDATOR.validator(schema)

        self.assertIs(FakeValidator.checked_schema, schema)
        self.assertIs(validator.schema, schema)
        self.assertIs(validator.format_checker, format_checker)


if __name__ == "__main__":
    unittest.main()
