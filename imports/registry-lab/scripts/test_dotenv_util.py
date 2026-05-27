#!/usr/bin/env python3
"""Focused tests for registry-lab dotenv parsing."""

from __future__ import annotations

import unittest

from dotenv_util import parse_dotenv_text


class DotenvUtilTest(unittest.TestCase):
    def test_shell_quoted_json_round_trips(self) -> None:
        values = parse_dotenv_text("REGISTRY_WITNESS_ISSUER_JWK='{\"kty\":\"OKP\"}'\n")
        self.assertEqual(values["REGISTRY_WITNESS_ISSUER_JWK"], '{"kty":"OKP"}')

    def test_legacy_unquoted_json_is_preserved(self) -> None:
        values = parse_dotenv_text('REGISTRY_WITNESS_ISSUER_JWK={"kty":"OKP"}\n')
        self.assertEqual(values["REGISTRY_WITNESS_ISSUER_JWK"], '{"kty":"OKP"}')

    def test_raw_tokens_are_preserved(self) -> None:
        values = parse_dotenv_text("TOKEN_RAW=abc-123_XYZ\n")
        self.assertEqual(values["TOKEN_RAW"], "abc-123_XYZ")


if __name__ == "__main__":
    unittest.main()
