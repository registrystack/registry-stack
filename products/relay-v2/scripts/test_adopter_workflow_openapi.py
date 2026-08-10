#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("test_adopter_workflow.py")
SPEC = importlib.util.spec_from_file_location("relay_v2_adopter_workflow", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
WORKFLOW = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WORKFLOW
SPEC.loader.exec_module(WORKFLOW)


class PublicOpenApiProjectionTests(unittest.TestCase):
    def test_rejects_a_protected_representation_in_public_output(self) -> None:
        public_profile = {
            "identifier": "public-register",
            "default": True,
            "disclosureProfile": "public-register",
            "processingHandling": "public",
            "disclosureHandling": "public",
            "transformIdentifiers": [],
            "schemaReference": "https://registry.example.invalid/v2/artifacts/public-schema",
            "semanticModelReference": "https://registry.example.invalid/v2/artifacts/public-vocabulary",
            "contextReference": "https://registry.example.invalid/v2/artifacts/public-context",
        }
        protected_profile = {
            **public_profile,
            "identifier": "registrar",
            "default": False,
            "disclosureProfile": "registrar",
            "processingHandling": "confidential",
            "disclosureHandling": "confidential",
            "schemaReference": "https://registry.example.invalid/v2/artifacts/registrar-schema",
            "semanticModelReference": "https://registry.example.invalid/v2/artifacts/registrar-vocabulary",
            "contextReference": "https://registry.example.invalid/v2/artifacts/registrar-context",
        }
        full = {
            "operationId": "business.read",
            "security": [{}, {"bearerAuth": []}],
            "x-registry-representations": [public_profile, protected_profile],
            "x-registry-required-scopes": [
                {"representation": "registrar", "scope": "registry:business:read-registrar"}
            ],
        }
        public = {
            "operationId": "business.read",
            "security": [],
            "parameters": [
                {
                    "name": "representation",
                    "in": "query",
                    "schema": {"enum": ["public-register", "registrar"]},
                }
            ],
            "x-registry-representations": [public_profile, copy.deepcopy(protected_profile)],
        }
        with self.assertRaisesRegex(WORKFLOW.GateFailure, "protected representation"):
            WORKFLOW.validate_public_operation(
                public,
                full,
                {"public-schema", "public-vocabulary", "public-context"},
            )


if __name__ == "__main__":
    unittest.main()
