#!/usr/bin/env python3
"""Focused tests for sync-coolify-compose-domains.py."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPT_DIR / "sync-coolify-compose-domains.py"


def load_script():
    spec = importlib.util.spec_from_file_location("sync_coolify_compose_domains", SCRIPT_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SyncCoolifyComposeDomainsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = load_script()

    def test_parses_required_domain_specs(self) -> None:
        self.assertEqual(
            {"citizen-portal": "https://portal.lab.registrystack.org:3000"},
            self.script.parse_domain_specs(
                ["citizen-portal=https://portal.lab.registrystack.org:3000"]
            ),
        )

    def test_rejects_domain_specs_without_scheme(self) -> None:
        with self.assertRaisesRegex(self.script.DomainSyncError, "must include"):
            self.script.parse_domain_specs(["citizen-portal=portal.lab.registrystack.org:3000"])

    def test_requires_domain_host_to_match_compose_extension(self) -> None:
        compose = {"x-hosted-domains": {"citizen-portal": "portal.lab.registrystack.org"}}
        self.script.require_compose_hosts(
            compose,
            {"citizen-portal": "https://portal.lab.registrystack.org:3000"},
        )

    def test_rejects_domain_host_that_drifted_from_compose(self) -> None:
        compose = {"x-hosted-domains": {"citizen-portal": "portal.lab.registrystack.org"}}
        with self.assertRaisesRegex(self.script.DomainSyncError, "does not match"):
            self.script.require_compose_hosts(
                compose,
                {"citizen-portal": "https://portal.example.test:3000"},
            )

    def test_extracts_domains_from_application_payload_json_string(self) -> None:
        payload = {
            "docker_compose_domains": (
                '{"lab-homepage":{"domain":"https://lab.registrystack.org"},'
                '"citizen-portal":{"domain":"https://portal.lab.registrystack.org:3000"}}'
            )
        }
        self.assertEqual(
            {
                "citizen-portal": "https://portal.lab.registrystack.org:3000",
                "lab-homepage": "https://lab.registrystack.org",
            },
            self.script.extract_stored_domains(payload),
        )

    def test_extracts_domains_from_endpoint_array_shape(self) -> None:
        payload = [
            {"name": "lab-homepage", "domain": "https://lab.registrystack.org"},
            {"name": "citizen-portal", "domain": "https://portal.lab.registrystack.org:3000"},
        ]
        self.assertEqual(
            {
                "citizen-portal": "https://portal.lab.registrystack.org:3000",
                "lab-homepage": "https://lab.registrystack.org",
            },
            self.script.extract_stored_domains(payload),
        )

    def test_ignores_application_update_uuid_response_as_domains(self) -> None:
        self.assertEqual({}, self.script.extract_stored_domains({"uuid": "app-uuid"}))

    def test_preserves_schemeless_existing_domain_values(self) -> None:
        self.assertEqual(
            {"lab-homepage": "lab.registrystack.org"},
            self.script.extract_stored_domains(
                {"docker_compose_domains": {"lab-homepage": "lab.registrystack.org"}}
            ),
        )

    def test_patch_entries_are_stable_and_keep_existing_domains(self) -> None:
        merged = {
            "lab-homepage": "https://lab.registrystack.org",
            "citizen-portal": "https://portal.lab.registrystack.org:3000",
        }
        self.assertEqual(
            [
                {"name": "citizen-portal", "domain": "https://portal.lab.registrystack.org:3000"},
                {"name": "lab-homepage", "domain": "https://lab.registrystack.org"},
            ],
            self.script.as_patch_entries(merged),
        )

    def test_sync_required_domains_retries_until_coolify_persists_domain(self) -> None:
        calls = []
        sleeps = []
        desired = {"citizen-portal": "https://portal.lab.registrystack.org:3000"}
        original_request_json = self.script.request_json
        original_sleep = self.script.time.sleep

        def fake_request_json(method, url, token, body=None):
            calls.append((method, url, token, body))
            patch_count = sum(1 for call in calls if call[0] == "PATCH")
            if method == "GET" and patch_count >= 2:
                return {
                    "docker_compose_domains": [
                        {
                            "name": "citizen-portal",
                            "domain": "https://portal.lab.registrystack.org:3000",
                        }
                    ]
                }
            if method == "PATCH":
                return {"uuid": "app-uuid"}
            return {"docker_compose_domains": []}

        self.script.request_json = fake_request_json
        self.script.time.sleep = lambda delay: sleeps.append(delay)
        try:
            self.script.sync_required_domains(
                "https://coolify.example/api/v1",
                "app-uuid",
                "token-value",
                desired,
                attempts=2,
                retry_delay=0.25,
            )
        finally:
            self.script.request_json = original_request_json
            self.script.time.sleep = original_sleep

        self.assertEqual([0.25], sleeps)
        self.assertEqual(2, sum(1 for call in calls if call[0] == "PATCH"))

    def test_patches_compose_domains_through_application_update_endpoint(self) -> None:
        calls = []
        original = self.script.request_json

        def fake_request_json(method, url, token, body=None):
            calls.append((method, url, token, body))
            return {"ok": True}

        self.script.request_json = fake_request_json
        try:
            self.assertEqual(
                {"ok": True},
                self.script.patch_compose_domains(
                    "https://coolify.example/api/v1",
                    "app-uuid",
                    "token-value",
                    {"citizen-portal": "https://portal.lab.registrystack.org:3000"},
                ),
            )
        finally:
            self.script.request_json = original

        self.assertEqual(
            [
                (
                    "PATCH",
                    "https://coolify.example/api/v1/applications/app-uuid",
                    "token-value",
                    {
                        "docker_compose_domains": [
                            {
                                "name": "citizen-portal",
                                "domain": "https://portal.lab.registrystack.org:3000",
                            }
                        ]
                    },
                )
            ],
            calls,
        )

    def test_rejects_missing_persisted_required_domain(self) -> None:
        with self.assertRaisesRegex(self.script.DomainSyncError, "did not persist"):
            self.script.assert_desired_stored(
                {"lab-homepage": "https://lab.registrystack.org"},
                {"citizen-portal": "https://portal.lab.registrystack.org:3000"},
            )


if __name__ == "__main__":
    unittest.main()
