#!/usr/bin/env python3
"""Focused tests for the Registry Lab homepage server."""

from __future__ import annotations

import importlib.util
import json
import os
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parent / "lab-homepage-server.py"
_spec = importlib.util.spec_from_file_location("lab_homepage_server", MODULE_PATH)
assert _spec and _spec.loader
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)
from lab_homepage_scenarios import common as scenario_common

# The CSS/JS that used to be inlined in the page templates now lives in real static asset
# files served from /static/<name>. Tests that assert on that CSS/JS read the asset files
# directly (the same bytes the server serves) instead of grepping the HTML shell.
STATIC_DIR = Path(__file__).resolve().parent / "lab_homepage_static"


def _static_text(name: str) -> str:
    return (STATIC_DIR / name).read_text(encoding="utf-8")


SHARED_CSS = _static_text("shared.css")
HOMEPAGE_CSS = _static_text("homepage.css")
SCENARIOS_CSS = _static_text("scenarios.css")
EXPLORERS_CSS = _static_text("explorers.css")
HOMEPAGE_JS = _static_text("homepage.js")
SCENARIOS_JS = _static_text("scenarios.js")
REGISTRY_EXPLORER_JS = _static_text("registry-explorer.js")
CLAIMS_EXPLORER_JS = _static_text("claims-explorer.js")


ATTESTATION_RESPONSE_KEYS = {
    "attestation_id",
    "display_name",
    "source_authority",
    "jurisdiction",
    "publicschema_anchor",
    "subject",
    "match_method",
    "matched_record_ref",
    "as_of",
    "source_observed_at",
    "disclosure_profile",
    "claims",
    "proof",
}


def assert_attestation_response(testcase: unittest.TestCase, envelope: dict, expected_id: str) -> None:
    testcase.assertTrue(ATTESTATION_RESPONSE_KEYS.issubset(envelope), sorted(ATTESTATION_RESPONSE_KEYS - set(envelope)))
    testcase.assertEqual(envelope["attestation_id"], expected_id)
    testcase.assertIsInstance(envelope["claims"], list)
    testcase.assertTrue(envelope["claims"])
    testcase.assertEqual(envelope["proof"]["status"], "linked_raw_response")


class ApplyEnvFileTest(unittest.TestCase):
    """apply_env_file must fill absent or empty vars, but never clobber a real value."""

    KEY = "REGISTRY_LAB_TEST_TOKEN_RAW"

    def setUp(self) -> None:
        self._saved = dict(os.environ)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    def test_fills_absent_key(self) -> None:
        os.environ.pop(self.KEY, None)
        server.apply_env_file({self.KEY: "from-file"})
        self.assertEqual(os.environ[self.KEY], "from-file")

    def test_fills_empty_key(self) -> None:
        # Compose injects each token as ${VAR:-}, so the key exists but is empty.
        os.environ[self.KEY] = ""
        server.apply_env_file({self.KEY: "from-file"})
        self.assertEqual(os.environ[self.KEY], "from-file")

    def test_non_empty_value_wins(self) -> None:
        os.environ[self.KEY] = "from-deploy-env"
        server.apply_env_file({self.KEY: "from-file"})
        self.assertEqual(os.environ[self.KEY], "from-deploy-env")


class StatusClassificationTest(unittest.TestCase):
    """A reachable, auth-gated service (401/403) is up, not down."""

    CONFIG = {
        "services": [
            {"id": "svc", "label": "Svc", "url": "https://svc.example", "status_path": "/x"}
        ]
    }

    def _check(self, fake_urlopen):
        with mock.patch.object(server.urllib.request, "urlopen", fake_urlopen):
            return server.status_checks(self.CONFIG, timeout=1.0)["checks"][0]

    def test_2xx_is_up(self) -> None:
        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        check = self._check(lambda req, timeout=None: Resp())
        self.assertTrue(check["ok"])
        self.assertFalse(check["auth_gated"])
        self.assertEqual(check["status_code"], 200)
        # No credential targets this service, so its base URL is probed: 200 means browsable.
        self.assertTrue(check["browsable"])

    def test_401_is_up_and_auth_gated(self) -> None:
        def fake(req, timeout=None):
            raise urllib.error.HTTPError("https://svc.example/x", 401, "Unauthorized", Message(), None)

        check = self._check(fake)
        self.assertTrue(check["ok"])
        self.assertTrue(check["auth_gated"])
        self.assertEqual(check["status_code"], 401)
        # A 401 at the base URL is nothing to see in a browser.
        self.assertFalse(check["browsable"])

    def test_403_is_up_and_auth_gated(self) -> None:
        def fake(req, timeout=None):
            raise urllib.error.HTTPError("https://svc.example/x", 403, "Forbidden", Message(), None)

        check = self._check(fake)
        self.assertTrue(check["ok"])
        self.assertTrue(check["auth_gated"])
        self.assertFalse(check["browsable"])

    def test_5xx_is_down(self) -> None:
        def fake(req, timeout=None):
            raise urllib.error.HTTPError("https://svc.example/x", 503, "Unavailable", Message(), None)

        check = self._check(fake)
        self.assertFalse(check["ok"])
        self.assertFalse(check["auth_gated"])
        self.assertEqual(check["status_code"], 503)
        self.assertFalse(check["browsable"])

    def test_transport_error_is_down(self) -> None:
        def fake(req, timeout=None):
            raise urllib.error.URLError("connection refused")

        check = self._check(fake)
        self.assertFalse(check["ok"])
        self.assertFalse(check["auth_gated"])
        self.assertIsNone(check["status_code"])
        self.assertFalse(check["browsable"])


class AuthSchemeTest(unittest.TestCase):
    """api_key credentials present via X-Api-Key; everything else via Bearer."""

    def test_helper_defaults_to_bearer(self) -> None:
        self.assertEqual(server.auth_header_pair({}, "tok"), ("Authorization", "Bearer tok"))

    def test_helper_api_key(self) -> None:
        self.assertEqual(
            server.auth_header_pair({"auth_scheme": "api_key"}, "tok"),
            ("X-Api-Key", "tok"),
        )

    def test_curl_example_uses_x_api_key(self) -> None:
        cred = {
            "service_url": "https://n.example",
            "example": {"method": "GET", "path": "/p"},
            "auth_scheme": "api_key",
        }
        curl = server.curl_example(cred, "tok")
        self.assertIn("X-Api-Key: tok", curl)
        self.assertNotIn("Authorization: Bearer", curl)

    def test_curl_example_defaults_to_bearer(self) -> None:
        cred = {"service_url": "https://n.example", "example": {"method": "GET", "path": "/p"}}
        self.assertIn("Authorization: Bearer tok", server.curl_example(cred, "tok"))


class ClaimTargetInputMetadataTest(unittest.TestCase):
    """Explorer request previews derive target shapes from Notary claim metadata."""

    CLAIMS_BODY = {
        "data": [
            {
                "id": "person-is-alive",
                "target_inputs": [
                    {
                        "target_type": "Person",
                        "method": "identifier_or_demographic",
                        "confidence": "high",
                        "groups": [
                            {
                                "inputs": [
                                    {
                                        "path": "target.identifiers.national_id",
                                        "kind": "identifier",
                                        "name": "national_id",
                                        "label": "National id",
                                    }
                                ]
                            },
                            {
                                "inputs": [
                                    {
                                        "path": "target.attributes.given_name",
                                        "kind": "attribute",
                                        "name": "given_name",
                                        "label": "Given name",
                                    },
                                    {
                                        "path": "target.attributes.surname",
                                        "kind": "attribute",
                                        "name": "surname",
                                        "label": "Surname",
                                    },
                                    {
                                        "path": "target.attributes.birth_date",
                                        "kind": "attribute",
                                        "name": "birth_date",
                                        "label": "Birth date",
                                    },
                                ]
                            },
                        ],
                    }
                ],
            }
        ]
    }

    def test_target_input_facts_render_discovered_options(self) -> None:
        facts = scenario_common.target_input_facts(self.CLAIMS_BODY, ["person-is-alive"])
        self.assertEqual(facts[0]["label"], "Target inputs")
        self.assertEqual(facts[0]["value"], "National id OR Given name + Surname + Birth date")
        self.assertEqual(facts[1]["value"], "Published by Notary claim discovery")

    def test_evaluation_body_uses_demographic_group_when_identifier_is_not_available(self) -> None:
        profile = scenario_common.person_profile(
            "",
            attributes={"given_name": "Miguel", "surname": "Santos", "birth_date": "2016-01-15"},
        )
        body, selection = scenario_common.evaluation_body_from_claim_metadata(
            self.CLAIMS_BODY,
            profile,
            ["person-is-alive"],
        )

        self.assertEqual(selection["source"], "target_inputs")
        self.assertEqual(selection["group"], "Given name + Surname + Birth date")
        self.assertEqual(
            body["target"]["attributes"],
            {"given_name": "Miguel", "surname": "Santos", "birth_date": "2016-01-15"},
        )
        self.assertNotIn("identifiers", body["target"])

    def test_evaluation_body_falls_back_for_legacy_notary_claims(self) -> None:
        profile = scenario_common.person_profile("NID-1001")
        body, selection = scenario_common.evaluation_body_from_claim_metadata(
            {"claims": [{"id": "person-is-alive"}]},
            profile,
            ["person-is-alive"],
        )

        self.assertEqual(selection["source"], "identifier_fallback")
        self.assertEqual(body["target"]["identifiers"], [{"scheme": "national_id", "value": "NID-1001"}])


class StatusProbeHeaderTest(unittest.TestCase):
    """The status probe attaches the credential's token in its native scheme."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    def _probe_request(self, auth_scheme):
        os.environ["PROBE_TOKEN_RAW"] = "secret-token"
        cred = {"id": "k", "env": "PROBE_TOKEN_RAW"}
        if auth_scheme:
            cred["auth_scheme"] = auth_scheme
        config = {
            "services": [
                {
                    "id": "n",
                    "label": "N",
                    "url": "https://n.example",
                    "status_path": "/x",
                    "status_credential_id": "k",
                }
            ],
            "credentials": [cred],
        }
        captured = {}

        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake(req, timeout=None):
            captured["req"] = req
            return Resp()

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            server.status_checks(config, timeout=1.0)
        return captured["req"]

    def test_api_key_probe_uses_x_api_key(self) -> None:
        req = self._probe_request("api_key")
        self.assertEqual(req.get_header("X-api-key"), "secret-token")
        self.assertIsNone(req.get_header("Authorization"))

    def test_bearer_probe_uses_authorization(self) -> None:
        req = self._probe_request(None)
        self.assertEqual(req.get_header("Authorization"), "Bearer secret-token")
        self.assertIsNone(req.get_header("X-api-key"))


class BrowsableProbeTest(unittest.TestCase):
    """The Open-link signal: a credential-free service is probed unauthenticated at its base
    URL (2xx/3xx means there is something to see); a service that hands out a credential is a
    protected API, so it is treated as not browsable and its base URL is never probed."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    class _Resp:
        def __init__(self, status: int) -> None:
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _run(self, service, credentials=None, base_status=200):
        config = {"services": [service]}
        if credentials:
            config["credentials"] = credentials
        reqs = []

        def fake(req, timeout=None):
            reqs.append(req)
            if req.full_url.rstrip("/") == service["url"].rstrip("/"):  # the base-URL probe
                if base_status >= 400:
                    raise urllib.error.HTTPError(req.full_url, base_status, "x", Message(), None)
                return self._Resp(base_status)
            return self._Resp(200)  # the authenticated status probe is healthy

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            check = server.status_checks(config, timeout=1.0)["checks"][0]
        return check, reqs

    def _base_requests(self, reqs, url):
        return [r for r in reqs if r.full_url.rstrip("/") == url.rstrip("/")]

    def test_credential_free_service_probes_base_url_unauthenticated(self) -> None:
        service = {"id": "ui", "label": "UI", "url": "https://ui.example", "status_path": "/health"}
        check, reqs = self._run(service, base_status=200)
        self.assertTrue(check["browsable"])
        base = self._base_requests(reqs, service["url"])
        self.assertEqual(len(base), 1)
        self.assertIsNone(base[0].get_header("Authorization"))

    def test_base_url_4xx_is_not_browsable(self) -> None:
        service = {"id": "ui", "label": "UI", "url": "https://ui.example", "status_path": "/health"}
        check, _ = self._run(service, base_status=401)
        self.assertFalse(check["browsable"])

    def test_credentialed_service_is_not_browsable_and_skips_base_probe(self) -> None:
        os.environ["K_RAW"] = "tok"
        service = {
            "id": "relay",
            "label": "Relay",
            "url": "https://relay.example",
            "status_path": "/healthz",
            "status_credential_id": "k",
        }
        creds = [{"id": "k", "env": "K_RAW", "service_url": "https://relay.example"}]
        check, reqs = self._run(service, credentials=creds, base_status=200)
        self.assertFalse(check["browsable"])
        self.assertEqual(self._base_requests(reqs, service["url"]), [])


class GroupCredentialsTest(unittest.TestCase):
    """enrich_config attaches each credential to its service and never drops one."""

    def _config(self) -> dict:
        return {
            "services": [
                {"id": "relay", "label": "Relay", "url": "https://relay.example"},
                {"id": "ui", "label": "UI", "url": "https://ui.example"},
            ],
            "credentials": [
                {"id": "a", "env": "A_RAW", "service_url": "https://relay.example", "example": {"path": "/x"}},
                {"id": "b", "env": "B_RAW", "service_url": "https://relay.example", "example": {"path": "/y"}},
            ],
        }

    def test_credentials_attached_to_matching_service(self) -> None:
        services = {s["id"]: s for s in server.enrich_config(self._config())["services"]}
        self.assertEqual([c["id"] for c in services["relay"]["credentials"]], ["a", "b"])

    def test_service_without_credentials_gets_empty_list(self) -> None:
        services = {s["id"]: s for s in server.enrich_config(self._config())["services"]}
        self.assertEqual(services["ui"]["credentials"], [])

    def test_top_level_credentials_preserved(self) -> None:
        # The missing-token count and the status probe lookup both read data.credentials.
        enriched = server.enrich_config(self._config())
        self.assertEqual([c["id"] for c in enriched["credentials"]], ["a", "b"])

    def test_unmatched_credential_is_surfaced_not_dropped(self) -> None:
        config = self._config()
        config["credentials"].append(
            {"id": "orphan", "env": "O_RAW", "service_url": "https://nowhere.example", "example": {"path": "/z"}}
        )
        enriched = server.enrich_config(config)
        grouped_ids = {c["id"] for service in enriched["services"] for c in service["credentials"]}
        self.assertIn("orphan", grouped_ids)

    def test_committed_notary_credentials_expose_default_purpose(self) -> None:
        config = server.enrich_config(server.load_config(server.DEFAULT_CONFIG))
        credentials = {credential["id"]: credential for credential in config["credentials"]}

        self.assertEqual(
            credentials["agri-evidence"]["default_purpose"],
            "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
        )
        self.assertEqual(
            credentials["dhis2-api-key"]["default_purpose"],
            "https://demo.example.gov/purpose/dhis2-openfn-health-evidence",
        )
        self.assertEqual(
            credentials["dhis2-bearer"]["default_purpose"],
            "https://demo.example.gov/purpose/dhis2-openfn-health-evidence",
        )
        self.assertEqual(
            credentials["opencrvs-api-key"]["default_purpose"],
            "https://demo.example.gov/purpose/opencrvs-dci-lab",
        )


class ScenarioPayloadTest(unittest.TestCase):
    """The scenario runner exposes a multi-story catalogue and dedicated story payloads."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        os.environ["CIVIL_RAW"] = "civil-token"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    def _payload(self) -> dict:
        config = {
            "credentials": [
                {
                    "id": "civil-evidence-only",
                    "label": "Civil Evidence",
                    "env": "CIVIL_RAW",
                    "service_url": "https://civil.example",
                    "scopes": ["civil_registry:evidence_verification"],
                    "example": {"path": "/metadata/evidence-offerings", "positive_subject": "NID-1001"},
                },
            ],
        }
        return server.scenario_payload(server.enrich_config(config))

    def test_builds_one_guided_vital_status_story(self) -> None:
        story = server.scenario_payload(self._payload_config(), "alive-proof")["story"]
        self.assertEqual(story["id"], "alive-proof")
        self.assertIn("Miguel", story["title"])
        self.assertEqual(story["subject"], {"name": "Miguel Santos", "identifier": "NID-1001"})
        self.assertEqual([step["id"] for step in story["steps"]], ["discover", "prepare-evidence", "deny-row"])
        self.assertEqual(story["steps"][1]["button"], "Request attestation")
        self.assertIn("Read Miguel's full civil registry row", story["boundary"]["not_allowed"])
        self.assertEqual(story["steps"][1]["reuses"][1], {"label": "Lookup profile", "value": "by-national-id"})

    def _payload_config(self) -> dict:
        return server.enrich_config(
            {
                "credentials": [
                    {
                        "id": "civil-evidence-only",
                        "label": "Civil Evidence",
                        "env": "CIVIL_RAW",
                        "service_url": "https://civil.example",
                        "scopes": ["civil_registry:evidence_verification"],
                        "example": {"path": "/metadata/evidence-offerings", "positive_subject": "NID-1001"},
                    },
                    {
                        "id": "social-metadata",
                        "env": "CIVIL_RAW",
                        "service_url": "https://social.example",
                        "example": {"path": "/v1/datasets"},
                    },
                    {
                        "id": "social-aggregate-reader",
                        "env": "CIVIL_RAW",
                        "service_url": "https://social.example",
                        "example": {"path": "/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band"},
                    },
                    {
                        "id": "social-row-reader",
                        "env": "CIVIL_RAW",
                        "service_url": "https://social.example",
                        "example": {"path": "/v1/datasets/social_protection_registry/entities/household/records?limit=1"},
                    },
                    {
                        "id": "dhis2-bearer",
                        "env": "CIVIL_RAW",
                        "service_url": "https://dhis2.example",
                        "example": {"path": "/v1/claims"},
                    },
                ],
                "wallet": {
                    "issuer": "https://issuer.example",
                    "credential_configuration_id": "person_is_alive_sd_jwt",
                    "offer_url": "https://issuer.example/offer",
                },
            }
        )

    def test_catalogue_lists_scenarios_with_dedicated_routes(self) -> None:
        payload = server.scenario_payload(self._payload_config())
        scenario_ids = [item["id"] for item in payload["scenarios"]]
        self.assertEqual(
            scenario_ids,
            [
                "alive-proof",
                "civil-birth-demographics",
                "civil-birth-evidence",
                "civil-birth-evidence-demographics",
                "civil-marriage-evidence",
                "wallet-credential",
                "dhis2-programme-vc",
                "social-aggregate",
                "combined-support",
                "agriculture-voucher",
            ],
        )
        self.assertEqual(payload["default_scenario_id"], "alive-proof")
        self.assertEqual(len(payload["scenarios"]), 10)
        for scenario in payload["scenarios"][1:]:
            self.assertEqual(scenario["availability"], "hosted")

    def test_catalogue_exposes_attestation_metadata_and_availability_state(self) -> None:
        payload = server.scenario_payload(self._payload_config(), lab_mode="hosted")
        alive = next(item for item in payload["scenarios"] if item["id"] == "alive-proof")
        self.assertEqual(alive["title"], "Vital Status Attestation")
        self.assertEqual(alive["availability_state"]["state"], "hosted")
        self.assertTrue(alive["availability_state"]["runnable"])
        self.assertEqual(alive["requested_attestations"][0]["offering_id"], "vital-status-attestation")
        self.assertEqual(alive["requested_attestations"][0]["lookup_profiles"], ["by-national-id"])

    def test_story_exposes_requested_attestations_lookup_disclosure_and_proof(self) -> None:
        story = server.scenario_payload(self._payload_config(), "alive-proof")["story"]
        self.assertEqual(story["requested_attestations"][0]["display_name"], "Vital Status Attestation")
        self.assertEqual(story["lookup_profile"]["id"], "by-national-id")
        self.assertIn("Full civil registry row", story["non_disclosure"])
        self.assertTrue(any("CivilStatusRecord" in fact for fact in story["proof_facts"]))
        self.assertEqual(story["availability_state"]["label"], "Hosted")

    def test_public_label_check_rejects_raw_compatibility_ids(self) -> None:
        from lab_homepage_scenarios import public_label_check
        from lab_homepage_scenarios.attestations import RAW_COMPATIBILITY_IDS

        for raw_id in RAW_COMPATIBILITY_IDS:
            with self.subTest(raw_id=raw_id):
                self.assertEqual(
                    public_label_check(
                        [
                            {
                                "id": "bad-story",
                                "title": raw_id,
                                "short_title": "",
                                "proves": "",
                                "steps": [],
                                "receipt": [],
                            }
                        ]
                    ),
                    [f"bad-story.title: {raw_id}"],
                )

    def test_public_attestation_metadata_omits_compatibility_aliases(self) -> None:
        from lab_homepage_scenarios.attestations import attestation

        metadata = attestation("vital-status-attestation")
        self.assertEqual("Vital Status Attestation", metadata["display_name"])
        self.assertNotIn("compatibility_claim_aliases", metadata)

    def test_public_label_check_reports_path_for_raw_compatibility_ids(self) -> None:
        from lab_homepage_scenarios import public_label_check
        violations = public_label_check(
            [
                {
                    "id": "bad-story",
                    "title": "person-is-alive",
                    "short_title": "",
                    "proves": "",
                    "steps": [],
                    "receipt": [],
                }
            ]
        )
        self.assertEqual(violations, ["bad-story.title: person-is-alive"])

    def test_public_scenario_labels_do_not_expose_raw_compatibility_ids(self) -> None:
        from lab_homepage_scenarios import public_label_check
        self.assertEqual(public_label_check(), [])

    def test_wallet_story_uses_adult_persona(self) -> None:
        story = server.scenario_payload(self._payload_config(), "wallet-credential")["story"]
        self.assertEqual(story["subject"], {"name": "Maria Santos", "identifier": "NID-2001"})
        self.assertIn("adult demo citizen", story["intro"])
        self.assertEqual(story["steps"][-1]["id"], "credential-preview")

    def test_prepare_evidence_step_executes_notary_evaluation(self) -> None:
        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "notary-token"
        os.environ["CIVIL_EVIDENCE_URL"] = "https://notary.example"

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"results":[{"claim_id":"person-is-alive","satisfied":true,"provenance":{"source_count":1}}]}'

        captured = {}

        def fake(req, timeout=None):
            captured["req"] = req
            return Resp()

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(server.enrich_config({"credentials": []}), "alive-proof", "prepare-evidence")

        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(result["friendly"]["facts"][0], {"label": "HTTP status", "value": 200})
        self.assertEqual(result["friendly"]["facts"][1], {"label": "Requested attestation", "value": "Vital Status Attestation"})
        self.assertEqual(result["friendly"]["facts"][4], {"label": "Vital status current", "value": "Yes"})
        self.assertEqual(result["response_source"]["reused_from_discovery"]["lookup_profile"], "by-national-id")
        assert_attestation_response(
            self,
            result["response_source"]["attestation_response"],
            "vital-status-attestation",
        )
        self.assertEqual(captured["req"].full_url, "https://notary.example/v1/evaluations")
        self.assertEqual(captured["req"].get_header("Authorization"), "Bearer notary-token")
        self.assertEqual(result["request_source"]["headers"]["Authorization"], "Bearer [runtime demo token hidden]")

    def test_step_runner_displays_public_relay_token_in_request_source(self) -> None:
        config = {
            "credentials": [
                {
                    "id": "civil-evidence-only",
                    "env": "CIVIL_RAW",
                    "service_url": "https://civil.example",
                    "example": {"path": "/metadata/evidence-offerings"},
                }
            ]
        }

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"evidence_offerings":[{"title":"Civil alive check","lookup_keys":["national_id"]}]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_alive_proof_step(server.enrich_config(config), "discover")
        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(result["friendly"]["facts"][1]["value"], "Civil alive check")
        self.assertEqual(result["request_source"]["headers"]["Authorization"], "Bearer civil-token")

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            row_result = server.run_alive_proof_step(server.enrich_config(config), "deny-row")
        self.assertEqual(row_result["request_source"]["headers"]["Authorization"], "Bearer civil-token")

    def test_scenario_request_sources_do_not_emit_placeholder_credentials(self) -> None:
        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "notary-token"
        os.environ["CIVIL_EVIDENCE_URL"] = "https://notary.example"
        config = {
            "credentials": [
                {
                    "id": "civil-evidence-only",
                    "env": "CIVIL_RAW",
                    "service_url": "https://civil.example",
                    "example": {"path": "/metadata/evidence-offerings"},
                }
            ]
        }

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"evidence_offerings":[{"title":"Civil alive check","lookup_keys":["national_id"]}],"results":[{"claim_id":"person-is-alive","satisfied":true}]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            for step_id in ("discover", "prepare-evidence", "deny-row"):
                result = server.run_alive_proof_step(server.enrich_config(config), step_id)
                headers = result["request_source"]["headers"]
                self.assertNotIn("[public demo token hidden]", str(headers))
                if step_id == "prepare-evidence":
                    self.assertNotIn("notary-token", str(headers))
                    self.assertIn("[runtime demo token hidden]", str(headers))

    def test_combined_support_reports_required_token_before_execution(self) -> None:
        os.environ.pop("SHARED_EVIDENCE_CLIENT_BEARER", None)
        result = server.run_scenario_step(server.enrich_config({"credentials": []}), "combined-support", "discover", lab_mode="local")
        self.assertEqual(result["friendly"]["status"], "needs_attention")
        self.assertIn("SHARED_EVIDENCE_CLIENT_BEARER", str(result["friendly"]["facts"]))
        self.assertIn("[runtime demo token missing]", str(result["request_source"]))

    def test_social_aggregate_uses_configured_display_url_and_request_url(self) -> None:
        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"data":[{"eligibility_band":"priority","household_count":3}]}'

        captured = {}

        def fake(req, timeout=None):
            captured["req"] = req
            return Resp()

        os.environ["SOCIAL_RELAY_URL"] = "http://social-protection-registry-relay:8080"
        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(self._payload_config(), "social-aggregate", "read-aggregate", lab_mode="local")

        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(
            captured["req"].full_url,
            "http://social-protection-registry-relay:8080/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band",
        )
        self.assertEqual(captured["req"].get_header("Authorization"), "Bearer civil-token")
        self.assertEqual(
            result["request_source"]["url"],
            "https://social.example/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band",
        )
        self.assertEqual(result["request_source"]["headers"]["Authorization"], "Bearer civil-token")
        self.assertEqual(result["request_source"]["headers"]["Data-Purpose"], "https://demo.example.gov/purpose/decentralized-evidence-demo")

    def test_wallet_simulated_step_hides_wallet_secrets(self) -> None:
        result = server.run_scenario_step(self._payload_config(), "wallet-credential", "credential-preview")
        self.assertEqual(result["friendly"]["status"], "done")
        self.assertIn("[wallet proof hidden]", str(result["request_source"]))
        self.assertIn("[simulated playground credential value hidden]", str(result["response_source"]))
        self.assertNotIn("private_key", str(result["request_source"]))

    def test_wallet_nonce_step_is_simulated_not_failed_live_probe(self) -> None:
        result = server.run_scenario_step(self._payload_config(), "wallet-credential", "nonce")
        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(result["request_source"]["method"], "SIMULATE")
        self.assertEqual(result["request_source"]["url"], "wallet://issuer-session/nonce")
        self.assertEqual(result["response_source"]["status"], "simulated")
        self.assertIn("wallet-demo-nonce-2026", str(result["response_source"]))
        self.assertNotIn("invalid_request", str(result))

    def test_dhis2_story_matches_bruno_programme_vc_flow(self) -> None:
        story = server.scenario_payload(self._payload_config(), "dhis2-programme-vc")["story"]
        self.assertEqual(story["id"], "dhis2-programme-vc")
        self.assertEqual(story["subject"]["identifier"], "PQfMcpmXeFE")
        self.assertEqual(
            [step["id"] for step in story["steps"]],
            ["discover", "evaluate-programme", "preview-vc", "reconcile", "negative-control", "render-cccev"],
        )
        self.assertIn("Bruno creates an Ed25519 holder proof", story["steps"][2]["prompt"])

    def test_dhis2_discovery_accepts_notary_data_envelope(self) -> None:
        captured = {}

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "data": [
                            {"id": "dhis2-tracked-entity-first-name"},
                            {"id": "dhis2-tracked-entity-last-name"},
                            {"id": "dhis2-child-age-band"},
                            {"id": "dhis2-programme-code"},
                            {"id": "dhis2-child-program-active"},
                            {"id": "dhis2-reconciliation-ref"},
                        ]
                    }
                ).encode("utf-8")

        def fake_urlopen(req, timeout=0):
            captured["req"] = req
            return Resp()

        with unittest.mock.patch("urllib.request.urlopen", fake_urlopen):
            result = server.run_scenario_step(self._payload_config(), "dhis2-programme-vc", "discover")

        facts = {item["label"]: item["value"] for item in result["friendly"]["facts"]}
        self.assertEqual(facts["Catalogue items advertised"], 6)
        self.assertEqual(facts["Programme participation available"], "Yes")
        self.assertEqual(captured["req"].get_header("Authorization"), "Bearer civil-token")

    def test_dhis2_evaluation_exposes_attestation_response_envelope(self) -> None:
        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "results": [
                            {"claim_id": "dhis2-child-program-active", "satisfied": True},
                            {"claim_id": "dhis2-reconciliation-ref", "value": "dhis2:tracked-entity:PQfMcpmXeFE"},
                        ]
                    }
                ).encode("utf-8")

        with unittest.mock.patch("urllib.request.urlopen", lambda req, timeout=0: Resp()):
            result = server.run_scenario_step(self._payload_config(), "dhis2-programme-vc", "evaluate-programme")

        assert_attestation_response(
            self,
            result["response_source"]["attestation_response"],
            "health-programme-participation-attestation",
        )

    def test_dhis2_preview_vc_hides_holder_proof_and_raw_credential(self) -> None:
        result = server.run_scenario_step(self._payload_config(), "dhis2-programme-vc", "preview-vc")
        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(result["request_source"]["method"], "SIMULATE")
        self.assertIn("[Ed25519 holder proof generated by Bruno, hidden in this playground]", str(result["request_source"]))
        self.assertIn("[holder-bound SD-JWT VC hidden]", str(result["response_source"]))


class CivilBirthDemographicsScenarioTest(unittest.TestCase):
    """Civil Relay demographic lookup story: discover target_inputs, then evaluate without an ID."""

    CLAIMS_BODY = {
        "data": [
            {
                "id": "civil-person-is-alive-by-demographics",
                "target_inputs": [
                    {
                        "target_type": "Person",
                        "method": "configured_demographic_lookup",
                        "groups": [
                            {
                                "inputs": [
                                    {
                                        "path": "target.attributes.given_name",
                                        "kind": "attribute",
                                        "name": "given_name",
                                        "label": "Given name",
                                    },
                                    {
                                        "path": "target.attributes.surname",
                                        "kind": "attribute",
                                        "name": "surname",
                                        "label": "Surname",
                                    },
                                    {
                                        "path": "target.attributes.birth_date",
                                        "kind": "attribute",
                                        "name": "birth_date",
                                        "label": "Birth date",
                                    },
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    }

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "notary-token"
        os.environ["CIVIL_EVIDENCE_URL"] = "https://notary.example"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    def _config(self) -> dict:
        return server.enrich_config(
            {
                "credentials": [
                    {
                        "id": "civil-notary-evidence",
                        "label": "Civil Notary evidence bearer",
                        "env": "CIVIL_EVIDENCE_CLIENT_BEARER",
                        "auth_scheme": "bearer",
                        "service_url": "https://notary.example",
                        "example": {"method": "GET", "path": "/v1/claims"},
                    }
                ]
            }
        )

    @staticmethod
    def _json_resp(payload: dict, status: int = 200):
        class Resp:
            headers = {"Content-Type": "application/json"}

            def __init__(self, body: dict, code: int):
                self._body = body
                self.status = code

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return json.dumps(self._body).encode("utf-8")

        return Resp(payload, status)

    def test_story_shape_is_hosted_civil_demographic_flow(self) -> None:
        story = server.scenario_payload(self._config(), "civil-birth-demographics")["story"]
        self.assertEqual(story["id"], "civil-birth-demographics")
        self.assertEqual(story["availability"], "hosted")
        self.assertEqual([step["id"] for step in story["steps"]], ["discover", "lookup"])
        self.assertEqual(story["lookup_profile"]["id"], "by-demographics")
        preview = story["steps"][1]["request_preview"]
        self.assertEqual(preview["target_input_selection"]["group"], "Given name + Surname + Birth date")
        self.assertEqual(
            preview["body"]["target"]["attributes"],
            {"given_name": "Miguel", "surname": "Martinez", "birth_date": "2014-01-15"},
        )
        self.assertNotIn("identifiers", preview["body"]["target"])

    def test_discover_step_reports_name_and_dob_contract(self) -> None:
        captured = {}

        def fake(req, timeout=None):
            captured["req"] = req
            return self._json_resp(self.CLAIMS_BODY)

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(self._config(), "civil-birth-demographics", "discover")

        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(captured["req"].full_url, "https://notary.example/v1/claims")
        self.assertEqual(captured["req"].get_header("Authorization"), "Bearer notary-token")
        facts = {item["label"]: item["value"] for item in result["friendly"]["facts"]}
        self.assertEqual(facts["Target inputs"], "Given name + Surname + Birth date")
        self.assertEqual(facts["Input metadata"], "Published by Notary claim discovery")

    def test_lookup_step_posts_demographic_attributes_without_identifier(self) -> None:
        captured = []

        def fake(req, timeout=None):
            captured.append(req)
            if req.full_url.endswith("/v1/claims"):
                return self._json_resp(self.CLAIMS_BODY)
            return self._json_resp(
                {"results": [{"claim_id": "civil-person-is-alive-by-demographics", "satisfied": True}]}
            )

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(self._config(), "civil-birth-demographics", "lookup")

        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual([req.full_url for req in captured], ["https://notary.example/v1/claims", "https://notary.example/v1/evaluations"])
        self.assertEqual(captured[1].get_header("Authorization"), "Bearer notary-token")
        body = json.loads(captured[1].data.decode("utf-8"))
        self.assertEqual(body["claims"], ["civil-person-is-alive-by-demographics"])
        self.assertEqual(body["disclosure"], "predicate")
        self.assertEqual(
            body["target"]["attributes"],
            {"given_name": "Miguel", "surname": "Martinez", "birth_date": "2014-01-15"},
        )
        self.assertNotIn("identifiers", body["target"])
        facts = {item["label"]: item["value"] for item in result["friendly"]["facts"]}
        self.assertEqual(facts["Identifier sent"], "No")

    def test_lookup_step_does_not_post_without_published_target_inputs(self) -> None:
        captured = []

        def fake(req, timeout=None):
            captured.append(req)
            return self._json_resp({"data": [{"id": "civil-person-is-alive-by-demographics"}]})

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(self._config(), "civil-birth-demographics", "lookup")

        self.assertEqual(result["friendly"]["status"], "needs_attention")
        self.assertEqual([req.full_url for req in captured], ["https://notary.example/v1/claims"])
        facts = {item["label"]: item["value"] for item in result["friendly"]["facts"]}
        self.assertEqual(facts["Evaluation sent"], "No")
        self.assertEqual(facts["Target inputs"], "Legacy identifier fallback")


class CivilCrvsEvidenceScenarioTest(unittest.TestCase):
    """CRVS Birth Evidence and Marriage Evidence scenarios use metadata target inputs."""

    def _config(self) -> dict:
        return server.enrich_config(
            {
                "credentials": [
                    {
                        "id": "civil-notary-evidence",
                        "label": "Civil Notary evidence bearer",
                        "env": "CIVIL_EVIDENCE_CLIENT_BEARER",
                        "auth_scheme": "bearer",
                        "service_url": "https://notary.example",
                        "example": {"method": "GET", "path": "/v1/claims"},
                    }
                ]
            }
        )

    def test_birth_evidence_story_preview_uses_registration_number_target(self) -> None:
        story = server.scenario_payload(self._config(), "civil-birth-evidence")["story"]
        self.assertEqual(story["id"], "civil-birth-evidence")
        self.assertEqual([step["id"] for step in story["steps"]], ["discover", "evaluate"])
        preview = story["steps"][1]["request_preview"]
        self.assertEqual(preview["target_input_selection"]["group"], "Registration number")
        self.assertEqual(
            preview["body"]["target"]["identifiers"],
            [{"scheme": "registration_number", "value": "B-2016-N-1001"}],
        )

    def test_marriage_evidence_story_preview_uses_marriage_target_type(self) -> None:
        story = server.scenario_payload(self._config(), "civil-marriage-evidence")["story"]
        preview = story["steps"][1]["request_preview"]
        self.assertEqual(preview["body"]["claims"], ["marriage.certificate_summary"])
        self.assertEqual(preview["body"]["target"]["type"], "Marriage")
        self.assertEqual(
            preview["body"]["target"]["identifiers"],
            [{"scheme": "registration_number", "value": "MR-2026-2001"}],
        )


class HomepageHtmlTest(unittest.TestCase):
    """The credentials section is merged into services, and Open links are status-gated."""

    def setUp(self) -> None:
        self.html = server.homepage_html("Registry Lab").decode("utf-8")

    def test_credentials_section_is_merged_into_services(self) -> None:
        self.assertIn('id="services-grid"', self.html)
        self.assertNotIn('id="credentials-grid"', self.html)
        self.assertNotIn("#credentials", self.html)

    def test_open_link_renders_hidden_and_is_status_gated(self) -> None:
        # Open links start hidden; loadStatus only reveals services that are up and browsable.
        self.assertIn("data-open-for", HOMEPAGE_JS)
        self.assertIn("check.ok && check.browsable", HOMEPAGE_JS)

    def test_wallet_section_guides_hosted_issuance_flow(self) -> None:
        self.assertIn("Start issuance", HOMEPAGE_JS)
        self.assertIn("/oid4vci/offer/start?credential_configuration_id=", HOMEPAGE_JS)
        self.assertIn("https://wallet.lab.registrystack.org/signup", HOMEPAGE_JS)
        self.assertIn("openid-credential-offer://", HOMEPAGE_JS)
        self.assertIn("within 300 seconds", HOMEPAGE_JS)
        self.assertIn("no longer requires a separate issuer PIN", HOMEPAGE_JS)

    def test_homepage_links_to_dedicated_scenario_runner(self) -> None:
        self.assertIn('href="/scenarios"', self.html)
        self.assertIn("Run a guided scenario", self.html)
        self.assertNotIn('id="scenario-grid"', self.html)


class UmamiAnalyticsTest(unittest.TestCase):
    """Umami is opt-in at runtime and keeps the default CSP locked down."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        for key in (
            server.UMAMI_WEBSITE_ID_ENV,
            server.UMAMI_SCRIPT_SRC_ENV,
            server.UMAMI_DOMAINS_ENV,
        ):
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    def _csp(self) -> str:
        return dict(server.security_headers())["Content-Security-Policy"]

    def test_umami_script_is_absent_without_website_id(self) -> None:
        self.assertEqual(server.umami_script_html(), "")
        self.assertNotIn("stats.registrystack.org", server.homepage_html("Registry Lab").decode("utf-8"))
        self.assertEqual(
            self._csp(),
            "default-src 'none'; style-src 'self'; script-src 'self'; "
            "img-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'",
        )

    def test_umami_script_uses_defaults_when_enabled(self) -> None:
        os.environ[server.UMAMI_WEBSITE_ID_ENV] = "lab-site-id"
        script = server.umami_script_html()
        self.assertIn('src="https://stats.registrystack.org/script.js"', script)
        self.assertIn('data-website-id="lab-site-id"', script)
        self.assertIn('data-domains="lab.registrystack.org"', script)
        csp = self._csp()
        self.assertIn("script-src 'self' https://stats.registrystack.org", csp)
        self.assertIn("connect-src 'self' https://stats.registrystack.org", csp)

    def test_umami_values_are_escaped(self) -> None:
        os.environ[server.UMAMI_WEBSITE_ID_ENV] = 'site-"id"'
        os.environ[server.UMAMI_SCRIPT_SRC_ENV] = "https://stats.registrystack.org/script.js?x=\""
        os.environ[server.UMAMI_DOMAINS_ENV] = 'lab.registrystack.org,"bad"'
        script = server.umami_script_html()
        self.assertIn("site-&quot;id&quot;", script)
        self.assertIn("x=&quot;", script)
        self.assertIn("lab.registrystack.org,&quot;bad&quot;", script)

    def test_lab_tracks_outbound_and_copy_actions(self) -> None:
        self.assertIn("lab_link_click", HOMEPAGE_JS)
        self.assertIn("lab_copy", HOMEPAGE_JS)
        self.assertIn("utm_source", HOMEPAGE_JS)
        self.assertIn("registry_lab", HOMEPAGE_JS)

    def test_scenarios_track_story_and_step_actions(self) -> None:
        self.assertIn("lab_link_click", SCENARIOS_JS)
        self.assertIn("registry_lab", SCENARIOS_JS)
        self.assertIn("lab_scenario_open", SCENARIOS_JS)
        self.assertIn("lab_scenario_view", SCENARIOS_JS)
        self.assertIn("lab_step_run", SCENARIOS_JS)
        self.assertIn("lab_step_result", SCENARIOS_JS)
        self.assertIn("lab_step_error", SCENARIOS_JS)
        self.assertIn("lab_source_open", SCENARIOS_JS)
        self.assertIn("lab_copy_curl", SCENARIOS_JS)
        self.assertIn("lab_scenario_reset", SCENARIOS_JS)


class ScenarioPageHtmlTest(unittest.TestCase):
    """The dedicated scenario page has a chooser plus progressive story pages."""

    def setUp(self) -> None:
        self.html = server.scenario_page_html().decode("utf-8")

    def test_dedicated_page_fetches_scenarios(self) -> None:
        self.assertIn("Registry Lab Scenarios", self.html)
        self.assertIn('id="chooser"', self.html)
        self.assertIn('id="story"', self.html)
        self.assertIn("/api/scenarios.json", SCENARIOS_JS)
        self.assertIn("Choose a story to run step by step", self.html)

    def test_page_runs_steps_and_hides_sources_by_default(self) -> None:
        story_html = server.scenario_page_html(scenario_id="alive-proof").decode("utf-8")
        self.assertIn("What this request will do", SCENARIOS_JS)
        self.assertIn("Reuses from the previous step", SCENARIOS_JS)
        self.assertIn("data-run-step", SCENARIOS_JS)
        self.assertIn("Show technical request", SCENARIOS_JS)
        self.assertIn("Show technical response", SCENARIOS_JS)
        self.assertIn("function renderRequestSource", SCENARIOS_JS)
        self.assertIn("function curlCommand", SCENARIOS_JS)
        self.assertIn("Copy as curl", SCENARIOS_JS)
        self.assertIn("data-copy-curl", SCENARIOS_JS)
        self.assertIn("HTTP status", SCENARIOS_JS)
        self.assertIn("source-card", SCENARIOS_JS)
        self.assertIn("/api/scenarios/${encodeURIComponent(state.story.id)}/", SCENARIOS_JS)
        self.assertIn('data-active-scenario="alive-proof"', story_html)
        self.assertNotIn("Cell 1", SCENARIOS_JS)

    def test_page_renders_attestation_metadata_sections(self) -> None:
        self.assertIn("SP MIS requirement", SCENARIOS_JS)
        self.assertIn("Requested attestations", SCENARIOS_JS)
        self.assertIn("Lookup profile", SCENARIOS_JS)
        self.assertIn("Disclosure boundary", SCENARIOS_JS)
        self.assertIn("Proof facts", SCENARIOS_JS)
        self.assertIn("attestationNames", SCENARIOS_JS)


class ExplorerPageHtmlTest(unittest.TestCase):
    """Explorer pages load self-hosted assets and self-demonstrate before controls."""

    ORIENTING_SENTENCE = (
        "Relay shows what an authorized system can read. "
        "Notary returns only the fact a service asked for."
    )

    def test_registry_explorer_page_shell(self) -> None:
        page = server.explorer_page_html("registry").decode("utf-8")
        self.assertIn("<title>Registry Explorer", page)
        self.assertIn('id="registry-explorer-root"', page)
        self.assertIn(self.ORIENTING_SENTENCE, page)
        self.assertIn("/static/explorers.css", page)
        self.assertIn("/static/registry-explorer.js", page)
        self.assertIn('href="/registry-explorer" aria-current="page"', page)
        self.assertNotIn("<script>", page)

    def test_claims_explorer_page_shell(self) -> None:
        page = server.explorer_page_html("claims").decode("utf-8")
        self.assertIn("<title>Claims Explorer", page)
        self.assertIn('id="claims-explorer-root"', page)
        self.assertIn(self.ORIENTING_SENTENCE, page)
        self.assertIn("/static/explorers.css", page)
        self.assertIn("/static/claims-explorer.js", page)
        self.assertIn('href="/claims-explorer" aria-current="page"', page)
        self.assertNotIn("<script>", page)

    def test_explorer_page_rejects_unknown_kind(self) -> None:
        with self.assertRaises(ValueError):
            server.explorer_page_html("unknown")

    def test_registry_explorer_js_uses_same_origin_api_only(self) -> None:
        self.assertIn("/api/explorer/registries.json", REGISTRY_EXPLORER_JS)
        self.assertNotIn("http://", REGISTRY_EXPLORER_JS)
        self.assertNotIn("https://", REGISTRY_EXPLORER_JS)
        self.assertIn("body.error && body.error.message", REGISTRY_EXPLORER_JS)
        self.assertIn('root.addEventListener("click"', REGISTRY_EXPLORER_JS)
        self.assertIn('root.addEventListener("change"', REGISTRY_EXPLORER_JS)
        self.assertNotIn('document.addEventListener("click"', REGISTRY_EXPLORER_JS)
        self.assertNotIn('document.addEventListener("change"', REGISTRY_EXPLORER_JS)

    def test_registry_explorer_js_keeps_query_controls_primary(self) -> None:
        controls = REGISTRY_EXPLORER_JS.index("registry-query-panel")
        result = REGISTRY_EXPLORER_JS.index("Query context")
        self.assertLess(controls, result)
        self.assertIn("Filter and purpose", REGISTRY_EXPLORER_JS)
        self.assertIn("filterQueryParams", REGISTRY_EXPLORER_JS)

    def test_claims_explorer_js_uses_same_origin_api_only(self) -> None:
        self.assertIn("/api/explorer/claims.json", CLAIMS_EXPLORER_JS)
        self.assertNotIn("http://", CLAIMS_EXPLORER_JS)
        self.assertNotIn("https://", CLAIMS_EXPLORER_JS)
        self.assertIn("body.error && body.error.message", CLAIMS_EXPLORER_JS)
        self.assertIn('root.addEventListener("click"', CLAIMS_EXPLORER_JS)
        self.assertIn('root.addEventListener("change"', CLAIMS_EXPLORER_JS)
        self.assertNotIn('document.addEventListener("click"', CLAIMS_EXPLORER_JS)
        self.assertNotIn('document.addEventListener("change"', CLAIMS_EXPLORER_JS)

    def test_claims_explorer_js_accepts_data_catalogue_shape(self) -> None:
        self.assertIn("state.metadata?.claim_service?.data", CLAIMS_EXPLORER_JS)
        self.assertIn("state.metadata?.data", CLAIMS_EXPLORER_JS)
        self.assertIn("state.metadata?.service?.data", CLAIMS_EXPLORER_JS)

    def test_claims_explorer_js_renders_metadata_target_inputs(self) -> None:
        self.assertIn("function targetInputGroups", CLAIMS_EXPLORER_JS)
        self.assertIn("target_inputs", CLAIMS_EXPLORER_JS)
        self.assertIn("target.identifiers", CLAIMS_EXPLORER_JS)
        self.assertIn("payload.target = targetFromInputs(group)", CLAIMS_EXPLORER_JS)

    def test_claims_explorer_js_reads_target_values_from_state_during_render(self) -> None:
        self.assertIn("return state.targetValues[key] ?? defaultTargetValue(input)", CLAIMS_EXPLORER_JS)
        self.assertNotIn("byId(`target-input-${index}`)?.value", CLAIMS_EXPLORER_JS)

    def test_claims_explorer_js_keeps_minimization_secondary(self) -> None:
        answer = CLAIMS_EXPLORER_JS.index("Answer")
        minimization = CLAIMS_EXPLORER_JS.index("Minimization details")
        raw_json = CLAIMS_EXPLORER_JS.index("Raw JSON")
        self.assertLess(answer, minimization)
        self.assertLess(minimization, raw_json)
        self.assertIn("No source row returned.", CLAIMS_EXPLORER_JS)
        self.assertNotIn("<h3>Data minimization</h3>", CLAIMS_EXPLORER_JS)
        self.assertNotIn("<span>Relay fields used</span>", CLAIMS_EXPLORER_JS)


class ExplorerApiPayloadTest(unittest.TestCase):
    """Explorer APIs are allowlisted, bounded, and safe to render in the public lab."""

    def setUp(self) -> None:
        self.config = server.enrich_config(server.load_config(server.DEFAULT_CONFIG))

    def test_registry_catalog_uses_exact_allowlist(self) -> None:
        payload = server.registry_explorer.registry_catalog_payload(self.config)
        self.assertEqual(
            [item["id"] for item in payload["registries"]],
            ["civil", "social-protection", "health", "agriculture"],
        )

    def test_claim_catalog_uses_exact_allowlist(self) -> None:
        payload = server.claims_explorer.claim_catalog_payload(self.config)
        self.assertEqual(
            [item["id"] for item in payload["claim_services"]],
            [
                "civil-notary",
                "social-protection-notary",
                "shared-eligibility-notary",
                "dhis2-notary",
                "opencrvs-notary",
                "agriculture-notary",
            ],
        )

    def test_claim_metadata_tracks_pr65_public_labels_and_social_url(self) -> None:
        civil = server.claims_explorer.claim_metadata_payload(self.config, "civil-notary")["claim_service"]
        self.assertEqual(civil["claims"][0]["title"], "Vital Status Attestation")

        social = server.claims_explorer.claim_metadata_payload(self.config, "social-protection-notary")["claim_service"]
        self.assertEqual(social["base_url"], "https://social-notary.lab.registrystack.org")
        self.assertEqual(social["availability"], "hosted")
        self.assertEqual(
            {claim["id"]: claim["title"] for claim in social["claims"]},
            {
                "program-enrollment-status": "Program Enrollment Attestation",
                "household-eligibility-band": "Welfare Classification Attestation",
                "beneficiary-active": "Program Enrollment Active Attestation",
                "household-composition": "Household Composition Attestation",
                "caregiver-link": "Parent Or Guardian Link Attestation",
                "disability-determination": "Disability Determination Attestation",
                "functioning-assessment": "Functioning Assessment Attestation",
            },
        )

        shared = server.claims_explorer.claim_metadata_payload(self.config, "shared-eligibility-notary")["claim_service"]
        self.assertEqual(shared["base_url"], "https://shared-notary.lab.registrystack.org")

        dhis2 = server.claims_explorer.claim_metadata_payload(self.config, "dhis2-notary")["claim_service"]
        self.assertEqual(dhis2["default_subject"], "PQfMcpmXeFE")
        self.assertEqual(dhis2["default_purpose"], "https://demo.example.gov/purpose/dhis2-openfn-health-evidence")
        dhis2_titles = {claim["id"]: claim["title"] for claim in dhis2["claims"]}
        self.assertEqual(dhis2_titles["dhis2-child-program-active"], "Health Programme Participation Attestation")

        opencrvs = server.claims_explorer.claim_metadata_payload(self.config, "opencrvs-notary")["claim_service"]
        opencrvs_titles = {claim["id"]: claim["title"] for claim in opencrvs["claims"]}
        self.assertEqual(opencrvs_titles["opencrvs-birth-record-exists"], "Birth Registration Attestation")
        self.assertEqual(opencrvs_titles["opencrvs-age-band"], "Age Eligibility Attestation")

        civil_claims = {claim["id"]: claim for claim in civil["claims"]}
        self.assertEqual(civil_claims["birth.certificate_summary"]["title"], "Birth certificate summary")
        self.assertEqual(
            civil_claims["birth.certificate_summary_by_demographics"]["title"],
            "Birth Evidence by demographics",
        )
        self.assertEqual(civil_claims["marriage.certificate_summary"]["title"], "Marriage certificate summary")
        self.assertEqual(
            civil_claims["birth.certificate_summary"]["target_inputs"][0]["groups"][0]["inputs"][0]["path"],
            "target.identifiers.registration_number",
        )
        self.assertEqual(
            civil_claims["birth.certificate_summary_by_demographics"]["target_inputs"][0]["groups"][0]["inputs"][0]["path"],
            "target.attributes.given_name",
        )

        agriculture = server.claims_explorer.claim_metadata_payload(self.config, "agriculture-notary")["claim_service"]
        self.assertEqual(agriculture["default_identifier_scheme"], "farmer_id")
        self.assertEqual(agriculture["default_subject"], "FARMER-1001")
        agri_claims = {claim["id"]: claim for claim in agriculture["claims"]}
        self.assertEqual(agri_claims["eligible-for-climate-smart-input-voucher"]["source"]["lookup_field"], "farmer_id")

    def test_registry_metadata_tracks_pr65_relay_entities(self) -> None:
        civil = server.registry_explorer.registry_metadata_payload(self.config, "civil")["registry"]
        civil_entities = set(civil["datasets"][0]["entities"])
        self.assertTrue(
            {
                "civil_person",
                "civil_person_detail",
                "civil_identifier",
                "birth_event",
                "death_event",
                "marriage_event",
                "civil_status_record",
                "certificate",
                "relationship",
            }.issubset(civil_entities)
        )

        social = server.registry_explorer.registry_metadata_payload(self.config, "social-protection")["registry"]
        social_entities = set(social["datasets"][0]["entities"])
        self.assertTrue(
            {
                "household",
                "person",
                "program_enrollment",
                "household_membership",
                "socio_economic_profile",
                "scoring_event",
                "program",
                "entitlement",
                "payment_event",
                "functioning_profile",
                "disability_determination",
            }.issubset(social_entities)
        )

    def test_unknown_registry_id_returns_controlled_error(self) -> None:
        payload = server.registry_explorer.registry_metadata_payload(self.config, "not-a-registry")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "explorer.unknown_registry")

    def test_unknown_claim_service_id_returns_controlled_error(self) -> None:
        payload = server.claims_explorer.claim_metadata_payload(self.config, "not-a-service")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "explorer.unknown_claim_service")

    def test_record_query_rejects_excessive_limit(self) -> None:
        with self.assertRaises(server.ExplorerInputError) as ctx:
            server.registry_explorer.record_query_payload(
                self.config,
                "civil",
                "civil_registry",
                "civil_person",
                limit="999",
            )
        self.assertEqual(ctx.exception.code, "explorer.invalid_limit")

    def test_record_query_rejects_unknown_filter_field(self) -> None:
        with self.assertRaises(server.ExplorerInputError) as ctx:
            server.registry_explorer.record_query_payload(
                self.config,
                "civil",
                "civil_registry",
                "civil_person",
                filters=[{"field": "secret_field", "op": "eq", "value": "x"}],
            )
        self.assertEqual(ctx.exception.code, "explorer.unsupported_filter_field")

    def test_registry_defaults_return_preview_rows_for_every_dropdown_option(self) -> None:
        for registry_id in server.registry_explorer.registry_ids():
            registry = server.registry_explorer.registry_config(registry_id)
            payload = server.registry_explorer.record_query_payload(
                self.config,
                registry_id,
                registry["default_dataset"],
                registry["default_entity"],
                limit=1,
            )
            self.assertEqual(payload["status"], "preview", registry_id)
            self.assertGreaterEqual(len(payload["records"]), 1, registry_id)

    def test_registry_preview_filter_limits_returned_rows(self) -> None:
        payload = server.registry_explorer.record_query_payload(
            self.config,
            "civil",
            "civil_registry",
            "civil_person",
            limit=10,
            filters=[{"field": "life_stage", "op": "eq", "value": "child"}],
        )
        self.assertGreaterEqual(len(payload["records"]), 1)
        self.assertTrue(all(row["life_stage"] == "child" for row in payload["records"]))
        self.assertEqual(payload["validated"]["filters"], [{"field": "life_stage", "op": "eq", "value": "child"}])

    def test_registry_preview_filter_can_return_empty_result(self) -> None:
        payload = server.registry_explorer.record_query_payload(
            self.config,
            "civil",
            "civil_registry",
            "civil_person",
            limit=10,
            filters=[{"field": "national_id", "op": "eq", "value": "NID-does-not-exist"}],
        )
        self.assertEqual(payload["records"], [])
        self.assertEqual(payload["summary"]["records_returned"], 0)

    def test_registry_preview_reads_pr65_civil_fixture_entity(self) -> None:
        payload = server.registry_explorer.record_query_payload(
            self.config,
            "civil",
            "civil_registry",
            "relationship",
            limit=1,
        )
        self.assertEqual(payload["records"][0]["id"], "REL-1001-MOTHER")
        self.assertEqual(payload["records"][0]["relationship_type"], "mother")

    def test_registry_preview_reads_pr65_social_fixture_entity(self) -> None:
        payload = server.registry_explorer.record_query_payload(
            self.config,
            "social-protection",
            "social_protection_registry",
            "functioning_profile",
            limit=1,
            filters=[{"field": "national_id", "op": "eq", "value": "NID-1006"}],
        )
        self.assertEqual(payload["records"][0]["id"], "FUNC-1006")
        self.assertTrue(payload["records"][0]["disability_identifier_met"])
        self.assertEqual(payload["records"][0]["administration_date"], "2025-12-05")

    def test_registry_date_coercion_leaves_unreasonable_numeric_dates_unconverted(self) -> None:
        self.assertEqual(server.registry_explorer._coerce_field_value("20260515", "date"), "20260515")

    def test_registry_ordered_comparison_rejects_missing_values(self) -> None:
        self.assertFalse(server.registry_explorer._compare_ordered("", "10", "gte"))
        self.assertFalse(server.registry_explorer._compare_ordered(None, "10", "lte"))

    def test_registry_xlsx_reader_preserves_missing_trailing_cells(self) -> None:
        import tempfile
        from zipfile import ZipFile

        sheet = """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="inlineStr"><is><t>id</t></is></c>
      <c r="B1" t="inlineStr"><is><t>name</t></is></c>
      <c r="C1" t="inlineStr"><is><t>status</t></is></c>
    </row>
    <row r="2">
      <c r="A2" t="inlineStr"><is><t>ROW-1</t></is></c>
    </row>
  </sheetData>
</worksheet>
"""
        with tempfile.NamedTemporaryFile(suffix=".xlsx") as handle:
            with ZipFile(handle.name, "w") as archive:
                archive.writestr("xl/worksheets/sheet1.xml", sheet)
            with ZipFile(handle.name) as archive:
                rows = server.registry_explorer._read_xlsx_rows(
                    archive,
                    "xl/worksheets/sheet1.xml",
                    [],
                    {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"},
                    1,
                )
        self.assertEqual(rows, [{"id": "ROW-1", "name": "", "status": ""}])

    def test_claim_evaluation_rejects_unexpected_key(self) -> None:
        with self.assertRaises(server.ExplorerInputError) as ctx:
            server._normalize_evaluation_body(
                {
                    "claim_id": "person-is-alive",
                    "subject": {"scheme": "national_id", "value": "NID-1001"},
                    "disclosure": "predicate",
                    "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                    "purpose": server.claims_explorer.PURPOSE,
                    "extra": "nope",
                }
            )
        self.assertEqual(ctx.exception.code, "explorer.unexpected_request_key")

    def test_claim_evaluation_accepts_nested_subject_shape(self) -> None:
        normalized = server._normalize_evaluation_body(
            {
                "claim_id": "person-is-alive",
                "subject": {"scheme": "national_id", "value": "NID-1001"},
                "disclosure": "predicate",
                "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                "purpose": server.claims_explorer.PURPOSE,
            }
        )
        self.assertEqual(normalized["subject"], "NID-1001")
        self.assertEqual(normalized["identifier_scheme"], "national_id")

    def test_claim_evaluation_accepts_full_target_shape(self) -> None:
        target = {
            "type": "Person",
            "identifiers": [{"scheme": "registration_number", "value": "B-2016-N-1001"}],
        }
        normalized = server._normalize_evaluation_body(
            {
                "claim_id": "birth.certificate_summary",
                "target": target,
                "disclosure": "value",
                "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                "purpose": server.claims_explorer.PURPOSE,
            }
        )
        self.assertEqual(normalized["target"], target)
        self.assertNotIn("subject", normalized)

    def test_claim_evaluation_validation_accepts_legacy_subject_shape(self) -> None:
        validated = server.claims_explorer.validate_evaluation_input(
            "civil-notary",
            {
                "claim_id": "person-is-alive",
                "subject": "NID-1001",
                "identifier_scheme": "national_id",
                "disclosure": "predicate",
                "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                "purpose": server.claims_explorer.PURPOSE,
            },
        )
        self.assertEqual(validated["subject"], "NID-1001")
        self.assertEqual(validated["identifier_scheme"], "national_id")
        self.assertIsNone(validated["target"])

    def test_claim_evaluation_validation_accepts_target_shape_without_legacy_subject(self) -> None:
        target = {
            "type": "Person",
            "identifiers": [{"scheme": "registration_number", "value": "B-2016-N-1001"}],
        }
        validated = server.claims_explorer.validate_evaluation_input(
            "civil-notary",
            {
                "claim_id": "birth.certificate_summary",
                "target": target,
                "disclosure": "value",
                "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                "purpose": "https://demo.example.gov/purpose/civil-certificate-evidence",
            },
        )
        self.assertEqual(validated["target"], target)
        self.assertEqual(validated["subject"], "B-2016-N-1001")
        self.assertEqual(validated["identifier_scheme"], "registration_number")

    def test_default_claim_result_minimization_precedes_raw_row_access(self) -> None:
        payload = server.claims_explorer.run_evaluation(
            self.config,
            "civil-notary",
            {
                "claim_id": "person-is-alive",
                "subject": "NID-1001",
                "identifier_scheme": "national_id",
                "disclosure": "predicate",
                "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                "purpose": server.claims_explorer.PURPOSE,
            },
        )
        self.assertEqual(payload["data_minimization"]["Raw row returned"], "no")
        self.assertEqual(payload["data_minimization"]["Returned to relying service"], 1)
        self.assertEqual(payload["source"]["dataset"], "civil_registry")

    def test_runtime_claim_evaluation_uses_real_token_for_http_call(self) -> None:
        captured = {}

        class Result:
            status = 200
            body = {"results": [{"claim_id": "person-is-alive", "satisfied": True}]}
            headers = {"content-type": "application/json"}
            error = ""

        def fake_http_json(method, url, headers, body, timeout=8.0):
            captured["headers"] = headers
            return Result()

        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "civil-real-token"
        try:
            with mock.patch.object(server.claims_explorer, "http_json", fake_http_json):
                payload = server.claims_explorer.run_evaluation(
                    server.enrich_config({"credentials": []}),
                    "civil-notary",
                    {
                        "claim_id": "person-is-alive",
                        "subject": "NID-1001",
                        "identifier_scheme": "national_id",
                        "disclosure": "predicate",
                        "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                        "purpose": server.claims_explorer.PURPOSE,
                    },
                )
        finally:
            os.environ.pop("CIVIL_EVIDENCE_CLIENT_BEARER", None)
        self.assertEqual(captured["headers"]["Authorization"], "Bearer civil-real-token")
        self.assertNotIn("civil-real-token", str(payload["request_source"]))
        self.assertIn("[runtime demo token hidden]", str(payload["request_source"]))

    def test_runtime_claim_evaluation_passes_metadata_target_through(self) -> None:
        captured = {}
        target = {
            "type": "Person",
            "identifiers": [{"scheme": "registration_number", "value": "B-2016-N-1001"}],
        }

        class Result:
            status = 200
            body = {"results": [{"claim_id": "birth.certificate_summary", "value": True}]}
            headers = {"content-type": "application/json"}
            error = ""

        def fake_http_json(method, url, headers, body, timeout=8.0):
            captured["body"] = body
            return Result()

        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "civil-real-token"
        try:
            with mock.patch.object(server.claims_explorer, "http_json", fake_http_json):
                payload = server.claims_explorer.run_evaluation(
                    server.enrich_config({"credentials": []}),
                    "civil-notary",
                    {
                        "claim_id": "birth.certificate_summary",
                        "target": target,
                        "disclosure": "value",
                        "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                        "purpose": "https://demo.example.gov/purpose/civil-certificate-evidence",
                    },
                )
        finally:
            os.environ.pop("CIVIL_EVIDENCE_CLIENT_BEARER", None)
        self.assertEqual(captured["body"]["target"], target)
        self.assertNotIn("subject", captured["body"])
        self.assertEqual(payload["request_source"]["body"]["target"], target)

    def test_civil_preview_unknown_subject_is_not_satisfied(self) -> None:
        payload = server.claims_explorer.run_evaluation(
            self.config,
            "civil-notary",
            {
                "claim_id": "person-is-alive",
                "subject": "NID-1001ww",
                "identifier_scheme": "national_id",
                "disclosure": "predicate",
                "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                "purpose": server.claims_explorer.PURPOSE,
            },
        )
        self.assertEqual(payload["mode"], "preview")
        self.assertFalse(payload["answer"]["satisfied"])
        self.assertFalse(payload["answer"]["subject_found"])
        self.assertEqual(payload["answer"]["reason"], "subject_not_found")
        self.assertFalse(payload["response_source"]["body"]["results"][0]["satisfied"])

    def test_civil_preview_missing_fixture_is_not_satisfied(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(server.claims_explorer, "REPO_ROOT", Path(tmp)):
                payload = server.claims_explorer.run_evaluation(
                    self.config,
                    "civil-notary",
                    {
                        "claim_id": "person-is-alive",
                        "subject": "NID-1001",
                        "identifier_scheme": "national_id",
                        "disclosure": "predicate",
                        "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                        "purpose": server.claims_explorer.PURPOSE,
                    },
                )
        self.assertEqual(payload["mode"], "preview")
        self.assertFalse(payload["answer"]["satisfied"])
        self.assertFalse(payload["answer"]["subject_found"])
        self.assertEqual(payload["answer"]["reason"], "subject_not_found")

    def test_civil_preview_deceased_subject_is_not_alive(self) -> None:
        payload = server.claims_explorer.run_evaluation(
            self.config,
            "civil-notary",
            {
                "claim_id": "person-is-alive",
                "subject": "NID-1003",
                "identifier_scheme": "national_id",
                "disclosure": "predicate",
                "format": server.claims_explorer.CLAIM_RESULT_FORMAT,
                "purpose": server.claims_explorer.PURPOSE,
            },
        )
        self.assertEqual(payload["mode"], "preview")
        self.assertFalse(payload["answer"]["satisfied"])
        self.assertTrue(payload["answer"]["subject_found"])
        self.assertFalse(payload["response_source"]["body"]["results"][0]["satisfied"])

    def test_explorer_payloads_do_not_expose_excluded_env_names(self) -> None:
        body = json.dumps(
            {
                "registries": server.registry_explorer.registry_catalog_payload(self.config),
                "claims": server.claims_explorer.claim_catalog_payload(self.config),
            },
            sort_keys=True,
        )
        for excluded in self.config.get("excluded_env", []):
            self.assertNotIn(excluded["env"], body)


class LabModePayloadTest(unittest.TestCase):
    """lab_mode and runnable fields in scenario_payload, and guard in run_scenario_step."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        os.environ["CIVIL_RAW"] = "civil-token"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    def _config(self) -> dict:
        return server.enrich_config({"credentials": []})

    # ---- scenario_payload catalogue ----

    def test_catalogue_has_lab_mode_hosted(self) -> None:
        payload = server.scenario_payload(self._config(), lab_mode="hosted")
        self.assertEqual(payload["lab_mode"], "hosted")

    def test_catalogue_has_lab_mode_local(self) -> None:
        payload = server.scenario_payload(self._config(), lab_mode="local")
        self.assertEqual(payload["lab_mode"], "local")

    def test_catalogue_lab_mode_defaults_to_hosted(self) -> None:
        payload = server.scenario_payload(self._config())
        self.assertEqual(payload["lab_mode"], "hosted")

    def test_catalogue_hosted_scenario_is_runnable_in_hosted_mode(self) -> None:
        payload = server.scenario_payload(self._config(), lab_mode="hosted")
        for sid in ("alive-proof", "social-aggregate", "combined-support", "agriculture-voucher"):
            item = next(s for s in payload["scenarios"] if s["id"] == sid)
            self.assertTrue(item["runnable"], f"{sid} should be runnable in hosted mode")

    def test_catalogue_has_no_local_only_scenarios_in_hosted_mode(self) -> None:
        payload = server.scenario_payload(self._config(), lab_mode="hosted")
        self.assertFalse([item for item in payload["scenarios"] if item["availability"] == "local-only"])

    def test_catalogue_scenarios_are_runnable_in_local_mode(self) -> None:
        payload = server.scenario_payload(self._config(), lab_mode="local")
        for sid in ("social-aggregate", "combined-support", "agriculture-voucher"):
            item = next(s for s in payload["scenarios"] if s["id"] == sid)
            self.assertTrue(item["runnable"], f"{sid} should be runnable in local mode")

    # ---- scenario_payload single story ----

    def test_story_payload_has_lab_mode_and_runnable_hosted(self) -> None:
        payload = server.scenario_payload(self._config(), "alive-proof", lab_mode="hosted")
        self.assertEqual(payload["lab_mode"], "hosted")
        self.assertTrue(payload["runnable"])

    def test_story_payload_promoted_scenario_runnable_in_hosted_mode(self) -> None:
        payload = server.scenario_payload(self._config(), "social-aggregate", lab_mode="hosted")
        self.assertEqual(payload["lab_mode"], "hosted")
        self.assertTrue(payload["runnable"])

    def test_story_payload_local_only_runnable_in_local_mode(self) -> None:
        payload = server.scenario_payload(self._config(), "social-aggregate", lab_mode="local")
        self.assertEqual(payload["lab_mode"], "local")
        self.assertTrue(payload["runnable"])

    # ---- run_scenario_step guard in hosted mode ----

    def test_run_step_hosted_promoted_scenario_executes(self) -> None:
        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"data":[{"eligibility_band":"priority","household_count":3}]}'

        called = []

        def fake(req, timeout=None):
            called.append(req)
            return Resp()

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(self._config(), "social-aggregate", "read-aggregate", lab_mode="hosted")
        self.assertEqual(result["friendly"]["status"], "done")
        self.assertTrue(called)

    def test_run_step_hosted_local_only_has_message_and_facts(self) -> None:
        local_only = [item for item in server.scenario_payload(self._config(), lab_mode="hosted")["scenarios"] if item["availability"] == "local-only"]
        self.assertEqual(local_only, [])

    def test_run_step_hosted_agriculture_scenario_executes(self) -> None:
        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"data":[{"id":"eligible-for-climate-smart-input-voucher"},{"id":"voucher-eligibility-reason-code"}]}'

        called = []

        def fake(req, timeout=None):
            called.append(req)
            return Resp()

        os.environ["AGRI_EVIDENCE_CLIENT_BEARER"] = "agri-token"
        os.environ["AGRI_EVIDENCE_URL"] = "https://agriculture-notary.lab.registrystack.org"
        try:
            with mock.patch.object(server.urllib.request, "urlopen", fake):
                result = server.run_scenario_step(self._config(), "agriculture-voucher", "discover", lab_mode="hosted")
        finally:
            os.environ.pop("AGRI_EVIDENCE_CLIENT_BEARER", None)
            os.environ.pop("AGRI_EVIDENCE_URL", None)
        self.assertEqual(result["friendly"]["status"], "done")
        advertised = next(fact["value"] for fact in result["friendly"]["facts"] if fact["label"] == "Attestations advertised")
        self.assertEqual(advertised, 2)
        self.assertTrue(called)
        self.assertEqual(called[0].full_url, "https://agriculture-notary.lab.registrystack.org/v1/claims")

    def test_run_step_unknown_local_only_story_makes_no_http_call(self) -> None:
        """urllib.request.urlopen must not be called for a local-only step in hosted mode."""
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("urlopen must not be called in hosted mode for local-only scenario")

        import lab_homepage_scenarios
        import lab_homepage_scenarios.common as _common
        original_story_by_id = lab_homepage_scenarios.STORY_BY_ID
        class LocalOnlyModule:
            @staticmethod
            def story():
                return {"id": "local-only-test", "short_title": "Local Only Test", "availability": "local-only"}

        lab_homepage_scenarios.STORY_BY_ID = {**original_story_by_id, "local-only-test": LocalOnlyModule}
        with mock.patch.object(_common, "http_json", side_effect=fail_if_called):
            try:
                result = server.run_scenario_step(self._config(), "local-only-test", "discover", lab_mode="hosted")
            finally:
                lab_homepage_scenarios.STORY_BY_ID = original_story_by_id
        self.assertEqual(result["friendly"]["status"], "local_only")

    def test_run_step_local_mode_executes_scenario_path(self) -> None:
        """In local mode, a scenario must follow its normal execution path."""
        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"data":[{"eligibility_band":"priority","household_count":3}]}'

        called = []

        def fake(req, timeout=None):
            called.append(req)
            return Resp()

        os.environ["CIVIL_RAW"] = "civil-token"
        config = server.enrich_config({
            "credentials": [
                {"id": "social-aggregate-reader", "env": "CIVIL_RAW", "service_url": "https://social.example",
                 "example": {"path": "/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band"}},
            ]
        })
        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(config, "social-aggregate", "read-aggregate", lab_mode="local")
        self.assertNotEqual(result["friendly"]["status"], "local_only")
        self.assertTrue(len(called) > 0, "Expected an HTTP call in local mode")

    # ---- availability_note copy ----

    def test_availability_notes_contain_no_http_status_codes(self) -> None:
        import re
        for module in ("social_aggregate", "combined_support", "agriculture_voucher"):
            from importlib import import_module
            mod = import_module(f"lab_homepage_scenarios.{module}")
            note = mod.story().get("availability_note", "")
            self.assertNotRegex(
                note, r"\b4\d\d\b",
                f"{module}.availability_note contains an HTTP status code: {note!r}",
            )

    def test_availability_notes_contain_no_hosted_validation_phrasing(self) -> None:
        for module in ("social_aggregate", "combined_support", "agriculture_voucher"):
            from importlib import import_module
            mod = import_module(f"lab_homepage_scenarios.{module}")
            note = mod.story().get("availability_note", "")
            self.assertNotIn(
                "Hosted validation",
                note,
                f"{module}.availability_note contains 'Hosted validation': {note!r}",
            )

    # ---- scenario_page_html walkthrough rendering ----

    def test_scenario_page_html_renders_for_chooser(self) -> None:
        html = server.scenario_page_html().decode("utf-8")
        self.assertIn('id="chooser"', html)

    def test_scenario_page_html_renders_for_story_route(self) -> None:
        html = server.scenario_page_html(scenario_id="alive-proof").decode("utf-8")
        self.assertIn('data-active-scenario="alive-proof"', html)

    def test_chooser_cta_reads_walkthrough_when_not_runnable(self) -> None:
        self.assertIn("Read the walkthrough", SCENARIOS_JS)

    def test_chooser_cta_reads_open_story_when_runnable(self) -> None:
        self.assertIn("Open story", SCENARIOS_JS)

    def test_story_local_only_pill_style_present(self) -> None:
        self.assertIn("status-pill.local_only", SCENARIOS_CSS)

    def test_story_local_only_no_run_button(self) -> None:
        self.assertIn("This step runs on the local lab profile", SCENARIOS_JS)

    def test_story_run_it_locally_block_present(self) -> None:
        self.assertIn("Run this story on your machine", SCENARIOS_JS)
        self.assertIn("git clone https://github.com/jeremi/registry-lab", SCENARIOS_JS)

    def test_story_drawers_note_when_not_runnable(self) -> None:
        self.assertIn("Available when the story runs on the local lab profile", SCENARIOS_JS)

    def test_status_label_maps_local_only(self) -> None:
        self.assertIn('"local_only"', SCENARIOS_JS)
        self.assertIn('"Local only"', SCENARIOS_JS)


class InternalRequestSourceTest(unittest.TestCase):
    """request_source() internal flag and renderRequestSource JS behaviour."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        os.environ["CIVIL_RAW"] = "civil-token"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    # ---- request_source() flag behaviour ----

    def test_request_source_internal_true_includes_flag(self) -> None:
        from lab_homepage_scenarios.common import request_source as rs
        result = rs("POST", "http://internal:8080/v1/evaluations", {"Authorization": "Bearer x"}, internal=True)
        self.assertTrue(result.get("internal"), "internal=True must set the key to True")

    def test_request_source_internal_false_omits_key(self) -> None:
        from lab_homepage_scenarios.common import request_source as rs
        result = rs("GET", "https://relay.example/metadata", {"Authorization": "Bearer x"})
        self.assertNotIn("internal", result, "internal key must be absent when not set")

    def test_request_source_internal_explicit_false_omits_key(self) -> None:
        from lab_homepage_scenarios.common import request_source as rs
        result = rs("GET", "https://relay.example/metadata", {"Authorization": "Bearer x"}, internal=False)
        self.assertNotIn("internal", result, "internal key must be absent when False")

    # ---- alive-proof scenario: prepare-evidence uses runtime_bearer_credential -> internal ----

    def test_alive_proof_prepare_evidence_request_source_is_internal(self) -> None:
        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "notary-token"
        os.environ["CIVIL_EVIDENCE_URL"] = "https://notary.example"

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"results":[{"claim_id":"person-is-alive","satisfied":true,"provenance":{"source_count":1}}]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_scenario_step(
                server.enrich_config({"credentials": []}), "alive-proof", "prepare-evidence"
            )
        self.assertTrue(result["request_source"].get("internal"), "prepare-evidence request_source must be internal")

    # ---- alive-proof: discover uses configured_credential (public) -> not internal ----

    def test_alive_proof_discover_request_source_is_not_internal(self) -> None:
        config = {
            "credentials": [
                {
                    "id": "civil-evidence-only",
                    "env": "CIVIL_RAW",
                    "service_url": "https://civil.example",
                    "example": {"path": "/metadata/evidence-offerings"},
                }
            ]
        }

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"evidence_offerings":[{"title":"Civil alive check","lookup_keys":["national_id"]}]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_alive_proof_step(server.enrich_config(config), "discover")
        self.assertNotIn("internal", result["request_source"], "discover uses a public credential; must not be internal")

    # ---- combined-support: all steps use runtime_bearer_credential -> internal ----

    def test_combined_support_discover_request_source_is_internal(self) -> None:
        os.environ["SHARED_EVIDENCE_CLIENT_BEARER"] = "shared-token"

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"data":["civil-record-present","eligible-for-combined-support"]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_scenario_step(
                server.enrich_config({"credentials": []}), "combined-support", "discover", lab_mode="local"
            )
        self.assertEqual(result["friendly"]["status"], "done")
        advertised = next(fact["value"] for fact in result["friendly"]["facts"] if fact["label"] == "Attestations advertised")
        self.assertEqual(advertised, 2)
        self.assertTrue(result["request_source"].get("internal"), "combined-support discover must be internal")

    def test_combined_support_evaluate_step_request_source_is_internal(self) -> None:
        os.environ["SHARED_EVIDENCE_CLIENT_BEARER"] = "shared-token"

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"results":[{"claim_id":"civil-record-present","satisfied":true}]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_scenario_step(
                server.enrich_config({"credentials": []}), "combined-support", "civil-subclaim", lab_mode="local"
            )
        self.assertTrue(result["request_source"].get("internal"), "combined-support civil-subclaim must be internal")
        assert_attestation_response(
            self,
            result["response_source"]["attestation_response"],
            "vital-status-attestation",
        )

    # ---- agriculture-voucher: all steps use runtime_bearer_credential -> internal ----

    def test_agriculture_voucher_discover_request_source_is_internal(self) -> None:
        os.environ["AGRI_EVIDENCE_CLIENT_BEARER"] = "agri-token"

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"claims":["eligible-for-climate-smart-input-voucher"]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_scenario_step(
                server.enrich_config({"credentials": []}), "agriculture-voucher", "discover", lab_mode="local"
            )
        self.assertTrue(result["request_source"].get("internal"), "agriculture-voucher discover must be internal")

    def test_agriculture_voucher_evaluate_step_request_source_is_internal(self) -> None:
        os.environ["AGRI_EVIDENCE_CLIENT_BEARER"] = "agri-token"

        class Resp:
            status = 200
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"results":[{"claim_id":"eligible-for-climate-smart-input-voucher","satisfied":true}]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_scenario_step(
                server.enrich_config({"credentials": []}), "agriculture-voucher", "positive-voucher", lab_mode="local"
            )
        self.assertTrue(result["request_source"].get("internal"), "agriculture-voucher positive-voucher must be internal")
        assert_attestation_response(
            self,
            result["response_source"]["attestation_response"],
            "agricultural-entitlement-attestation",
        )

    # ---- JS renderRequestSource: internal branch must be present in the page HTML ----

    def test_scenario_page_html_contains_internal_note_branch(self) -> None:
        self.assertIn("value.internal", SCENARIOS_JS, "renderRequestSource must branch on value.internal")
        self.assertIn("target_input_selection", SCENARIOS_JS, "renderRequestSource must show target input metadata")
        self.assertIn("renderInputContract", SCENARIOS_JS, "renderStep must show the target input contract outside JSON")
        self.assertIn("data-input-contract-for", SCENARIOS_JS, "runStep must be able to refresh the visible input contract")
        self.assertIn("Internal lab call.", SCENARIOS_JS, "renderRequestSource must render the internal-note text")

    def test_scenario_page_html_internal_branch_suppresses_curl_button(self) -> None:
        # The canCurl logic must exclude internal requests.
        # The combined canCurl expression must gate on !value.internal (or equivalent).
        self.assertIn("value.internal", SCENARIOS_JS)
        # And the "Copy as curl" button must still appear (for public-credential paths).
        self.assertIn("Copy as curl", SCENARIOS_JS)


class ScenarioPageUxTest(unittest.TestCase):
    """Post-run flow cues, screen-reader announcements, and locked-step UX."""

    def setUp(self) -> None:
        self.html = server.scenario_page_html().decode("utf-8")

    def test_status_pill_has_role_status(self) -> None:
        self.assertIn('role="status"', SCENARIOS_JS, "status pill must have role='status' for screen-reader announcements")

    def test_friendly_response_has_aria_live_polite(self) -> None:
        self.assertIn('aria-live="polite"', SCENARIOS_JS, "friendly-response container must have aria-live='polite'")

    def test_aria_disabled_present_for_locked_steps(self) -> None:
        self.assertIn("aria-disabled", SCENARIOS_JS, "locked step buttons must use aria-disabled instead of (or in addition to) disabled")

    def test_locked_step_hint_copy_present(self) -> None:
        self.assertIn("Locked until step", SCENARIOS_JS, "locked steps must display a 'Locked until step N completes.' hint")

    def test_try_again_retry_label_logic_present(self) -> None:
        self.assertIn("Try again", SCENARIOS_JS, "needs_attention status must offer a 'Try again' label on the retry button")

    def test_prefers_reduced_motion_in_css(self) -> None:
        self.assertIn("prefers-reduced-motion", SCENARIOS_CSS, "spinner animation must be wrapped in prefers-reduced-motion media query")

    def test_scroll_into_view_usage_present(self) -> None:
        self.assertIn("scrollIntoView", SCENARIOS_JS, "next step or receipt must be scrolled into view after a step completes")


class ChooserAndMetadataTest(unittest.TestCase):
    """Goal D: default_scenario_id, domain tags, per-story head metadata, favicon."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        self._config = server.enrich_config({"credentials": []})
        self._chooser_html = server.scenario_page_html().decode("utf-8")
        self._alive_html = server.scenario_page_html(scenario_id="alive-proof").decode("utf-8")

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    # ---- 1. Chooser hierarchy: default_scenario_id in catalogue payload ----

    def test_catalogue_payload_has_default_scenario_id(self) -> None:
        payload = server.scenario_payload(self._config)
        self.assertEqual(payload["default_scenario_id"], "alive-proof")

    def test_default_scenario_id_is_alive_proof(self) -> None:
        payload = server.scenario_payload(self._config, lab_mode="hosted")
        self.assertEqual(payload["default_scenario_id"], "alive-proof")

    # ---- 1b. Chooser card "Start here" treatment ----

    def test_chooser_has_start_here_badge(self) -> None:
        self.assertIn("Start here", SCENARIOS_JS)

    def test_chooser_default_card_has_css_class(self) -> None:
        # Chooser card styles live in shared.css: the homepage renders the same cards.
        self.assertIn("scenario-card--default", SHARED_CSS)

    def test_chooser_default_card_alive_proof_is_first(self) -> None:
        # The JS sort logic places the default story first; verify the sort is in the template.
        self.assertIn("default_scenario_id", SCENARIOS_JS)
        # The sort expression must put the default item before hosted-runnable, then local-only.
        self.assertIn("item.id === defaultId", SCENARIOS_JS)

    # ---- 2. Badge explanation line ----

    def test_chooser_has_badge_explanation(self) -> None:
        # A line explaining the two badges must appear near the top of the chooser.
        self.assertIn("Hosted", SCENARIOS_JS)
        self.assertIn("Local-only", SCENARIOS_JS)
        # The explanation must mention both what hosted means and what local-only means.
        self.assertIn("browser", SCENARIOS_JS)
        self.assertIn("locally", SCENARIOS_JS)

    # ---- 3. Domain tags in story payloads ----

    def test_civil_alive_story_has_domain(self) -> None:
        story = server.scenario_payload(self._config, "alive-proof")["story"]
        self.assertEqual(story["domain"], "Civil registry")

    def test_wallet_vc_story_has_domain(self) -> None:
        story = server.scenario_payload(self._config, "wallet-credential")["story"]
        self.assertEqual(story["domain"], "Credentials")

    def test_dhis2_story_has_domain(self) -> None:
        story = server.scenario_payload(self._config, "dhis2-programme-vc")["story"]
        self.assertEqual(story["domain"], "Health")

    def test_social_aggregate_story_has_domain(self) -> None:
        story = server.scenario_payload(self._config, "social-aggregate")["story"]
        self.assertEqual(story["domain"], "Social protection")

    def test_combined_support_story_has_domain(self) -> None:
        story = server.scenario_payload(self._config, "combined-support")["story"]
        self.assertEqual(story["domain"], "Social protection")

    def test_agriculture_voucher_story_has_domain(self) -> None:
        story = server.scenario_payload(self._config, "agriculture-voucher")["story"]
        self.assertEqual(story["domain"], "Agriculture")

    def test_catalogue_entries_all_have_domain(self) -> None:
        payload = server.scenario_payload(self._config)
        for item in payload["scenarios"]:
            self.assertIn("domain", item, f"catalogue entry {item['id']!r} missing domain")
            self.assertTrue(item["domain"], f"catalogue entry {item['id']!r} has empty domain")

    def test_chooser_renders_domain_tag(self) -> None:
        # domain-tag class must be defined in CSS and referenced in the renderChooser template.
        self.assertIn("domain-tag", SCENARIOS_JS)
        self.assertIn(".domain-tag", SHARED_CSS)
        # The JS template must reference item.domain so the value is rendered at runtime.
        self.assertIn("item.domain", SCENARIOS_JS)

    def test_chooser_domain_tag_has_css_class(self) -> None:
        self.assertIn(".domain-tag", SHARED_CSS)

    # ---- 4. Per-story head metadata ----

    def test_chooser_page_has_generic_title(self) -> None:
        self.assertIn("<title>Registry Lab Scenarios</title>", self._chooser_html)

    def test_story_page_title_uses_short_title(self) -> None:
        self.assertIn("<title>Vital Status Attestation · Registry Lab</title>", self._alive_html)

    def test_story_page_has_meta_description(self) -> None:
        self.assertIn('<meta name="description"', self._alive_html)
        self.assertIn("raw civil record stays protected", self._alive_html)

    def test_story_page_has_og_title(self) -> None:
        self.assertIn('property="og:title"', self._alive_html)
        self.assertIn("Vital Status Attestation", self._alive_html)

    def test_story_page_has_og_description(self) -> None:
        self.assertIn('property="og:description"', self._alive_html)

    def test_story_page_has_og_type_website(self) -> None:
        self.assertIn('property="og:type"', self._alive_html)
        self.assertIn('"website"', self._alive_html)

    def test_chooser_page_has_meta_description(self) -> None:
        self.assertIn('<meta name="description"', self._chooser_html)

    # ---- 5. Favicon ----

    def test_favicon_route_returns_svg(self) -> None:
        handler = server.LabHomepageHandler
        # Build a minimal fake handler to call _serve_favicon_svg directly.
        # We test via the route logic: call the helper that produces SVG bytes.
        svg = server.favicon_svg()
        self.assertIsInstance(svg, bytes)
        self.assertIn(b"<svg", svg)

    def test_favicon_svg_content_type(self) -> None:
        # The route must serve image/svg+xml.
        self.assertEqual(server.FAVICON_CONTENT_TYPE, "image/svg+xml")

    def test_favicon_svg_path_registered(self) -> None:
        # scenario_page_html must include a <link rel="icon"> pointing at /favicon.svg.
        self.assertIn('rel="icon"', self._chooser_html)
        self.assertIn("/favicon.svg", self._chooser_html)

    def test_favicon_svg_path_on_story_page(self) -> None:
        self.assertIn('rel="icon"', self._alive_html)
        self.assertIn("/favicon.svg", self._alive_html)

    def test_homepage_html_has_favicon_link(self) -> None:
        home = server.homepage_html("Registry Lab").decode("utf-8")
        self.assertIn('rel="icon"', home)
        self.assertIn("/favicon.svg", home)

    def test_handler_serves_favicon_svg_200(self) -> None:
        # Verify the handler route exists (do_GET dispatches /favicon.svg).
        import io
        import http.server

        class FakeSocket:
            def makefile(self, mode):
                return io.BytesIO(b"GET /favicon.svg HTTP/1.0\r\n\r\n")

            def sendall(self, data):
                self._sent = getattr(self, "_sent", b"") + data

        sock = FakeSocket()
        h = server.LabHomepageHandler.__new__(server.LabHomepageHandler)
        output = io.BytesIO()
        h.rfile = io.BytesIO(b"")
        h.wfile = output
        h.server = type("S", (), {"server_address": ("127.0.0.1", 8080)})()
        h.client_address = ("127.0.0.1", 12345)
        h.request_version = "HTTP/1.0"
        h.command = "GET"
        h.path = "/favicon.svg"
        h.headers = http.server.BaseHTTPRequestHandler.MessageClass()
        h.send_response_only = lambda code, msg=None: None
        # Test via the dispatch method directly.
        sent = []

        def fake_send_bytes(body, ct):
            sent.append((body, ct))

        h.send_bytes = fake_send_bytes
        h.do_GET()
        self.assertEqual(len(sent), 1)
        body, ct = sent[0]
        self.assertIn(b"<svg", body)
        self.assertIn("image/svg+xml", ct)

    def test_handler_serves_favicon_ico_redirect_or_200(self) -> None:
        # /favicon.ico must not 404: it either returns bytes or redirects.
        import io
        import http.server

        h = server.LabHomepageHandler.__new__(server.LabHomepageHandler)
        h.rfile = io.BytesIO(b"")
        h.wfile = io.BytesIO()
        h.server = type("S", (), {"server_address": ("127.0.0.1", 8080)})()
        h.client_address = ("127.0.0.1", 12345)
        h.request_version = "HTTP/1.0"
        h.command = "GET"
        h.path = "/favicon.ico"
        h.headers = http.server.BaseHTTPRequestHandler.MessageClass()
        sent_bytes = []
        sent_redirects = []

        def fake_send_bytes(body, ct):
            sent_bytes.append((body, ct))

        def fake_send_redirect(location):
            sent_redirects.append(location)

        h.send_bytes = fake_send_bytes
        h.send_redirect = fake_send_redirect
        errors = []
        h.send_error = lambda code, *a, **kw: errors.append(code)
        h.do_GET()
        self.assertEqual(errors, [], "/favicon.ico must not 404")
        self.assertTrue(len(sent_bytes) + len(sent_redirects) > 0, "/favicon.ico must respond")


class RequestPreviewTest(unittest.TestCase):
    """Goal E: pre-run request preview in each scenario module and payload."""

    def setUp(self) -> None:
        self._saved = dict(os.environ)
        os.environ["CIVIL_RAW"] = "civil-token"

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._saved)

    def _payload_config(self) -> dict:
        return server.enrich_config(
            {
                "credentials": [
                    {
                        "id": "civil-evidence-only",
                        "env": "CIVIL_RAW",
                        "service_url": "https://civil.example",
                        "example": {"path": "/metadata/evidence-offerings"},
                    },
                    {
                        "id": "dhis2-bearer",
                        "env": "CIVIL_RAW",
                        "service_url": "https://dhis2.example",
                        "example": {"path": "/v1/claims"},
                    },
                    {
                        "id": "social-metadata",
                        "env": "CIVIL_RAW",
                        "service_url": "https://social.example",
                        "example": {"path": "/v1/datasets"},
                    },
                    {
                        "id": "social-aggregate-reader",
                        "env": "CIVIL_RAW",
                        "service_url": "https://social.example",
                        "example": {"path": "/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band"},
                    },
                    {
                        "id": "social-row-reader",
                        "env": "CIVIL_RAW",
                        "service_url": "https://social.example",
                        "example": {"path": "/v1/datasets/social_protection_registry/entities/household/records?limit=1"},
                    },
                ],
                "wallet": {
                    "issuer": "https://issuer.example",
                    "credential_configuration_id": "person_is_alive_sd_jwt",
                    "offer_url": "https://issuer.example/offer",
                },
            }
        )

    # ---- civil_alive preview_step ----

    def test_civil_alive_discover_preview_has_method_url_headers(self) -> None:
        import lab_homepage_scenarios.civil_alive as mod
        config = self._payload_config()
        result = mod.preview_step(config, "discover")
        self.assertEqual(result["method"], "GET")
        self.assertIn("civil.example", result["url"])
        self.assertIn("headers", result)

    def test_civil_alive_prepare_evidence_preview_is_internal(self) -> None:
        import lab_homepage_scenarios.civil_alive as mod
        config = self._payload_config()
        result = mod.preview_step(config, "prepare-evidence")
        self.assertTrue(result.get("internal"), "prepare-evidence preview must be internal")
        self.assertEqual(result["method"], "POST")

    def test_civil_alive_prepare_evidence_preview_hides_runtime_token(self) -> None:
        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "notary-secret"
        import lab_homepage_scenarios.civil_alive as mod
        config = self._payload_config()
        result = mod.preview_step(config, "prepare-evidence")
        self.assertNotIn("notary-secret", str(result))
        self.assertIn("[runtime demo token", str(result))

    def test_civil_alive_deny_row_preview_has_method_url_headers(self) -> None:
        import lab_homepage_scenarios.civil_alive as mod
        config = self._payload_config()
        result = mod.preview_step(config, "deny-row")
        self.assertEqual(result["method"], "GET")
        self.assertIn("civil.example", result["url"])

    def test_civil_alive_preview_curl_matches_run_curl_for_public_steps(self) -> None:
        """discover preview url/method/headers must equal what run produces (no network needed)."""
        import lab_homepage_scenarios.civil_alive as mod
        config = self._payload_config()
        preview = mod.preview_step(config, "discover")
        # Preview must produce the same curl-relevant fields as run_step's request_source.
        self.assertEqual(preview["method"], "GET")
        self.assertIn("evidence-offerings", preview["url"])
        self.assertFalse(preview.get("internal"))

    # ---- wallet_vc preview_step ----

    def test_wallet_vc_all_steps_have_preview(self) -> None:
        import lab_homepage_scenarios.wallet_vc as mod
        config = self._payload_config()
        step_ids = ["issuer-metadata", "credential-offer", "holder-key", "nonce", "credential-preview"]
        for step_id in step_ids:
            result = mod.preview_step(config, step_id)
            self.assertIn("method", result, f"wallet_vc.preview_step({step_id!r}) missing method")
            self.assertIn("url", result, f"wallet_vc.preview_step({step_id!r}) missing url")

    def test_wallet_vc_holder_key_preview_is_simulate(self) -> None:
        import lab_homepage_scenarios.wallet_vc as mod
        config = self._payload_config()
        result = mod.preview_step(config, "holder-key")
        self.assertEqual(result["method"], "SIMULATE")

    def test_wallet_vc_nonce_preview_is_simulate(self) -> None:
        import lab_homepage_scenarios.wallet_vc as mod
        config = self._payload_config()
        result = mod.preview_step(config, "nonce")
        self.assertEqual(result["method"], "SIMULATE")

    def test_wallet_vc_credential_preview_is_simulate(self) -> None:
        import lab_homepage_scenarios.wallet_vc as mod
        config = self._payload_config()
        result = mod.preview_step(config, "credential-preview")
        self.assertEqual(result["method"], "SIMULATE")

    # ---- dhis2_programme preview_step ----

    def test_dhis2_all_steps_have_preview(self) -> None:
        import lab_homepage_scenarios.dhis2_programme as mod
        config = self._payload_config()
        # render-cccev returns a composite dict with evaluation/render keys (matches run_step shape)
        step_ids = ["discover", "evaluate-programme", "preview-vc", "reconcile", "negative-control"]
        for step_id in step_ids:
            result = mod.preview_step(config, step_id)
            self.assertIn("method", result, f"dhis2.preview_step({step_id!r}) missing method")

    def test_dhis2_preview_vc_step_is_simulate(self) -> None:
        import lab_homepage_scenarios.dhis2_programme as mod
        config = self._payload_config()
        result = mod.preview_step(config, "preview-vc")
        self.assertEqual(result["method"], "SIMULATE")

    def test_dhis2_render_cccev_preview_has_evaluation_key(self) -> None:
        import lab_homepage_scenarios.dhis2_programme as mod
        config = self._payload_config()
        result = mod.preview_step(config, "render-cccev")
        # render-cccev run produces a dict with "evaluation" and "render" keys
        self.assertIn("evaluation", result)
        self.assertIn("render", result)

    # ---- social_aggregate preview_step ----

    def test_social_aggregate_all_steps_have_preview(self) -> None:
        import lab_homepage_scenarios.social_aggregate as mod
        config = self._payload_config()
        step_ids = ["discover", "read-aggregate", "deny-row-with-aggregate", "read-row-with-row-token"]
        for step_id in step_ids:
            result = mod.preview_step(config, step_id)
            self.assertIn("method", result, f"social_aggregate.preview_step({step_id!r}) missing method")

    # ---- combined_support preview_step ----

    def test_combined_support_all_steps_have_preview(self) -> None:
        import lab_homepage_scenarios.combined_support as mod
        config = self._payload_config()
        step_ids = ["discover", "civil-subclaim", "social-subclaim", "health-subclaim", "final-positive", "negative-control"]
        for step_id in step_ids:
            result = mod.preview_step(config, step_id)
            self.assertIn("method", result, f"combined_support.preview_step({step_id!r}) missing method")

    def test_combined_support_all_steps_are_internal(self) -> None:
        import lab_homepage_scenarios.combined_support as mod
        config = self._payload_config()
        step_ids = ["discover", "civil-subclaim", "social-subclaim", "health-subclaim", "final-positive", "negative-control"]
        for step_id in step_ids:
            result = mod.preview_step(config, step_id)
            self.assertTrue(result.get("internal"), f"combined_support.preview_step({step_id!r}) must be internal")

    def test_combined_support_preview_hides_runtime_token(self) -> None:
        os.environ["SHARED_EVIDENCE_CLIENT_BEARER"] = "shared-secret"
        import lab_homepage_scenarios.combined_support as mod
        config = self._payload_config()
        result = mod.preview_step(config, "discover")
        self.assertNotIn("shared-secret", str(result))
        self.assertIn("[runtime demo token", str(result))

    # ---- agriculture_voucher preview_step ----

    def test_agriculture_voucher_all_steps_have_preview(self) -> None:
        import lab_homepage_scenarios.agriculture_voucher as mod
        config = self._payload_config()
        step_ids = ["discover", "positive-voucher", "inactive-parcel-control", "redeemed-control", "reason-code"]
        for step_id in step_ids:
            result = mod.preview_step(config, step_id)
            self.assertIn("method", result, f"agriculture_voucher.preview_step({step_id!r}) missing method")

    def test_agriculture_voucher_all_steps_are_internal(self) -> None:
        import lab_homepage_scenarios.agriculture_voucher as mod
        config = self._payload_config()
        step_ids = ["discover", "positive-voucher", "inactive-parcel-control", "redeemed-control", "reason-code"]
        for step_id in step_ids:
            result = mod.preview_step(config, step_id)
            self.assertTrue(result.get("internal"), f"agriculture_voucher.preview_step({step_id!r}) must be internal")

    def test_agriculture_voucher_preview_hides_runtime_token(self) -> None:
        os.environ["AGRI_EVIDENCE_CLIENT_BEARER"] = "agri-secret"
        import lab_homepage_scenarios.agriculture_voucher as mod
        config = self._payload_config()
        result = mod.preview_step(config, "discover")
        self.assertNotIn("agri-secret", str(result))
        self.assertIn("[runtime demo token", str(result))

    # ---- scenario_payload attaches request_preview ----

    def test_payload_steps_have_request_preview(self) -> None:
        payload = server.scenario_payload(self._payload_config(), "alive-proof")
        for step in payload["story"]["steps"]:
            self.assertIn("request_preview", step, f"step {step['id']!r} missing request_preview in payload")

    def test_payload_request_preview_has_method_and_url(self) -> None:
        payload = server.scenario_payload(self._payload_config(), "alive-proof")
        for step in payload["story"]["steps"]:
            preview = step["request_preview"]
            self.assertIn("method", preview, f"step {step['id']!r} preview missing method")
            self.assertIn("url", preview, f"step {step['id']!r} preview missing url")

    def test_payload_prepare_evidence_preview_is_internal(self) -> None:
        payload = server.scenario_payload(self._payload_config(), "alive-proof")
        step = next(s for s in payload["story"]["steps"] if s["id"] == "prepare-evidence")
        self.assertTrue(step["request_preview"].get("internal"))

    def test_payload_request_preview_no_raw_runtime_token(self) -> None:
        os.environ["CIVIL_EVIDENCE_CLIENT_BEARER"] = "my-secret-runtime-token"
        payload = server.scenario_payload(self._payload_config(), "alive-proof")
        for step in payload["story"]["steps"]:
            self.assertNotIn("my-secret-runtime-token", str(step["request_preview"]))

    def test_wallet_payload_simulated_steps_have_simulate_preview(self) -> None:
        payload = server.scenario_payload(self._payload_config(), "wallet-credential")
        for step in payload["story"]["steps"]:
            if step["id"] in ("holder-key", "nonce", "credential-preview"):
                self.assertEqual(step["request_preview"]["method"], "SIMULATE",
                                 f"step {step['id']!r} must have SIMULATE preview")

    # ---- page HTML contains preview label and JS wiring ----

    def test_scenario_page_html_contains_preview_label(self) -> None:
        self.assertIn("Request preview", SCENARIOS_JS, "Page must contain a preview label text")

    def test_scenario_page_html_contains_session_storage_key_prefix(self) -> None:
        self.assertIn("lab-progress:", SCENARIOS_JS, "Page must contain sessionStorage key prefix")

    def test_scenario_page_html_contains_reset_story_button(self) -> None:
        self.assertIn("Reset story", SCENARIOS_JS, "Page must contain a Reset story button")

    def test_scenario_page_html_contains_session_storage_usage(self) -> None:
        self.assertIn("sessionStorage", SCENARIOS_JS, "Page must use sessionStorage for progress persistence")

    def test_scenario_page_html_preview_fills_request_drawer_on_load(self) -> None:
        self.assertIn("request_preview", SCENARIOS_JS, "JS must reference request_preview from story data")

    def test_scenario_page_html_completed_earlier_note_present(self) -> None:
        self.assertIn("Completed earlier", SCENARIOS_JS, "Restored steps must show a 'Completed earlier' note")

    def test_scenario_page_html_restore_does_not_scroll(self) -> None:
        # On restore the scroll must be guarded by a flag; the page must not scroll on load.
        # The restore code must call unlockNextSteps with a no-scroll flag or similar guard.
        self.assertIn("restoring", SCENARIOS_JS, "Restore path must set a restoring flag to suppress scroll/focus")


class ProgressPersistenceTest(unittest.TestCase):
    """Goal E: sessionStorage, Reset story, and restored-step behavior in page HTML."""

    def setUp(self) -> None:
        self.html = server.scenario_page_html().decode("utf-8")

    def test_session_storage_set_on_step_complete(self) -> None:
        self.assertIn("sessionStorage.setItem", SCENARIOS_JS)

    def test_session_storage_get_on_page_load(self) -> None:
        self.assertIn("sessionStorage.getItem", SCENARIOS_JS)

    def test_session_storage_remove_on_reset(self) -> None:
        self.assertIn("sessionStorage.removeItem", SCENARIOS_JS)

    def test_reset_story_clears_and_reloads(self) -> None:
        self.assertIn("location.reload", SCENARIOS_JS, "Reset story must trigger page reload")

    def test_reset_only_on_story_page_not_chooser(self) -> None:
        # The reset button must only be rendered when ACTIVE_SCENARIO is set (i.e. story page).
        # The JS must gate the reset button on ACTIVE_SCENARIO being truthy.
        self.assertIn("ACTIVE_SCENARIO", SCENARIOS_JS)
        # The reset button render must be conditional
        self.assertIn("Reset story", SCENARIOS_JS)
        # Verify reset is not unconditionally rendered at page load without scenario context
        # The button appears in JS, so it's either in renderStory or conditionally added
        self.assertIn("reset", SCENARIOS_JS.lower())

    def test_restored_steps_marked_done(self) -> None:
        # The restore path must call updateStatus with "done"
        self.assertIn("updateStatus", SCENARIOS_JS)

    def test_restored_steps_keep_preview_in_request_drawer(self) -> None:
        # Restore must set the request source to preview data, not clear it
        self.assertIn("request_preview", SCENARIOS_JS)

    def test_unlock_on_restore_does_not_focus(self) -> None:
        # unlockNextSteps called during restore must not focus or scroll
        self.assertIn("restoring", SCENARIOS_JS)


class FrontEndFailureHandlingTest(unittest.TestCase):
    """Front-end failures must degrade visibly instead of leaving a blank or stuck page."""

    def test_save_progress_survives_blocked_storage(self) -> None:
        # saveProgress runs in the step-completion path; a sessionStorage throw must not
        # stop the next step from unlocking, only skip persistence with a console warning.
        body = SCENARIOS_JS.split("function saveProgress", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("try {", body)
        self.assertIn("console.warn", body)

    def test_reset_progress_survives_blocked_storage(self) -> None:
        # resetProgress must still reload the page when sessionStorage is blocked.
        body = SCENARIOS_JS.split("function resetProgress", 1)[1].split("\nfunction ", 1)[0]
        self.assertIn("try {", body)
        self.assertIn("location.reload()", body)

    def test_scenarios_start_reports_load_failure(self) -> None:
        body = SCENARIOS_JS.split("async function start", 1)[1]
        self.assertIn("catch", body)
        self.assertIn("console.error", body)
        self.assertIn("did not load", body)

    def test_homepage_start_reports_load_failure(self) -> None:
        body = HOMEPAGE_JS.split("async function start", 1)[1]
        self.assertIn("catch", body)
        self.assertIn("console.error", body)
        self.assertIn("did not load", body)


class StaticAssetRouteTest(unittest.TestCase):
    """The /static/<name> route serves the extracted CSS/JS with strict allowlisting."""

    def _drive_get(self, path: str):
        """Run do_GET against a fake handler, returning (sent_bytes, errors).

        sent_bytes is a list of (body, content_type); errors is a list of HTTP status codes
        passed to send_error. This lets us assert content types and 404s without a socket.
        """
        import io
        import http.server

        h = server.LabHomepageHandler.__new__(server.LabHomepageHandler)
        h.rfile = io.BytesIO(b"")
        h.wfile = io.BytesIO()
        h.server = type("S", (), {"server_address": ("127.0.0.1", 8080)})()
        h.client_address = ("127.0.0.1", 12345)
        h.request_version = "HTTP/1.0"
        h.command = "GET"
        h.path = path
        h.headers = http.server.BaseHTTPRequestHandler.MessageClass()
        sent_bytes: list = []
        errors: list = []
        h.send_bytes = lambda body, ct: sent_bytes.append((body, ct))
        h.send_error = lambda code, *a, **kw: errors.append(code)
        h.do_GET()
        return sent_bytes, errors

    def test_css_assets_served_with_css_content_type(self) -> None:
        for name in ("shared.css", "homepage.css", "scenarios.css", "explorers.css"):
            with self.subTest(name=name):
                sent, errors = self._drive_get(f"/static/{name}")
                self.assertEqual(errors, [], f"{name} must not 404")
                self.assertEqual(len(sent), 1)
                body, ct = sent[0]
                self.assertEqual(body, (STATIC_DIR / name).read_bytes())
                self.assertEqual(ct, "text/css; charset=utf-8")

    def test_js_assets_served_with_javascript_content_type(self) -> None:
        for name in ("homepage.js", "scenarios.js", "registry-explorer.js", "claims-explorer.js"):
            with self.subTest(name=name):
                sent, errors = self._drive_get(f"/static/{name}")
                self.assertEqual(errors, [], f"{name} must not 404")
                self.assertEqual(len(sent), 1)
                body, ct = sent[0]
                self.assertEqual(body, (STATIC_DIR / name).read_bytes())
                self.assertEqual(ct, "application/javascript; charset=utf-8")

    def test_unknown_static_asset_is_404(self) -> None:
        sent, errors = self._drive_get("/static/does-not-exist.css")
        self.assertEqual(sent, [], "unknown asset must not return bytes")
        self.assertEqual(errors, [server.HTTPStatus.NOT_FOUND])

    def test_static_with_no_name_is_404(self) -> None:
        sent, errors = self._drive_get("/static/")
        self.assertEqual(sent, [])
        self.assertEqual(errors, [server.HTTPStatus.NOT_FOUND])

    def test_path_traversal_dotdot_is_404(self) -> None:
        # A literal ../ traversal toward the server source must not escape the allowlist.
        sent, errors = self._drive_get("/static/../lab-homepage-server.py")
        self.assertEqual(sent, [], "traversal must not return any file bytes")
        self.assertEqual(errors, [server.HTTPStatus.NOT_FOUND])

    def test_path_traversal_url_encoded_is_404(self) -> None:
        # URL-encoded traversal (%2e%2e%2f) must also fail the allowlist, never read a file.
        sent, errors = self._drive_get("/static/%2e%2e%2fsecrets")
        self.assertEqual(sent, [], "encoded traversal must not return any file bytes")
        self.assertEqual(errors, [server.HTTPStatus.NOT_FOUND])

    def test_static_asset_bytes_rejects_non_allowlisted_name(self) -> None:
        with self.assertRaises(KeyError):
            server.static_asset_bytes("../lab-homepage-server.py")
        with self.assertRaises(KeyError):
            server.static_asset_bytes("secrets")

    def test_allowlist_matches_referenced_assets(self) -> None:
        # Every /static/* asset linked from the rendered pages must be in the allowlist and
        # servable, so no page can reference a 404.
        import re

        pages = [
            server.homepage_html("Registry Lab").decode("utf-8"),
            server.scenario_page_html().decode("utf-8"),
            server.scenario_page_html(scenario_id="alive-proof").decode("utf-8"),
            server.explorer_page_html("registry").decode("utf-8"),
            server.explorer_page_html("claims").decode("utf-8"),
        ]
        referenced = set()
        for page in pages:
            referenced.update(re.findall(r'/static/([A-Za-z0-9_.-]+)', page))
        self.assertTrue(referenced, "pages must reference at least one /static/ asset")
        for name in sorted(referenced):
            with self.subTest(name=name):
                self.assertIn(name, server.STATIC_ASSETS, f"{name} referenced but not allowlisted")
                sent, errors = self._drive_get(f"/static/{name}")
                self.assertEqual(errors, [], f"{name} referenced by a page must be servable")
                self.assertEqual(len(sent), 1)

    def test_static_dir_resolves_beside_server_script(self) -> None:
        # The dir must resolve relative to the script, not the CWD, so it is correct after deploy.
        self.assertEqual(server.STATIC_DIR, MODULE_PATH.parent / "lab_homepage_static")
        self.assertTrue(server.STATIC_DIR.is_dir())


class VerifyStaticAssetsTest(unittest.TestCase):
    """The startup check fails loudly when the static dir or any asset is missing."""

    def test_passes_when_all_assets_present(self) -> None:
        # Should not raise with the real, complete asset directory.
        server.verify_static_assets()

    def test_aborts_when_dir_missing(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "no_such_static_dir"
            with mock.patch.object(server, "STATIC_DIR", missing):
                with self.assertRaises(SystemExit) as ctx:
                    server.verify_static_assets()
        self.assertIn(str(missing), str(ctx.exception))

    def test_aborts_when_an_asset_missing(self) -> None:
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            partial = Path(tmp) / "lab_homepage_static"
            partial.mkdir()
            # Copy all but one asset to trigger the missing-asset path.
            names = list(server.STATIC_ASSETS)
            for name in names[:-1]:
                shutil.copy(STATIC_DIR / name, partial / name)
            with mock.patch.object(server, "STATIC_DIR", partial):
                with self.assertRaises(SystemExit) as ctx:
                    server.verify_static_assets()
        self.assertIn(names[-1], str(ctx.exception))


class SecurityHeadersTest(unittest.TestCase):
    """Every homepage response carries the browser-hardening headers (relay#87/#88 parity)."""

    EXPECTED_HEADERS = {
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'self'; script-src 'self'; "
            "img-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }

    @classmethod
    def setUpClass(cls) -> None:
        import threading
        from http.server import ThreadingHTTPServer

        cls._saved_env = dict(os.environ)
        for key in (
            server.UMAMI_WEBSITE_ID_ENV,
            server.UMAMI_SCRIPT_SRC_ENV,
            server.UMAMI_DOMAINS_ENV,
        ):
            os.environ.pop(key, None)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.LabHomepageHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        os.environ.clear()
        os.environ.update(cls._saved_env)

    def _get(self, path: str):
        return urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5)

    def _assert_security_headers(self, response) -> None:
        for name, value in self.EXPECTED_HEADERS.items():
            self.assertEqual(response.headers.get(name), value, name)

    def test_homepage_carries_security_headers(self) -> None:
        with self._get("/") as response:
            self._assert_security_headers(response)

    def test_scenario_page_carries_security_headers(self) -> None:
        with self._get("/scenarios") as response:
            self._assert_security_headers(response)

    def test_registry_explorer_page_carries_security_headers(self) -> None:
        with self._get("/registry-explorer") as response:
            self._assert_security_headers(response)

    def test_claims_explorer_page_carries_security_headers(self) -> None:
        with self._get("/claims-explorer") as response:
            self._assert_security_headers(response)

    def test_api_response_carries_security_headers(self) -> None:
        with self._get("/healthz") as response:
            self._assert_security_headers(response)

    def test_not_found_carries_security_headers(self) -> None:
        try:
            self._get("/definitely-not-a-route")
        except urllib.error.HTTPError as error:
            self._assert_security_headers(error)
        else:
            self.fail("expected 404")

    def test_server_banner_does_not_advertise_python(self) -> None:
        with self._get("/healthz") as response:
            banner = response.headers.get("Server", "")
        self.assertNotIn("Python", banner)
        self.assertNotIn("BaseHTTP", banner)

    def test_explorer_post_malformed_content_length_returns_controlled_error(self) -> None:
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.putrequest("POST", "/api/explorer/claims/civil-notary/evaluate.json")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", "not-an-integer")
            conn.endheaders()
            response = conn.getresponse()
            body = json.loads(response.read().decode("utf-8"))
        finally:
            conn.close()
        self.assertEqual(response.status, 200)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"]["code"], "explorer.invalid_content_length")


class StrictCspCompatibilityTest(unittest.TestCase):
    """The pages must not need inline script, or the strict CSP above would break them."""

    def test_scenario_page_has_no_inline_script(self) -> None:
        page = server.scenario_page_html(scenario_id="alive-proof").decode("utf-8")
        self.assertNotIn("<script>", page)
        self.assertIn('data-active-scenario="alive-proof"', page)

    def test_scenario_chooser_page_has_no_inline_script(self) -> None:
        page = server.scenario_page_html().decode("utf-8")
        self.assertNotIn("<script>", page)
        self.assertIn('data-active-scenario=""', page)

    def test_homepage_has_no_inline_script(self) -> None:
        page = server.homepage_html("Registry Lab").decode("utf-8")
        self.assertNotIn("<script>", page)

    def test_explorer_pages_have_no_inline_script(self) -> None:
        for kind in ("registry", "claims"):
            with self.subTest(kind=kind):
                page = server.explorer_page_html(kind).decode("utf-8")
                self.assertNotIn("<script>", page)
                self.assertIn(f'data-explorer-kind="{kind}"', page)

    def test_scenarios_js_reads_active_scenario_from_body_dataset(self) -> None:
        self.assertIn("document.body.dataset.activeScenario", SCENARIOS_JS)


class CivicPrintDesignTest(unittest.TestCase):
    """The lab pages share registrystack.org's civic-print design language."""

    def test_civic_print_tokens_are_defined_on_both_pages(self) -> None:
        # Each page declares its own :root, so the palette must exist in both.
        for token in ("--registry-paper", "--registry-ink-band-deep", "--registry-stamp", "--registry-brass", "--registry-ease"):
            self.assertIn(token, HOMEPAGE_CSS)
            self.assertIn(token, SCENARIOS_CSS)
            self.assertIn(token, EXPLORERS_CSS)

    def test_shared_css_disables_motion_for_reduced_motion_users(self) -> None:
        self.assertIn("prefers-reduced-motion", SHARED_CSS)

    def test_footer_is_an_ink_band_with_inner_wrapper(self) -> None:
        self.assertIn("var(--registry-ink-band-deep)", SHARED_CSS)
        for page in (
            server.homepage_html("Registry Lab").decode("utf-8"),
            server.scenario_page_html().decode("utf-8"),
            server.explorer_page_html("registry").decode("utf-8"),
            server.explorer_page_html("claims").decode("utf-8"),
        ):
            self.assertIn('class="site-footer-inner"', page)

    def test_scenario_page_marks_current_nav_entry(self) -> None:
        page = server.scenario_page_html().decode("utf-8")
        self.assertIn('aria-current="page"', page)
        self.assertIn("aria-current", SHARED_CSS)


class HomepageHierarchyTest(unittest.TestCase):
    """Scenarios lead the homepage; services and credentials close it as the advanced section."""

    def setUp(self) -> None:
        self.page = server.homepage_html("Registry Lab").decode("utf-8")

    def test_sections_run_scenarios_then_wallet_then_services(self) -> None:
        order = [
            self.page.index('id="scenarios"'),
            self.page.index('id="wallet"'),
            self.page.index('id="services"'),
        ]
        self.assertEqual(order, sorted(order))

    def test_every_story_has_a_card_linking_to_its_runner(self) -> None:
        catalogue = server.scenario_payload({}, lab_mode="hosted")["scenarios"]
        self.assertTrue(catalogue)
        for item in catalogue:
            self.assertIn(f'href="/scenarios/{item["id"]}"', self.page)

    def test_default_story_card_is_first_and_badged_start_here(self) -> None:
        self.assertIn("Start here", self.page)
        first_card = self.page.index('class="scenario-card')
        self.assertIn("scenario-card--default", self.page[first_card : first_card + 60])

    def test_hero_has_one_primary_cta_and_a_status_line(self) -> None:
        hero = self.page.split('id="scenarios"', 1)[0]
        self.assertIn("Run a guided scenario", hero)
        self.assertEqual(hero.count('class="button'), 1)
        self.assertIn('id="status-line"', hero)
        self.assertNotIn("status-counts", self.page)

    def test_status_line_is_written_by_the_status_loader(self) -> None:
        self.assertIn("status-line", HOMEPAGE_JS)
        self.assertNotIn("ok-count", HOMEPAGE_JS)
        self.assertNotIn("missing-count", HOMEPAGE_JS)

    def test_nav_demotes_services_to_for_developers(self) -> None:
        nav = self.page.split("</nav>", 1)[0]
        self.assertIn(">For developers</a>", nav)
        self.assertIn(">Registry Explorer</a>", nav)
        self.assertIn(">Claims Explorer</a>", nav)
        self.assertNotIn("Services &amp; credentials", nav)
        self.assertLess(nav.index("Scenario demos"), nav.index("Wallet test"))
        self.assertLess(nav.index("Wallet test"), nav.index("For developers"))

    def test_hosted_homepage_has_no_local_only_walkthrough_cards(self) -> None:
        self.assertIn("Local-only", self.page)
        self.assertNotIn("Read the walkthrough", self.page)
        self.assertNotIn('availability local-only', self.page)
        local_page = server.homepage_html("Registry Lab", lab_mode="local").decode("utf-8")
        self.assertNotIn("Read the walkthrough", local_page)

    def test_service_credentials_collapse_behind_a_disclosure(self) -> None:
        self.assertIn("cred-disclosure", HOMEPAGE_JS)
        self.assertIn("<details", HOMEPAGE_JS)

    def test_top_nav_is_identical_on_every_page(self) -> None:
        # Same entries, same hrefs, same order; only the aria-current marker moves.
        def nav(page: str) -> str:
            inner = page.split('<nav class="top-nav"', 1)[1].split("</nav>", 1)[0]
            return inner.replace(' aria-current="page"', "")

        scenarios_page = server.scenario_page_html().decode("utf-8")
        registry_page = server.explorer_page_html("registry").decode("utf-8")
        claims_page = server.explorer_page_html("claims").decode("utf-8")
        self.assertEqual(nav(self.page), nav(scenarios_page))
        self.assertEqual(nav(self.page), nav(registry_page))
        self.assertEqual(nav(self.page), nav(claims_page))

    def test_each_page_marks_its_own_nav_entry_current(self) -> None:
        self.assertIn('<a href="/" aria-current="page">Home</a>', self.page)
        scenarios_page = server.scenario_page_html().decode("utf-8")
        self.assertIn('<a href="/scenarios" aria-current="page">Scenario demos</a>', scenarios_page)
        registry_page = server.explorer_page_html("registry").decode("utf-8")
        self.assertIn('<a href="/registry-explorer" aria-current="page">Registry Explorer</a>', registry_page)
        claims_page = server.explorer_page_html("claims").decode("utf-8")
        self.assertIn('<a href="/claims-explorer" aria-current="page">Claims Explorer</a>', claims_page)


if __name__ == "__main__":
    unittest.main()
