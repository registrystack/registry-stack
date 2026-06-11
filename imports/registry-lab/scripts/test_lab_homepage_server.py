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

    def test_builds_one_guided_alive_proof_story(self) -> None:
        story = server.scenario_payload(self._payload_config(), "alive-proof")["story"]
        self.assertEqual(story["id"], "alive-proof")
        self.assertIn("Miguel", story["title"])
        self.assertEqual(story["subject"], {"name": "Miguel Santos", "identifier": "NID-1001"})
        self.assertEqual([step["id"] for step in story["steps"]], ["discover", "prepare-evidence", "deny-row"])
        self.assertEqual(story["steps"][1]["button"], "Check if Miguel is alive")
        self.assertIn("Read Miguel's full civil registry row", story["boundary"]["not_allowed"])
        self.assertEqual(story["steps"][1]["reuses"][1], {"label": "Lookup key", "value": "national_id"})

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
                "wallet-credential",
                "dhis2-programme-vc",
                "social-aggregate",
                "combined-support",
                "agriculture-voucher",
            ],
        )
        self.assertEqual(payload["default_scenario_id"], "alive-proof")
        self.assertEqual(len(payload["scenarios"]), 6)
        self.assertEqual(payload["scenarios"][2]["availability"], "hosted")
        self.assertEqual(payload["scenarios"][3]["availability"], "local-only")
        self.assertEqual(payload["scenarios"][4]["availability"], "local-only")

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
        self.assertEqual(result["friendly"]["facts"][1], {"label": "From Step 1", "value": "Civil vital status evidence service"})
        self.assertEqual(result["friendly"]["facts"][4], {"label": "Answer", "value": "Yes"})
        self.assertEqual(result["response_source"]["reused_from_discovery"]["lookup_key"], "national_id")
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

    def test_local_only_scenarios_report_required_token_before_execution(self) -> None:
        os.environ.pop("SHARED_EVIDENCE_CLIENT_BEARER", None)
        result = server.run_scenario_step(server.enrich_config({"credentials": []}), "combined-support", "discover", lab_mode="local")
        self.assertEqual(result["friendly"]["status"], "needs_attention")
        self.assertIn("SHARED_EVIDENCE_CLIENT_BEARER", str(result["friendly"]["facts"]))
        self.assertIn("[runtime demo token missing]", str(result["request_source"]))

    def test_social_aggregate_uses_local_relay_until_hosted_scope_passes(self) -> None:
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

        with mock.patch.object(server.urllib.request, "urlopen", fake):
            result = server.run_scenario_step(self._payload_config(), "social-aggregate", "read-aggregate", lab_mode="local")

        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(
            captured["req"].full_url,
            "http://127.0.0.1:4312/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band",
        )
        self.assertEqual(captured["req"].get_header("Authorization"), "Bearer civil-token")
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
        self.assertEqual(facts["Claims advertised"], 6)
        self.assertEqual(facts["Programme claims present"], "Yes")
        self.assertEqual(captured["req"].get_header("Authorization"), "Bearer civil-token")

    def test_dhis2_preview_vc_hides_holder_proof_and_raw_credential(self) -> None:
        result = server.run_scenario_step(self._payload_config(), "dhis2-programme-vc", "preview-vc")
        self.assertEqual(result["friendly"]["status"], "done")
        self.assertEqual(result["request_source"]["method"], "SIMULATE")
        self.assertIn("[Ed25519 holder proof generated by Bruno, hidden in this playground]", str(result["request_source"]))
        self.assertIn("[holder-bound SD-JWT VC hidden]", str(result["response_source"]))


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
        self.assertIn("data-open-for", self.html)
        self.assertIn("check.ok && check.browsable", self.html)

    def test_wallet_section_guides_hosted_issuance_flow(self) -> None:
        self.assertIn("Start issuance", self.html)
        self.assertIn("/oid4vci/offer/start?credential_configuration_id=", self.html)
        self.assertIn("https://wallet.lab.registrystack.org/signup", self.html)
        self.assertIn("openid-credential-offer://", self.html)
        self.assertIn("within 300 seconds", self.html)
        self.assertIn("no longer requires a separate issuer PIN", self.html)

    def test_homepage_links_to_dedicated_scenario_runner(self) -> None:
        self.assertIn('href="/scenarios"', self.html)
        self.assertIn("Try a scenario", self.html)
        self.assertNotIn('id="scenario-grid"', self.html)


class ScenarioPageHtmlTest(unittest.TestCase):
    """The dedicated scenario page has a chooser plus progressive story pages."""

    def setUp(self) -> None:
        self.html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")

    def test_dedicated_page_fetches_scenarios(self) -> None:
        self.assertIn("Registry Lab Scenarios", self.html)
        self.assertIn('id="chooser"', self.html)
        self.assertIn('id="story"', self.html)
        self.assertIn("/api/scenarios.json", self.html)
        self.assertIn("Choose a story to run step by step", self.html)

    def test_page_runs_steps_and_hides_sources_by_default(self) -> None:
        story_html = server.scenario_page_html("Registry Lab Scenarios", "alive-proof").decode("utf-8")
        self.assertIn("What this request will do", self.html)
        self.assertIn("Reuses from the previous step", self.html)
        self.assertIn("data-run-step", self.html)
        self.assertIn("Show technical request", self.html)
        self.assertIn("Show technical response", self.html)
        self.assertIn("function renderRequestSource", self.html)
        self.assertIn("function curlCommand", self.html)
        self.assertIn("Copy as curl", self.html)
        self.assertIn("data-copy-curl", self.html)
        self.assertIn("HTTP status", self.html)
        self.assertIn("source-card", self.html)
        self.assertIn("/api/scenarios/${encodeURIComponent(state.story.id)}/", self.html)
        self.assertIn('const ACTIVE_SCENARIO = "alive-proof"', story_html)
        self.assertNotIn("Cell 1", self.html)


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
        item = next(s for s in payload["scenarios"] if s["id"] == "alive-proof")
        self.assertTrue(item["runnable"])

    def test_catalogue_local_only_scenario_not_runnable_in_hosted_mode(self) -> None:
        payload = server.scenario_payload(self._config(), lab_mode="hosted")
        for sid in ("social-aggregate", "combined-support", "agriculture-voucher"):
            item = next(s for s in payload["scenarios"] if s["id"] == sid)
            self.assertFalse(item["runnable"], f"{sid} should not be runnable in hosted mode")

    def test_catalogue_local_only_scenario_is_runnable_in_local_mode(self) -> None:
        payload = server.scenario_payload(self._config(), lab_mode="local")
        for sid in ("social-aggregate", "combined-support", "agriculture-voucher"):
            item = next(s for s in payload["scenarios"] if s["id"] == sid)
            self.assertTrue(item["runnable"], f"{sid} should be runnable in local mode")

    # ---- scenario_payload single story ----

    def test_story_payload_has_lab_mode_and_runnable_hosted(self) -> None:
        payload = server.scenario_payload(self._config(), "alive-proof", lab_mode="hosted")
        self.assertEqual(payload["lab_mode"], "hosted")
        self.assertTrue(payload["runnable"])

    def test_story_payload_local_only_not_runnable_in_hosted_mode(self) -> None:
        payload = server.scenario_payload(self._config(), "social-aggregate", lab_mode="hosted")
        self.assertEqual(payload["lab_mode"], "hosted")
        self.assertFalse(payload["runnable"])

    def test_story_payload_local_only_runnable_in_local_mode(self) -> None:
        payload = server.scenario_payload(self._config(), "social-aggregate", lab_mode="local")
        self.assertEqual(payload["lab_mode"], "local")
        self.assertTrue(payload["runnable"])

    # ---- run_scenario_step guard in hosted mode ----

    def test_run_step_hosted_local_only_returns_local_only_status(self) -> None:
        result = server.run_scenario_step(self._config(), "social-aggregate", "read-aggregate", lab_mode="hosted")
        self.assertEqual(result["friendly"]["status"], "local_only")

    def test_run_step_hosted_local_only_has_correct_title(self) -> None:
        result = server.run_scenario_step(self._config(), "social-aggregate", "read-aggregate", lab_mode="hosted")
        self.assertIn("Aggregate versus row access", result["friendly"]["title"])
        self.assertIn("local lab profile", result["friendly"]["title"])

    def test_run_step_hosted_local_only_has_message_and_facts(self) -> None:
        result = server.run_scenario_step(self._config(), "combined-support", "discover", lab_mode="hosted")
        self.assertEqual(result["friendly"]["status"], "local_only")
        self.assertIn("hosted lab does not run", result["friendly"]["message"].lower())
        facts = {f["label"]: f["value"] for f in result["friendly"]["facts"]}
        self.assertEqual(facts["Availability"], "Local only")
        self.assertIn("github.com/jeremi/registry-lab", facts["Run it locally"])

    def test_run_step_hosted_local_only_has_note_sources(self) -> None:
        result = server.run_scenario_step(self._config(), "agriculture-voucher", "discover", lab_mode="hosted")
        self.assertIn("note", result["request_source"])
        self.assertIn("local lab profile", result["request_source"]["note"])
        self.assertIn("note", result["response_source"])
        self.assertIn("local lab profile", result["response_source"]["note"])

    def test_run_step_hosted_local_only_makes_no_http_call(self) -> None:
        """urllib.request.urlopen must not be called for a local-only step in hosted mode."""
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("urlopen must not be called in hosted mode for local-only scenario")

        import lab_homepage_scenarios.common as _common
        with mock.patch.object(_common, "http_json", side_effect=fail_if_called):
            # Should NOT raise; if it does, the guard is missing.
            result = server.run_scenario_step(self._config(), "social-aggregate", "read-aggregate", lab_mode="hosted")
        self.assertEqual(result["friendly"]["status"], "local_only")

    def test_run_step_local_mode_local_only_still_executes(self) -> None:
        """In local mode, a local-only scenario must follow its normal execution path."""
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
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn('id="chooser"', html)

    def test_scenario_page_html_renders_for_story_route(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios", "alive-proof").decode("utf-8")
        self.assertIn('const ACTIVE_SCENARIO = "alive-proof"', html)

    def test_chooser_cta_reads_walkthrough_when_not_runnable(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn("Read the walkthrough", html)

    def test_chooser_cta_reads_open_story_when_runnable(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn("Open story", html)

    def test_story_local_only_pill_style_present(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn("status-pill.local_only", html)

    def test_story_local_only_no_run_button(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn("This step runs on the local lab profile", html)

    def test_story_run_it_locally_block_present(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn("Run this story on your machine", html)
        self.assertIn("git clone https://github.com/jeremi/registry-lab", html)

    def test_story_drawers_note_when_not_runnable(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn("Available when the story runs on the local lab profile", html)

    def test_status_label_maps_local_only(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn('"local_only"', html)
        self.assertIn('"Local only"', html)


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
                return b'{"claims":["civil-record-present","eligible-for-combined-support"]}'

        with mock.patch.object(server.urllib.request, "urlopen", lambda req, timeout=None: Resp()):
            result = server.run_scenario_step(
                server.enrich_config({"credentials": []}), "combined-support", "discover", lab_mode="local"
            )
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

    # ---- JS renderRequestSource: internal branch must be present in the page HTML ----

    def test_scenario_page_html_contains_internal_note_branch(self) -> None:
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        self.assertIn("value.internal", html, "renderRequestSource must branch on value.internal")
        self.assertIn("Internal lab call.", html, "renderRequestSource must render the internal-note text")

    def test_scenario_page_html_internal_branch_suppresses_curl_button(self) -> None:
        # The canCurl logic must exclude internal requests.
        html = server.scenario_page_html("Registry Lab Scenarios").decode("utf-8")
        # The combined canCurl expression must gate on !value.internal (or equivalent).
        self.assertIn("value.internal", html)
        # And the "Copy as curl" button must still appear (for public-credential paths).
        self.assertIn("Copy as curl", html)


if __name__ == "__main__":
    unittest.main()
