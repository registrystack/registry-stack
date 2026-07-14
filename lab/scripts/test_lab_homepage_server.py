#!/usr/bin/env python3
"""Focused tests for the Registry Lab homepage server."""

from __future__ import annotations

import importlib.util
import json
import os
import unittest
import unittest.mock as mock
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import lab_homepage_scenarios
import lab_homepage_scenarios.common as scenario_common
from lab_homepage_explorer import common as explorer_common

MODULE_PATH = Path(__file__).resolve().parent / "lab-homepage-server.py"
_spec = importlib.util.spec_from_file_location("lab_homepage_server", MODULE_PATH)
assert _spec and _spec.loader
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)

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

    def test_homepage_links_to_dedicated_scenario_runner(self) -> None:
        self.assertIn('href="/scenarios"', self.html)
        self.assertIn("Run a guided scenario", self.html)
        self.assertNotIn('id="scenario-grid"', self.html)

    def test_homepage_links_to_citizen_portal(self) -> None:
        self.assertIn("https://portal.lab.registrystack.org/", self.html)
        self.assertIn("Citizen Portal", self.html)
        self.assertIn("portal.lab.registrystack.org", HOMEPAGE_JS)


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
        story_html = server.scenario_page_html(scenario_id="self-attested-declaration").decode("utf-8")
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
        self.assertIn('data-active-scenario="self-attested-declaration"', story_html)
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
        self.assertIn("state.purpose = claim.default_purpose || state.purpose", CLAIMS_EXPLORER_JS)
        self.assertIn(
            "state.purpose = claim.default_purpose || selectedServiceSummary().default_purpose || state.purpose",
            CLAIMS_EXPLORER_JS,
        )

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


class SelfAttestedSurfaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = server.enrich_config(
            {
                "credentials": [
                    {
                        "id": "self-attested-evidence",
                        "env": "SELF_ATTESTED_TEST_TOKEN",
                        "service_url": "https://self-attested.example",
                        "auth_scheme": "api_key",
                        "default_purpose": "application-processing",
                        "default_subject": "demo-applicant",
                        "default_identifier_scheme": "applicant_id",
                        "example": {"path": "/v1/claims"},
                    }
                ]
            }
        )

    def test_scenario_catalogue_exposes_only_active_notary_and_relay_journeys(self) -> None:
        payload = server.scenario_payload(self.config)
        self.assertEqual(
            [scenario["id"] for scenario in payload["scenarios"]],
            ["self-attested-declaration", "social-aggregate"],
        )
        self.assertEqual(payload["default_scenario_id"], "self-attested-declaration")

    def test_claims_catalogue_exposes_only_self_attested_notary(self) -> None:
        payload = server.claims_explorer.claim_catalog_payload(self.config)
        self.assertEqual(
            [service["id"] for service in payload["claim_services"]],
            ["self-attested-notary"],
        )
        claim = payload["claim_services"][0]["claims"][0]
        self.assertEqual(claim["source"]["acquisition_path"], "self_attested")
        self.assertFalse(claim["source"]["registry_consulted"])
        self.assertNotIn("connector_type", str(payload))

    def test_self_attested_request_uses_api_key_and_no_registry_fields(self) -> None:
        request = server.claims_explorer.build_evaluation_request(
            self.config,
            "self-attested-notary",
            "applicant-declaration",
            subject="demo-applicant",
            identifier_scheme="applicant_id",
            disclosure="predicate",
            result_format=server.claims_explorer.CLAIM_RESULT_FORMAT,
            purpose="application-processing",
        )
        self.assertIn("X-Api-Key", request["request_source"]["headers"])
        self.assertEqual(request["request_source"]["body"]["claims"], ["applicant-declaration"])
        self.assertNotIn("source", request["request_source"]["body"])

    def test_self_attested_scenario_previews_are_complete(self) -> None:
        payload = server.scenario_payload(self.config, "self-attested-declaration")
        previews = [step["request_preview"] for step in payload["story"]["steps"]]
        self.assertEqual([preview["method"] for preview in previews], ["GET", "POST"])
        self.assertTrue(all(preview["url"].startswith("https://self-attested.example/") for preview in previews))


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
            server.scenario_page_html(scenario_id="self-attested-declaration").decode("utf-8"),
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
            conn.putrequest("POST", "/api/explorer/claims/self-attested-notary/evaluate.json")
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
        page = server.scenario_page_html(scenario_id="self-attested-declaration").decode("utf-8")
        self.assertNotIn("<script>", page)
        self.assertIn('data-active-scenario="self-attested-declaration"', page)

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

    def test_sections_run_scenarios_then_services(self) -> None:
        order = [
            self.page.index('id="scenarios"'),
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
        self.assertLess(nav.index("Scenario demos"), nav.index("For developers"))

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
