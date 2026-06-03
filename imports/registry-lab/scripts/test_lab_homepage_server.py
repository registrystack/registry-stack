#!/usr/bin/env python3
"""Focused tests for the Registry Lab homepage server."""

from __future__ import annotations

import importlib.util
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
        self.assertIn("no longer requires a separate issuer PIN", self.html)


if __name__ == "__main__":
    unittest.main()
