"""Framework-neutral holder sign-in and renewable-session contract."""

from __future__ import annotations

from dataclasses import replace
import importlib
import importlib.util
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_portal_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
portal = importlib.import_module(f"{PACKAGE}.portal")


def policy(name: str, resource: str, scope: str):
    return portal.GrantPolicy(
        name=name,
        resource=resource,
        scopes=(scope,),
        profile=f"{name}-holder",
        required_claims={"registry_role": "holder"},
    )


def verified(
    grant_policy,
    *,
    subject: str = "citizen-001",
    principal: str = "person-001",
    access_token: str | None = None,
    refresh_token: str | None = None,
    expires_at: float = 1_300,
    issuer: str = "https://issuer.example.test",
    client_id: str = "holder-portal",
    persona: str = "holder",
    resource: str | None = None,
    profile: str | None = None,
    scopes: tuple[str, ...] | None = None,
    authorized_party: str | None = "holder-portal",
    client_id_claim: str | None = "holder-portal",
):
    return portal.VerifiedGrant(
        access_token=(
            access_token if access_token is not None else f"access-{grant_policy.name}"
        ),
        refresh_token=(
            refresh_token
            if refresh_token is not None
            else f"refresh-{grant_policy.name}"
        ),
        id_token=f"id-{grant_policy.name}",
        expires_at=expires_at,
        issuer=issuer,
        client_id=client_id,
        subject=subject,
        principal=principal,
        persona=persona,
        resource=resource or grant_policy.resource,
        profile=profile or grant_policy.profile,
        scopes=scopes or grant_policy.scopes,
        claims={"registry_role": "holder"},
        authorized_party=authorized_party,
        client_id_claim=client_id_claim,
    )


class FakeOIDC:
    def __init__(self):
        self.authorizations = []
        self.exchanges = []
        self.exchange_results = []
        self.refreshes = []
        self.refresh_results = []
        self.logout_error: BaseException | None = None

    def authorization_url(self, grant_policy, *, state, nonce, code_verifier):
        self.authorizations.append((grant_policy, state, nonce, code_verifier))
        return (
            "https://issuer.example.test/authorize?"
            f"state={state}&nonce={nonce}&resource={grant_policy.resource}"
        )

    def exchange(self, callback_url, pending, grant_policy):
        self.exchanges.append((callback_url, pending, grant_policy))
        result = self.exchange_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def refresh(self, current, grant_policy):
        self.refreshes.append((current, grant_policy))
        result = self.refresh_results.pop(0)
        if callable(result):
            return result(current, grant_policy)
        if isinstance(result, BaseException):
            raise result
        return result

    def end_session_url(self, session, *, state, switch=False):
        if self.logout_error is not None:
            raise self.logout_error
        return f"https://issuer.example.test/logout?state={state}&switch={int(switch)}"


class Clock:
    def __init__(self, value=1_000.0):
        self.value = value

    def __call__(self):
        return self.value


class PortalTests(unittest.TestCase):
    def test_resource_grants_accept_urn_audiences(self):
        breg = policy("breg", "urn:breg:p0-audience", "records.holder")
        casework = policy("casework", "urn:casework:p0-audience", "reviews.initiator")
        config = portal.PortalConfig(
            issuer="https://issuer.example.test",
            client_id="holder-portal",
            redirect_uri="https://portal.example.test/auth/callback",
            origin="https://portal.example.test",
            persona="holder",
            grants=(breg, casework),
        )
        self.assertEqual(config.grants[0].resource, "urn:breg:p0-audience")
        for invalid in ("urn:", "https:///missing-host", "urn:breg:p0#fragment"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                policy("breg", invalid, "records.holder")

    def setUp(self):
        self.breg = policy("breg", "https://breg.example.test", "records.holder")
        self.casework = policy(
            "casework", "https://casework.example.test", "reviews.initiator"
        )
        self.config = portal.PortalConfig(
            issuer="https://issuer.example.test",
            client_id="holder-portal",
            redirect_uri="https://portal.example.test/auth/callback",
            origin="https://portal.example.test",
            persona="holder",
            grants=(self.breg, self.casework),
        )
        self.clock = Clock()
        self.oidc = FakeOIDC()
        self.store = portal.MemorySessionStore()
        self.sessions = portal.PortalSessions(
            self.config, self.oidc, self.store, clock=self.clock
        )

    @unittest.skipUnless(
        importlib.util.find_spec("authlib") and importlib.util.find_spec("requests"),
        "the human sign-in extra is required",
    )
    def test_actual_authlib_authorization_url_pins_resource_state_nonce_and_pkce(self):
        client = portal.AuthlibOIDCClient(
            client_id="holder-portal",
            client_secret=None,
            redirect_uri=self.config.redirect_uri,
            authorization_endpoint="https://issuer.example.test/authorize",
            token_endpoint="https://issuer.example.test/token",
            end_session_endpoint=None,
            verify_token=lambda *_: None,
        )
        url = client.authorization_url(
            self.breg,
            state="pending-state",
            nonce="pending-nonce",
            code_verifier="pkce-verifier-value",
        )
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["state"], ["pending-state"])
        self.assertEqual(query["nonce"], ["pending-nonce"])
        self.assertEqual(query["resource"], [self.breg.resource])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertIn("code_challenge", query)
        self.assertNotIn("code_verifier", query)

        bridge = portal.GrantPolicy(
            "casework",
            "urn:example:casework",
            ("casework:review", "licensing:audit"),
            "reviewer",
            {"registry_actor_kind": "human"},
            forward_resource="urn:example:breg",
        )
        bridge_url = client.authorization_url(
            bridge,
            state="bridge-state",
            nonce="bridge-nonce",
            code_verifier="bridge-verifier-value",
        )
        self.assertEqual(
            parse_qs(urlsplit(bridge_url).query)["resource"],
            ["urn:example:casework", "urn:example:breg"],
        )

    @unittest.skipUnless(
        importlib.util.find_spec("authlib") and importlib.util.find_spec("requests"),
        "the human sign-in extra is required",
    )
    def test_actual_authlib_exchange_sends_pkce_and_exact_resource(self):
        import requests

        seen_requests = []

        def send(_session, prepared, **_kwargs):
            seen_requests.append(prepared)
            response = requests.Response()
            response.status_code = 200
            response.url = prepared.url
            response.request = prepared
            response.headers["Content-Type"] = "application/json"
            response._content = (
                b'{"access_token":"access-canary","token_type":"Bearer",'
                b'"refresh_token":"refresh-canary","id_token":"id-canary",'
                b'"expires_in":300}'
            )
            return response

        verified_tokens = []

        def verify_token(token, nonce, grant_policy, current):
            verified_tokens.append((dict(token), nonce, grant_policy, current))
            return verified(grant_policy)

        client = portal.AuthlibOIDCClient(
            client_id="holder-portal",
            client_secret=None,
            redirect_uri=self.config.redirect_uri,
            authorization_endpoint="https://issuer.example.test/authorize",
            token_endpoint="https://issuer.example.test/token",
            end_session_endpoint=None,
            verify_token=verify_token,
        )
        pending = portal.PendingGrant(
            "pending-state",
            "chain",
            "pending-nonce",
            "pkce-verifier-value",
            0,
            1000,
            1300,
            "/",
            (),
        )
        with patch.object(requests.Session, "send", send):
            client.exchange(
                "https://portal.example.test/auth/callback?code=code-one&state=pending-state",
                pending,
                self.breg,
            )
        self.assertEqual(len(seen_requests), 1)
        form = parse_qs(seen_requests[0].body)
        self.assertEqual(form["code_verifier"], ["pkce-verifier-value"])
        self.assertEqual(form["resource"], [self.breg.resource])
        self.assertEqual(verified_tokens[0][1], "pending-nonce")

        bridge = portal.GrantPolicy(
            "casework",
            "urn:example:casework",
            ("casework:review", "licensing:audit"),
            "reviewer",
            {"registry_actor_kind": "human"},
            forward_resource="urn:example:breg",
        )
        with patch.object(requests.Session, "send", send):
            client.exchange(
                "https://portal.example.test/auth/callback?code=code-two&state=pending-state",
                pending,
                bridge,
            )
        self.assertEqual(
            parse_qs(seen_requests[-1].body)["resource"],
            ["urn:example:casework", "urn:example:breg"],
        )

    @unittest.skipUnless(
        importlib.util.find_spec("authlib") and importlib.util.find_spec("requests"),
        "the human sign-in extra is required",
    )
    def test_actual_authlib_refresh_sends_one_resource_and_retains_reused_refresh_token(
        self,
    ):
        import requests

        seen_requests = []

        def send(_session, prepared, **_kwargs):
            seen_requests.append(prepared)
            response = requests.Response()
            response.status_code = 200
            response.url = prepared.url
            response.request = prepared
            response.headers["Content-Type"] = "application/json"
            response._content = b'{"access_token":"renewed-canary","token_type":"Bearer","expires_in":300}'
            return response

        verified_tokens = []

        def verify_token(token, nonce, grant_policy, current):
            verified_tokens.append((dict(token), nonce, grant_policy, current))
            return verified(
                grant_policy,
                access_token=token["access_token"],
                refresh_token=token["refresh_token"],
            )

        client = portal.AuthlibOIDCClient(
            client_id="holder-portal",
            client_secret=None,
            redirect_uri=self.config.redirect_uri,
            authorization_endpoint="https://issuer.example.test/authorize",
            token_endpoint="https://issuer.example.test/token",
            end_session_endpoint=None,
            verify_token=verify_token,
        )
        current = verified(self.breg, refresh_token="refresh-canary")
        with patch.object(requests.Session, "send", send):
            renewed = client.refresh(current, self.breg)
        self.assertEqual(len(seen_requests), 1)
        form = parse_qs(seen_requests[0].body)
        self.assertEqual(form["refresh_token"], ["refresh-canary"])
        self.assertEqual(form["resource"], [self.breg.resource])
        self.assertEqual(form["scope"], ["records.holder"])
        self.assertEqual(verified_tokens[0][0]["refresh_token"], "refresh-canary")
        self.assertIs(verified_tokens[0][3], current)
        self.assertEqual(renewed.access_token, "renewed-canary")

        bridge = portal.GrantPolicy(
            "casework",
            "urn:example:casework",
            ("casework:review", "licensing:audit"),
            "reviewer",
            {"registry_actor_kind": "human"},
            forward_resource="urn:example:breg",
        )
        with patch.object(requests.Session, "send", send):
            client.refresh(verified(bridge, refresh_token="bridge-refresh"), bridge)
        self.assertEqual(
            parse_qs(seen_requests[-1].body)["resource"],
            ["urn:example:casework", "urn:example:breg"],
        )

    def _complete(self):
        self.oidc.exchange_results.extend(
            [verified(self.breg), verified(self.casework)]
        )
        first = self.sessions.start("/application/continue")
        partial = self.sessions.callback(
            f"https://portal.example.test/auth/callback?code=one&state={first.state}",
            state=first.state,
        )
        complete = self.sessions.callback(
            "https://portal.example.test/auth/callback?"
            f"code=two&state={partial.authorization.state}",
            state=partial.authorization.state,
        )
        return first, partial, complete

    def test_two_independent_resource_grants_create_no_partial_session(self):
        first, partial, complete = self._complete()

        self.assertIsNone(partial.session_id)
        self.assertIsNotNone(partial.authorization)
        self.assertNotEqual(first.state, partial.authorization.state)
        first_pending = self.oidc.exchanges[0][1]
        second_pending = self.oidc.exchanges[1][1]
        self.assertNotEqual(first_pending.nonce, second_pending.nonce)
        self.assertNotEqual(first_pending.code_verifier, second_pending.code_verifier)
        self.assertEqual(complete.return_to, "/application/continue")
        self.assertIsNone(complete.authorization)

        context = self.sessions.context(complete.session_id, minimum_valid_seconds=0)
        self.assertEqual(context.subject, "citizen-001")
        self.assertEqual(context.principal, "person-001")
        self.assertEqual(context.persona, "holder")
        self.assertEqual(context._token_for("breg"), "access-breg")
        self.assertEqual(context._token_for("casework"), "access-casework")
        self.assertFalse(hasattr(context, "access_tokens"))
        self.assertNotIn("access", complete.session_id)
        self.assertNotIn("refresh", complete.session_id)

        resources = [item[0].resource for item in self.oidc.authorizations]
        self.assertEqual(resources, [self.breg.resource, self.casework.resource])
        for grant_policy, authorization in zip(
            (self.breg, self.casework),
            (first, partial.authorization),
            strict=True,
        ):
            query = parse_qs(urlsplit(authorization.url).query)
            self.assertEqual(query["resource"], [grant_policy.resource])
            self.assertNotIn("prompt", query)

    def test_state_is_single_use_and_a_failed_exchange_creates_no_session(self):
        self.oidc.exchange_results.append(RuntimeError("synthetic token failure"))
        request = self.sessions.start("/")
        with self.assertRaises(portal.AdmissionError):
            self.sessions.callback(
                f"https://portal.example.test/auth/callback?code=bad&state={request.state}",
                state=request.state,
            )
        with self.assertRaises(portal.AdmissionError):
            self.sessions.callback(
                f"https://portal.example.test/auth/callback?code=replay&state={request.state}",
                state=request.state,
            )
        self.assertEqual(self.store.session_count(), 0)

    def test_callback_state_is_bound_to_the_exact_registered_url(self):
        self.oidc.exchange_results.append(verified(self.breg))
        request = self.sessions.start("/")
        with self.assertRaises(portal.AdmissionError):
            self.sessions.callback(
                f"https://other.example.test/auth/callback?code=one&state={request.state}",
                state=request.state,
            )
        with self.assertRaises(portal.AdmissionError):
            self.sessions.callback(
                "https://portal.example.test/auth/callback?"
                f"code=one&state={request.state}",
                state=request.state,
            )
        self.assertEqual(len(self.oidc.exchanges), 0)

    def test_callback_after_login_cancellation_is_refused(self):
        self.oidc.exchange_results.append(verified(self.breg))
        request = self.sessions.start("/")
        self.sessions.cancel(request.chain_id)

        with self.assertRaises(portal.AdmissionError):
            self.sessions.callback(
                "https://portal.example.test/auth/callback?"
                f"code=late&state={request.state}",
                state=request.state,
            )
        self.assertEqual(len(self.oidc.exchanges), 0)
        self.assertEqual(self.store.session_count(), 0)

    def test_callback_is_bound_to_the_browser_login_chain(self):
        self.oidc.exchange_results.append(verified(self.breg))
        request = self.sessions.start("/")
        other_chain = "A" * 43

        with self.assertRaises(portal.AdmissionError):
            self.sessions._callback_for_chain(
                "https://portal.example.test/auth/callback?"
                f"code=late&state={request.state}",
                state=request.state,
                chain_id=other_chain,
            )

        self.assertEqual(len(self.oidc.exchanges), 0)
        result = self.sessions._callback_for_chain(
            "https://portal.example.test/auth/callback?"
            f"code=accepted&state={request.state}",
            state=request.state,
            chain_id=request.chain_id,
        )
        self.assertIsNotNone(result.authorization)
        self.assertEqual(self.store.session_count(), 0)

    def test_untrusted_chain_ids_do_not_grow_store_state(self):
        closed_before = len(self.store._closed_chains)

        for chain_id in (
            "",
            "short",
            "A" * 42,
            "A" * 43,
            "A" * 44,
            "!" + "A" * 42,
        ):
            self.sessions.cancel(chain_id)

        self.assertEqual(len(self.store._closed_chains), closed_before)

    def test_second_resource_cannot_change_the_person(self):
        self.oidc.exchange_results.extend(
            [
                verified(self.breg),
                verified(self.casework, subject="citizen-002", principal="person-002"),
            ]
        )
        first = self.sessions.start("/")
        partial = self.sessions.callback(
            f"https://portal.example.test/auth/callback?code=one&state={first.state}",
            state=first.state,
        )
        with self.assertRaises(portal.AdmissionError):
            self.sessions.callback(
                "https://portal.example.test/auth/callback?"
                f"code=two&state={partial.authorization.state}",
                state=partial.authorization.state,
            )
        self.assertEqual(self.store.session_count(), 0)

    def test_every_grant_is_bound_to_exact_authority_and_required_scope(self):
        mutations = [
            {"issuer": "https://other.example.test"},
            {"client_id": "other-client"},
            {"authorized_party": "other-client"},
            {"client_id_claim": "other-client"},
            {"persona": "staff"},
            {"resource": "https://other.example.test"},
            {"profile": "breg-officer"},
            {"scopes": ("records.public",)},
            {"refresh_token": ""},
        ]
        for changes in mutations:
            with self.subTest(changes=changes):
                oidc = FakeOIDC()
                store = portal.MemorySessionStore()
                sessions = portal.PortalSessions(
                    self.config, oidc, store, clock=self.clock
                )
                oidc.exchange_results.append(verified(self.breg, **changes))
                request = sessions.start("/")
                with self.assertRaises(portal.AdmissionError):
                    sessions.callback(
                        "https://portal.example.test/auth/callback?"
                        f"code=one&state={request.state}",
                        state=request.state,
                    )
                self.assertEqual(store.session_count(), 0)

    def test_each_initial_resource_grant_requires_a_verified_id_token(self):
        self.oidc.exchange_results.append(replace(verified(self.breg), id_token=None))
        request = self.sessions.start("/")

        with self.assertRaises(portal.AdmissionError):
            self.sessions.callback(
                "https://portal.example.test/auth/callback?"
                f"code=one&state={request.state}",
                state=request.state,
            )
        self.assertEqual(self.store.session_count(), 0)

    def test_refresh_publishes_one_complete_generation_without_extending_session(self):
        _, _, complete = self._complete()
        original = self.store.get_session(complete.session_id)
        self.clock.value = 1_250
        self.oidc.refresh_results.extend(
            [
                replace(
                    verified(self.breg),
                    access_token="access-breg-2",
                    refresh_token="refresh-breg-2",
                    expires_at=1_550,
                ),
                replace(
                    verified(self.casework),
                    access_token="access-casework-2",
                    refresh_token="refresh-casework-2",
                    expires_at=1_550,
                ),
            ]
        )

        context = self.sessions.context(complete.session_id, minimum_valid_seconds=100)
        updated = self.store.get_session(complete.session_id)
        self.assertEqual(context._token_for("breg"), "access-breg-2")
        self.assertEqual(context._token_for("casework"), "access-casework-2")
        self.assertEqual(updated.generation, original.generation + 1)
        self.assertEqual(updated.expires_at, original.expires_at)

    def test_failed_required_refresh_never_publishes_a_mixed_session(self):
        _, _, complete = self._complete()
        self.clock.value = 1_250
        self.oidc.refresh_results.extend(
            [
                replace(
                    verified(self.breg),
                    access_token="access-breg-2",
                    expires_at=1_550,
                ),
                RuntimeError("casework refresh denied"),
            ]
        )
        with self.assertRaises(portal.ReauthenticationRequired):
            self.sessions.context(complete.session_id, minimum_valid_seconds=100)
        self.assertIsNone(self.store.get_session(complete.session_id))

    def test_refresh_cannot_change_identity_or_authority(self):
        _, _, complete = self._complete()
        self.clock.value = 1_250
        self.oidc.refresh_results.append(
            replace(
                verified(self.breg),
                subject="citizen-002",
                principal="person-002",
                expires_at=1_550,
            )
        )
        with self.assertRaises(portal.ReauthenticationRequired):
            self.sessions.context(complete.session_id, minimum_valid_seconds=100)
        self.assertIsNone(self.store.get_session(complete.session_id))

    def test_concurrent_refreshes_publish_only_one_generation(self):
        _, _, complete = self._complete()
        self.clock.value = 1_250
        entered = threading.Event()
        release = threading.Event()
        duplicate = threading.Event()
        calls = []
        calls_lock = threading.Lock()

        def rotate(current, grant_policy):
            with calls_lock:
                calls.append((grant_policy.name, current.refresh_token))
                first = len(calls) == 1
            if first:
                entered.set()
                release.wait(2)
            elif grant_policy.name == "breg":
                duplicate.set()
                raise RuntimeError("refresh token was already redeemed")
            return replace(
                verified(grant_policy),
                access_token=f"access-{grant_policy.name}-2",
                refresh_token=f"refresh-{grant_policy.name}-2",
                expires_at=1_550,
            )

        self.oidc.refresh_results.extend([rotate, rotate, rotate])
        results = []
        errors = []

        def refresh():
            try:
                results.append(
                    self.sessions.context(
                        complete.session_id, minimum_valid_seconds=100
                    )
                )
            except Exception as error:
                errors.append(error)

        first = threading.Thread(target=refresh)
        second = threading.Thread(target=refresh)
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        duplicate.wait(0.2)
        release.set()
        threads = (first, second)
        for thread in threads:
            thread.join(2)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertFalse(
            duplicate.is_set(), "a rotating refresh token was redeemed twice"
        )
        self.assertFalse(errors)
        self.assertEqual(len(results), 2)
        self.assertEqual([name for name, _ in calls], ["breg", "casework"])
        current = self.store.get_session(complete.session_id)
        self.assertEqual(current.generation, 1)
        self.assertEqual(
            {result._token_for("breg") for result in results},
            {current.grants[0].access_token},
        )
        self.assertEqual(
            {result._token_for("casework") for result in results},
            {current.grants[1].access_token},
        )

    def test_logout_wins_over_a_late_refresh(self):
        _, _, complete = self._complete()
        self.clock.value = 1_250
        entered = threading.Event()
        release = threading.Event()

        def late_refresh(current, grant_policy):
            entered.set()
            release.wait(2)
            return replace(
                verified(grant_policy),
                access_token=f"late-{grant_policy.name}",
                expires_at=1_550,
            )

        self.oidc.refresh_results.extend(
            [late_refresh, replace(verified(self.casework), expires_at=1_550)]
        )
        result = []

        def refresh():
            try:
                self.sessions.context(complete.session_id, minimum_valid_seconds=100)
            except Exception as error:
                result.append(error)

        thread = threading.Thread(target=refresh)
        thread.start()
        self.assertTrue(entered.wait(1))
        self.sessions.logout(complete.session_id)
        release.set()
        thread.join(2)

        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], portal.ReauthenticationRequired)
        self.assertIsNone(self.store.get_session(complete.session_id))

    def test_absolute_expiry_and_csrf_are_separate_from_token_renewal(self):
        _, _, complete = self._complete()
        context = self.sessions.context(complete.session_id, minimum_valid_seconds=0)
        self.sessions.authorize_mutation(
            complete.session_id,
            origin="https://portal.example.test",
            csrf_token=context.csrf_token,
        )
        for origin, csrf in [
            ("https://other.example.test", context.csrf_token),
            ("https://portal.example.test", "wrong-token"),
        ]:
            with self.assertRaises(portal.CSRFError):
                self.sessions.authorize_mutation(
                    complete.session_id, origin=origin, csrf_token=csrf
                )
        self.clock.value = 1_901
        with self.assertRaises(portal.ReauthenticationRequired):
            self.sessions.context(complete.session_id, minimum_valid_seconds=0)

    def test_local_logout_survives_issuer_logout_failure(self):
        _, _, complete = self._complete()
        self.oidc.logout_error = RuntimeError("issuer unavailable")
        result = self.sessions.logout(complete.session_id)
        self.assertIsNone(result.end_session_url)
        self.assertFalse(result.issuer_logout_available)
        with self.assertRaises(portal.ReauthenticationRequired):
            self.sessions.context(complete.session_id, minimum_valid_seconds=0)

    def test_account_switch_closes_local_session_and_requests_issuer_switch(self):
        _, _, complete = self._complete()
        result = self.sessions.logout(complete.session_id, switch=True)
        self.assertIn("switch=1", result.end_session_url)
        with self.assertRaises(portal.ReauthenticationRequired):
            self.sessions.context(complete.session_id, minimum_valid_seconds=0)

    def test_authlib_switch_uses_same_origin_login_return(self):
        client = portal.AuthlibOIDCClient(
            client_id="holder-portal",
            client_secret=None,
            redirect_uri=self.config.redirect_uri,
            authorization_endpoint="https://issuer.example.test/authorize",
            token_endpoint="https://issuer.example.test/token",
            end_session_endpoint="https://issuer.example.test/logout",
            switch_redirect_uri="https://portal.example.test/auth/login",
            verify_token=lambda *_: None,
        )
        _, _, complete = self._complete()
        session = self.store.get_session(complete.session_id)
        assert session is not None
        query = parse_qs(
            urlsplit(client.end_session_url(session, state="s", switch=True)).query
        )
        self.assertEqual(
            query["post_logout_redirect_uri"],
            ["https://portal.example.test/auth/login"],
        )
        self.assertEqual(query["id_token_hint"], ["id-breg"])
        with self.assertRaises(ValueError):
            portal.AuthlibOIDCClient(
                client_id="holder-portal",
                client_secret=None,
                redirect_uri=self.config.redirect_uri,
                authorization_endpoint="https://issuer.example.test/authorize",
                token_endpoint="https://issuer.example.test/token",
                end_session_endpoint="https://issuer.example.test/logout",
                switch_redirect_uri="https://other.example.test/auth/login",
                verify_token=lambda *_: None,
            )

    def test_memory_store_restart_loses_sessions_clearly(self):
        _, _, complete = self._complete()
        restarted = portal.PortalSessions(
            self.config,
            self.oidc,
            portal.MemorySessionStore(),
            clock=self.clock,
        )
        with self.assertRaises(portal.ReauthenticationRequired):
            restarted.context(complete.session_id, minimum_valid_seconds=0)

    def test_memory_refresh_locks_do_not_block_other_sessions(self):
        first_held = threading.Event()
        second_acquired = threading.Event()
        release = threading.Event()

        def hold_first():
            with self.store.refresh_lock("session-one"):
                first_held.set()
                release.wait(2)

        def enter_second():
            with self.store.refresh_lock("session-two"):
                second_acquired.set()

        first = threading.Thread(target=hold_first)
        second = threading.Thread(target=enter_second)
        first.start()
        self.assertTrue(first_held.wait(2))
        second.start()
        try:
            self.assertTrue(second_acquired.wait(2))
        finally:
            release.set()
            first.join(2)
            second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())

    def test_invalid_session_limits_and_unsafe_return_targets_are_refused(self):
        for seconds in (0, -1, float("inf"), float("nan")):
            with self.subTest(seconds=seconds):
                with self.assertRaises(ValueError):
                    replace(self.config, session_seconds=seconds)
        for target in ("https://other.example.test/", "//other.example.test", "bad\n"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    self.sessions.start(target)

    def test_authlib_client_binds_pkce_state_nonce_resource_and_refresh(self):
        sessions = []

        class RecordingOAuth2Session:
            def __init__(self, **kwargs):
                self.configuration = kwargs
                self.authorization = None
                self.exchange = None
                self.renewal = None
                self.closed = False
                sessions.append(self)

            def create_authorization_url(self, endpoint, **kwargs):
                self.authorization = (endpoint, kwargs)
                return f"{endpoint}?state={kwargs['state']}", kwargs["state"]

            def fetch_token(self, endpoint, **kwargs):
                self.exchange = (endpoint, kwargs)
                return {
                    "access_token": "access-breg",
                    "refresh_token": "refresh-breg",
                    "id_token": "id-breg",
                }

            def refresh_token(self, endpoint, **kwargs):
                self.renewal = (endpoint, kwargs)
                return {"access_token": "access-breg-2"}

            def close(self):
                self.closed = True

        authlib = types.ModuleType("authlib")
        integrations = types.ModuleType("authlib.integrations")
        requests_client = types.ModuleType("authlib.integrations.requests_client")
        setattr(requests_client, "OAuth2Session", RecordingOAuth2Session)
        setattr(authlib, "integrations", integrations)
        setattr(integrations, "requests_client", requests_client)
        modules = {
            "authlib": authlib,
            "authlib.integrations": integrations,
            "authlib.integrations.requests_client": requests_client,
        }
        verifications = []

        def verify_token(token, nonce, grant_policy, current):
            verifications.append((dict(token), nonce, grant_policy, current))
            return replace(
                verified(grant_policy),
                access_token=token["access_token"],
                refresh_token=token["refresh_token"],
            )

        client = portal.AuthlibOIDCClient(
            client_id="holder-portal",
            client_secret="synthetic-client-secret",
            redirect_uri=self.config.redirect_uri,
            authorization_endpoint="https://issuer.example.test/authorize",
            token_endpoint="https://issuer.example.test/token",
            end_session_endpoint="https://issuer.example.test/logout",
            verify_token=verify_token,
            timeout_seconds=4,
        )
        pending = portal.PendingGrant(
            state="expected-state",
            chain_id="chain",
            nonce="expected-nonce",
            code_verifier="verifier-value",
            grant_index=0,
            created_at=1_000,
            expires_at=1_300,
            return_to="/",
            grants=(),
        )

        with patch.dict(sys.modules, modules):
            authorization_url = client.authorization_url(
                self.breg,
                state=pending.state,
                nonce=pending.nonce,
                code_verifier=pending.code_verifier,
            )
            initial = client.exchange(
                "https://portal.example.test/auth/callback?"
                "code=one&state=expected-state",
                pending,
                self.breg,
            )
            renewed = client.refresh(initial, self.breg)

        self.assertEqual(len(sessions), 3)
        self.assertEqual(
            authorization_url,
            "https://issuer.example.test/authorize?state=expected-state",
        )
        authorization = sessions[0]
        self.assertEqual(
            authorization.configuration["scope"],
            "openid offline_access records.holder",
        )
        self.assertEqual(
            authorization.configuration["token_endpoint_auth_method"],
            "client_secret_post",
        )
        self.assertEqual(authorization.configuration["code_challenge_method"], "S256")
        self.assertEqual(authorization.configuration["default_timeout"], 4)
        authorization_arguments = authorization.authorization[1]
        self.assertEqual(authorization_arguments["state"], pending.state)
        self.assertEqual(authorization_arguments["nonce"], pending.nonce)
        self.assertEqual(
            authorization_arguments["code_verifier"], pending.code_verifier
        )
        self.assertEqual(authorization_arguments["resource"], self.breg.resource)
        self.assertNotIn("prompt", authorization_arguments)

        exchange_arguments = sessions[1].exchange[1]
        self.assertEqual(exchange_arguments["state"], pending.state)
        self.assertEqual(exchange_arguments["code_verifier"], pending.code_verifier)
        self.assertEqual(
            parse_qs(exchange_arguments["body"])["resource"], [self.breg.resource]
        )
        renewal_arguments = sessions[2].renewal[1]
        self.assertEqual(renewal_arguments["refresh_token"], "refresh-breg")
        self.assertEqual(
            parse_qs(renewal_arguments["body"])["resource"], [self.breg.resource]
        )
        self.assertEqual(renewal_arguments["scope"], "records.holder")
        self.assertEqual(renewed.refresh_token, "refresh-breg")
        self.assertEqual(verifications[0][1], pending.nonce)
        self.assertIsNone(verifications[0][3])
        self.assertIsNone(verifications[1][1])
        self.assertEqual(verifications[1][3], initial)
        self.assertTrue(all(session.closed for session in sessions))


if __name__ == "__main__":
    unittest.main()
