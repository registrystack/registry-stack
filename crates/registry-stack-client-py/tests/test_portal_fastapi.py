"""FastAPI portal translation preserves the server-side session boundary."""

import asyncio
import importlib
from pathlib import Path
import sys
import threading
import types
import unittest

from fastapi import FastAPI, Request
import httpx


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_portal_fastapi_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
portal = importlib.import_module(f"{PACKAGE}.portal")
web = importlib.import_module(f"{PACKAGE}.web")
CHAIN_ID = "c" * 43


class Sessions:
    def __init__(self, *, issuer_logout=True, persona="holder"):
        self.session_id = "session-secret-canary"
        self.issuer_logout = issuer_logout
        self.persona = persona
        self.return_to = "/"
        self.calls = []
        self.cancel_calls = []

    def _called(self, operation):
        self.calls.append((operation, threading.get_ident()))

    def start(self, return_to="/"):
        self._called("start")
        self.return_to = return_to
        return portal.AuthorizationRequest(
            "https://issuer.example.test/authorize?state=one", "one", CHAIN_ID
        )

    def callback(self, callback_url, *, state):
        self._called("callback")
        if state == "one":
            return portal.CallbackResult(
                portal.AuthorizationRequest(
                    "https://issuer.example.test/authorize?state=two", "two", CHAIN_ID
                ),
                None,
                None,
            )
        if state == "two":
            return portal.CallbackResult(None, self.session_id, self.return_to)
        raise portal.AdmissionError()

    def _callback_for_chain(self, callback_url, *, state, chain_id):
        self._called("callback_for_chain")
        if chain_id != CHAIN_ID:
            raise portal.AdmissionError()
        return self.callback(callback_url, state=state)

    def cancel(self, chain_id):
        self._called("cancel")
        self.cancel_calls.append(chain_id)

    def context(self, session_id, *, minimum_valid_seconds=30):
        self._called("context")
        if session_id != self.session_id:
            raise portal.ReauthenticationRequired()
        return portal.PortalContext(
            session_id,
            "person-1",
            "principal-1",
            self.persona,
            {
                "breg": "breg-bearer-canary",
                "casework": "casework-bearer-canary",
            },
            "csrf-canary",
            2_000,
        )

    def authorize_mutation(self, session_id, *, origin, csrf_token):
        self._called("authorize_mutation")
        if session_id != self.session_id:
            raise portal.ReauthenticationRequired()
        if origin != "https://portal.example.test" or csrf_token != "csrf-canary":
            raise portal.CSRFError()
        return self.context(session_id)

    def logout(self, session_id, *, switch=False):
        self._called("logout")
        if session_id != self.session_id:
            return portal.LogoutResult(None, False)
        self.session_id = "closed"
        if self.issuer_logout:
            return portal.LogoutResult("https://issuer.example.test/logout", True)
        return portal.LogoutResult(None, False)


def application(sessions, *, persona="holder", same_site="Lax"):
    module = importlib.import_module(f"{PACKAGE}.portal_fastapi")
    app = FastAPI()
    factory_threads = []

    @app.get("/private")
    def private(request: Request):
        return {"subject": request.state.registry_person.subject}

    @app.post("/effect")
    def effect(request: Request):
        return {"subject": request.state.registry_person.subject}

    @app.get("/public")
    @web.public
    def public():
        return {"status": "open"}

    def person_factory(context):
        factory_threads.append(threading.get_ident())
        return context

    module.install(
        app,
        sessions,
        origin="https://portal.example.test",
        persona=persona,
        person_factory=person_factory,
        request_seconds=5,
        same_site=same_site,
    )
    return app, factory_threads


class FastAPIPortalTests(unittest.TestCase):
    def test_complete_grants_precede_host_only_cookie_and_protected_dispatch(self):
        sessions = Sessions()
        app, factory_threads = application(sessions)

        async def check():
            event_loop_thread = threading.get_ident()
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="https://portal.example.test",
                follow_redirects=False,
            ) as client:
                refused = await client.get("/private")
                self.assertEqual(refused.status_code, 401)
                self.assertEqual(
                    refused.json(), {"code": "authentication.reauthenticate"}
                )
                self.assertEqual(refused.headers["cache-control"], "no-store")
                self.assertEqual(
                    (await client.get("/public")).json(), {"status": "open"}
                )

                login = await client.get("/auth/login?return_to=/private")
                self.assertEqual(login.status_code, 302)
                self.assertIn("/authorize?state=one", login.headers["location"])
                self.assertEqual(login.headers["cache-control"], "no-store")

                partial = await client.get("/auth/callback?code=a&state=one")
                self.assertEqual(partial.status_code, 302)
                self.assertIn("/authorize?state=two", partial.headers["location"])
                self.assertNotIn("set-cookie", partial.headers)

                complete = await client.get("/auth/callback?code=b&state=two")
                self.assertEqual(complete.status_code, 302)
                self.assertEqual(complete.headers["location"], "/private")
                cookie = complete.headers["set-cookie"]
                self.assertIn("__Host-registry-holder=session-secret-canary", cookie)
                for attribute in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"):
                    self.assertIn(attribute, cookie)
                self.assertNotIn("Domain=", cookie)
                self.assertNotIn("breg-bearer-canary", cookie)
                self.assertNotIn("casework-bearer-canary", cookie)

                self.assertEqual(
                    (await client.get("/private")).json(), {"subject": "person-1"}
                )
                self.assertEqual((await client.post("/effect")).status_code, 403)
                headers = {
                    "Origin": "https://portal.example.test",
                    "X-CSRF-Token": "csrf-canary",
                }
                self.assertEqual(
                    (await client.post("/effect", headers=headers)).json(),
                    {"subject": "person-1"},
                )

            self.assertTrue(sessions.calls)
            self.assertTrue(factory_threads)
            self.assertTrue(
                all(thread != event_loop_thread for _, thread in sessions.calls)
            )
            self.assertTrue(
                all(thread != event_loop_thread for thread in factory_threads)
            )

        asyncio.run(check())

    def test_host_origin_persona_and_callback_refusals_never_dispatch(self):
        sessions = Sessions(persona="staff")
        app, factory_threads = application(sessions, persona="holder")

        async def check():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="https://portal.example.test"
            ) as client:
                wrong_host = await client.get(
                    "/auth/login", headers={"Host": "wrong.example.test"}
                )
                self.assertEqual(wrong_host.status_code, 400)
                self.assertEqual(
                    wrong_host.json(), {"code": "authentication.origin-refused"}
                )
                self.assertFalse(any(call == "start" for call, _ in sessions.calls))

                bad_callback = await client.get("/auth/callback?code=a&state=replayed")
                self.assertEqual(bad_callback.status_code, 401)
                self.assertNotIn("set-cookie", bad_callback.headers)

                await client.get("/auth/login")
                await client.get("/auth/callback?code=a&state=one")
                await client.get("/auth/callback?code=b&state=two")
                protected = await client.get("/private")
                self.assertEqual(protected.status_code, 401)
                self.assertFalse(factory_threads)

                mutation = await client.post(
                    "/effect",
                    headers={
                        "Origin": "https://other.example.test",
                        "X-CSRF-Token": "csrf-canary",
                    },
                )
                self.assertEqual(mutation.status_code, 403)

        asyncio.run(check())

    def test_logout_is_local_first_and_switch_requires_issuer_end_session(self):
        async def signed_in_client(sessions):
            app, _ = application(sessions)
            transport = httpx.ASGITransport(app=app)
            client = httpx.AsyncClient(
                transport=transport, base_url="https://portal.example.test"
            )
            await client.get("/auth/login")
            await client.get("/auth/callback?code=a&state=one")
            await client.get("/auth/callback?code=b&state=two")
            return client

        async def check():
            headers = {
                "Origin": "https://portal.example.test",
                "X-CSRF-Token": "csrf-canary",
            }
            sessions = Sessions(issuer_logout=False)
            client = await signed_in_client(sessions)
            try:
                logout = await client.post("/auth/logout", headers=headers)
                self.assertEqual(logout.status_code, 302)
                self.assertEqual(logout.headers["location"], "/")
                self.assertIn("Max-Age=0", logout.headers["set-cookie"])
                self.assertEqual((await client.get("/private")).status_code, 401)
            finally:
                await client.aclose()

            sessions = Sessions(issuer_logout=False)
            client = await signed_in_client(sessions)
            try:
                switch = await client.post("/auth/switch", headers=headers)
                self.assertEqual(switch.status_code, 409)
                self.assertEqual(
                    switch.json(),
                    {"code": "authentication.account-switch-unavailable"},
                )
                self.assertIn("Max-Age=0", switch.headers["set-cookie"])
                self.assertEqual((await client.get("/private")).status_code, 401)
            finally:
                await client.aclose()

            sessions = Sessions(issuer_logout=True)
            client = await signed_in_client(sessions)
            try:
                switch = await client.post("/auth/switch", headers=headers)
                self.assertEqual(switch.status_code, 302)
                self.assertEqual(
                    switch.headers["location"],
                    "https://issuer.example.test/logout",
                )
                self.assertEqual((await client.get("/private")).status_code, 401)
            finally:
                await client.aclose()

        asyncio.run(check())

    def test_install_rejects_unsupported_persona_or_cookie_policy(self):
        module = importlib.import_module(f"{PACKAGE}.portal_fastapi")
        for persona, same_site in (("machine", "Lax"), ("holder", "None")):
            with self.subTest(persona=persona, same_site=same_site):
                with self.assertRaises(ValueError):
                    module.install(
                        FastAPI(),
                        Sessions(),
                        origin="https://portal.example.test",
                        persona=persona,
                        person_factory=lambda context: context,
                        request_seconds=5,
                        same_site=same_site,
                    )


if __name__ == "__main__":
    unittest.main()
