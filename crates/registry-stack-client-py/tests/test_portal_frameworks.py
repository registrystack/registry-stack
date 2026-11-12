"""Flask and FastAPI keep person authority in server-side sessions."""

import asyncio
import importlib
from pathlib import Path
import sys
import types
import unittest

from flask import Flask, g
from fastapi import FastAPI, Request
import httpx


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_portal_frameworks_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
portal = importlib.import_module(f"{PACKAGE}.portal")
CHAIN_ID = "c" * 43
CHAIN_A = "a" * 43
CHAIN_B = "b" * 43


class Sessions:
    def __init__(self):
        self.session_id = "session-secret-canary"
        self.context_calls = []
        self.logout_calls = []
        self.cancel_calls = []
        self.events = []

    def start(self, return_to="/"):
        self.return_to = return_to
        return portal.AuthorizationRequest(
            "https://issuer.example.test/authorize?state=one", "one", CHAIN_ID
        )

    def callback(self, callback_url, *, state):
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
        self.events.append(("callback", chain_id))
        if chain_id != CHAIN_ID:
            raise portal.AdmissionError()
        return self.callback(callback_url, state=state)

    def cancel(self, chain_id):
        self.events.append(("cancel", chain_id))
        self.cancel_calls.append(chain_id)

    def context(self, session_id, *, minimum_valid_seconds=30):
        self.context_calls.append(session_id)
        if session_id != self.session_id:
            raise portal.ReauthenticationRequired()
        return portal.PortalContext(
            session_id,
            "person-1",
            "principal-1",
            "holder",
            {"breg": "breg-bearer-canary", "casework": "casework-bearer-canary"},
            "csrf-canary",
            2000,
        )

    def authorize_mutation(self, session_id, *, origin, csrf_token):
        context = self.context(session_id)
        if origin != "https://portal.example.test" or csrf_token != "csrf-canary":
            raise portal.CSRFError()
        return context

    def logout(self, session_id, *, switch=False):
        self.events.append(("logout", session_id))
        self.logout_calls.append(session_id)
        self.session_id = "closed"
        return portal.LogoutResult("https://issuer.example.test/logout", True)


class ReplacementSessions(Sessions):
    def __init__(self):
        super().__init__()
        self.start_count = 0

    def start(self, return_to="/"):
        self.return_to = return_to
        self.start_count += 1
        if self.start_count == 1:
            return portal.AuthorizationRequest(
                "https://issuer.example.test/authorize?state=state-a",
                "state-a",
                CHAIN_A,
            )
        return portal.AuthorizationRequest(
            "https://issuer.example.test/authorize?state=state-b",
            "state-b",
            CHAIN_B,
        )

    def _callback_for_chain(self, callback_url, *, state, chain_id):
        self.events.append(("callback", chain_id))
        expected = {"state-a": CHAIN_A, "state-b": CHAIN_B}.get(state)
        if expected != chain_id:
            raise portal._PendingChainMismatch()
        return portal.CallbackResult(None, self.session_id, self.return_to)


class PortalFrameworkTests(unittest.TestCase):
    def test_form_csrf_parser_rejects_duplicate_or_unbounded_fields(self):
        web = importlib.import_module(f"{PACKAGE}.web")
        valid = b"csrf_token=csrf-canary&value=yes"
        self.assertEqual(
            web.form_csrf_token(
                content_type="application/x-www-form-urlencoded",
                content_length=len(valid),
                body=valid,
            ),
            "csrf-canary",
        )
        for body in (
            b"csrf_token=one&csrf_token=two",
            b"csrf_token=%FF",
            b"csrf_token=one&broken",
            b"csrf_token=one&" + b"x=1&" * 65,
        ):
            with self.subTest(body=body[:30]):
                self.assertEqual(
                    web.form_csrf_token(
                        content_type="application/x-www-form-urlencoded",
                        content_length=len(body),
                        body=body,
                    ),
                    "",
                )
        self.assertEqual(
            web.form_csrf_token(
                content_type="application/json",
                content_length=len(valid),
                body=valid,
            ),
            "",
        )
        self.assertEqual(
            web.form_csrf_token(
                content_type="application/x-www-form-urlencoded",
                content_length=65_537,
                body=b"x" * 65_537,
            ),
            "",
        )

    def test_flask_complete_callback_cookie_csrf_and_logout(self):
        module = importlib.import_module(f"{PACKAGE}.portal_flask")
        app = Flask(__name__)
        sessions = Sessions()

        @app.get("/private")
        def private():
            return g.registry_person.subject

        @app.post("/effect")
        def effect():
            return g.registry_person.subject

        module.install(
            app,
            sessions,
            origin="https://portal.example.test",
            persona="holder",
            person_factory=lambda context: context,
            request_seconds=5,
        )
        client = app.test_client()
        base = "https://portal.example.test"
        self.assertEqual(client.get("/private", base_url=base).status_code, 401)
        login = client.get("/auth/login?return_to=/private", base_url=base)
        self.assertEqual(login.status_code, 302)
        self.assertIn("/authorize?state=one", login.location)
        self.assertIn(
            f"__Host-registry-holder-pending={CHAIN_ID}",
            login.headers["Set-Cookie"],
        )
        partial = client.get("/auth/callback?code=a&state=one", base_url=base)
        self.assertEqual(partial.status_code, 302)
        self.assertNotIn("Set-Cookie", partial.headers)
        complete = client.get("/auth/callback?code=b&state=two", base_url=base)
        self.assertEqual(complete.status_code, 302)
        cookies = complete.headers.getlist("Set-Cookie")
        cookie = "\n".join(cookies)
        self.assertIn("__Host-registry-holder=session-secret-canary", cookie)
        self.assertTrue(
            any(
                "__Host-registry-holder-pending=" in value and "Expires=" in value
                for value in cookies
            )
        )
        for attribute in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
            self.assertIn(attribute, cookie)
        self.assertNotIn("breg-bearer-canary", cookie)
        self.assertEqual(client.get("/private", base_url=base).text, "person-1")
        self.assertEqual(client.post("/effect", base_url=base).status_code, 403)
        headers = {"Origin": base, "X-CSRF-Token": "csrf-canary"}
        self.assertEqual(
            client.post("/effect", base_url=base, headers=headers).status_code, 200
        )
        replacement_login = client.get("/auth/login", base_url=base)
        self.assertEqual(replacement_login.status_code, 302)
        logout = client.post("/auth/logout", base_url=base, headers=headers)
        self.assertEqual(logout.status_code, 302)
        self.assertIn("/logout", logout.location)
        self.assertEqual(sessions.cancel_calls, [CHAIN_ID])
        self.assertLess(
            sessions.events.index(("cancel", CHAIN_ID)),
            sessions.events.index(("logout", "session-secret-canary")),
        )
        callback_events = sessions.events.count(("callback", CHAIN_ID))
        late = client.get("/auth/callback?code=late&state=one", base_url=base)
        self.assertEqual(late.status_code, 401)
        self.assertEqual(sessions.events.count(("callback", CHAIN_ID)), callback_events)
        self.assertEqual(client.get("/private", base_url=base).status_code, 401)
        self.assertEqual(
            client.get(
                "/auth/login", base_url="https://wrong.example.test"
            ).status_code,
            400,
        )

    def test_fastapi_complete_callback_cookie_csrf_and_logout(self):
        module = importlib.import_module(f"{PACKAGE}.portal_fastapi")
        app = FastAPI()
        sessions = Sessions()

        @app.get("/private")
        def private(request: Request):
            return {"subject": request.state.registry_person.subject}

        @app.post("/effect")
        def effect(request: Request):
            return {"subject": request.state.registry_person.subject}

        module.install(
            app,
            sessions,
            origin="https://portal.example.test",
            persona="holder",
            person_factory=lambda context: context,
            request_seconds=5,
        )

        async def check():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="https://portal.example.test"
            ) as client:
                self.assertEqual((await client.get("/private")).status_code, 401)
                self.assertEqual(
                    (await client.get("/auth/login?return_to=/private")).status_code,
                    302,
                )
                self.assertEqual(
                    client.cookies.get("__Host-registry-holder-pending"), CHAIN_ID
                )
                partial = await client.get("/auth/callback?code=a&state=one")
                self.assertNotIn("set-cookie", partial.headers)
                complete = await client.get("/auth/callback?code=b&state=two")
                self.assertEqual(complete.status_code, 302)
                cookie = complete.headers["set-cookie"]
                self.assertIn("__Host-registry-holder=session-secret-canary", cookie)
                self.assertIn("Secure", cookie)
                self.assertIn("HttpOnly", cookie)
                self.assertNotIn("casework-bearer-canary", cookie)
                self.assertIsNone(client.cookies.get("__Host-registry-holder-pending"))
                self.assertEqual(
                    (await client.get("/private")).json(), {"subject": "person-1"}
                )
                self.assertEqual((await client.post("/effect")).status_code, 403)
                headers = {
                    "Origin": "https://portal.example.test",
                    "X-CSRF-Token": "csrf-canary",
                }
                self.assertEqual(
                    (await client.post("/effect", headers=headers)).status_code, 200
                )
                self.assertEqual((await client.get("/auth/login")).status_code, 302)
                logout = await client.post("/auth/logout", headers=headers)
                self.assertEqual(logout.status_code, 302)
                self.assertEqual(sessions.cancel_calls, [CHAIN_ID])
                self.assertLess(
                    sessions.events.index(("cancel", CHAIN_ID)),
                    sessions.events.index(("logout", "session-secret-canary")),
                )
                callback_events = sessions.events.count(("callback", CHAIN_ID))
                late = await client.get("/auth/callback?code=late&state=one")
                self.assertEqual(late.status_code, 401)
                self.assertEqual(
                    sessions.events.count(("callback", CHAIN_ID)), callback_events
                )
                self.assertEqual((await client.get("/private")).status_code, 401)
                self.assertEqual(
                    (
                        await client.get(
                            "/auth/login", headers={"Host": "wrong.example.test"}
                        )
                    ).status_code,
                    400,
                )

        asyncio.run(check())

    def test_flask_html_form_can_navigate_to_issuer_logout(self):
        module = importlib.import_module(f"{PACKAGE}.portal_flask")
        app = Flask(__name__)
        sessions = Sessions()
        module.install(
            app,
            sessions,
            origin="https://portal.example.test",
            persona="holder",
            person_factory=lambda context: context,
            request_seconds=5,
        )
        client = app.test_client()
        base = "https://portal.example.test"
        client.get("/auth/login", base_url=base)
        client.get("/auth/callback?state=one", base_url=base)
        client.get("/auth/callback?state=two", base_url=base)
        wrong = client.post(
            "/auth/switch",
            base_url=base,
            data={"csrf_token": "wrong"},
            headers={"Origin": base},
        )
        self.assertEqual(wrong.status_code, 403)
        no_origin = client.post(
            "/auth/switch",
            base_url=base,
            data={"csrf_token": "csrf-canary"},
        )
        self.assertEqual(no_origin.status_code, 403)
        self.assertEqual(client.get("/auth/login", base_url=base).status_code, 302)
        switched = client.post(
            "/auth/switch",
            base_url=base,
            data={"csrf_token": "csrf-canary"},
            headers={"Origin": base},
        )
        self.assertEqual(switched.status_code, 302)
        self.assertIn("issuer.example.test/logout", switched.location)
        self.assertIn("Max-Age=0", switched.headers["Set-Cookie"])
        self.assertEqual(sessions.cancel_calls, [CHAIN_ID])

    def test_fastapi_html_form_can_navigate_to_issuer_logout(self):
        module = importlib.import_module(f"{PACKAGE}.portal_fastapi")
        app = FastAPI()
        sessions = Sessions()

        @app.post("/form-effect")
        async def form_effect(request: Request):
            return {"body": (await request.body()).decode()}

        module.install(
            app,
            sessions,
            origin="https://portal.example.test",
            persona="holder",
            person_factory=lambda context: context,
            request_seconds=5,
        )

        async def check():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="https://portal.example.test"
            ) as client:
                await client.get("/auth/login")
                await client.get("/auth/callback?state=one")
                await client.get("/auth/callback?state=two")
                origin = {"Origin": "https://portal.example.test"}
                wrong = await client.post(
                    "/auth/switch", data={"csrf_token": "wrong"}, headers=origin
                )
                self.assertEqual(wrong.status_code, 403)
                effect = await client.post(
                    "/form-effect",
                    data={"csrf_token": "csrf-canary", "value": "yes"},
                    headers=origin,
                )
                self.assertEqual(effect.status_code, 200)
                self.assertIn("value=yes", effect.json()["body"])
                self.assertEqual((await client.get("/auth/login")).status_code, 302)
                switched = await client.post(
                    "/auth/switch", data={"csrf_token": "csrf-canary"}, headers=origin
                )
                self.assertEqual(switched.status_code, 302)
                self.assertIn(
                    "issuer.example.test/logout", switched.headers["location"]
                )
                self.assertIn("Max-Age=0", switched.headers["set-cookie"])
                self.assertEqual(sessions.cancel_calls, [CHAIN_ID])

        asyncio.run(check())

    def test_flask_rejects_untrusted_cookie_without_cancelling_or_losing_new_chain(
        self,
    ):
        module = importlib.import_module(f"{PACKAGE}.portal_flask")
        app = Flask(__name__)
        sessions = ReplacementSessions()
        module.install(
            app,
            sessions,
            origin="https://portal.example.test",
            persona="holder",
            person_factory=lambda context: context,
            request_seconds=5,
        )
        client = app.test_client()
        base = "https://portal.example.test"
        client.set_cookie(
            "__Host-registry-holder-pending",
            "attacker-controlled",
            domain="portal.example.test",
            secure=True,
        )

        self.assertEqual(client.get("/auth/login", base_url=base).status_code, 302)
        self.assertEqual(sessions.cancel_calls, [])
        self.assertEqual(client.get("/auth/login", base_url=base).status_code, 302)
        self.assertEqual(sessions.cancel_calls, [CHAIN_A])
        stale = client.get("/auth/callback?code=stale&state=state-a", base_url=base)
        self.assertEqual(stale.status_code, 401)
        self.assertEqual(sessions.cancel_calls, [CHAIN_A])
        self.assertEqual(
            client.get_cookie(
                "__Host-registry-holder-pending", domain="portal.example.test"
            ).value,
            CHAIN_B,
        )
        accepted = client.get(
            "/auth/callback?code=accepted&state=state-b", base_url=base
        )
        self.assertEqual(accepted.status_code, 302)

    def test_fastapi_rejects_untrusted_cookie_without_cancelling_or_losing_new_chain(
        self,
    ):
        module = importlib.import_module(f"{PACKAGE}.portal_fastapi")
        app = FastAPI()
        sessions = ReplacementSessions()
        module.install(
            app,
            sessions,
            origin="https://portal.example.test",
            persona="holder",
            person_factory=lambda context: context,
            request_seconds=5,
        )

        async def check():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="https://portal.example.test"
            ) as client:
                invalid = await client.get(
                    "/auth/callback?code=attacker&state=attacker",
                    headers={
                        "Cookie": ("__Host-registry-holder-pending=attacker-controlled")
                    },
                )
                self.assertEqual(invalid.status_code, 401)
                self.assertEqual(sessions.cancel_calls, [])
                self.assertEqual((await client.get("/auth/login")).status_code, 302)
                self.assertEqual(sessions.cancel_calls, [])
                self.assertEqual((await client.get("/auth/login")).status_code, 302)
                self.assertEqual(sessions.cancel_calls, [CHAIN_A])
                stale = await client.get("/auth/callback?code=stale&state=state-a")
                self.assertEqual(stale.status_code, 401)
                self.assertEqual(sessions.cancel_calls, [CHAIN_A])
                self.assertEqual(
                    client.cookies.get("__Host-registry-holder-pending"), CHAIN_B
                )
                accepted = await client.get(
                    "/auth/callback?code=accepted&state=state-b"
                )
                self.assertEqual(accepted.status_code, 302)

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
