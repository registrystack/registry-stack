"""Both optional web adapters enforce the same machine admission boundary."""

import asyncio
from pathlib import Path
import importlib
import sys
import types
import unittest

from flask import Flask, g
from fastapi import FastAPI, Request
import httpx


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_framework_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
machine = importlib.import_module(f"{PACKAGE}.machine")
flask_adapter = importlib.import_module(f"{PACKAGE}.flask_adapter")
fastapi_adapter = importlib.import_module(f"{PACKAGE}.fastapi_adapter")
web = importlib.import_module(f"{PACKAGE}.web")
workload = importlib.import_module(f"{PACKAGE}.workload")


class Stack:
    def __init__(self):
        self.calls = []

    def admit(self, values):
        self.calls.append(values)
        if values.get("authorization") == ["Bearer outage"]:
            raise machine.AdmissionUnavailable()
        if values.get("authorization") != ["Bearer admitted"]:
            raise machine.AdmissionError()
        return machine.MachineContext("caller", "coordinator-client", "invoker", "https://issuer.example.invalid/", "urn:registry:python:test")


class FrameworkAdapterTests(unittest.TestCase):
    def test_flask_protects_by_default_and_public_route_is_explicit(self):
        app = Flask(__name__)
        stack = Stack()

        @app.get("/private")
        def private():
            return g.registry_context.client_id

        @app.get("/public")
        @web.public
        def public():
            return "open"

        flask_adapter.install(app, stack, request_seconds=1)
        client = app.test_client()
        self.assertEqual(client.get("/private").status_code, 401)
        self.assertEqual(
            client.get("/private", headers={"Cookie": "session=canary"}).status_code,
            401,
        )
        admitted = client.get("/private", headers={"Authorization": "Bearer admitted"})
        self.assertEqual(admitted.status_code, 200)
        self.assertEqual(admitted.text, "coordinator-client")
        self.assertEqual(client.get("/public").text, "open")
        unavailable = client.get("/private", headers={"Authorization": "Bearer outage"})
        self.assertEqual(unavailable.status_code, 503)
        self.assertEqual(unavailable.json, {"code": "authentication.unavailable"})
        self.assertEqual(len(stack.calls), 4)

    def test_fastapi_protects_by_default_and_public_route_is_explicit(self):
        app = FastAPI()
        stack = Stack()

        @app.get("/private")
        def private(request: Request):
            return {"client": request.state.registry_context.client_id}

        @app.get("/public")
        @web.public
        def public():
            return {"status": "open"}

        fastapi_adapter.install(app, stack, request_seconds=1)

        async def check():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                self.assertEqual((await client.get("/private")).status_code, 401)
                client.cookies.set("session", "canary")
                self.assertEqual((await client.get("/private")).status_code, 401)
                client.cookies.clear()
                admitted = await client.get(
                    "/private", headers={"Authorization": "Bearer admitted"}
                )
                self.assertEqual(admitted.status_code, 200)
                self.assertEqual(admitted.json(), {"client": "coordinator-client"})
                self.assertEqual(
                    (await client.get("/public")).json(), {"status": "open"}
                )
                unavailable = await client.get(
                    "/private", headers={"Authorization": "Bearer outage"}
                )
                self.assertEqual(unavailable.status_code, 503)
                self.assertEqual(
                    unavailable.json(), {"code": "authentication.unavailable"}
                )

        asyncio.run(check())
        self.assertEqual(len(stack.calls), 4)

    def test_fastapi_sync_and_explicit_offload_are_supported(self):
        app = FastAPI()
        stack = Stack()

        @app.get("/sync")
        def sync_handler():
            workload._require_sync()
            return {"status": "sync"}

        @app.get("/async")
        async def async_handler():
            try:
                workload._require_sync()
            except RuntimeError:
                return {"status": "guarded"}
            return {"status": "unguarded"}

        @app.get("/offload")
        async def offloaded_handler():
            await asyncio.to_thread(workload._require_sync)
            return {"status": "offloaded"}

        fastapi_adapter.install(app, stack, request_seconds=1)

        async def check():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                headers = {"Authorization": "Bearer admitted"}
                self.assertEqual(
                    (await client.get("/sync", headers=headers)).json(),
                    {"status": "sync"},
                )
                self.assertEqual(
                    (await client.get("/async", headers=headers)).json(),
                    {"status": "guarded"},
                )
                self.assertEqual(
                    (await client.get("/offload", headers=headers)).json(),
                    {"status": "offloaded"},
                )

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
