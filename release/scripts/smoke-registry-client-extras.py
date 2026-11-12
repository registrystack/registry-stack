#!/usr/bin/env python3
"""Check isolated optional service installs of an assembled client wheel."""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
from pathlib import Path

import registry_client
from registry_client.machine import MachineContext


def present(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def check_dependencies(mode: str) -> None:
    expected = {
        "flask": mode in ("flask", "human-flask"),
        "fastapi": mode in ("fastapi", "human-fastapi"),
        "authlib": mode.startswith("human-"),
        "psycopg": mode.startswith("human-"),
        "cryptography": mode.startswith("human-"),
    }
    for package, required in expected.items():
        if present(package) != required:
            raise AssertionError(f"{mode} has the wrong {package} dependency boundary")
    if not callable(registry_client.connect):
        raise AssertionError("the installed core API is missing")
    if "site-packages" not in Path(registry_client.__file__).resolve().parts:
        raise AssertionError("the smoke must import an installed wheel")


class Stack:
    def admit(self, values):
        if values.get("authorization") != ["Bearer synthetic-machine"]:
            from registry_client.machine import AdmissionError

            raise AdmissionError()
        return MachineContext(
            "caller",
            "client",
            "invoker",
            "https://issuer.example.invalid/",
            "urn:example:service",
        )


def flask_request() -> None:
    from flask import Flask, g, jsonify
    from registry_client.flask_adapter import install

    app = Flask(__name__)

    @app.get("/work")
    def work():
        return jsonify({"subject": g.registry_context.subject})

    install(app, Stack(), request_seconds=5)
    client = app.test_client()
    if client.get("/work").status_code != 401:
        raise AssertionError("Flask allowed a missing bearer")
    response = client.get(
        "/work", headers={"Authorization": "Bearer synthetic-machine"}
    )
    if response.status_code != 200 or response.json != {"subject": "caller"}:
        raise AssertionError("Flask did not admit the installed machine client")


def fastapi_request() -> None:
    import httpx
    from fastapi import FastAPI, Request
    from registry_client.fastapi_adapter import install

    app = FastAPI()

    def work(request: Request):
        return {"subject": request.state.registry_context.subject}

    # Request is imported inside this optional-dependency check, so give FastAPI
    # the concrete annotation before route registration.
    work.__annotations__["request"] = Request
    app.get("/work")(work)
    install(app, Stack(), request_seconds=5)

    async def check() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="https://service.example.invalid"
        ) as client:
            if (await client.get("/work")).status_code != 401:
                raise AssertionError("FastAPI allowed a missing bearer")
            response = await client.get(
                "/work", headers={"Authorization": "Bearer synthetic-machine"}
            )
        if response.status_code != 200 or response.json() != {"subject": "caller"}:
            raise AssertionError("FastAPI did not admit the installed machine client")

    asyncio.run(check())


def human_import(framework: str) -> None:
    from registry_client.portal import AuthlibOIDCClient, GrantPolicy
    from registry_client.portal_postgres import (
        PortalEncryptionKeys,
        PostgresSessionStore,
    )

    if not callable(AuthlibOIDCClient) or not callable(PostgresSessionStore):
        raise AssertionError("the human session modules are unavailable")
    PortalEncryptionKeys(primary_key_id="test", keys={"test": b"s" * 32})
    policy = GrantPolicy(
        "casework",
        "urn:example:casework",
        ("casework:review", "breg:read"),
        "reviewer",
        {"registry_actor_kind": "human"},
        forward_resource="urn:example:breg",
    )
    if policy.requested_resources != ("urn:example:casework", "urn:example:breg"):
        raise AssertionError("the human bridge policy is missing")
    if framework == "flask":
        from registry_client.portal_flask import install
    else:
        from registry_client.portal_fastapi import install
    if not callable(install):
        raise AssertionError("the human framework adapter is unavailable")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("core", "flask", "fastapi", "human-flask", "human-fastapi")
    )
    mode = parser.parse_args().mode
    check_dependencies(mode)
    if mode == "flask":
        flask_request()
    elif mode == "fastapi":
        fastapi_request()
    elif mode.startswith("human-"):
        human_import(mode.removeprefix("human-"))
    print(f"Installed Python client {mode} boundary passed")


if __name__ == "__main__":
    main()
