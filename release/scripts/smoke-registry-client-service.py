#!/usr/bin/env python3
"""Exercise service authority APIs from an installed unified Python wheel."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import registry_client
from registry_client import fastapi_adapter, flask_adapter, portal_fastapi, portal_flask
from registry_client.machine import MachineAdmission
from registry_client.oidc import AccessTokenVerifier, TokenVerificationError
from registry_client.portal import GrantPolicy, PortalContext
from registry_client.portal_postgres import PortalEncryptionKeys
from registry_client.portal_products import bind_person


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class MachineToken:
    kind: str = "access"
    issuer: str = "https://issuer.example.invalid/"
    audiences: tuple[str, ...] = ("urn:example:machine",)
    client_id: str = "coordinator-client"
    subject: str = "coordinator-service"
    scopes: tuple[str, ...] = ("service:invoke",)
    claims: dict[str, str] | None = None


class MachineVerifier:
    def verify(self, token: str) -> MachineToken:
        if token != "synthetic-token":
            raise ValueError("invalid synthetic token")
        return MachineToken(claims={"registry_actor_kind": "machine"})


def main() -> None:
    if not callable(registry_client.connect):
        raise AssertionError("the installed connection entry point is missing")
    for adapter in (fastapi_adapter, flask_adapter, portal_fastapi, portal_flask):
        if not callable(adapter.install):
            raise AssertionError("the installed framework adapter is missing")
    package = Path(registry_client.__file__).resolve()
    if "site-packages" not in package.parts:
        raise AssertionError("the service smoke must import the installed wheel")

    connection_document = {
        "apiVersion": "id.registrystack.org/formats/platform/python-connection/v1alpha1",
        "kind": "PlatformPythonConnection",
        "service": "installed-wheel-smoke",
        "audience": "service",
        "secretProviders": {"environment": {}},
        "bindings": [
            {
                "name": "notices",
                "product": "messaging",
                "url": "https://messaging.example.invalid/",
                "default": True,
                "credential": {
                    "type": "private-key-jwt",
                    "issuer": "https://issuer.example.invalid/",
                    "subject": "notice-service",
                    "tokenEndpoint": "https://issuer.example.invalid/token",
                    "clientId": "notice-client",
                    "profile": "service-sender",
                    "clientKeyRef": "secret:env/REGISTRY_CLIENT_SMOKE_KEY",
                    "resource": "urn:registry:messaging:test",
                    "scopes": ["messaging:send"],
                    "claims": {"registry_actor_kind": "service"},
                },
            }
        ],
    }
    with tempfile.TemporaryDirectory() as temporary:
        connection_path = Path(temporary) / "connection.json"
        connection_path.write_text(json.dumps(connection_document), encoding="utf-8")
        stack = registry_client.connect(path=connection_path)
    authority = stack.authority("messaging")
    expected_authority = (
        "messaging",
        "https://issuer.example.invalid/",
        "notice-service",
        "notice-client",
        "service-sender",
        "urn:registry:messaging:test",
        ("messaging:send",),
        {"registry_actor_kind": "service"},
    )
    actual_authority = (
        authority.product,
        authority.issuer,
        authority.subject,
        authority.client_id,
        authority.profile,
        authority.resource,
        authority.scopes,
        dict(authority.claims),
    )
    if actual_authority != expected_authority:
        raise AssertionError("the installed connection lost declared authority fields")
    if authority.fingerprint != (
        "2695c2353eb6efea60f324d2f432f0cd747bfee5ff5fa84fb5f6b54fc475df35"
    ):
        raise AssertionError(
            "the installed connection changed its authority fingerprint"
        )

    admission = MachineAdmission(
        MachineVerifier(),
        issuer="https://issuer.example.invalid/",
        resource="urn:example:machine",
        client_id="coordinator-client",
        profile="invoker",
        required_scopes=("service:invoke",),
        required_claims={"registry_actor_kind": "machine"},
    )
    caller = admission.admit({"authorization": "Bearer synthetic-token"})
    if (caller.issuer, caller.resource) != (
        "https://issuer.example.invalid/",
        "urn:example:machine",
    ):
        raise AssertionError("machine authority lost its issuer or resource")

    context = PortalContext(
        "session",
        "person",
        "person",
        "holder",
        {"breg": "breg-canary", "casework": "casework-canary"},
        "csrf",
        time.time() + 300,
    )
    products = bind_person(
        context,
        persona="holder",
        breg_url="https://breg.example.invalid/",
        casework_url="https://casework.example.invalid/",
        casework_profile="applicant",
    )
    if hasattr(products.casework, "review_tasks") or not callable(
        products.casework.review_history
    ):
        raise AssertionError("the installed holder Casework surface is too broad")
    PortalEncryptionKeys(primary_key_id="test", keys={"test": b"s" * 32})

    casework = "urn:example:casework"
    breg = "urn:example:breg"
    grant = GrantPolicy(
        "casework",
        casework,
        ("casework:review", "breg:read"),
        "reviewer",
        {"registry_actor_kind": "human"},
        forward_resource=breg,
    )
    if grant.requested_resources != (casework, breg):
        raise AssertionError("the installed portal lost its forwarded resource")

    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwks = json.dumps(
        {
            "keys": [
                {"kty": "OKP", "crv": "Ed25519", "kid": "test", "x": encoded(public)}
            ]
        }
    )
    verifier = AccessTokenVerifier.from_static_jwks(
        jwks,
        "https://issuer.example.invalid/",
        casework,
        "portal-client",
        algorithm="EdDSA",
        maximum_access_token_lifetime_seconds=600,
        clock_skew_seconds=0,
        additional_audiences=(breg,),
    )

    def token(audiences: list[str]) -> str:
        now = int(time.time())
        header = encoded(
            json.dumps({"alg": "EdDSA", "kid": "test", "typ": "at+jwt"}).encode()
        )
        claims = encoded(
            json.dumps(
                {
                    "iss": "https://issuer.example.invalid/",
                    "aud": audiences,
                    "sub": "person",
                    "azp": "portal-client",
                    "iat": now,
                    "nbf": now - 1,
                    "exp": now + 300,
                    "scope": "casework:review breg:read",
                }
            ).encode()
        )
        value = f"{header}.{claims}"
        return f"{value}.{encoded(key.sign(value.encode('ascii')))}"

    if set(verifier.verify(token([casework, breg])).audiences) != {casework, breg}:
        raise AssertionError("the installed native verifier lost the bridge audience")
    try:
        verifier.verify(token([casework]))
    except TokenVerificationError:
        pass
    else:
        raise AssertionError(
            "the installed native verifier accepted a partial audience"
        )
    print("Installed Python service client smoke passed")


if __name__ == "__main__":
    main()
