"""Python contract tests for the bounded native OIDC verifier."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import tempfile
import time
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_platform_oidc import (  # noqa: E402
    AccessTokenVerifier,
    TokenVerificationError,
)

ISSUER = "https://issuer.example"
RESOURCE = "urn:registry:service"
CLIENT = "service-client"
KID = "registry-platform-testing-ed25519-1"
PUBLIC_X = "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc"
PRIVATE_D = "2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(typ: str, claims: dict[str, object]) -> str:
    header = {"alg": "EdDSA", "kid": KID, "typ": typ}
    parts = [
        _base64url(json.dumps(value, separators=(",", ":")).encode("utf-8"))
        for value in (header, claims)
    ]
    signing_input = ".".join(parts).encode("ascii")
    pkcs8 = bytes.fromhex("302e020100300506032b657004220420") + _decode_base64url(
        PRIVATE_D
    )
    with tempfile.TemporaryDirectory() as directory:
        key_path = pathlib.Path(directory) / "signing-key.der"
        input_path = pathlib.Path(directory) / "signing-input"
        key_path.write_bytes(pkcs8)
        input_path.write_bytes(signing_input)
        os.chmod(key_path, 0o600)
        os.chmod(input_path, 0o600)
        signed = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key_path),
                "-keyform",
                "DER",
                "-in",
                str(input_path),
            ],
            capture_output=True,
            check=True,
        ).stdout
    return f"{parts[0]}.{parts[1]}.{_base64url(signed)}"


def _claims(audience: str | list[str]) -> dict[str, object]:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "aud": audience,
        "sub": "subject-1",
        "azp": CLIENT,
        "exp": now + 300,
        "iat": now,
        "nbf": now - 1,
        "scope": "command:submit job:read",
        "registry_principal": "principal-1",
        "actor_kind": "service",
        "unselected": "must-not-cross-the-binding",
    }


def _verifier() -> AccessTokenVerifier:
    jwks = json.dumps(
        {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": KID, "x": PUBLIC_X}]}
    )
    return AccessTokenVerifier.from_static_jwks(
        jwks,
        ISSUER,
        RESOURCE,
        CLIENT,
        algorithm="EdDSA",
        maximum_access_token_lifetime_seconds=600,
        clock_skew_seconds=0,
        claim_names=("registry_principal", "actor_kind"),
    )


class VerifierTests(unittest.TestCase):
    def test_access_token_returns_only_bounded_selected_claims(self) -> None:
        token = _sign("at+jwt", _claims(RESOURCE))
        verified = _verifier().verify(token)
        self.assertEqual(verified.kind, "access")
        self.assertEqual(verified.issuer, ISSUER)
        self.assertEqual(verified.audiences, (RESOURCE,))
        self.assertEqual(verified.subject, "subject-1")
        self.assertEqual(verified.client_id, CLIENT)
        self.assertEqual(verified.scopes, ("command:submit", "job:read"))
        self.assertEqual(
            dict(verified.claims),
            {"actor_kind": "service", "registry_principal": "principal-1"},
        )

    def test_conflicting_client_claims_and_extra_audience_fail_closed(self) -> None:
        conflict = _claims(RESOURCE)
        conflict["client_id"] = "other-client"
        for token in (
            _sign("at+jwt", conflict),
            _sign("at+jwt", _claims([RESOURCE, "urn:registry:other"])),
        ):
            with self.subTest(token_shape=token.count(".")):
                with self.assertRaises(TokenVerificationError) as raised:
                    _verifier().verify(token)
                self.assertEqual(raised.exception.kind, "verification")
                self.assertEqual(str(raised.exception), "Token verification failed")
                self.assertNotIn(token, repr(raised.exception))

    def test_configured_forward_audience_requires_exact_audience_set(self) -> None:
        jwks = json.dumps(
            {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": KID, "x": PUBLIC_X}]}
        )
        verifier = AccessTokenVerifier.from_static_jwks(
            jwks,
            ISSUER,
            RESOURCE,
            CLIENT,
            algorithm="EdDSA",
            maximum_access_token_lifetime_seconds=600,
            clock_skew_seconds=0,
            additional_audiences=("urn:registry:breg",),
        )
        self.assertEqual(
            verifier.verify(
                _sign("at+jwt", _claims([RESOURCE, "urn:registry:breg"]))
            ).audiences,
            (RESOURCE, "urn:registry:breg"),
        )
        self.assertEqual(
            verifier.verify(
                _sign("at+jwt", _claims(["urn:registry:breg", RESOURCE]))
            ).audiences,
            ("urn:registry:breg", RESOURCE),
        )
        for audiences in (
            RESOURCE,
            [RESOURCE, "urn:registry:other"],
            [RESOURCE, "urn:registry:breg", "urn:registry:other"],
        ):
            with (
                self.subTest(audiences=audiences),
                self.assertRaises(TokenVerificationError),
            ):
                verifier.verify(_sign("at+jwt", _claims(audiences)))

    def test_related_id_token_requires_expected_nonce(self) -> None:
        claims = _claims(CLIENT)
        claims.pop("scope")
        claims.pop("azp")
        claims["nonce"] = "pending-nonce"
        token = _sign("JWT", claims)
        verified = _verifier().verify_id_token(token, "pending-nonce")
        self.assertEqual(verified.kind, "id")
        self.assertEqual(verified.audiences, (CLIENT,))
        with self.assertRaises(TokenVerificationError) as raised:
            _verifier().verify_id_token(token, "different-nonce")
        self.assertEqual(raised.exception.kind, "verification")

    def test_configuration_rejects_symmetric_algorithms_without_values(self) -> None:
        with self.assertRaises(TokenVerificationError) as raised:
            AccessTokenVerifier.from_static_jwks(
                '{"keys":[]}',
                ISSUER,
                RESOURCE,
                CLIENT,
                algorithm="HS256",  # type: ignore[arg-type]
                maximum_access_token_lifetime_seconds=600,
            )
        self.assertEqual(raised.exception.kind, "configuration")
        self.assertEqual(
            str(raised.exception), "Token verifier configuration is invalid"
        )


if __name__ == "__main__":
    unittest.main()
