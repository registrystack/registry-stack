#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42", "requests>=2.31"]
# ///
"""Delegated, subject-bound access, end to end, in four requests.

An agent needs to know which region one person lives in. It must not be able to
learn that about anyone else, even if the agent's own code is wrong.

  1. The client signs a request for a token, naming the agent it is acting as
     and the person it is acting for.
  2. Mint checks that request against the client's registration and issues a
     token carrying both.
  3. The client asks Evidence for evidence, and does not name the person.
  4. The client tries to name a different person, and cannot.

Every request below is printed before it is sent. Run it with:

    crates/registry-mint/demo/run.sh
"""

import base64
import json
import secrets
import sys
from pathlib import Path

import requests
from cryptography.hazmat.primitives.asymmetric import ed25519

MINT = "https://localhost:8443"
EVIDENCE = "http://127.0.0.1:8080"

REQUIREMENT = "urn:example:demo:requirement:residence-region:v1"
PURPOSE = "demo-routing"
AGENT = "urn:example:demo:agent:appointment-scheduler"

AMARA = {"given_name": "Amara", "family_name": "Okafor", "birth_date": "1998-04-02"}
KOFI = {"given_name": "Kofi", "family_name": "Mensah", "birth_date": "1971-11-30"}


# --------------------------------------------------------------------------
# Step 1: the client assertion.
#
# The client authenticates to Mint with a JWT it signs with its own key
# (RFC 7523 `private_key_jwt`). There is no shared secret to leak, and Mint
# holds only public keys.
#
# The delegation request rides *inside* that JWT, in `on_behalf_of`. That
# placement is the point: the actor and the subject are covered by the client's
# signature, so nothing between the client and Mint can alter who the token is
# for.
# --------------------------------------------------------------------------


def build_client_assertion(client_id, private_key, jti, on_behalf_of=None):
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": f"{MINT}/token",
        "iat": now(),
        "exp": now() + 120,
        "jti": jti,  # Mint refuses a second assertion with the same jti
    }
    if on_behalf_of is not None:
        claims["on_behalf_of"] = on_behalf_of

    announce("the client assertion the client is about to sign", claims)
    return sign_jwt({"alg": "EdDSA", "typ": "JWT", "kid": private_key["kid"]}, claims,
                    private_key)


# --------------------------------------------------------------------------
# Step 2: the token request.
#
# Mint verifies the signature against the keys registered for this client, then
# checks the delegation request against the same registration: is this an actor
# the client may act as, and are these exactly the selector fields it may bind?
# Neither answer comes from the request.
# --------------------------------------------------------------------------


def request_token(assertion):
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }
    announce(f"POST {MINT}/token", {**form, "client_assertion": "<the JWT above>"})
    return requests.post(f"{MINT}/token", data=form, verify=CA, timeout=10)


# --------------------------------------------------------------------------
# Step 3: the evidence request.
#
# Note what is *not* in this body: the person. The bundle declares the subject's
# `valueOrigin` as `authenticated-context`, so Evidence reads the selector out
# of the token's claims and refuses to read it from the request.
# --------------------------------------------------------------------------


def request_evidence(token, subject_values=None):
    selector = {"profile": "demographics-v1"}
    if subject_values is not None:
        selector["values"] = subject_values
    body = {
        # A caller-generated correlation value. Evidence echoes it into the
        # assertion and keeps it away from authorization, sources, and audit.
        "requestNonce": request_nonce(),
        "requirement": REQUIREMENT,
        "purpose": PURPOSE,
        "subjects": [{"role": "subject", "selector": selector}],
    }
    announce(f"POST {EVIDENCE}/v1/evidence", body, header="Authorization: Bearer <the token>")
    return requests.post(
        f"{EVIDENCE}/v1/evidence",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )


def main(run_dir):
    global CA
    CA = str(run_dir / "ca.pem")
    scheduler = load_jwk(run_dir / "client-keys/scheduler.jwk")
    service_desk = load_jwk(run_dir / "client-keys/service-desk.jwk")

    heading("1. The client asks Mint for a token to act for one person")
    assertion = build_client_assertion(
        "scheduler",
        scheduler,
        "demo-1",
        on_behalf_of={"actor": AGENT, "subject": AMARA},
    )
    response = request_token(assertion)
    expect(response, 200)
    token = response.json()["access_token"]

    heading("2. What Mint put in the token")
    claims = decode_jwt_claims(token)
    show(claims)
    note(
        "`evidence_actor` says who is acting. `identity.*` says who they are acting for.",
        "Both were checked against the client's registration, not taken on trust.",
    )

    heading("3. The client asks Evidence for evidence, naming no one")
    response = request_evidence(token)
    expect(response, 200)
    show(decode_evidence(response.json()))
    note(
        "Evidence resolved the subject from the token, called the source, and",
        "returned a coarse region. The person's name and their residence code",
        "are in neither the request nor the answer. The subject appears only as",
        "an opaque binding that cannot be reversed into a name.",
    )

    heading("4. The same token, pointed at somebody else")
    response = request_evidence(token, subject_values=KOFI)
    expect(response, 400)
    show(response.json())
    note(
        "This is the containment. A bug in the client that puts the wrong person",
        "in the request body does not reach that person: Evidence refuses the",
        "request for carrying selector values at all, not for carrying the wrong",
        "ones. There is no request this token can make about Kofi Mensah.",
    )

    heading("5. Mint refuses what it was not asked to allow")
    for jti, description, client_id, key, on_behalf_of in (
        (
            "demo-wrong-actor",
            "an actor this client may not act as",
            "scheduler",
            scheduler,
            {"actor": "urn:example:demo:agent:someone-else", "subject": AMARA},
        ),
        (
            "demo-undelegated",
            "a client with no delegation in its registration",
            "service-desk",
            service_desk,
            {"actor": AGENT, "subject": AMARA},
        ),
        (
            "demo-extra-field",
            "a subject carrying a field the registration does not bind",
            "scheduler",
            scheduler,
            {"actor": AGENT, "subject": {**AMARA, "national_id": "synthetic-1"}},
        ),
    ):
        response = request_token(
            build_client_assertion(client_id, key, jti, on_behalf_of=on_behalf_of)
        )
        expect(response, 401)
        print(f"  refused: {description} -> {response.status_code} {response.json()}\n")

    heading("6. And an undelegated token cannot use the delegated grant")
    response = request_token(build_client_assertion("service-desk", service_desk, "demo-plain"))
    expect(response, 200)
    plain_token = response.json()["access_token"]
    note(
        "This token is valid and carries the same requester tag. It simply has no",
        "`evidence_actor` and no `identity.*`, so there is no subject to resolve.",
    )
    response = request_evidence(plain_token)
    expect(response, 400)
    show(response.json())
    note(
        "Worth being precise about the shape of this refusal. Evidence confines",
        "an actor-bearing token to `kind: delegated` authority profiles, but it",
        "does not require an actor to reach one. So this token matches the grant",
        "and is stopped when the subject cannot be resolved, rather than at the",
        "authority match. Nothing leaks either way.",
    )

    print("\nAll six steps behaved as described.")


# --------------------------------------------------------------------------
# Below here is only formatting and JWT mechanics. Nothing decides anything.
# --------------------------------------------------------------------------


def now():
    import time

    return int(time.time())


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def request_nonce() -> str:
    """32 random bytes, base64url without padding. Evidence rejects anything else."""
    return b64url(secrets.token_bytes(32))


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def load_jwk(path: Path) -> dict:
    return json.loads(path.read_text())


def sign_jwt(header: dict, claims: dict, private_jwk: dict) -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(unb64url(private_jwk["d"]))
    signing_input = ".".join(
        b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    return f"{signing_input}.{b64url(key.sign(signing_input.encode()))}"


def decode_jwt_claims(token: str) -> dict:
    """Read the claims without verifying. Evidence verifies; this only shows."""
    return json.loads(unb64url(token.split(".")[1]))


def decode_evidence(assertion: dict) -> dict:
    """Show the signed evidence assertion's payload rather than its base64.

    A verifier would check the signature over `protected` and `payload` against
    Evidence's published key set. This only makes the answer legible.
    """
    return {
        "protected": json.loads(unb64url(assertion["protected"])),
        "payload": json.loads(unb64url(assertion["payload"])),
        "signature": assertion["signature"][:16] + "...",
    }


def heading(text):
    print(f"\n{'=' * 76}\n{text}\n{'=' * 76}")


def announce(what, payload, header=None):
    print(f"\n  {what}")
    if header:
        print(f"    {header}")
    for line in json.dumps(payload, indent=2).splitlines():
        print(f"    {line}")
    print()


def show(payload):
    for line in json.dumps(payload, indent=2).splitlines():
        print(f"    {line}")


def note(*lines):
    print()
    for line in lines:
        print(f"  -> {line}")


def expect(response, status):
    if response.status_code != status:
        print(f"\nunexpected {response.status_code}: {response.text}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
