#!/usr/bin/env python3
"""Offline smoke for an installed Registry Evidence Python client wheel."""

import registry_evidence_client as client_module


JWKS = {
    "keys": [
        {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "kid": "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo",
            "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
            "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU",
        }
    ]
}
SPEC = {
    "response_format": "signed-jws",
    "requirement": "urn:example:requirement:v1",
    "purpose": "example-purpose",
    "audience": "urn:example:audience",
    "evidence_type": "urn:example:evidence-type:v1",
    "issued_by": "urn:example:issuer",
    "provided_by": "urn:example:provider",
    "configuration_revision": "sha256:" + "0" * 64,
    "expected_assurance_profile": "local",
    "subjects": [{"role": "subject", "selector_profile": "national-id"}],
    "expected_outputs": [
        {"concept": "urn:example:concept:status-holds", "form": "boolean"}
    ],
    "maximum_assertion_lifetime_seconds": 300,
    "clock_skew_seconds": 60,
    "subject_expectations": "accept_first_use",
}


def main() -> None:
    # This reserved host and placeholder token make the smoke fail closed if a
    # regression unexpectedly attempts network I/O.
    client = client_module.EvidenceClient(
        "https://evidence.invalid", JWKS, [], "placeholder-not-a-credential"
    )
    prepared = client.prepare(SPEC)
    if len(prepared.request_nonce) != 43:
        raise SystemExit(f"unexpected nonce length {len(prepared.request_nonce)}")
    if prepared.policy_document["audience"] != SPEC["audience"]:
        raise SystemExit("the prepared policy does not carry the requested audience")
    if prepared.subject_expectations != "accept_first_use":
        raise SystemExit("the prepared request lost its subject expectations")

    try:
        client.prepare(dict(SPEC, configuration_revision=""))
    except client_module.ConfigurationError as error:
        if error.kind != "configuration":
            raise SystemExit(f"unexpected error kind {error.kind!r}") from error
    else:
        raise SystemExit("an empty configuration revision must be refused")

    print("Python client package smoke passed")


if __name__ == "__main__":
    main()
