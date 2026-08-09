"""Shared constants for the Python test suite.

`VALID_JWKS` is a syntactically well-formed key set, never used to verify
anything for real: `EvidenceClient.send` never parses or verifies the
response body it reads (only `verify`/`verify_as_of` do, via
`registry-evidence-verifier`), so every test in this suite that only calls
`send` needs a key set shaped correctly enough to construct a client, not one
that actually corresponds to any signing key. Its key material is an
obviously placeholder, all-zero value, distinct from the real committed
golden fixture key at `tests/fixtures/jwks.json`.

`request_spec()` is the specification every `send`-level test prepares
against, matching `crates/registry-evidence-client-py/tests/happy_path.rs`'s
own `request_spec_json`. `subject_expectations` is `"accept_first_use"`, so
nothing here needs a subject binding decided ahead of time.
"""

from __future__ import annotations

import json

VALID_JWKS = {
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


def request_spec() -> dict:
    return {
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


def request_batch_spec() -> dict:
    """Two positional subject requests sharing one batch policy."""
    singular = request_spec()
    return {
        "requirement": singular["requirement"],
        "purpose": singular["purpose"],
        "audience": singular["audience"],
        "evidence_type": singular["evidence_type"],
        "issued_by": singular["issued_by"],
        "provided_by": singular["provided_by"],
        "configuration_revision": singular["configuration_revision"],
        "expected_assurance_profile": singular["expected_assurance_profile"],
        "expected_outputs": singular["expected_outputs"],
        "maximum_assertion_lifetime_seconds": singular[
            "maximum_assertion_lifetime_seconds"
        ],
        "clock_skew_seconds": singular["clock_skew_seconds"],
        "items": [
            {
                "subjects": [
                    {
                        "role": "subject",
                        "selector_profile": "national-id",
                        "selector_values": {"record_reference": "synthetic-001"},
                    }
                ],
                "subject_expectations": "accept_first_use",
            },
            {
                "subjects": [
                    {
                        "role": "subject",
                        "selector_profile": "national-id",
                        "selector_values": {"record_reference": "synthetic-002"},
                    }
                ],
                "subject_expectations": "accept_first_use",
            },
        ],
    }


def problem_body(
    status: int, code: str, operation: str = "01JQ0QZ8YHZ0000000000000AB"
) -> bytes:
    """A body satisfying the Evidence problem contract exactly: `type`,
    `title`, `status`, `code`, and `operation`, and nothing else (the server
    side, `crates/registry-evidence-client/src/problem.rs`, denies unknown
    fields). `operation` defaults to the same fixed value
    `problem.rs`'s own tests use, bounded alphanumeric, so tests can assert
    it survives unchanged into the mapped exception's `operation` attribute.
    """
    return json.dumps(
        {
            "type": "https://registrystack.org/problems/evidence",
            "title": "stub problem",
            "status": status,
            "code": code,
            "operation": operation,
        }
    ).encode("utf-8")
