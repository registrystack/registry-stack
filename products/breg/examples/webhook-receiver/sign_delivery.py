"""Sign synthetic BReg webhook deliveries for receiver tests and fixtures.

This is the sender side of the Version 1 delivery signature, written with the
Python standard library so tests can produce requests without a runtime. A
receiver never uses it: `receiver.py` verifies with the client binding's
`verify_webhook_delivery`, which runs the shared Rust verifier.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

WEBHOOK_SIGNATURE_DOMAIN = b"breg-webhook-signature-v1"


def _length_prefixed(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def webhook_signature(
    key: bytes, headers: dict[str, str], body: bytes, request_target: str = "/events"
) -> str:
    """Return the `x-registry-signature` value for lowercase `headers` and `body`."""
    signed = bytearray(WEBHOOK_SIGNATURE_DOMAIN)
    for value in (
        headers["ce-specversion"].encode("ascii"),
        headers["ce-id"].encode("ascii"),
        headers["ce-source"].encode("ascii"),
        headers["ce-type"].encode("ascii"),
        headers["ce-time"].encode("ascii"),
        headers["ce-dataschema"].encode("ascii"),
        headers["x-registry-event-generation"].encode("ascii"),
        headers["x-registry-delivery-attempt"].encode("ascii"),
        headers["x-registry-delivery-time"].encode("ascii"),
        b"POST",
        request_target.encode("ascii"),
        b"application/json",
        headers["idempotency-key"].encode("ascii"),
        body,
    ):
        signed.extend(_length_prefixed(value))
    encoded = base64.urlsafe_b64encode(hmac.new(key, signed, hashlib.sha256).digest()).rstrip(b"=")
    return "v1=" + encoded.decode("ascii")
