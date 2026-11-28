"""Sign synthetic Standard Webhooks deliveries with the Python standard library."""
from __future__ import annotations

import base64
import hmac
from collections.abc import Sequence


def webhook_signature(keys: Sequence[bytes], webhook_id: str, timestamp: int, body: bytes) -> str:
    """Return the webhook-signature value: one v1 entry per key, current key first."""
    if not keys or any(not 32 <= len(key) <= 64 for key in keys):
        raise ValueError("supply at least one key of 32 to 64 bytes")
    signed = f"{webhook_id}.{timestamp}.".encode("ascii") + body
    return " ".join(
        "v1," + base64.b64encode(hmac.digest(key, signed, "sha256")).decode("ascii")
        for key in keys
    )
