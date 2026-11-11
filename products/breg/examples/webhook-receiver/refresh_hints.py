#!/usr/bin/env python3
"""Turn one reviewed BReg webhook into scoped external refresh hints."""
from __future__ import annotations

import argparse
import hmac
import http.client
import json
import os
import re
import stat
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from receiver import ReceiverError, make_server


def read_secret(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as secret:
            metadata = os.fstat(secret.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_mode & 0o077
                or metadata.st_uid != os.getuid()
            ):
                raise OSError
            value = secret.read(16_385)
    except OSError:
        raise OSError("the notifier needs an owner-only credential file") from None
    if not 0 < len(value) <= 16_384:
        raise OSError("the notifier refused credential length")
    return value


def selector_is_valid(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value.encode("utf-8")) <= 512
        and value.strip() == value
        and not any(unicodedata.category(char) == "Cc" for char in value)
    )


class RefreshHints:
    def __init__(
        self, *, origin: str, plan: str, projection: str, scheme: str, fields: list[str],
        token_file: Path, id_key: bytes,
    ) -> None:
        url = urlsplit(origin)
        if (
            not url.hostname
            or url.username is not None
            or url.password is not None
            or url.path not in ("", "/")
            or url.query
            or url.fragment
            or (url.scheme != "https" and not (url.scheme == "http" and url.hostname in ("127.0.0.1", "::1")))
        ):
            raise ValueError("configure an HTTPS origin or loopback HTTP origin")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", plan):
            raise ValueError("configure a refresh plan identifier")
        if not selector_is_valid(projection) or not selector_is_valid(scheme):
            raise ValueError("configure a projection and selector scheme")
        if not 1 <= len(fields) <= 2 or len(set(fields)) != len(fields):
            raise ValueError("configure one selector field or two distinct parent fields")
        if len(id_key) < 32:
            raise ValueError("the hint ID key needs at least 32 bytes")
        self.host = url.hostname
        self.port = url.port
        self.connection = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        self.plan = plan
        self.path = f"/v1/external-refresh-plans/{plan}/hints"
        self.projection = projection
        self.scheme = scheme
        self.fields = tuple(fields)
        self.token_file = token_file
        self.id_key = id_key

    def accept(self, headers: dict[str, str], body: bytes) -> None:
        values = json.loads(body)["data"]["values"]
        selectors = [values[field] for field in self.fields]
        if not all(selector_is_valid(selector) for selector in selectors):
            raise ReceiverError("the notifier refused the selector values")
        token = read_secret(self.token_file).strip()
        if not re.fullmatch(rb"[A-Za-z0-9._~+/-]+=*", token):
            raise OSError("the notifier refused the service token format")
        for selector in dict.fromkeys(selectors):
            # Delivery attempt and operator replay generation can change. The
            # source/event identity and receiving target determine the hint.
            identity = json.dumps(
                [headers["ce-source"], headers["ce-id"], self.plan, self.projection, self.scheme, selector],
                separators=(",", ":"), ensure_ascii=False,
            ).encode()
            hint_id = hmac.digest(self.id_key, b"breg-refresh-hint-v1\0" + identity, "sha256").hex()
            payload = {
                "hintId": hint_id, "projection": self.projection,
                "selectorScheme": self.scheme, "selector": selector,
            }
            self.submit(payload, token.decode("ascii"))

    def submit(self, payload: dict[str, str], token: str) -> None:
        connection = self.connection(self.host, self.port, timeout=2)
        try:
            connection.request(
                "POST", self.path, json.dumps(payload).encode(),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            with connection.getresponse() as response:
                if response.status != 202:
                    raise OSError("the receiving registry did not accept the hint")
        except http.client.HTTPException:
            raise OSError("the receiving registry did not acknowledge the hint") from None
        finally:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--record-type", required=True)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--trigger", choices=("created", "patched", "tombstoned"), required=True)
    parser.add_argument("--schema-digest", required=True)
    parser.add_argument("--selector-field", action="append", required=True)
    parser.add_argument("--destination-origin", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--projection", required=True)
    parser.add_argument("--selector-scheme", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--hint-id-key", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.schema_digest):
        parser.error("configure the exact 64-character event schema digest")
    try:
        key = read_secret(args.key)
        if len(key) < 32:
            raise ValueError("the webhook key needs at least 32 bytes")
        acceptance = RefreshHints(
            origin=args.destination_origin, plan=args.plan, projection=args.projection,
            scheme=args.selector_scheme, fields=args.selector_field, token_file=args.token_file,
            id_key=read_secret(args.hint_id_key),
        )
    except (OSError, ValueError):
        parser.error("check notifier origin, plan, projection, selector fields and credential files")
    else:
        schema = (
            f"urn:breg:event-schema:{args.registry_id}:{args.record_type}:"
            f"{args.event_id}:sha256:{args.schema_digest}"
        )
        contract = {
            "registry_id": args.registry_id, "instance_id": args.instance_id,
            "record_type": args.record_type, "event_id": args.event_id, "trigger": args.trigger,
            "data_schema": schema, "event_values": args.selector_field,
        }
        with make_server(args.port, key, contract, acceptance) as server:
            server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
