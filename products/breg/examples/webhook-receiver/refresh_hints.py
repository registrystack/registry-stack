#!/usr/bin/env python3
"""Turn one reviewed BReg webhook into scoped external source changes."""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from receiver import ReceiverError, make_server, read_hook_keys

if TYPE_CHECKING:
    from registry_client.breg import VerifiedHookDelivery


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


class SourceChanges:
    def __init__(
        self, *, origin: str, plan: str, projection: str, fields: list[str], token_file: Path,
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
        if not selector_is_valid(projection):
            raise ValueError("configure a projection")
        if not 1 <= len(fields) <= 2 or len(set(fields)) != len(fields):
            raise ValueError("configure one selector field or two distinct parent fields")
        self.host = url.hostname
        self.port = url.port
        self.connection = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        self.plan = plan
        self.path = f"/v1/external-refresh-plans/{plan}/source-changes"
        self.projection = projection
        self.fields = tuple(fields)
        self.token_file = token_file

    def accept(self, delivery: VerifiedHookDelivery, body: bytes) -> None:
        values = json.loads(body)["data"]["values"]
        selectors = [values[field] for field in self.fields]
        if not all(selector_is_valid(selector) for selector in selectors):
            raise ReceiverError("the notifier refused the selector values")
        token = read_secret(self.token_file).strip()
        if not re.fullmatch(rb"[A-Za-z0-9._~+/-]+=*", token):
            raise OSError("the notifier refused the service token format")
        for selector in dict.fromkeys(selectors):
            # A repeated change for the same selector is admitted again with
            # 202, so a retry after a lost response needs no identity.
            self.submit({"projection": self.projection, "selector": selector}, token.decode("ascii"))

    def submit(self, payload: dict[str, str], token: str) -> None:
        connection = self.connection(self.host, self.port, timeout=2)
        try:
            connection.request(
                "POST", self.path, json.dumps(payload).encode(),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            with connection.getresponse() as response:
                if response.status != 202:
                    raise OSError("the receiving registry did not accept the source change")
        except http.client.HTTPException:
            raise OSError("the receiving registry did not acknowledge the source change") from None
        finally:
            connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--previous-key", type=Path)
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
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.schema_digest):
        parser.error("configure the exact 64-character event schema digest")
    try:
        key, previous_key = read_hook_keys(args.key, args.previous_key)
    except ValueError as error:
        parser.error(str(error))
    try:
        acceptance = SourceChanges(
            origin=args.destination_origin, plan=args.plan, projection=args.projection,
            fields=args.selector_field, token_file=args.token_file,
        )
    except (OSError, ValueError):
        parser.error("check notifier origin, plan, projection, selector fields and credential file")
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
        with make_server(
            args.port, key, contract, acceptance, previous_key=previous_key,
        ) as server:
            server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
