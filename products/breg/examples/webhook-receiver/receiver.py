#!/usr/bin/env python3
"""Verify BReg Standard Webhooks and commit receiver-owned acceptance before ACK."""
from __future__ import annotations

import argparse
import http.server
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Protocol

from registry_client import breg

WEBHOOK_RECEIVER_MAX_BODY_BYTES = 1024 * 1024


class ReceiverError(RuntimeError):
    pass


class WebhookAcceptance(Protocol):
    def accept(self, delivery: breg.VerifiedHookDelivery, body: bytes) -> None:
        raise NotImplementedError


def _verify_webhook_request(
    key: bytes,
    path: str,
    header_pairs: list[tuple[str, str]],
    body: bytes,
    contract: dict[str, Any],
) -> breg.VerifiedHookDelivery:
    if path != "/events":
        raise ReceiverError("the receiver refused the webhook route")
    verified = breg.verify_hook_delivery(headers=header_pairs, body=body, key=key)
    if verified["type"] != contract["event_id"]:
        raise ReceiverError("the receiver refused the event type")
    expected_source = (
        f"urn:registrystack:registry:{contract['registry_id']}:"
        f"instance:{contract['instance_id']}"
    )
    if verified["source"] != expected_source:
        raise ReceiverError("the receiver refused the event source")
    expected_schema_prefix = (
        f"urn:breg:event-schema:{contract['registry_id']}:{contract['record_type']}:"
        f"{contract['event_id']}:sha256:"
    )
    schema = verified["dataschema"]
    if not schema.startswith(expected_schema_prefix) or schema != contract.get("data_schema", schema):
        raise ReceiverError("the receiver refused the event data schema")
    document = json.loads(verified["body"])
    subject = document["subject"]
    causation = document["causation"]
    if (
        not isinstance(subject, dict)
        or set(subject) != {"recordReference", "recordRevision"}
        or not isinstance(subject["recordReference"], str)
        or not subject["recordReference"]
        or not isinstance(subject["recordRevision"], int)
        or subject["recordRevision"] < 1
        or not isinstance(causation, dict)
        or set(causation) - {"root", "parent", "hop"}
        or causation["root"] != document["id"]
        or causation["hop"] != 0
    ):
        raise ReceiverError("the receiver refused the envelope subject or causation")
    document = document["data"]
    if set(document) != {"recordType", "recordId", "revision", "trigger", "packageRevision", "values"}:
        raise ReceiverError("the receiver refused the webhook body shape")
    if (
        document["recordType"] != contract["record_type"]
        or document["trigger"] != contract.get("trigger", "created")
        or not isinstance(document["revision"], int)
        or document["revision"] < 1
        or not isinstance(document["packageRevision"], str)
        or not document["packageRevision"].startswith("sha256:")
        or str(uuid.UUID(document["recordId"])) != document["recordId"]
        or not isinstance(document["values"], dict)
        or set(document["values"]) != set(contract["event_values"])
    ):
        raise ReceiverError("the receiver refused the event data contract")
    return verified


class WebhookInbox:
    """Receiver-owned durable acceptance, not a registry delivery or worker API."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
                raise ReceiverError("the webhook inbox must be an owner-only regular file")
        else:
            os.close(descriptor)
        connection = sqlite3.connect(path)
        try:
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS accepted_events ("
                    "source TEXT NOT NULL, event_id TEXT NOT NULL, metadata TEXT NOT NULL, "
                    "body BLOB NOT NULL, PRIMARY KEY (source, event_id))"
                )
        finally:
            connection.close()

    def accept(self, delivery: breg.VerifiedHookDelivery, body: bytes) -> None:
        # The same event id identifies retries and operator replays.
        metadata = json.dumps(
            {name: delivery[name] for name in ("id", "source", "type", "time", "dataschema")},
            sort_keys=True,
            separators=(",", ":"),
        )
        connection = sqlite3.connect(self.path)
        try:
            with connection:
                connection.execute("PRAGMA synchronous = FULL")
                connection.execute(
                    "INSERT INTO accepted_events (source, event_id, metadata, body) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (source, event_id) DO NOTHING",
                    (delivery["source"], delivery["id"], metadata, body),
                )
                retained = connection.execute(
                    "SELECT body FROM accepted_events WHERE source = ? AND event_id = ?",
                    (delivery["source"], delivery["id"]),
                ).fetchone()
                if retained != (body,):
                    raise ReceiverError("the receiver refused conflicting duplicate content")
            # The commit completes before the HTTP receiver can acknowledge.
        finally:
            connection.close()


class WebhookReceiver(http.server.BaseHTTPRequestHandler):
    server_version = "RegistryWebhookReceiver/1"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler callback
        self.send_response(200 if self.path == "/ready" else 404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler callback
        try:
            raw_length = self.headers.get("Content-Length", "")
            if not raw_length.isdecimal():
                raise ReceiverError("the receiver refused the webhook length")
            length = int(raw_length)
            if length <= 0 or length > WEBHOOK_RECEIVER_MAX_BODY_BYTES:
                raise ReceiverError("the receiver refused the webhook length")
            body = self.rfile.read(length)
            header_pairs = list(self.headers.raw_items())
            delivery = _verify_webhook_request(
                self.server.webhook_key, self.path, header_pairs, body, self.server.contract
            )
        except (
            ReceiverError, breg.BaseRegistryClientError, KeyError, TypeError, ValueError,
            UnicodeError,
        ):
            status = 400
        else:
            try:
                self.server.webhook_acceptance.accept(delivery, delivery["body"])
            except ReceiverError:
                status = 409
            except (OSError, sqlite3.Error):
                status = 503
            else:
                status = 204
        self.send_response(status)
        self.end_headers()


def make_server(port: int, key: bytes, contract: dict[str, Any], acceptance: WebhookAcceptance):
    server = http.server.HTTPServer(("127.0.0.1", port), WebhookReceiver)
    server.webhook_key = key
    server.contract = contract
    server.webhook_acceptance = acceptance
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--record-type", required=True)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--field", action="append", required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    args = parser.parse_args()
    if not args.key.is_file() or args.key.is_symlink() or args.key.stat().st_mode & 0o077:
        parser.error("key must be an owner-only regular file")
    key = args.key.read_bytes()
    if not 32 <= len(key) <= 64:
        parser.error("key must contain 32 to 64 bytes")
    parent = args.inbox.parent
    if not parent.is_dir() or parent.is_symlink() or parent.stat().st_mode & 0o077:
        parser.error("inbox parent must be an owner-only directory")
    contract = {"registry_id": args.registry_id, "instance_id": args.instance_id,
                "record_type": args.record_type, "event_id": args.event_id,
                "event_values": args.field}
    with make_server(args.port, key, contract, WebhookInbox(args.inbox)) as server:
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
