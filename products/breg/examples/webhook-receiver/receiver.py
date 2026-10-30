#!/usr/bin/env python3
"""Verify BReg signed CloudEvents and commit receiver-owned acceptance before ACK."""
from __future__ import annotations

import argparse
import http.server
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from registry_client import breg

WEBHOOK_RECEIVER_MAX_BODY_BYTES = 1024 * 1024


class ReceiverError(RuntimeError):
    pass


def _verify_webhook_request(
    key: bytes,
    path: str,
    header_pairs: list[tuple[str, str]],
    body: bytes,
    contract: dict[str, Any],
) -> dict[str, str]:
    required = {
        "accept",
        "content-type",
        "ce-specversion",
        "ce-id",
        "ce-source",
        "ce-type",
        "ce-time",
        "ce-dataschema",
        "x-registry-event-generation",
        "x-registry-delivery-attempt",
        "x-registry-delivery-time",
        "idempotency-key",
        "x-registry-signature",
    }
    # The shared Rust verifier authenticates the signed attributes, request
    # target, content type, idempotency key and exact body, and checks that
    # generation and attempt are positive decimals. The checks below apply this
    # receiver's own contract and clock policy to the authenticated values.
    verified = breg.verify_hook_delivery(
        method="POST", path=path, headers=header_pairs, body=body, key=key
    )
    headers: dict[str, str] = {}
    for name, value in header_pairs:
        normalized_name = name.lower()
        if normalized_name in headers:
            raise ReceiverError("the receiver refused a repeated webhook header")
        headers[normalized_name] = value
    if path != "/events" or not required.issubset(headers):
        raise ReceiverError("the receiver refused the webhook request shape")
    if (
        headers["accept"] != "application/json"
        or headers["content-type"] != "application/json"
        or headers["ce-specversion"] != "1.0"
    ):
        raise ReceiverError("the receiver refused the CloudEvents profile")
    event_uuid = str(uuid.UUID(headers["ce-id"]))
    if event_uuid != headers["ce-id"] or headers["ce-type"] != contract["event_id"]:
        raise ReceiverError("the receiver refused the CloudEvents identity")
    expected_source = (
        f"urn:registrystack:registry:{contract['registry_id']}:"
        f"instance:{contract['instance_id']}"
    )
    if headers["ce-source"] != expected_source:
        raise ReceiverError("the receiver refused the CloudEvents source")
    expected_schema_prefix = (
        f"urn:breg:event-schema:{contract['registry_id']}:{contract['record_type']}:"
        f"{contract['event_id']}:sha256:"
    )
    if not headers["ce-dataschema"].startswith(expected_schema_prefix):
        raise ReceiverError("the receiver refused the CloudEvents data schema")
    event_time = datetime.fromisoformat(headers["ce-time"].replace("Z", "+00:00"))
    delivery_time = datetime.fromisoformat(
        headers["x-registry-delivery-time"].replace("Z", "+00:00")
    )
    if event_time.tzinfo is None or delivery_time.tzinfo is None:
        raise ReceiverError("the receiver refused unzoned event time")
    if abs((datetime.now(timezone.utc) - delivery_time).total_seconds()) > 30:
        raise ReceiverError("the receiver refused stale delivery time")
    idempotency_key = verified["idempotency_key"]
    if not idempotency_key.startswith("sha256:") or len(idempotency_key) != 71:
        raise ReceiverError("the receiver refused the idempotency key")
    if len(body) == 0 or len(body) > WEBHOOK_RECEIVER_MAX_BODY_BYTES:
        raise ReceiverError("the receiver refused the webhook body bounds")
    document = json.loads(body)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if canonical != body or not isinstance(document, dict):
        raise ReceiverError("the receiver refused a non-canonical webhook body")
    if set(document) != {
        "id",
        "type",
        "source",
        "time",
        "subject",
        "dataschema",
        "data",
        "causation",
    }:
        raise ReceiverError("the receiver refused the webhook envelope shape")
    if (
        document["id"] != headers["ce-id"]
        or document["type"] != headers["ce-type"]
        or document["source"] != headers["ce-source"]
        or document["dataschema"] != headers["ce-dataschema"]
        or document["time"] != headers["ce-time"]
    ):
        raise ReceiverError("the receiver refused an envelope that contradicts its headers")
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
        or document["trigger"] != "created"
        or not isinstance(document["revision"], int)
        or document["revision"] < 1
        or not isinstance(document["packageRevision"], str)
        or not document["packageRevision"].startswith("sha256:")
        or str(uuid.UUID(document["recordId"])) != document["recordId"]
        or not isinstance(document["values"], dict)
        or set(document["values"]) != set(contract["event_values"])
    ):
        raise ReceiverError("the receiver refused the event data contract")
    return headers


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
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS accepted_deliveries ("
                    "idempotency_key TEXT PRIMARY KEY, source TEXT NOT NULL, "
                    "event_id TEXT NOT NULL, generation TEXT NOT NULL)"
                )
        finally:
            connection.close()

    def accept(self, headers: dict[str, str], body: bytes) -> None:
        # Call only after request verification. Attempt/time/signature change on
        # retry; generation also changes on operator replay. The event identity
        # must still denote one work item if earlier acknowledgements were lost.
        metadata = json.dumps(
            {
                name: headers[name]
                for name in (
                    "ce-specversion", "ce-id", "ce-source", "ce-type", "ce-time",
                    "ce-dataschema",
                )
            },
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
                    (headers["ce-source"], headers["ce-id"], metadata, body),
                )
                retained = connection.execute(
                    "SELECT metadata, body FROM accepted_events WHERE source = ? AND event_id = ?",
                    (headers["ce-source"], headers["ce-id"]),
                ).fetchone()
                if retained != (metadata, body):
                    raise ReceiverError("the receiver refused conflicting duplicate content")
                binding = (
                    headers["ce-source"], headers["ce-id"],
                    headers["x-registry-event-generation"],
                )
                connection.execute(
                    "INSERT INTO accepted_deliveries (idempotency_key, source, event_id, generation) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT (idempotency_key) DO NOTHING",
                    (headers["idempotency-key"], *binding),
                )
                retained_binding = connection.execute(
                    "SELECT source, event_id, generation FROM accepted_deliveries "
                    "WHERE idempotency_key = ?",
                    (headers["idempotency-key"],),
                ).fetchone()
                if retained_binding != binding:
                    raise ReceiverError("the receiver refused conflicting delivery identity")
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
            headers = _verify_webhook_request(
                self.server.webhook_key, self.path, header_pairs, body, self.server.contract
            )
        except (
            ReceiverError, breg.BaseRegistryClientError, KeyError, TypeError, ValueError,
            UnicodeError,
        ):
            status = 400
        else:
            try:
                self.server.webhook_inbox.accept(headers, body)
            except ReceiverError:
                status = 409
            except (OSError, sqlite3.Error):
                status = 503
            else:
                status = 204
        self.send_response(status)
        self.end_headers()


def make_server(port: int, key: bytes, contract: dict[str, Any], inbox: WebhookInbox):
    server = http.server.HTTPServer(("127.0.0.1", port), WebhookReceiver)
    server.webhook_key = key
    server.contract = contract
    server.webhook_inbox = inbox
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
    if len(key) < 32:
        parser.error("key must contain at least 32 bytes")
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
