#!/usr/bin/env python3
"""Direct BReg, Casework, and Messaging composition over released clients.

The completion receiver records hints only. Source state, exact Proposal
version/effects, and BReg's lifecycle guards decide whether Apply is possible.
"""

from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
import sqlite3
import uuid

LOG = logging.getLogger("python-composition")
MAXIMUM_BODY = 8192
MAXIMUM_ATTEMPTS = 12


class WakeRefused(ValueError):
    """An unauthenticated, malformed, or conflicting wake was refused."""


class CompositionError(RuntimeError):
    """A value-free reference service refusal."""


def strict_json(body):
    def members(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    return json.loads(body, object_pairs_hook=members)


class Inbox:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS wakes (id TEXT PRIMARY KEY, digest TEXT NOT NULL, accepted_at TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, body TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'prepared', attempts INTEGER NOT NULL DEFAULT 0)"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def accept(self, authorization, recipient, key, body, *, token, binding):
        if (
            not isinstance(authorization, str)
            or not hmac.compare_digest(
                authorization.encode(), ("Bearer " + token).encode()
            )
            or recipient != binding
            or not body
            or len(body) > MAXIMUM_BODY
        ):
            raise WakeRefused("completion credential, binding, or body was refused")
        try:
            event = strict_json(body)
            if (
                set(event)
                != {"type", "eventId", "requestId", "resultId", "completedAt"}
                or event["type"] != "review.completed"
                or event["eventId"] != key
            ):
                raise ValueError("completion shape")
            for field in ("eventId", "requestId", "resultId"):
                if str(uuid.UUID(event[field])) != event[field]:
                    raise ValueError("completion identifier")
            instant = datetime.fromisoformat(
                event["completedAt"].replace("Z", "+00:00")
            )
            if instant.tzinfo is None:
                raise ValueError("completion time")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise WakeRefused("completion envelope was refused") from None
        digest = hashlib.sha256(body).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT digest FROM wakes WHERE id=?", (key,)
            ).fetchone()
            if previous:
                if previous[0] != digest:
                    raise WakeRefused(
                        "completion identity conflicts with its accepted bytes"
                    )
                return False
            db.execute(
                "INSERT INTO wakes VALUES (?,?,?)", (key, digest, event["completedAt"])
            )
        return True

    def pending(self):
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM wakes").fetchone()[0]

    def register(self, proposal_id, version, effect_digest, notice):
        body = json.dumps(
            {"version": version, "effectDigest": effect_digest, "notice": notice},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT body FROM jobs WHERE id=?", (proposal_id,)
            ).fetchone()
            if previous and previous[0] != body:
                raise CompositionError(
                    "a Proposal job cannot change its accepted version, effects, or notice"
                )
            if not previous:
                db.execute(
                    "INSERT INTO jobs(id,body) VALUES (?,?)", (proposal_id, body)
                )

    def jobs(self):
        with self.connect() as db:
            return db.execute(
                "SELECT id,body,state,attempts FROM jobs WHERE state!='notified' ORDER BY id LIMIT 100"
            ).fetchall()


class TokenSource:
    """One independent provider per product resource, with no token logging."""

    def __init__(self, config):
        self.config = config
        self.provider = None
        if "privateKeyJwt" in config:
            # Present in released clients; registry_client.auth exposes the
            # identical class once the neutral alias is published.
            from registry_client.breg import PrivateKeyJwt

            self.provider = PrivateKeyJwt(config["privateKeyJwt"])

    def bearer_token(self):
        if self.provider is not None:
            return self.provider.bearer_token()
        try:
            lines = Path(self.config["headerFile"]).read_text().splitlines()
            values = [
                line[len("Authorization: Bearer ") :]
                for line in lines
                if line.startswith("Authorization: Bearer ")
            ]
            if (
                len(values) != 1
                or not values[0]
                or any(character.isspace() for character in values[0])
            ):
                raise ValueError("credential shape")
            return values[0]
        except (OSError, KeyError, ValueError):
            raise CompositionError(
                "the configured product credential could not be read"
            ) from None

    def breg_authorization(self):
        if self.provider is not None:
            return {"private_key_jwt": self.config["privateKeyJwt"]}
        return {"static": self.bearer_token()}


class Composition:
    def __init__(self, config, inbox):
        from registry_client import breg, casework, messaging

        self.config, self.inbox = config, inbox
        self.tokens = {
            name: TokenSource(value) for name, value in config["tokens"].items()
        }
        self.registry = breg.BaseRegistryClient(
            config["bregUrl"],
            authorization=self.tokens["breg"].breg_authorization(),
            maximum_mutation_retries=0,
        )
        self.reviews = (
            casework.CaseworkClient(config["caseworkUrl"], maximum_mutation_retries=0)
            if "caseworkUrl" in config
            else None
        )
        self.messages = (
            messaging.MessagingClient(
                config["messagingUrl"], maximum_mutation_retries=0
            )
            if "messagingUrl" in config
            else None
        )

    def prepare(self, action, inputs, key):
        profile = self.config["bregProfile"]
        binding = self.registry.registry_contract(profile).select_action(
            action, profile
        )
        draft = self.registry.start_proposal(binding, inputs, key + ":draft")
        # Inputs are the officer's separate issuance terms. Original intake
        # and attachment references remain explicit fields in that Action.
        return self.registry.execute_proposal(
            self.registry.prepare_proposal(draft, "submit", {}, key + ":submit")
        )

    def review_tasks(self):
        if self.reviews is None:
            raise CompositionError(
                "configure the selected Casework deployment before listing tasks"
            )
        return self.reviews.review_tasks(
            self.tokens["casework"].bearer_token(), self.config["caseworkProfile"]
        )

    def decide(self, task_id, revision, key, decision):
        # An explicit human action, never called by a wake or background pass.
        if self.reviews is None:
            raise CompositionError(
                "configure the selected Casework deployment before deciding a task"
            )
        return self.reviews.decide_review_task(
            self.tokens["casework"].bearer_token(),
            self.config["caseworkProfile"],
            task_id,
            revision,
            key,
            decision,
        )

    def reconcile(self):
        if self.messages is None:
            raise CompositionError(
                "configure Messaging before applying and notifying registered jobs"
            )
        profile = self.config["bregProfile"]
        binding = self.registry.registry_contract(profile).select_proposal_get(profile)
        count = 0
        for proposal_id, body, state, attempts in self.inbox.jobs():
            if attempts >= MAXIMUM_ATTEMPTS:
                LOG.error(
                    "job needs operator recovery after its bounded attempt budget"
                )
                continue
            job = json.loads(body)
            current = self.registry.get_proposal(binding, proposal_id)
            document = current.document
            if (
                document["submissionVersion"] != job["version"]
                or document.get("effectDigest") != job["effectDigest"]
            ):
                raise CompositionError(
                    "the Proposal version or effects no longer match the registered job"
                )
            if document["state"] != "applied":
                # The native SDK selects the source-issued lifecycle link and
                # opaque ETag. An unavailable Apply is refused before mutation.
                try:
                    prepared = self.registry.prepare_proposal(
                        current,
                        "apply",
                        {
                            "submissionVersion": job["version"],
                            "effectDigest": job["effectDigest"],
                        },
                        f"{proposal_id}:{job['version']}:apply",
                    )
                except Exception as error:
                    if getattr(error, "kind", None) == "invalid-request":
                        LOG.info(
                            "Proposal is not currently applicable; awaiting authoritative source state"
                        )
                        continue
                    raise
                with self.inbox.connect() as db:
                    db.execute(
                        "UPDATE jobs SET attempts=attempts+1 WHERE id=?", (proposal_id,)
                    )
                self.registry.execute_proposal(prepared)
                current = self.registry.get_proposal(binding, proposal_id)
                if current.document["state"] != "applied":
                    raise CompositionError("source Apply was not confirmed")
            with self.inbox.connect() as db:
                db.execute(
                    "UPDATE jobs SET state='issued',attempts=attempts+1 WHERE id=?",
                    (proposal_id,),
                )
            self.messages.submit(
                self.tokens["messaging"].bearer_token(),
                f"{proposal_id}:{job['version']}:notice",
                job["notice"],
            )
            with self.inbox.connect() as db:
                db.execute(
                    "UPDATE jobs SET state='notified' WHERE id=?", (proposal_id,)
                )
            count += 1
        return count


def receiver(inbox, *, token, binding):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def refuse(self, status, code, detail):
            body = json.dumps(
                {
                    "type": "https://example.org/problems/" + code,
                    "title": "Completion refused",
                    "status": status,
                    "detail": detail,
                    "code": code,
                    "traceId": uuid.uuid4().hex,
                }
            ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/problem+json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if (
                self.path != "/casework/completion"
                or len(self.headers.get_all("Authorization", [])) != 1
                or len(self.headers.get_all("Registry-Recipient-Binding", [])) != 1
                or len(self.headers.get_all("Idempotency-Key", [])) != 1
                or len(self.headers.get_all("Content-Length", [])) != 1
            ):
                self.refuse(
                    403,
                    "receiver.wake-refused",
                    "The completion credential, binding, or envelope was refused.",
                )
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if (
                    not 0 < length <= MAXIMUM_BODY
                    or self.headers.get("Transfer-Encoding")
                    or self.headers.get_content_type() != "application/json"
                ):
                    raise WakeRefused("body framing refused")
                inbox.accept(
                    self.headers["Authorization"],
                    self.headers["Registry-Recipient-Binding"],
                    self.headers["Idempotency-Key"],
                    self.rfile.read(length),
                    token=token,
                    binding=binding,
                )
            except (ValueError, WakeRefused):
                self.refuse(
                    403,
                    "receiver.wake-refused",
                    "The completion credential, binding, or envelope was refused.",
                )
                return
            except sqlite3.Error:
                LOG.error("completion persistence unavailable")
                self.refuse(
                    503,
                    "receiver.persistence-unavailable",
                    "The completion could not be persisted; retry with the same event identity.",
                )
                return
            # Commit succeeded, including an identical replay. No downstream
            # call occurs before this acknowledgement.
            self.send_response(204)
            self.end_headers()

        def log_message(self, message, *args):
            LOG.info("completion HTTP request handled")

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve-wakes")
    sub.add_parser("review-tasks")
    sub.add_parser("reconcile")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("action")
    prepare.add_argument("inputs", type=Path)
    prepare.add_argument("key")
    register = sub.add_parser("register")
    register.add_argument("proposal_id")
    register.add_argument("version", type=int)
    register.add_argument("effect_digest")
    register.add_argument("notice", type=Path)
    decide = sub.add_parser("decide")
    decide.add_argument("task_id")
    decide.add_argument("revision", type=int)
    decide.add_argument("key")
    decide.add_argument("decision", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    config = strict_json(args.config.read_bytes())
    inbox = Inbox(Path(config["inbox"]))
    if args.command == "serve-wakes":
        token = Path(config["wakeTokenFile"]).read_text().strip()
        if len(token) < 32:
            raise CompositionError(
                "completion credential must contain at least 32 characters"
            )
        host, port = config.get("listen", "127.0.0.1:9300").rsplit(":", 1)
        if host != "127.0.0.1":
            raise CompositionError("put the example receiver behind a local TLS proxy")
        ThreadingHTTPServer(
            (host, int(port)),
            receiver(inbox, token=token, binding=config["wakeRecipientBinding"]),
        ).serve_forever()
        return
    if args.command == "register":
        inbox.register(
            args.proposal_id,
            args.version,
            args.effect_digest,
            strict_json(args.notice.read_bytes()),
        )
        print(json.dumps({"registered": True}))
        return
    app = Composition(config, inbox)
    if args.command == "prepare":
        proposal = app.prepare(
            args.action, strict_json(args.inputs.read_bytes()), args.key
        )
        print(
            json.dumps(
                {
                    "proposalId": proposal.identifier,
                    "submissionVersion": proposal.document["submissionVersion"],
                    "effectDigest": proposal.document.get("effectDigest"),
                }
            )
        )
    elif args.command == "review-tasks":
        result = app.review_tasks()
        print(json.dumps(result))
    elif args.command == "decide":
        app.decide(
            args.task_id,
            args.revision,
            args.key,
            strict_json(args.decision.read_bytes()),
        )
        print(json.dumps({"decisionRecorded": True}))
    else:
        print(json.dumps({"completed": app.reconcile()}))


if __name__ == "__main__":
    main()
