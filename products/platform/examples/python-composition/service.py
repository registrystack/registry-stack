#!/usr/bin/env python3
"""Direct BReg, Casework, and Messaging composition over released clients.

The BReg hook receiver records hints only. Source state, exact Proposal
version/effects, and BReg's lifecycle guards decide whether Apply is possible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

PROPOSAL_SCHEMA = "https://id.registrystack.org/contracts/breg/proposal-event/v1"
PROPOSAL_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "breg/generated/event-schemas/proposal-lifecycle.schema.json"
)
PROPOSAL_PAYLOAD = Draft202012Validator(
    json.loads(PROPOSAL_SCHEMA_PATH.read_text()),
    format_checker=FormatChecker(),
)

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


def proposal_subject(verified):
    """Read the native Proposal envelope, never an adopter approval document."""
    try:
        envelope = strict_json(verified["body"])
        if set(envelope) != {
            "id",
            "type",
            "source",
            "time",
            "dataschema",
            "subject",
            "data",
            "causation",
        }:
            raise ValueError("envelope shape")
        if verified["dataschema"] != PROPOSAL_SCHEMA or any(
            envelope[name] != verified[name]
            for name in ("id", "type", "source", "time", "dataschema")
        ):
            raise ValueError("signed metadata differs")
        data = envelope["data"]
        PROPOSAL_PAYLOAD.validate(data)
        if (
            not isinstance(envelope["subject"], dict)
            or type(envelope["subject"].get("recordRevision")) is not int
            or envelope["type"] != "proposal." + data["transition"]
            or envelope["subject"]
            != {
                "recordReference": "/v1/proposals/" + data["proposalId"],
                "recordRevision": data["revision"],
            }
        ):
            raise ValueError("subject differs")
        causation = envelope["causation"]
        if (
            not isinstance(causation, dict)
            or set(causation) - {"root", "hop", "parent"}
            or type(causation.get("hop")) is not int
            or causation["hop"] < 0
            or str(uuid.UUID(causation["root"])) != causation["root"]
            or (
                causation["hop"] == 0
                and (causation["root"] != envelope["id"] or "parent" in causation)
            )
            or (
                causation["hop"] > 0
                and str(uuid.UUID(causation["parent"])) != causation["parent"]
            )
        ):
            raise ValueError("causation differs")
        return data["proposalId"], data["submissionVersion"], data["effectDigest"]
    except (ValueError, TypeError, KeyError, ValidationError):
        raise WakeRefused(
            "the authenticated native Proposal envelope was refused"
        ) from None


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
                "CREATE TABLE IF NOT EXISTS wake_subjects (wake_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, version INTEGER NOT NULL, effect_digest TEXT, consumed INTEGER NOT NULL DEFAULT 0)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS poll_order (proposal_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)"
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

    def accept(
        self, method, path, headers, body, *, key, source, event_type, schema, now=None
    ):
        from registry_client.breg import (
            BaseRegistryClientError,
            verify_webhook_delivery,
        )

        if not body or len(body) > MAXIMUM_BODY:
            raise WakeRefused("hook body was refused")
        try:
            verified = verify_webhook_delivery(
                method=method, path=path, headers=headers, body=body, key=key
            )
            delivered = datetime.fromisoformat(verified["delivery_time"])
            instant = datetime.now(UTC) if now is None else now
            if abs((instant - delivered).total_seconds()) > 300:
                raise WakeRefused("hook delivery time is outside the accepted window")
            if (verified["source"], verified["type"], verified["dataschema"]) != (
                source,
                event_type,
                schema,
            ):
                raise WakeRefused("hook source, type, or schema was refused")
        except (BaseRegistryClientError, ValueError, TypeError, KeyError):
            raise WakeRefused(
                "hook signature or expected envelope was refused"
            ) from None
        proposal_id, version, effect_digest = proposal_subject(verified)
        # Replay generations change the transport idempotency key. The event
        # identity and captured bytes remain stable across every generation.
        identity = json.dumps(
            [verified["source"], verified["id"]], separators=(",", ":")
        )
        digest = hashlib.sha256(verified["body"]).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT digest FROM wakes WHERE id=?", (identity,)
            ).fetchone()
            if previous:
                if previous[0] != digest:
                    raise WakeRefused("hook identity conflicts with its accepted bytes")
                return False
            db.execute(
                "INSERT INTO wakes VALUES (?,?,?)", (identity, digest, verified["time"])
            )
            db.execute(
                "INSERT INTO wake_subjects(wake_id,proposal_id,version,effect_digest) VALUES (?,?,?,?)",
                (identity, proposal_id, version, effect_digest),
            )
        return True

    def pending(self):
        with self.connect() as db:
            return db.execute(
                "SELECT COUNT(*) FROM wake_subjects WHERE consumed=0"
            ).fetchone()[0]

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
            db.execute("BEGIN IMMEDIATE")
            sequence = db.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM poll_order"
            ).fetchone()[0]
            rows = db.execute(
                "SELECT j.id,j.body,j.state,j.attempts FROM jobs j LEFT JOIN poll_order p ON p.proposal_id=j.id WHERE state!='notified' "
                "ORDER BY COALESCE(p.sequence,0),EXISTS(SELECT 1 FROM wake_subjects w WHERE w.consumed=0 AND w.proposal_id=j.id "
                "AND w.version=json_extract(j.body,'$.version') AND w.effect_digest=json_extract(j.body,'$.effectDigest')) DESC,j.id LIMIT 100"
            ).fetchall()
            # Rotate durable bounded batches even when earlier work is awaiting
            # review or needs operator recovery. Hints prioritize equally due work.
            db.executemany(
                "INSERT INTO poll_order VALUES (?,?) ON CONFLICT(proposal_id) DO UPDATE SET sequence=excluded.sequence",
                ((row[0], sequence) for row in rows),
            )
            return rows

    def consume(self, proposal_id, version, effect_digest):
        with self.connect() as db:
            db.execute(
                "UPDATE wake_subjects SET consumed=1 WHERE proposal_id=? AND version=? AND effect_digest=?",
                (proposal_id, version, effect_digest),
            )


class TokenSource:
    """One independent provider per product resource, with no token logging."""

    def __init__(self, config):
        if not isinstance(config, dict):
            raise CompositionError("product token configuration must be an object")
        if set(config) == {"headerFile", "resource", "scopes"}:
            resource, scopes = config["resource"], config["scopes"]
            if not isinstance(config["headerFile"], str) or not config["headerFile"]:
                raise CompositionError("product credential file is required")
        elif set(config) == {"privateKeyJwt"} and isinstance(
            config["privateKeyJwt"], dict
        ):
            resource = config["privateKeyJwt"].get("resource")
            scopes = config["privateKeyJwt"].get("scopes")
        else:
            raise CompositionError(
                "choose exactly one headerFile or privateKeyJwt product credential"
            )
        if (
            not isinstance(resource, str)
            or not resource
            or any(c.isspace() for c in resource)
            or not isinstance(scopes, list)
            or not scopes
            or any(
                not isinstance(value, str)
                or not value
                or any(c.isspace() for c in value)
                for value in scopes
            )
        ):
            raise CompositionError(
                "configure the product resource and its non-empty scope list"
            )
        self.config = config
        self.provider = None
        if "privateKeyJwt" in config:
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
        if (
            set(config["tokens"]) - {"breg", "casework", "messaging"}
            or "breg" not in config["tokens"]
        ):
            raise CompositionError(
                "configure only the selected product token providers"
            )
        selected = {"breg"} | {
            name for name in ("casework", "messaging") if name + "Url" in config
        }
        if set(config["tokens"]) != selected:
            raise CompositionError("each selected product needs its own token provider")
        self.tokens = {
            name: TokenSource(value) for name, value in config["tokens"].items()
        }
        self.registry = breg.BaseRegistryClient(
            config["bregUrl"],
            authorization=self.tokens["breg"].breg_authorization(),
            max_mutation_retries=0,
        )
        self.reviews = (
            casework.CaseworkClient(config["caseworkUrl"], max_mutation_retries=0)
            if "caseworkUrl" in config
            else None
        )
        self.messages = (
            messaging.MessagingClient(config["messagingUrl"], max_mutation_retries=0)
            if "messagingUrl" in config
            else None
        )

    def prepare(self, action, inputs, key, intake_proposal_id=None):
        profile = self.config["bregProfile"]
        attachment = None
        if intake_proposal_id is not None:
            get_binding = self.registry.registry_contract(profile).select_proposal_get(
                profile
            )
            intake = self.registry.get_proposal(get_binding, intake_proposal_id)
            document = intake.document
            receipt = document.get("application", {})
            if (
                document.get("actionId") != "submit-application"
                or document.get("state") != "applied"
                or not document.get("effectDigest")
                or receipt.get("effectDigest") != document.get("effectDigest")
                or receipt.get("submissionVersion") != document.get("submissionVersion")
                or not inputs.get("application")
                or receipt.get("resultLinks")
                != [
                    {
                        "recordType": "application",
                        "recordId": inputs["application"],
                        "revision": 1,
                    }
                ]
            ):
                raise CompositionError(
                    "the native intake receipt does not bind this application"
                )
            attachment = self.registry.download_proposal_attachment(
                intake, "supporting-document"
            )
        binding = self.registry.registry_contract(profile).select_action(
            action, profile
        )
        draft = self.registry.start_proposal(binding, inputs, key + ":draft")
        # The optional licensing adaptation copies a governed slot before
        # Submit. Attachment bytes are never invented Action input fields.
        if attachment is not None:
            draft = self.registry.upload_proposal_attachment(
                draft,
                "supporting-document",
                attachment["media_type"],
                attachment["body"],
                key + ":document",
            )
        return self.registry.execute_proposal(
            self.registry.prepare_proposal(draft, "submit", {}, key + ":submit")
        )

    def review_tasks(self):
        if self.reviews is None:
            raise CompositionError(
                "configure the selected Casework deployment before listing tasks"
            )
        return self.reviews.review_tasks(
            self.tokens["casework"].bearer_token(),
            self.config["caseworkProfile"],
            source_profile=self.config.get("caseworkSourceProfile"),
        )

    def review_context(self, task_id):
        if self.reviews is None:
            raise CompositionError("configure Casework before reading review context")
        return self.reviews.review_task_context(
            self.tokens["casework"].bearer_token(),
            self.config["caseworkProfile"],
            task_id,
            source_profile=self.config.get("caseworkSourceProfile"),
        )

    def claim(self, task_id, revision, key):
        if self.reviews is None:
            raise CompositionError("configure Casework before claiming a task")
        return self.reviews.claim_review_task(
            self.tokens["casework"].bearer_token(),
            self.config["caseworkProfile"],
            task_id,
            revision,
            key,
            source_profile=self.config.get("caseworkSourceProfile"),
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
            source_profile=self.config.get("caseworkSourceProfile"),
        )

    def _job_failed(self, proposal_id, stage, *, charge=False):
        if charge:
            with self.inbox.connect() as db:
                db.execute(
                    "UPDATE jobs SET attempts=attempts+1 WHERE id=?", (proposal_id,)
                )
        reference = hashlib.sha256(proposal_id.encode()).hexdigest()[:16]
        LOG.error(
            "job reconciliation refused; stage=%s job=%s; inspect the stored job "
            "and authoritative source or original notice receipt before retrying",
            stage,
            reference,
        )

    def reconcile(self):
        if self.messages is None:
            raise CompositionError(
                "configure Messaging before applying and notifying registered jobs"
            )
        from registry_client.messaging import MessagingClientError

        profile = self.config["bregProfile"]
        binding = self.registry.registry_contract(profile).select_proposal_get(profile)
        count = 0
        for proposal_id, body, state, attempts in self.inbox.jobs():
            if state != "notice-uncertain" and attempts >= MAXIMUM_ATTEMPTS:
                self._job_failed(proposal_id, "budget")
                continue
            job = json.loads(body)
            version, effect_digest, notice = (
                job["version"],
                job["effectDigest"],
                job["notice"],
            )
            try:
                current = self.registry.get_proposal(binding, proposal_id)
            except Exception:
                self._job_failed(
                    proposal_id, "read", charge=state != "notice-uncertain"
                )
                continue
            document = current.document
            if (
                document["submissionVersion"] != version
                or document.get("effectDigest") != effect_digest
            ):
                self._job_failed(
                    proposal_id, "binding", charge=state != "notice-uncertain"
                )
                continue
            self.inbox.consume(proposal_id, version, effect_digest)
            if document["state"] != "applied":
                # The native SDK selects the source-issued lifecycle link and
                # opaque ETag. An unavailable Apply is refused before mutation.
                try:
                    prepared = self.registry.prepare_proposal(
                        current,
                        "apply",
                        {
                            "submissionVersion": version,
                            "effectDigest": effect_digest,
                        },
                        f"{proposal_id}:{version}:apply",
                    )
                except Exception as error:
                    if getattr(error, "kind", None) == "invalid-request":
                        LOG.info(
                            "Proposal is not currently applicable; awaiting authoritative source state"
                        )
                        continue
                    self._job_failed(
                        proposal_id, "prepare", charge=state != "notice-uncertain"
                    )
                    continue
                if attempts >= MAXIMUM_ATTEMPTS:
                    self._job_failed(proposal_id, "budget")
                    continue
                with self.inbox.connect() as db:
                    db.execute(
                        "UPDATE jobs SET attempts=attempts+1 WHERE id=?", (proposal_id,)
                    )
                attempts += 1
                try:
                    self.registry.execute_proposal(prepared)
                except Exception:
                    self._job_failed(proposal_id, "apply")
                    continue
                try:
                    current = self.registry.get_proposal(binding, proposal_id)
                except Exception:
                    self._job_failed(proposal_id, "confirm")
                    continue
                if current.document["state"] != "applied":
                    self._job_failed(proposal_id, "confirm")
                    continue
            notice_key = f"{proposal_id}:{version}:notice"
            if state == "notice-uncertain":
                token = self.tokens["messaging"].bearer_token()
                try:
                    receipt = self.messages.message_receipt(token, notice_key, notice)
                except Exception:
                    self._job_failed(proposal_id, "receipt")
                    continue
                if receipt.get("kind") != "complete":
                    self._job_failed(proposal_id, "receipt")
                    continue
            else:
                if attempts >= MAXIMUM_ATTEMPTS:
                    self._job_failed(proposal_id, "budget")
                    continue
                with self.inbox.connect() as db:
                    db.execute(
                        "UPDATE jobs SET state='notice-uncertain',attempts=attempts+1 WHERE id=?",
                        (proposal_id,),
                    )
                # A lost response leaves notice-uncertain on disk. The next
                # pass reads the receipt; it never blindly repeats submission.
                token = self.tokens["messaging"].bearer_token()
                try:
                    self.messages.submit(token, notice_key, notice)
                except MessagingClientError as error:
                    # A native known refusal permits another bounded attempt.
                    # Expired or conflicting keys can describe earlier accepted
                    # work and still require original-command investigation.
                    if error.outcome_unknown is False and error.code not in {
                        "idempotency.expired",
                        "idempotency.key-reused",
                    }:
                        with self.inbox.connect() as db:
                            db.execute(
                                "UPDATE jobs SET state='prepared' WHERE id=?",
                                (proposal_id,),
                            )
                    self._job_failed(proposal_id, "submit")
                    continue
                except Exception:
                    self._job_failed(proposal_id, "submit")
                    continue
            with self.inbox.connect() as db:
                db.execute(
                    "UPDATE jobs SET state='notified' WHERE id=?", (proposal_id,)
                )
            count += 1
        return count


def receiver(inbox, *, key, source, event_type, schema):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def refuse(self, status, code, detail):
            trace = uuid.uuid4().hex
            body = json.dumps(
                {
                    "type": "https://example.org/problems/" + code,
                    "title": "Hook refused",
                    "status": status,
                    "detail": detail,
                    "code": code,
                    "traceId": trace,
                }
            ).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/problem+json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("traceparent", f"00-{trace}-{uuid.uuid4().hex[:16]}-01")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            try:
                if (
                    self.path != "/hooks/breg"
                    or len(self.headers.get_all("Content-Length", [])) != 1
                    or self.headers.get("Transfer-Encoding")
                ):
                    raise WakeRefused("hook target or body framing refused")
                length = int(self.headers["Content-Length"])
                if not 0 < length <= MAXIMUM_BODY:
                    raise WakeRefused("hook body exceeds its bound")
                headers = {}
                seen = set()
                for name, value in self.headers.items():
                    if name.lower() in seen:
                        raise WakeRefused("a hook header is repeated")
                    headers[name] = value
                    seen.add(name.lower())
                inbox.accept(
                    "POST",
                    self.path,
                    headers,
                    self.rfile.read(length),
                    key=key,
                    source=source,
                    event_type=event_type,
                    schema=schema,
                )
            except (ValueError, WakeRefused):
                self.refuse(
                    403,
                    "receiver.hook-refused",
                    "The hook signature, target, or envelope was refused.",
                )
                return
            except sqlite3.Error:
                LOG.error("hook persistence unavailable")
                self.refuse(
                    503,
                    "receiver.persistence-unavailable",
                    "The hook could not be persisted; retry the same event.",
                )
                return
            self.send_response(204)
            self.end_headers()

        def log_message(self, message, *args):
            LOG.info("hook HTTP request handled")

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve-wakes")
    sub.add_parser("review-tasks")
    context = sub.add_parser("review-context")
    context.add_argument("task_id")
    sub.add_parser("reconcile")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("action")
    prepare.add_argument("inputs", type=Path)
    prepare.add_argument("key")
    prepare.add_argument(
        "--intake-proposal",
        help="copy the native licensing intake supporting-document slot before Submit",
    )
    register = sub.add_parser("register")
    register.add_argument("proposal_id")
    register.add_argument("version", type=int)
    register.add_argument("effect_digest")
    register.add_argument("notice", type=Path)
    claim = sub.add_parser("claim")
    claim.add_argument("task_id")
    claim.add_argument("revision", type=int)
    claim.add_argument("key")
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
        key = Path(config["hookKeyFile"]).read_bytes()
        host, port = config.get("listen", "127.0.0.1:9300").rsplit(":", 1)
        if host != "127.0.0.1":
            raise CompositionError("put the example receiver behind a local TLS proxy")
        ThreadingHTTPServer(
            (host, int(port)),
            receiver(
                inbox,
                key=key,
                source=config["hookSource"],
                event_type=config["hookType"],
                schema=config["hookSchema"],
            ),
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
            args.action,
            strict_json(args.inputs.read_bytes()),
            args.key,
            intake_proposal_id=args.intake_proposal,
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
    elif args.command == "review-context":
        print(json.dumps(app.review_context(args.task_id)))
    elif args.command == "claim":
        print(json.dumps(app.claim(args.task_id, args.revision, args.key)))
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
