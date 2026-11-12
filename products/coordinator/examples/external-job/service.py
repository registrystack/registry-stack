"""Application-owned durable admission for the external-job Coordinator example.

The table and transaction in this module belong to this example application.
They are not a Registry Stack job store, callback protocol, or idempotency
decorator. Coordinator owns command recovery and bounded observation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from http import HTTPStatus
import json
import os
import re
from socketserver import ThreadingMixIn
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.parse import parse_qs
import uuid
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server


_SCHEMA = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
_STATES = frozenset(("queued", "running", "succeeded", "failed"))
_MAX_BODY_BYTES = 16 * 1024
_MAX_KEY_BYTES = 200


class AdmissionConflict(ValueError):
    """One Coordinator command key was already bound to different work."""

    def __init__(self) -> None:
        super().__init__("idempotency-conflict")


@dataclass(frozen=True)
class JobReceipt:
    """The stable result of admitting one application job."""

    job_id: str

    def as_json(self) -> dict[str, str]:
        return {"jobId": self.job_id}


class JobStore:
    """The example application's PostgreSQL job table and transaction."""

    def __init__(self, database_url: str, *, schema: str = "external_job_example"):
        if not database_url:
            raise ValueError("database_url is required")
        if not _SCHEMA.fullmatch(schema):
            raise ValueError("schema must be a bounded PostgreSQL identifier")
        self._database_url = database_url
        self._schema = schema

    def migrate(self) -> None:
        """Create this example's application-owned table."""
        from psycopg import sql

        statement = sql.SQL(
            """
            CREATE SCHEMA IF NOT EXISTS {};
            CREATE TABLE IF NOT EXISTS {}.jobs (
                job_id uuid PRIMARY KEY,
                admission_key varchar(200) NOT NULL UNIQUE,
                request_digest bytea NOT NULL,
                request_body jsonb NOT NULL,
                receipt jsonb NOT NULL,
                state text NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
                created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
                CHECK (receipt = jsonb_build_object('jobId', job_id::text))
            )
            """
        ).format(sql.Identifier(self._schema), sql.Identifier(self._schema))
        with self._connect() as connection:
            connection.execute(statement)

    def admit(
        self,
        key: str,
        request: Mapping[str, object],
        *,
        after_commit: Callable[[JobReceipt], None] | None = None,
    ) -> JobReceipt:
        """Commit the job and its stable receipt in one application transaction."""
        self._validate_key(key)
        request_bytes = _canonical_json(request)
        request_digest = hashlib.sha256(request_bytes).digest()
        job_id = str(uuid.uuid4())
        receipt = JobReceipt(job_id)

        from psycopg import sql

        insert = sql.SQL(
            """
            INSERT INTO {}.jobs
                (job_id, admission_key, request_digest, request_body, receipt)
            VALUES (%s, %s, %s, %s::jsonb, %s::jsonb)
            ON CONFLICT (admission_key) DO NOTHING
            RETURNING receipt
            """
        ).format(sql.Identifier(self._schema))
        existing = sql.SQL(
            "SELECT request_digest, receipt FROM {}.jobs WHERE admission_key = %s"
        ).format(sql.Identifier(self._schema))

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    insert,
                    (
                        job_id,
                        key,
                        request_digest,
                        request_bytes.decode("utf-8"),
                        json.dumps(receipt.as_json(), separators=(",", ":")),
                    ),
                )
                row = cursor.fetchone()
                if row is None:
                    cursor.execute(existing, (key,))
                    row = cursor.fetchone()
                    if row is None:
                        raise RuntimeError("duplicate admission has no durable receipt")
                    saved_digest, saved_receipt = row
                    if bytes(saved_digest) != request_digest:
                        raise AdmissionConflict()
                    receipt = _receipt(saved_receipt)
                else:
                    receipt = _receipt(row[0])

        if after_commit is not None:
            after_commit(receipt)
        return receipt

    def status(self, job_id: str) -> str | None:
        """Read the current state of one exact durable job."""
        try:
            uuid.UUID(job_id)
        except (ValueError, AttributeError):
            return None
        from psycopg import sql

        statement = sql.SQL("SELECT state FROM {}.jobs WHERE job_id = %s").format(
            sql.Identifier(self._schema)
        )
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement, (job_id,))
                row = cursor.fetchone()
        return None if row is None else row[0]

    def transition(self, job_id: str, state: str) -> None:
        """Move a job along the example worker's finite state machine."""
        if state not in _STATES or state == "queued":
            raise ValueError("invalid job transition")
        from psycopg import sql

        allowed = ("queued",) if state == "running" else ("running",)
        statement = sql.SQL(
            """
            UPDATE {}.jobs
            SET state = %s, updated_at = clock_timestamp()
            WHERE job_id = %s AND state = ANY(%s)
            """
        ).format(sql.Identifier(self._schema))
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement, (state, job_id, list(allowed)))
                changed = cursor.rowcount
        if changed != 1:
            raise ValueError("invalid job transition")

    def _connect(self):
        import psycopg

        return psycopg.connect(self._database_url)

    @staticmethod
    def _validate_key(key: str) -> None:
        if (
            not isinstance(key, str)
            or not key
            or len(key.encode("utf-8")) > _MAX_KEY_BYTES
            or key.strip() != key
            or any(ord(character) < 33 or ord(character) == 127 for character in key)
        ):
            raise ValueError("invalid idempotency key")


class _Store(Protocol):
    def admit(self, key: str, request: dict[str, object]) -> JobReceipt: ...

    def status(self, job_id: str) -> str | None: ...


class _MachineAdmission(Protocol):
    def admit(self, request_values: Mapping[str, Any]) -> object: ...


class JobApplication:
    """A small WSGI boundary for Coordinator's exact POST and GET contracts."""

    def __init__(
        self,
        store: _Store,
        admission: _MachineAdmission,
        *,
        encode_json: Callable[[object], bytes] | None = None,
    ):
        self._store = store
        self._machine_admission = admission
        self._encode_json = encode_json or _encode_json

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], None],
    ) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD")
        path = environ.get("PATH_INFO")
        if method == "POST" and path == "/jobs":
            refused = self._admit_machine(environ, start_response)
            if refused is not None:
                return refused
            return self._admit(environ, start_response)
        if method == "GET" and path == "/jobs/status":
            refused = self._admit_machine(environ, start_response)
            if refused is not None:
                return refused
            return self._status(environ, start_response)
        return self._response(
            start_response, HTTPStatus.NOT_FOUND, {"reason": "route-not-found"}
        )

    def _admit_machine(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], None],
    ) -> Iterable[bytes] | None:
        try:
            self._machine_admission.admit(
                {"authorization": environ.get("HTTP_AUTHORIZATION")}
            )
        except Exception as error:
            code = getattr(error, "code", None)
            if code == "authentication.refused":
                return self._response(
                    start_response,
                    HTTPStatus.UNAUTHORIZED,
                    {"code": "authentication.refused"},
                )
            if code == "authentication.unavailable":
                return self._response(
                    start_response,
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"code": "authentication.unavailable"},
                )
            raise
        return None

    def _admit(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], None],
    ) -> Iterable[bytes]:
        key = environ.get("HTTP_IDEMPOTENCY_KEY")
        if not isinstance(key, str) or not key:
            return self._response(
                start_response,
                HTTPStatus.BAD_REQUEST,
                {"reason": "missing-idempotency-key"},
            )
        try:
            length = int(environ.get("CONTENT_LENGTH", ""))
            if length < 2 or length > _MAX_BODY_BYTES:
                raise ValueError
            raw = environ["wsgi.input"].read(length)
            if len(raw) != length:
                raise ValueError
            body = json.loads(raw)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return self._response(
                start_response,
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"reason": "invalid-job"},
            )
        if not _valid_job(body):
            return self._response(
                start_response,
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"reason": "invalid-job"},
            )
        try:
            receipt = self._store.admit(key, body)
        except AdmissionConflict:
            return self._response(
                start_response,
                HTTPStatus.CONFLICT,
                {"reason": "idempotency-conflict"},
            )
        except ValueError:
            return self._response(
                start_response,
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"reason": "invalid-job"},
            )
        return self._response(start_response, HTTPStatus.CREATED, receipt.as_json())

    def _status(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], None],
    ) -> Iterable[bytes]:
        try:
            query = parse_qs(
                environ.get("QUERY_STRING", ""),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=1,
            )
            identifiers = query["id"]
            if len(query) != 1 or len(identifiers) != 1 or not identifiers[0]:
                raise ValueError
            job_id = identifiers[0]
        except (KeyError, TypeError, ValueError):
            return self._response(
                start_response,
                HTTPStatus.BAD_REQUEST,
                {"reason": "invalid-job-reference"},
            )
        state = self._store.status(job_id)
        if state is None:
            return self._response(
                start_response,
                HTTPStatus.NOT_FOUND,
                {"reason": "job-not-found"},
            )
        return self._response(
            start_response,
            HTTPStatus.OK,
            {"jobId": job_id, "state": state},
        )

    def _response(
        self,
        start_response: Callable[[str, list[tuple[str, str]]], None],
        status: HTTPStatus,
        body: object,
    ) -> Iterable[bytes]:
        encoded = self._encode_json(body)
        start_response(
            f"{status.value} {status.phrase}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(encoded))),
                ("Cache-Control", "no-store"),
            ],
        )
        return (encoded,)


def _canonical_json(value: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("invalid job request") from error


def _encode_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _receipt(value: object) -> JobReceipt:
    if not isinstance(value, dict) or set(value) != {"jobId"}:
        raise RuntimeError("durable receipt is invalid")
    job_id = value["jobId"]
    if not isinstance(job_id, str):
        raise RuntimeError("durable receipt is invalid")
    try:
        uuid.UUID(job_id)
    except ValueError as error:
        raise RuntimeError("durable receipt is invalid") from error
    return JobReceipt(job_id)


def _valid_job(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"reference"}:
        return False
    reference = value["reference"]
    return (
        isinstance(reference, str)
        and 1 <= len(reference) <= 64
        and reference.strip() == reference
        and not any(ord(character) < 32 or ord(character) == 127 for character in reference)
    )


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def main() -> None:
    from registry_client import connect

    database_url = os.environ.get("EXTERNAL_JOB_DATABASE_URL")
    if not database_url:
        raise SystemExit("EXTERNAL_JOB_DATABASE_URL is required")
    try:
        port = int(os.environ.get("EXTERNAL_JOB_PORT", "9010"))
    except ValueError as error:
        raise SystemExit("EXTERNAL_JOB_PORT must be an integer") from error
    if port < 1 or port > 65535:
        raise SystemExit("EXTERNAL_JOB_PORT must be between 1 and 65535")
    store = JobStore(database_url)
    store.migrate()
    app = JobApplication(store, connect())
    with make_server(
        "127.0.0.1",
        port,
        app,
        server_class=_ThreadingWSGIServer,
        handler_class=WSGIRequestHandler,
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
