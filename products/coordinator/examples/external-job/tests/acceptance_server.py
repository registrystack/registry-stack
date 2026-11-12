"""Test-only HTTP host for the maintained external-job application.

The host composes the existing application and store with the installed
Registry Stack Python wheel. It is an acceptance fixture, not a reusable job
server, authentication server, or production entry point.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
from socketserver import ThreadingMixIn
import sys
import threading
from typing import Any, Mapping
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server


EXAMPLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE))

from service import (  # noqa: E402
    AdmissionConflict,
    JobApplication,
    JobReceipt,
    JobStore,
)

__all__ = [
    "AcceptanceServer",
    "AcceptanceJobStore",
    "AdmissionConflict",
    "JobReceipt",
    "MachineAdmission",
    "POST_COMMIT_EXIT_CODE",
    "SYNTHETIC_TOKEN",
    "installed_wheel_available",
]

try:
    from registry_client.machine import MachineAdmission
except ModuleNotFoundError:
    MachineAdmission = None


SYNTHETIC_TOKEN = "external-job-acceptance-token"
POST_COMMIT_EXIT_CODE = 86
FAULTS = (
    "none",
    "declared-refusal",
    "malformed-response-after-commit",
    "encoding-error-after-commit",
    "process-exit-after-commit",
)

_ISSUER = "https://issuer.example.invalid/"
_RESOURCE = "urn:example:external-job"
_CLIENT_ID = "coordinator-external-job"
_PROFILE = "coordinator-invoker"
_SCOPES = ("external-job:admit", "external-job:observe")
_CLAIMS = {"registry_actor_kind": "service"}


@dataclass(frozen=True)
class _VerifiedToken:
    kind: str = "access"
    issuer: str = _ISSUER
    audiences: tuple[str, ...] = (_RESOURCE,)
    subject: str = "coordinator-service"
    client_id: str = _CLIENT_ID
    scopes: tuple[str, ...] = _SCOPES
    claims: Mapping[str, str] | None = None


class _VerificationFailure(ValueError):
    kind = "verification"


class _SyntheticVerifier:
    """A deterministic verifier seam for composition without a live issuer."""

    def verify(self, token: str) -> _VerifiedToken:
        if token != SYNTHETIC_TOKEN:
            raise _VerificationFailure("synthetic token refused")
        return _VerifiedToken(claims=_CLAIMS)


def _machine_admission():
    if not installed_wheel_available():
        raise RuntimeError(
            "the external-job acceptance server requires an installed "
            "assembled registry-stack-client wheel"
        )
    return MachineAdmission(
        _SyntheticVerifier(),
        issuer=_ISSUER,
        resource=_RESOURCE,
        client_id=_CLIENT_ID,
        profile=_PROFILE,
        required_scopes=_SCOPES,
        required_claims=_CLAIMS,
    )


def installed_wheel_available() -> bool:
    if MachineAdmission is None:
        return False
    source = Path(sys.modules[MachineAdmission.__module__].__file__).resolve()
    return "site-packages" in source.parts


class _FaultingStore:
    def __init__(self, store: Any, fault: str):
        self._store = store
        self._fault = fault

    def admit(self, key: str, request: dict[str, object]) -> JobReceipt:
        if self._fault == "declared-refusal":
            raise ValueError("synthetic declared refusal")
        if self._fault == "process-exit-after-commit":
            return self._store.admit(
                key,
                request,
                after_commit=lambda _receipt: os._exit(POST_COMMIT_EXIT_CODE),
            )
        return self._store.admit(key, request)

    def status(self, job_id: str) -> str | None:
        return self._store.status(job_id)

    def transition(self, job_id: str, state: str) -> None:
        self._store.transition(job_id, state)

    def snapshot(self) -> list[dict[str, object]]:
        return self._store.snapshot()


class _SnapshotLimit(RuntimeError):
    pass


class AcceptanceJobStore(JobStore):
    """The application store plus one bounded, test-only inspection."""

    def snapshot(self) -> list[dict[str, object]]:
        from psycopg import sql

        statement = sql.SQL(
            """
            SELECT admission_key, request_body, receipt
            FROM {}.jobs
            ORDER BY created_at, job_id
            LIMIT 17
            """
        ).format(sql.Identifier(self._schema))
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement)
                rows = cursor.fetchall()
        if len(rows) > 16:
            raise _SnapshotLimit("the external-job acceptance snapshot is full")
        return [
            {"key": key, "request": request, "receipt": receipt}
            for key, request, receipt in rows
        ]


class _ResponseEncoder:
    def __init__(self, fault: str):
        self._fault = fault
        self._used = False
        self._lock = threading.Lock()

    def __call__(self, value: object) -> bytes:
        is_receipt = isinstance(value, dict) and set(value) == {"jobId"}
        with self._lock:
            inject = is_receipt and not self._used
            if inject:
                self._used = True
        if inject and self._fault == "malformed-response-after-commit":
            return b"not-json"
        if inject and self._fault == "encoding-error-after-commit":
            raise UnicodeError("synthetic response encoding failure")
        return json.dumps(value, separators=(",", ":")).encode("utf-8")


class _AcceptanceApplication:
    """Machine-protected controls around the maintained application."""

    def __init__(
        self, application: JobApplication, store: _FaultingStore, admission: Any
    ):
        self._application = application
        self._store = store
        self._admission = admission

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD")
        path = environ.get("PATH_INFO")
        if method == "POST" and path == "/test/transition":
            refused = self._admit(environ, start_response)
            if refused is not None:
                return refused
            return self._transition(environ, start_response)
        if method == "GET" and path == "/test/snapshot":
            refused = self._admit(environ, start_response)
            if refused is not None:
                return refused
            return self._snapshot(start_response)
        return self._application(environ, start_response)

    def _admit(self, environ, start_response):
        try:
            self._admission.admit({"authorization": environ.get("HTTP_AUTHORIZATION")})
        except Exception as error:
            code = getattr(error, "code", None)
            if code == "authentication.refused":
                return self._response(
                    start_response, 401, {"code": "authentication.refused"}
                )
            if code == "authentication.unavailable":
                return self._response(
                    start_response, 503, {"code": "authentication.unavailable"}
                )
            raise
        return None

    def _transition(self, environ, start_response):
        try:
            length = int(environ.get("CONTENT_LENGTH", ""))
            if (
                not 2 <= length <= 4096
                or environ.get("CONTENT_TYPE") != "application/json"
            ):
                raise ValueError
            raw = environ["wsgi.input"].read(length)
            if len(raw) != length:
                raise ValueError

            def unique_members(pairs):
                value = {}
                for name, member in pairs:
                    if name in value:
                        raise ValueError
                    value[name] = member
                return value

            body = json.loads(raw, object_pairs_hook=unique_members)
            if (
                not isinstance(body, dict)
                or set(body) != {"jobId", "state"}
                or not isinstance(body["jobId"], str)
                or body["state"] not in ("running", "succeeded", "failed")
            ):
                raise ValueError
            self._store.transition(body["jobId"], body["state"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return self._response(start_response, 422, {"reason": "invalid-transition"})
        return self._response(start_response, 204, None)

    def _snapshot(self, start_response):
        try:
            jobs = self._store.snapshot()
            if len(jobs) > 16:
                raise _SnapshotLimit("the external-job acceptance snapshot is full")
        except _SnapshotLimit:
            return self._response(
                start_response, 503, {"reason": "snapshot-unavailable"}
            )
        return self._response(
            start_response, 200, {"jobCount": len(jobs), "jobs": jobs}
        )

    @staticmethod
    def _response(start_response, status: int, body: object):
        phrases = {
            200: "OK",
            204: "No Content",
            401: "Unauthorized",
            422: "Unprocessable Content",
            503: "Service Unavailable",
        }
        encoded = (
            b""
            if body is None
            else json.dumps(body, separators=(",", ":")).encode("utf-8")
        )
        headers = [("Content-Length", str(len(encoded))), ("Cache-Control", "no-store")]
        if body is not None:
            headers.append(("Content-Type", "application/json"))
        start_response(f"{status} {phrases[status]}", headers)
        return (encoded,)


class _ThreadingServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietRequestHandler(WSGIRequestHandler):
    def log_message(self, _format: str, *args: object) -> None:
        return None


class AcceptanceServer:
    """A loopback host around the existing external-job WSGI application."""

    def __init__(
        self,
        store: Any,
        *,
        fault: str = "none",
        port: int = 0,
    ) -> None:
        if fault not in FAULTS:
            raise ValueError("unknown external-job acceptance fault")
        admission = _machine_admission()
        faulting_store = _FaultingStore(store, fault)
        application = JobApplication(
            faulting_store,
            admission,
            encode_json=_ResponseEncoder(fault),
        )
        application = _AcceptanceApplication(application, faulting_store, admission)
        self._server = make_server(
            "127.0.0.1",
            port,
            application,
            server_class=_ThreadingServer,
            handler_class=_QuietRequestHandler,
        )
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("the external-job acceptance server is already running")
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="external-job-acceptance",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._thread is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("the external-job acceptance server did not stop")
        self._thread = None

    def wait(self) -> None:
        thread = self._thread
        if thread is None:
            raise RuntimeError("the external-job acceptance server is not running")
        thread.join()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--fault", choices=FAULTS, default="none")
    parser.add_argument("--schema", default="external_job_acceptance")
    args = parser.parse_args()
    database_url = os.environ.get("EXTERNAL_JOB_DATABASE_URL")
    if not database_url:
        raise SystemExit("EXTERNAL_JOB_DATABASE_URL is required")
    store = AcceptanceJobStore(database_url, schema=args.schema)
    store.migrate()
    server = AcceptanceServer(store, fault=args.fault, port=args.port)
    server.start()
    print(json.dumps({"baseUrl": server.base_url}, separators=(",", ":")), flush=True)
    try:
        server.wait()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
