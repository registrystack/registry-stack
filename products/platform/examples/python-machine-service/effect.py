"""Application-owned recovery for one keyed Messaging effect.

This is deliberately example application code, not a generic idempotency
helper. Registry Messaging remains the authority for message acceptance and
receipt recovery.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
from typing import Any, Mapping, Protocol


_OPERATION = "registry-messaging.submit/v1"
_UNKNOWN_CODES = frozenset(
    ("idempotency.expired", "idempotency.key-reused", "receipt.unresolved")
)


class CommandConflict(ValueError):
    """A caller reused its command key for different immutable work."""

    def __init__(self, recovery: str) -> None:
        self.recovery = recovery
        super().__init__("message-effect.command-conflict")


class NoticeConflict(ValueError):
    """Protected application state was rewritten under an existing ID."""


class NoticeNotFound(LookupError):
    """The admitted caller has no such protected notice."""


class TargetUnavailable(LookupError):
    """The original workload authority is not configured in this process."""


class _MachineContext(Protocol):
    issuer: str
    resource: str
    subject: str
    client_id: str
    profile: str
    persona: str


class _Messaging(Protocol):
    def submit(self, key: str, request: dict[str, Any]) -> dict[str, Any]: ...

    def message_receipt(self, key: str, request: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class EffectResult:
    """The bounded HTTP contract consumed by the Coordinator interpreter."""

    status: int
    body: dict[str, Any]


@dataclass(frozen=True)
class _Notice:
    authority: str
    request: dict[str, Any]


@dataclass(frozen=True)
class _Command:
    command_id: str
    authority: str
    request: dict[str, Any]
    state: str
    receipt: dict[str, Any] | None
    refusal_code: str | None


class MessageEffectStore:
    """The example application's durable SQLite command snapshot."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def migrate(self) -> None:
        """Create the application-owned protected notice and command tables."""
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self._path.parent.stat()
        if stat.S_IMODE(parent.st_mode) & 0o077:
            raise PermissionError("message effect directory must be owner-only")
        descriptor = os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        database = self._path.stat()
        if database.st_uid != os.getuid() or stat.S_IMODE(database.st_mode) & 0o077:
            raise PermissionError("message effect database must be owner-only")
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS protected_notices (
                    owner_id TEXT NOT NULL,
                    notice_id TEXT NOT NULL,
                    authority_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    PRIMARY KEY (owner_id, notice_id)
                );
                CREATE TABLE IF NOT EXISTS message_commands (
                    command_id TEXT PRIMARY KEY,
                    authority_id TEXT NOT NULL,
                    request_digest BLOB NOT NULL,
                    request_json TEXT NOT NULL,
                    state TEXT NOT NULL
                        CHECK (state IN ('prepared', 'unknown', 'accepted', 'refused')),
                    receipt_json TEXT,
                    refusal_code TEXT,
                    CHECK (
                        (state = 'accepted' AND receipt_json IS NOT NULL AND refusal_code IS NULL)
                        OR (state = 'refused' AND receipt_json IS NULL AND refusal_code IS NOT NULL)
                        OR (state IN ('prepared', 'unknown')
                            AND receipt_json IS NULL AND refusal_code IS NULL)
                    )
                );
                """
            )
        finally:
            connection.close()

    def put_notice(
        self,
        owner: _MachineContext,
        notice_id: str,
        authority: str,
        request: Mapping[str, Any],
        *,
        service_namespace: str,
    ) -> None:
        """Insert immutable, protected business state for a later effect."""
        _bounded_text(notice_id, "notice_id", maximum_bytes=128)
        _bounded_text(authority, "authority", maximum_bytes=256)
        owner_id = _owner_id(service_namespace, owner)
        encoded = _canonical_json(request).decode("utf-8")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO protected_notices
                    (owner_id, notice_id, authority_id, request_json)
                VALUES (?, ?, ?, ?)
                """,
                (owner_id, notice_id, authority, encoded),
            )
            if cursor.rowcount == 0:
                row = connection.execute(
                    """
                    SELECT authority_id, request_json
                    FROM protected_notices
                    WHERE owner_id = ? AND notice_id = ?
                    """,
                    (owner_id, notice_id),
                ).fetchone()
                if row is None or row[0] != authority or row[1] != encoded:
                    raise NoticeConflict("protected notice is immutable")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def notice(
        self,
        owner: _MachineContext,
        notice_id: str,
        *,
        service_namespace: str,
    ) -> _Notice:
        _bounded_text(notice_id, "notice_id", maximum_bytes=128)
        owner_id = _owner_id(service_namespace, owner)
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT authority_id, request_json
                FROM protected_notices
                WHERE owner_id = ? AND notice_id = ?
                """,
                (owner_id, notice_id),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise NoticeNotFound("notice not found")
        return _Notice(row[0], json.loads(row[1]))

    def command(
        self,
        command_id: str,
        authority: str,
        request: Mapping[str, Any],
    ) -> _Command:
        """Insert one immutable snapshot, or read the exact existing one."""
        encoded = _canonical_json(request)
        digest = hashlib.sha256(authority.encode("utf-8") + b"\0" + encoded).digest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT OR IGNORE INTO message_commands
                    (command_id, authority_id, request_digest, request_json, state)
                VALUES (?, ?, ?, ?, 'prepared')
                """,
                (command_id, authority, digest, encoded.decode("utf-8")),
            )
            row = connection.execute(
                """
                SELECT authority_id, request_digest, request_json, state,
                       receipt_json, refusal_code
                FROM message_commands
                WHERE command_id = ?
                """,
                (command_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError("command insert was not readable")
            if (
                row[0] != authority
                or bytes(row[1]) != digest
                or row[2] != encoded.decode("utf-8")
            ):
                raise CommandConflict(command_id)
            connection.commit()
            return self._row(command_id, row)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def read_command(self, command_id: str) -> _Command:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT authority_id, request_digest, request_json, state,
                       receipt_json, refusal_code
                FROM message_commands
                WHERE command_id = ?
                """,
                (command_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise RuntimeError("durable command disappeared")
        return self._row(command_id, row)

    def start_submission(self, command_id: str) -> bool:
        """Commit unknown before the only call that may create the effect."""
        connection = self._connect()
        try:
            with connection:
                cursor = connection.execute(
                    """
                    UPDATE message_commands
                    SET state = 'unknown'
                    WHERE command_id = ? AND state = 'prepared'
                    """,
                    (command_id,),
                )
        finally:
            connection.close()
        return cursor.rowcount == 1

    def accept(self, command_id: str, receipt: Mapping[str, Any]) -> _Command:
        encoded = _canonical_json(receipt).decode("utf-8")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE message_commands
                SET state = 'accepted', receipt_json = ?
                WHERE command_id = ? AND state = 'unknown'
                """,
                (encoded, command_id),
            )
            current = self._read_on(connection, command_id)
            if cursor.rowcount == 0 and (
                current.state != "accepted" or current.receipt != receipt
            ):
                raise RuntimeError("command reached a conflicting terminal state")
            connection.commit()
            return current
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def refuse(self, command_id: str, code: str) -> _Command:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE message_commands
                SET state = 'refused', refusal_code = ?
                WHERE command_id = ? AND state = 'unknown'
                """,
                (code, command_id),
            )
            current = self._read_on(connection, command_id)
            if cursor.rowcount == 0 and (
                current.state != "refused" or current.refusal_code != code
            ):
                raise RuntimeError("command reached a conflicting terminal state")
            connection.commit()
            return current
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _read_on(self, connection: sqlite3.Connection, command_id: str) -> _Command:
        row = connection.execute(
            """
            SELECT authority_id, request_digest, request_json, state,
                   receipt_json, refusal_code
            FROM message_commands
            WHERE command_id = ?
            """,
            (command_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("durable command disappeared")
        return self._row(command_id, row)

    @staticmethod
    def _row(command_id: str, row: tuple[Any, ...]) -> _Command:
        return _Command(
            command_id=command_id,
            authority=row[0],
            request=json.loads(row[2]),
            state=row[3],
            receipt=None if row[4] is None else json.loads(row[4]),
            refusal_code=row[5],
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=5,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection


class MessagingTargets:
    """Resolve protected authority IDs to configured default or named bindings."""

    def __init__(
        self,
        stack: Any,
        bindings: Mapping[str, str | None],
    ) -> None:
        if not bindings:
            raise ValueError("at least one Messaging authority is required")
        normalized: dict[str, str | None] = {}
        for fingerprint, binding in bindings.items():
            _bounded_text(fingerprint, "authority", maximum_bytes=256)
            if binding is not None:
                _bounded_text(binding, "binding", maximum_bytes=128)
                authority = stack.using(binding).authority
            else:
                authority = stack.authority("messaging")
            if authority.product != "messaging":
                raise ValueError("target binding does not provide Messaging")
            if fingerprint != authority.fingerprint:
                raise ValueError(
                    "configured authority fingerprint does not match the binding"
                )
            normalized[fingerprint] = binding
        self._stack = stack
        self._bindings = normalized

    def resolve(self, authority: str) -> _Messaging:
        if authority not in self._bindings:
            raise TargetUnavailable("original Messaging authority is unavailable")
        binding = self._bindings[authority]
        if binding is None:
            return self._stack.messaging
        return self._stack.using(binding).messaging


class MessageEffect:
    """Perform or observe one caller-namespaced, application-owned command."""

    def __init__(
        self,
        store: MessageEffectStore,
        targets: MessagingTargets,
        *,
        service_namespace: str,
        maximum_inflight_submissions: int = 32,
    ) -> None:
        _bounded_text(service_namespace, "service_namespace", maximum_bytes=512)
        if not isinstance(maximum_inflight_submissions, int) or not (
            1 <= maximum_inflight_submissions <= 1024
        ):
            raise ValueError("maximum_inflight_submissions must be from 1 to 1024")
        self._store = store
        self._targets = targets
        self._service_namespace = service_namespace
        self._submissions = threading.BoundedSemaphore(maximum_inflight_submissions)

    def execute(
        self,
        caller: _MachineContext,
        client_key: str,
        notice_id: str,
    ) -> EffectResult:
        _bounded_text(client_key, "key", maximum_bytes=128)
        notice = self._store.notice(
            caller,
            notice_id,
            service_namespace=self._service_namespace,
        )
        command_id = _command_id(self._service_namespace, caller, client_key)
        command = self._store.command(
            command_id,
            notice.authority,
            notice.request,
        )
        if command.state == "accepted":
            return self._accepted(command)
        if command.state == "refused":
            return self._refused(command)
        if command.state == "unknown":
            return self._recover(command)

        if not self._submissions.acquire(blocking=False):
            current = self._store.read_command(command.command_id)
            if current.state == "unknown":
                return self._recover(current)
            if current.state == "accepted":
                return self._accepted(current)
            if current.state == "refused":
                return self._refused(current)
            return EffectResult(429, {"state": "not-processed", "code": "busy"})
        try:
            try:
                client = self._targets.resolve(command.authority)
            except TargetUnavailable:
                return self._uncertain(command.command_id)
            if not self._store.start_submission(command.command_id):
                return self._resume(self._store.read_command(command.command_id))
            try:
                completed = client.submit(command.command_id, command.request)
                receipt = _receipt(completed)
            except Exception as error:
                code = _declared_refusal(error)
                if code is None:
                    return self._uncertain(command.command_id)
                return self._refused(self._store.refuse(command.command_id, code))
            return self._accepted(self._store.accept(command.command_id, receipt))
        finally:
            self._submissions.release()

    def _resume(self, command: _Command) -> EffectResult:
        if command.state == "accepted":
            return self._accepted(command)
        if command.state == "refused":
            return self._refused(command)
        if command.state == "unknown":
            return self._recover(command)
        return EffectResult(429, {"state": "not-processed", "code": "busy"})

    def _recover(self, command: _Command) -> EffectResult:
        try:
            client = self._targets.resolve(command.authority)
            completed = client.message_receipt(command.command_id, command.request)
            receipt = _receipt(completed)
        except Exception:
            return self._uncertain(command.command_id)
        return self._accepted(self._store.accept(command.command_id, receipt))

    @staticmethod
    def _accepted(command: _Command) -> EffectResult:
        if command.receipt is None:
            raise RuntimeError("accepted command has no receipt")
        return EffectResult(
            200,
            {
                "state": "accepted",
                "receipt": command.receipt,
                "recovery": command.command_id,
            },
        )

    @staticmethod
    def _refused(command: _Command) -> EffectResult:
        if command.refusal_code is None:
            raise RuntimeError("refused command has no code")
        return EffectResult(
            422,
            {"state": "refused", "code": command.refusal_code},
        )

    @staticmethod
    def _uncertain(command_id: str) -> EffectResult:
        return EffectResult(
            202,
            {"state": "uncertain", "recovery": command_id},
        )


def _owner_id(service_namespace: str, caller: _MachineContext) -> str:
    values = _caller_values(service_namespace, caller)
    return hashlib.sha256(_canonical_json(values)).hexdigest()


def _command_id(
    service_namespace: str,
    caller: _MachineContext,
    client_key: str,
) -> str:
    values = {
        **_caller_values(service_namespace, caller),
        "operation": _OPERATION,
        "key": client_key,
    }
    return hashlib.sha256(_canonical_json(values)).hexdigest()


def _caller_values(service_namespace: str, caller: _MachineContext) -> dict[str, str]:
    values = {
        "service": service_namespace,
        "issuer": caller.issuer,
        "resource": caller.resource,
        "subject": caller.subject,
        "client": caller.client_id,
        "profile": caller.profile,
        "persona": caller.persona,
    }
    for name, value in values.items():
        _bounded_text(value, name, maximum_bytes=512)
    return values


def _receipt(completed: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(completed, Mapping) or completed.get("kind") != "complete":
        raise ValueError("Messaging response is not complete")
    receipt = completed.get("value")
    if not isinstance(receipt, dict):
        raise ValueError("Messaging response has no receipt")
    if (
        not isinstance(receipt.get("id"), str)
        or not isinstance(receipt.get("status"), str)
        or not isinstance(receipt.get("links"), dict)
    ):
        raise ValueError("Messaging receipt is malformed")
    return receipt


def _declared_refusal(error: Exception) -> str | None:
    code = getattr(error, "code", None)
    status = getattr(error, "status", None)
    if (
        getattr(error, "kind", None) == "problem"
        and getattr(error, "outcome_unknown", None) is False
        and isinstance(code, str)
        and code not in _UNKNOWN_CODES
        and isinstance(status, int)
        and 400 <= status <= 499
    ):
        return code
    return None


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value must be canonical JSON") from error


def _bounded_text(value: str, name: str, *, maximum_bytes: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > maximum_bytes
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} must be bounded non-whitespace text")
