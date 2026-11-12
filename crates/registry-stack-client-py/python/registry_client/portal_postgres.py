"""Encrypted PostgreSQL persistence for :mod:`registry_client.portal`.

The caller resolves operator-managed encryption keys and supplies a connection
factory. Browser cookie secrets are deliberately not accepted. Migrations and
key rotation are explicit operator actions; ordinary reads and writes refuse a
missing or changed migration and coordinate on the database's active key.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import secrets
from typing import Any

from .portal import PendingGrant, PortalSession, VerifiedGrant


_FORMAT = 1
_MAX_PLAINTEXT_BYTES = 1024 * 1024
_MIGRATION_VERSION = 1
_MIGRATION_PATH = Path(__file__).with_name("_sql") / "portal_postgres_v1.sql"
_PendingGrantConstructor: Any = PendingGrant
_PortalSessionConstructor: Any = PortalSession


class SessionStoreError(RuntimeError):
    """The durable portal store could not safely complete an operation."""

    code = "authentication.session-store-unavailable"

    def __init__(self, message: str = "portal session store is unavailable"):
        super().__init__(message)


class SessionStateError(SessionStoreError):
    """Persisted portal state or its migration cannot be trusted."""

    code = "authentication.session-state-invalid"


class PortalEncryptionKeys:
    """Operator-supplied AES-256-GCM keys with one intended rotation target."""

    __slots__ = ("_ciphers", "_primary_key_id")

    def __init__(self, *, primary_key_id: str, keys: Mapping[str, bytes]):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # pyright: ignore[reportMissingImports]
        except ImportError:
            raise RuntimeError(
                "encrypted portal sessions require the cryptography package"
            ) from None
        if not _identifier(primary_key_id) or primary_key_id not in keys or not keys:
            raise ValueError("portal encryption keys need a valid primary key id")
        ciphers: dict[str, Any] = {}
        for key_id, material in keys.items():
            if (
                not _identifier(key_id)
                or not isinstance(material, bytes)
                or len(material) != 32
            ):
                raise ValueError(
                    "each portal encryption key must be 32 bytes with a valid id"
                )
            ciphers[key_id] = AESGCM(material)
        self._primary_key_id = primary_key_id
        self._ciphers = ciphers

    @property
    def primary_key_id(self) -> str:
        return self._primary_key_id

    def __repr__(self) -> str:
        return "PortalEncryptionKeys(<redacted>)"

    def _contains(self, key_id: str) -> bool:
        return key_id in self._ciphers

    def _seal(
        self,
        key_id: str,
        kind: str,
        lookup_digest: bytes,
        generation: int,
        plaintext: bytes,
    ) -> bytes:
        cipher = self._ciphers.get(key_id)
        if cipher is None:
            raise SessionStateError("portal session encryption key is unavailable")
        nonce = secrets.token_bytes(12)
        return nonce + cipher.encrypt(
            nonce,
            plaintext,
            _associated_data(kind, lookup_digest, generation),
        )

    def _open(
        self,
        key_id: str,
        kind: str,
        lookup_digest: bytes,
        generation: int,
        ciphertext: bytes,
    ) -> bytes:
        cipher = self._ciphers.get(key_id)
        if cipher is None or len(ciphertext) < 29:
            raise SessionStateError("portal session state is unreadable")
        nonce, encrypted = ciphertext[:12], ciphertext[12:]
        try:
            plaintext = cipher.decrypt(
                nonce,
                encrypted,
                _associated_data(kind, lookup_digest, generation),
            )
        except Exception:
            raise SessionStateError("portal session state is unreadable") from None
        if len(plaintext) > _MAX_PLAINTEXT_BYTES:
            raise SessionStateError("portal session state is unreadable")
        return plaintext


class PostgresSessionStore:
    """Cross-worker portal state with encrypted payloads and generation CAS."""

    def __init__(self, connect: Callable[[], Any], keys: PortalEncryptionKeys):
        if not callable(connect) or not isinstance(keys, PortalEncryptionKeys):
            raise TypeError("PostgresSessionStore needs a connection factory and keys")
        self._connect = connect
        self._keys = keys

    def migrate(self) -> None:
        """Apply schema v1 and bind a fresh store to the configured primary key."""
        sql, checksum = _migration()
        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(sql)
                    cursor.execute(
                        "SELECT version, checksum "
                        "FROM registry_client_portal.migrations "
                        "ORDER BY version FOR UPDATE"
                    )
                    rows = cursor.fetchall()
                    if not rows:
                        cursor.execute(
                            "INSERT INTO registry_client_portal.migrations "
                            "(version, checksum) VALUES (%s, %s)",
                            (_MIGRATION_VERSION, checksum),
                        )
                    elif rows != [(_MIGRATION_VERSION, checksum)]:
                        raise SessionStateError(
                            "portal session migration is not current"
                        )
                    cursor.execute(
                        "INSERT INTO registry_client_portal.key_state "
                        "(singleton, active_key_id) VALUES (true, %s) "
                        "ON CONFLICT (singleton) DO NOTHING",
                        (self._keys.primary_key_id,),
                    )
                    cursor.execute(
                        "SELECT active_key_id FROM registry_client_portal.key_state "
                        "WHERE singleton = true FOR UPDATE"
                    )
                    key_row = cursor.fetchone()
                    if key_row is None or not self._keys._contains(key_row[0]):
                        raise SessionStateError(
                            "portal session encryption key is unavailable"
                        )
        except SessionStoreError:
            raise
        except Exception:
            raise SessionStoreError("portal session migration failed") from None

    def check_ready(self) -> None:
        with self._transaction() as cursor:
            self._assert_ready(cursor)

    @contextmanager
    def refresh_lock(self, session_id: str) -> Iterator[None]:
        """Serialize one session's rotating refresh exchange across workers."""
        session_digest = _lookup_digest("session", session_id)
        lock_keys = (
            int.from_bytes(session_digest[:4], "big", signed=True),
            int.from_bytes(session_digest[4:8], "big", signed=True),
        )
        entered_body = False
        body_completed = False
        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    try:
                        self._assert_ready(cursor)
                        cursor.execute(
                            "SELECT pg_advisory_xact_lock(%s, %s)", lock_keys
                        )
                    except SessionStoreError:
                        raise
                    except Exception:
                        raise SessionStoreError() from None
                    entered_body = True
                    yield
                    body_completed = True
        except SessionStoreError:
            raise
        except Exception:
            if entered_body and not body_completed:
                raise
            raise SessionStoreError() from None

    def put_pending(self, pending: PendingGrant) -> bool:
        plaintext = _encode_pending(pending)
        state_digest = _lookup_digest("state", pending.state)
        chain_digest = _lookup_digest("chain", pending.chain_id)
        with self._transaction() as cursor:
            active_key = self._assert_ready(cursor)
            ciphertext = self._keys._seal(
                active_key, "pending", state_digest, 0, plaintext
            )
            cursor.execute(
                "INSERT INTO registry_client_portal.chains "
                "(chain_digest, closed) VALUES (%s, false) "
                "ON CONFLICT (chain_digest) DO NOTHING",
                (chain_digest,),
            )
            cursor.execute(
                "SELECT closed FROM registry_client_portal.chains "
                "WHERE chain_digest = %s FOR UPDATE",
                (chain_digest,),
            )
            row = cursor.fetchone()
            if row is None:
                raise SessionStateError("portal session state is unreadable")
            if row[0]:
                return False
            cursor.execute(
                "INSERT INTO registry_client_portal.pending "
                "(state_digest, chain_digest, expires_at, key_id, ciphertext) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (state_digest) DO NOTHING RETURNING state_digest",
                (
                    state_digest,
                    chain_digest,
                    pending.expires_at,
                    active_key,
                    ciphertext,
                ),
            )
            return cursor.fetchone() is not None

    def consume_pending(self, state: str) -> PendingGrant | None:
        state_digest = _lookup_digest("state", state)
        row = None
        with self._transaction() as cursor:
            self._assert_ready(cursor)
            cursor.execute(
                "DELETE FROM registry_client_portal.pending "
                "WHERE state_digest = %s RETURNING key_id, ciphertext",
                (state_digest,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        plaintext = self._keys._open(row[0], "pending", state_digest, 0, bytes(row[1]))
        result = _decode_pending(plaintext)
        if result.state != state:
            raise SessionStateError("portal session state is unreadable")
        return result

    def close_chain(self, chain_id: str) -> None:
        chain_digest = _lookup_digest("chain", chain_id)
        with self._transaction() as cursor:
            self._assert_ready(cursor)
            cursor.execute(
                "INSERT INTO registry_client_portal.chains "
                "(chain_digest, closed) VALUES (%s, true) "
                "ON CONFLICT (chain_digest) DO UPDATE "
                "SET closed = true, updated_at = transaction_timestamp()",
                (chain_digest,),
            )
            cursor.execute(
                "DELETE FROM registry_client_portal.pending WHERE chain_digest = %s",
                (chain_digest,),
            )

    def create_session(self, chain_id: str, session: PortalSession) -> bool:
        plaintext = _encode_session(session)
        chain_digest = _lookup_digest("chain", chain_id)
        session_digest = _lookup_digest("session", session.session_id)
        with self._transaction() as cursor:
            active_key = self._assert_ready(cursor)
            cursor.execute(
                "SELECT closed FROM registry_client_portal.chains "
                "WHERE chain_digest = %s FOR UPDATE",
                (chain_digest,),
            )
            chain = cursor.fetchone()
            if chain is None or chain[0]:
                return False
            ciphertext = self._keys._seal(
                active_key,
                "session",
                session_digest,
                session.generation,
                plaintext,
            )
            cursor.execute(
                "INSERT INTO registry_client_portal.sessions "
                "(session_digest, generation, expires_at, key_id, ciphertext) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (session_digest) DO NOTHING RETURNING session_digest",
                (
                    session_digest,
                    session.generation,
                    session.expires_at,
                    active_key,
                    ciphertext,
                ),
            )
            if cursor.fetchone() is None:
                return False
            cursor.execute(
                "UPDATE registry_client_portal.chains "
                "SET closed = true, updated_at = transaction_timestamp() "
                "WHERE chain_digest = %s",
                (chain_digest,),
            )
            cursor.execute(
                "DELETE FROM registry_client_portal.pending WHERE chain_digest = %s",
                (chain_digest,),
            )
            return True

    def get_session(self, session_id: str) -> PortalSession | None:
        session_digest = _lookup_digest("session", session_id)
        row = None
        with self._transaction() as cursor:
            self._assert_ready(cursor)
            cursor.execute(
                "SELECT generation, key_id, ciphertext "
                "FROM registry_client_portal.sessions WHERE session_digest = %s",
                (session_digest,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        result = self._decrypt_session(session_digest, row)
        if result.session_id != session_id:
            raise SessionStateError("portal session state is unreadable")
        return result

    def replace_session(
        self, session_id: str, expected_generation: int, session: PortalSession
    ) -> bool:
        if (
            session.session_id != session_id
            or expected_generation < 0
            or session.generation != expected_generation + 1
        ):
            raise ValueError("replacement must advance the same portal session once")
        plaintext = _encode_session(session)
        session_digest = _lookup_digest("session", session_id)
        with self._transaction() as cursor:
            active_key = self._assert_ready(cursor)
            ciphertext = self._keys._seal(
                active_key,
                "session",
                session_digest,
                session.generation,
                plaintext,
            )
            cursor.execute(
                "UPDATE registry_client_portal.sessions "
                "SET generation = %s, expires_at = %s, key_id = %s, ciphertext = %s "
                "WHERE session_digest = %s AND generation = %s "
                "RETURNING session_digest",
                (
                    session.generation,
                    session.expires_at,
                    active_key,
                    ciphertext,
                    session_digest,
                    expected_generation,
                ),
            )
            return cursor.fetchone() is not None

    def delete_session(
        self, session_id: str, expected_generation: int | None = None
    ) -> PortalSession | None:
        if expected_generation is not None and expected_generation < 0:
            raise ValueError("expected_generation must be nonnegative")
        session_digest = _lookup_digest("session", session_id)
        row = None
        with self._transaction() as cursor:
            self._assert_ready(cursor)
            if expected_generation is None:
                cursor.execute(
                    "DELETE FROM registry_client_portal.sessions "
                    "WHERE session_digest = %s "
                    "RETURNING generation, key_id, ciphertext",
                    (session_digest,),
                )
            else:
                cursor.execute(
                    "DELETE FROM registry_client_portal.sessions "
                    "WHERE session_digest = %s AND generation = %s "
                    "RETURNING generation, key_id, ciphertext",
                    (session_digest, expected_generation),
                )
            row = cursor.fetchone()
        if row is None:
            return None
        result = self._decrypt_session(session_digest, row)
        if result.session_id != session_id:
            raise SessionStateError("portal session state is unreadable")
        return result

    def rotate_encryption(self) -> int:
        """Atomically rewrite every payload and activate the configured primary.

        Deploy every worker with the new and previous keys before calling this.
        The database key-state lock makes old-key-only workers fail closed after
        activation. Remove the previous key only after this transaction passes.
        """
        target = self._keys.primary_key_id
        rewritten = 0
        with self._transaction() as cursor:
            self._assert_ready(cursor, exclusive=True)
            for table, kind, generation_expression in (
                ("pending", "pending", "0"),
                ("sessions", "session", "generation"),
            ):
                digest_column = (
                    "state_digest" if table == "pending" else "session_digest"
                )
                cursor.execute(
                    f"SELECT {digest_column}, key_id, ciphertext, "
                    f"{generation_expression} FROM registry_client_portal.{table} "
                    "FOR UPDATE"
                )
                for digest, key_id, ciphertext, generation in cursor.fetchall():
                    plaintext = self._keys._open(
                        key_id,
                        kind,
                        bytes(digest),
                        generation,
                        bytes(ciphertext),
                    )
                    if key_id == target:
                        continue
                    replacement = self._keys._seal(
                        target, kind, bytes(digest), generation, plaintext
                    )
                    cursor.execute(
                        f"UPDATE registry_client_portal.{table} "
                        f"SET key_id = %s, ciphertext = %s WHERE {digest_column} = %s",
                        (target, replacement, digest),
                    )
                    rewritten += 1
            cursor.execute(
                "UPDATE registry_client_portal.key_state "
                "SET active_key_id = %s, updated_at = transaction_timestamp() "
                "WHERE singleton = true",
                (target,),
            )
        return rewritten

    def _decrypt_session(self, digest: bytes, row: Any) -> PortalSession:
        generation, key_id, ciphertext = row
        plaintext = self._keys._open(
            key_id, "session", digest, generation, bytes(ciphertext)
        )
        result = _decode_session(plaintext)
        if result.generation != generation:
            raise SessionStateError("portal session state is unreadable")
        return result

    def _assert_ready(self, cursor: Any, *, exclusive: bool = False) -> str:
        _, checksum = _migration()
        lock = "FOR UPDATE" if exclusive else "FOR SHARE"
        try:
            cursor.execute(
                "SELECT "
                "to_regclass('registry_client_portal.migrations'), "
                "to_regclass('registry_client_portal.key_state')"
            )
            relations = cursor.fetchone()
            if relations is None or None in relations:
                raise SessionStateError("portal session migration is not current")
            cursor.execute(
                "SELECT version, checksum "
                "FROM registry_client_portal.migrations "
                f"ORDER BY version {lock}"
            )
            migrations = cursor.fetchall()
            cursor.execute(
                "SELECT active_key_id FROM registry_client_portal.key_state "
                f"WHERE singleton = true {lock}"
            )
            key_state = cursor.fetchone()
        except Exception:
            raise SessionStateError("portal session migration is not current") from None
        if migrations != [(_MIGRATION_VERSION, checksum)]:
            raise SessionStateError("portal session migration is not current")
        if key_state is None or not self._keys._contains(key_state[0]):
            raise SessionStateError("portal session encryption key is unavailable")
        return key_state[0]

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    yield cursor
        except SessionStoreError:
            raise
        except Exception:
            raise SessionStoreError() from None


def _migration() -> tuple[str, str]:
    try:
        data = _MIGRATION_PATH.read_bytes()
        sql = data.decode("utf-8")
    except (OSError, UnicodeError):
        raise SessionStateError("portal session migration is not current") from None
    return sql, hashlib.sha256(data).hexdigest()


def _associated_data(kind: str, lookup_digest: bytes, generation: int) -> bytes:
    if kind not in {"pending", "session"} or len(lookup_digest) != 32:
        raise SessionStateError("portal session state is unreadable")
    return (
        b"registry-client-portal-v1\x00"
        + kind.encode("ascii")
        + b"\x00"
        + lookup_digest
        + generation.to_bytes(8, "big", signed=False)
    )


def _lookup_digest(kind: str, value: str) -> bytes:
    if kind not in {"state", "chain", "session"} or not _bounded_text(value, 512):
        raise ValueError("portal state identifier is invalid")
    return hashlib.sha256(
        b"registry-client-portal-lookup-v1\x00"
        + kind.encode("ascii")
        + b"\x00"
        + value.encode("utf-8")
    ).digest()


def _encode_pending(pending: PendingGrant) -> bytes:
    return _encode(
        {
            "format": _FORMAT,
            "kind": "pending",
            "state": pending.state,
            "chain_id": pending.chain_id,
            "nonce": pending.nonce,
            "code_verifier": pending.code_verifier,
            "grant_index": pending.grant_index,
            "created_at": pending.created_at,
            "expires_at": pending.expires_at,
            "return_to": pending.return_to,
            "grants": [_grant_to_dict(grant) for grant in pending.grants],
        }
    )


def _decode_pending(payload: bytes) -> PendingGrant:
    value = _decode(payload)
    _exact_keys(
        value,
        {
            "format",
            "kind",
            "state",
            "chain_id",
            "nonce",
            "code_verifier",
            "grant_index",
            "created_at",
            "expires_at",
            "return_to",
            "grants",
        },
    )
    if value["format"] != _FORMAT or value["kind"] != "pending":
        raise SessionStateError("portal session state is unreadable")
    grants = value["grants"]
    if not isinstance(grants, list) or len(grants) > 16:
        raise SessionStateError("portal session state is unreadable")
    return _PendingGrantConstructor(
        state=_string(value["state"]),
        chain_id=_string(value["chain_id"]),
        nonce=_string(value["nonce"]),
        code_verifier=_string(value["code_verifier"]),
        grant_index=_integer(value["grant_index"]),
        created_at=_number(value["created_at"]),
        expires_at=_number(value["expires_at"]),
        return_to=_string(value["return_to"], maximum=4096),
        grants=tuple(_grant_from_dict(item) for item in grants),
    )


def _encode_session(session: PortalSession) -> bytes:
    return _encode(
        {
            "format": _FORMAT,
            "kind": "session",
            "session_id": session.session_id,
            "subject": session.subject,
            "principal": session.principal,
            "persona": session.persona,
            "grants": [_grant_to_dict(grant) for grant in session.grants],
            "csrf_token": session.csrf_token,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "generation": session.generation,
        }
    )


def _decode_session(payload: bytes) -> PortalSession:
    value = _decode(payload)
    _exact_keys(
        value,
        {
            "format",
            "kind",
            "session_id",
            "subject",
            "principal",
            "persona",
            "grants",
            "csrf_token",
            "created_at",
            "expires_at",
            "generation",
        },
    )
    if value["format"] != _FORMAT or value["kind"] != "session":
        raise SessionStateError("portal session state is unreadable")
    grants = value["grants"]
    if not isinstance(grants, list) or not grants or len(grants) > 16:
        raise SessionStateError("portal session state is unreadable")
    return _PortalSessionConstructor(
        session_id=_string(value["session_id"]),
        subject=_string(value["subject"]),
        principal=_string(value["principal"]),
        persona=_string(value["persona"]),
        grants=tuple(_grant_from_dict(item) for item in grants),
        csrf_token=_string(value["csrf_token"]),
        created_at=_number(value["created_at"]),
        expires_at=_number(value["expires_at"]),
        generation=_integer(value["generation"]),
    )


def _grant_to_dict(grant: VerifiedGrant) -> dict[str, Any]:
    claims = dict(grant.claims)
    if any(
        not _bounded_text(name, 256) or not _bounded_text(value, 2048)
        for name, value in claims.items()
    ):
        raise ValueError("verified portal claims must be bounded strings")
    values = (
        grant.access_token,
        grant.refresh_token,
        grant.issuer,
        grant.client_id,
        grant.subject,
        grant.principal,
        grant.persona,
        grant.resource,
        grant.profile,
    )
    if (
        any(not _bounded_text(value, 131072) for value in values)
        or (grant.id_token is not None and not _bounded_text(grant.id_token, 131072))
        or not math.isfinite(grant.expires_at)
        or len(grant.scopes) > 256
        or any(not _bounded_text(scope, 512) for scope in grant.scopes)
    ):
        raise ValueError("verified portal grant is not serializable")
    return {
        "access_token": grant.access_token,
        "refresh_token": grant.refresh_token,
        "id_token": grant.id_token,
        "expires_at": grant.expires_at,
        "issuer": grant.issuer,
        "client_id": grant.client_id,
        "subject": grant.subject,
        "principal": grant.principal,
        "persona": grant.persona,
        "resource": grant.resource,
        "profile": grant.profile,
        "scopes": list(grant.scopes),
        "claims": claims,
        "authorized_party": grant.authorized_party,
        "client_id_claim": grant.client_id_claim,
    }


def _grant_from_dict(value: Any) -> VerifiedGrant:
    if not isinstance(value, dict):
        raise SessionStateError("portal session state is unreadable")
    _exact_keys(
        value,
        {
            "access_token",
            "refresh_token",
            "id_token",
            "expires_at",
            "issuer",
            "client_id",
            "subject",
            "principal",
            "persona",
            "resource",
            "profile",
            "scopes",
            "claims",
            "authorized_party",
            "client_id_claim",
        },
    )
    scopes = value["scopes"]
    claims = value["claims"]
    if (
        not isinstance(scopes, list)
        or len(scopes) > 256
        or not isinstance(claims, dict)
        or len(claims) > 32
    ):
        raise SessionStateError("portal session state is unreadable")
    decoded_claims = {
        _string(name, maximum=256): _string(claim, maximum=2048)
        for name, claim in claims.items()
    }
    return VerifiedGrant(
        access_token=_string(value["access_token"], maximum=131072),
        refresh_token=_string(value["refresh_token"], maximum=131072),
        id_token=_optional_string(value["id_token"], maximum=131072),
        expires_at=_number(value["expires_at"]),
        issuer=_string(value["issuer"], maximum=131072),
        client_id=_string(value["client_id"]),
        subject=_string(value["subject"]),
        principal=_string(value["principal"]),
        persona=_string(value["persona"]),
        resource=_string(value["resource"], maximum=131072),
        profile=_string(value["profile"]),
        scopes=tuple(_string(scope, maximum=512) for scope in scopes),
        claims=decoded_claims,
        authorized_party=_optional_string(value["authorized_party"]),
        client_id_claim=_optional_string(value["client_id_claim"]),
    )


def _encode(value: Mapping[str, Any]) -> bytes:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ValueError("portal session state is not serializable") from None
    if len(payload) > _MAX_PLAINTEXT_BYTES:
        raise ValueError("portal session state is too large")
    return payload


def _decode(payload: bytes) -> dict[str, Any]:
    if len(payload) > _MAX_PLAINTEXT_BYTES:
        raise SessionStateError("portal session state is unreadable")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError):
        raise SessionStateError("portal session state is unreadable") from None
    if not isinstance(value, dict):
        raise SessionStateError("portal session state is unreadable")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate member")
        result[name] = value
    return result


def _exact_keys(value: Mapping[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise SessionStateError("portal session state is unreadable")


def _string(value: Any, *, maximum: int = 512) -> str:
    if not _bounded_text(value, maximum):
        raise SessionStateError("portal session state is unreadable")
    return value


def _optional_string(value: Any, *, maximum: int = 512) -> str | None:
    if value is None:
        return None
    return _string(value, maximum=maximum)


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SessionStateError("portal session state is unreadable")
    result = float(value)
    if not math.isfinite(result):
        raise SessionStateError("portal session state is unreadable")
    return result


def _integer(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SessionStateError("portal session state is unreadable")
    return value


def _identifier(value: Any) -> bool:
    return bool(
        _bounded_text(value, 128)
        and not any(character.isspace() for character in value)
    )


def _bounded_text(value: Any, maximum: int) -> bool:
    return bool(
        isinstance(value, str)
        and 1 <= len(value.encode("utf-8")) <= maximum
        and value.strip() == value
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )
