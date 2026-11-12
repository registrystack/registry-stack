"""Encrypted PostgreSQL persistence for browser portal sessions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import importlib
import importlib.util
import os
from pathlib import Path
import sys
from threading import Event
import types
import unittest
from urllib.parse import urlsplit


SOURCE = Path(__file__).resolve().parents[1] / "python" / "registry_client"
PACKAGE = "_registry_client_portal_postgres_test"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(SOURCE)]
sys.modules[PACKAGE] = package
portal = importlib.import_module(f"{PACKAGE}.portal")
portal_postgres = importlib.import_module(f"{PACKAGE}.portal_postgres")


def encryption_keys(primary: str, *key_ids: str):
    material = {
        "key-a": b"A" * 32,
        "key-b": b"B" * 32,
        "key-c": b"C" * 32,
    }
    return portal_postgres.PortalEncryptionKeys(
        primary_key_id=primary,
        keys={key_id: material[key_id] for key_id in key_ids},
    )


def grant(name: str, token_suffix: str = "one"):
    return portal.VerifiedGrant(
        access_token=f"access-token-canary-{name}-{token_suffix}",
        refresh_token=f"refresh-token-canary-{name}-{token_suffix}",
        id_token=f"id-token-canary-{name}-{token_suffix}",
        expires_at=1_700_000_300,
        issuer="https://issuer.example.test",
        client_id="holder-portal",
        subject="citizen-001",
        principal="person-001",
        persona="holder",
        resource=f"https://{name}.example.test",
        profile=f"{name}-holder",
        scopes=(f"{name}.holder",),
        claims={"registry_role": "holder"},
        authorized_party="holder-portal",
        client_id_claim="holder-portal",
    )


def pending(state: str = "pending-state-one", chain: str = "chain-one"):
    return portal.PendingGrant(
        state=state,
        chain_id=chain,
        nonce="nonce-canary-one",
        code_verifier="pkce-verifier-canary-one",
        grant_index=1,
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
        return_to="/application/continue",
        grants=(grant("breg"),),
    )


def session(
    session_id: str = "opaque-session-one",
    *,
    generation: int = 0,
    suffix: str = "one",
):
    return portal.PortalSession(
        session_id=session_id,
        subject="citizen-001",
        principal="person-001",
        persona="holder",
        grants=(grant("breg", suffix), grant("casework", suffix)),
        csrf_token="csrf-canary-one",
        created_at=1_700_000_000,
        expires_at=1_700_000_900,
        generation=generation,
    )


class EncryptionKeyTests(unittest.TestCase):
    def test_postgres_store_declares_a_refresh_lock(self):
        self.assertTrue(
            callable(
                getattr(portal_postgres.PostgresSessionStore, "refresh_lock", None)
            )
        )

    @unittest.skipUnless(
        importlib.util.find_spec("cryptography"), "cryptography is not installed"
    )
    def test_keys_are_operator_supplied_and_secret_free_in_repr(self):
        keys = encryption_keys("key-a", "key-a")
        self.assertNotIn("AAAA", repr(keys))
        self.assertEqual(keys.primary_key_id, "key-a")

        for key_id, key_material in [
            ("", b"A" * 32),
            ("key-a", b"short"),
            ("key-a\n", b"A" * 32),
        ]:
            with self.subTest(key_id=key_id):
                with self.assertRaises(ValueError):
                    portal_postgres.PortalEncryptionKeys(
                        primary_key_id=key_id,
                        keys={key_id: key_material},
                    )


class RefreshLockUnitTests(unittest.TestCase):
    class Cursor:
        def __init__(self):
            self.executed = []

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def execute(self, statement, parameters):
            self.executed.append((statement, parameters))

    class Connection:
        def __init__(self):
            self.cursor_value = RefreshLockUnitTests.Cursor()
            self.exited = False

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.exited = True
            return False

        def cursor(self):
            return self.cursor_value

    def store(self, connections):
        store = portal_postgres.PostgresSessionStore.__new__(
            portal_postgres.PostgresSessionStore
        )

        def connect():
            connection = self.Connection()
            connections.append(connection)
            return connection

        store._connect = connect
        store._assert_ready = lambda cursor: "key-a"
        return store

    def test_refresh_lock_uses_per_session_transaction_keys_and_preserves_body_error(
        self,
    ):
        connections = []
        store = self.store(connections)

        class RefreshFailed(Exception):
            pass

        with self.assertRaises(RefreshFailed):
            with store.refresh_lock("opaque-session-one"):
                raise RefreshFailed
        with store.refresh_lock("opaque-session-one"):
            pass
        with store.refresh_lock("opaque-session-two"):
            pass

        self.assertTrue(all(connection.exited for connection in connections))
        calls = [connection.cursor_value.executed for connection in connections]
        self.assertTrue(
            all(
                statements
                and statements[-1][0] == "SELECT pg_advisory_xact_lock(%s, %s)"
                for statements in calls
            )
        )
        first_key = calls[0][-1][1]
        self.assertEqual(calls[1][-1][1], first_key)
        self.assertNotEqual(calls[2][-1][1], first_key)
        self.assertTrue(all(-(2**31) <= key < 2**31 for key in first_key))


DATABASE_URL = os.environ.get("PORTAL_POSTGRES_TEST_DATABASE_URL")
HAS_DEPENDENCIES = bool(
    importlib.util.find_spec("cryptography") and importlib.util.find_spec("psycopg")
)


@unittest.skipUnless(
    DATABASE_URL and HAS_DEPENDENCIES,
    "PORTAL_POSTGRES_TEST_DATABASE_URL and PostgreSQL dependencies are required",
)
class PostgresSessionStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not isinstance(DATABASE_URL, str):
            raise RuntimeError("portal PostgreSQL test database is not configured")
        parsed = urlsplit(DATABASE_URL)
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError("portal PostgreSQL tests require a loopback database")
        if not parsed.path.lstrip("/").startswith("portal_test_"):
            raise RuntimeError(
                "portal PostgreSQL tests require a portal_test_ database"
            )
        cls.psycopg = importlib.import_module("psycopg")

    def connect(self):
        return self.psycopg.connect(DATABASE_URL)

    def setUp(self):
        with self.connect() as connection:
            connection.execute("DROP SCHEMA IF EXISTS registry_client_portal CASCADE")
        self.store = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-a", "key-a")
        )
        self.store.migrate()

    def tearDown(self):
        with self.connect() as connection:
            connection.execute("DROP SCHEMA IF EXISTS registry_client_portal CASCADE")

    def raw_rows(self, table: str):
        if table not in {"pending", "sessions"}:
            raise ValueError("unexpected table")
        with self.connect() as connection:
            return connection.execute(
                f"SELECT key_id, ciphertext FROM registry_client_portal.{table}"
            ).fetchall()

    def test_pending_consume_is_atomic_across_workers_and_chain_close_wins(self):
        self.assertTrue(self.store.put_pending(pending()))
        second = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-a", "key-a")
        )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    lambda store: store.consume_pending("pending-state-one"),
                    (self.store, second),
                )
            )
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(
            [result.state for result in results if result is not None],
            ["pending-state-one"],
        )

        self.store.close_chain("closed-before-write")
        self.assertFalse(
            second.put_pending(pending("late-state", "closed-before-write"))
        )

    def test_restart_preserves_complete_session_and_never_stores_token_canaries(self):
        item = pending()
        self.assertTrue(self.store.put_pending(item))
        self.assertIsNotNone(self.store.consume_pending(item.state))
        complete = session()
        self.assertTrue(self.store.create_session(item.chain_id, complete))

        restarted = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-a", "key-a")
        )
        self.assertEqual(restarted.get_session(complete.session_id), complete)
        rows = self.raw_rows("sessions")
        self.assertEqual(rows[0][0], "key-a")
        self.assertNotIn(b"access-token-canary", bytes(rows[0][1]))
        self.assertNotIn(b"refresh-token-canary", bytes(rows[0][1]))
        with self.connect() as connection:
            identifiers = connection.execute(
                "SELECT session_digest FROM registry_client_portal.sessions"
            ).fetchall()
        self.assertNotIn(complete.session_id.encode(), bytes(identifiers[0][0]))

    def test_generation_compare_and_swap_prevents_mixed_worker_updates(self):
        item = pending()
        self.assertTrue(self.store.put_pending(item))
        self.assertIsNotNone(self.store.consume_pending(item.state))
        original = session()
        self.assertTrue(self.store.create_session(item.chain_id, original))
        second = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-a", "key-a")
        )

        winner = replace(
            session(generation=1, suffix="winner"), csrf_token=original.csrf_token
        )
        loser = replace(
            session(generation=1, suffix="loser"), csrf_token=original.csrf_token
        )
        self.assertTrue(second.replace_session(original.session_id, 0, winner))
        self.assertFalse(self.store.replace_session(original.session_id, 0, loser))
        self.assertEqual(self.store.get_session(original.session_id), winner)

    def test_refresh_lock_serializes_workers_for_one_session_and_releases(self):
        second = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-a", "key-a")
        )
        first_entered = Event()
        release_first = Event()
        second_attempting = Event()
        second_entered = Event()

        def first_worker():
            with self.store.refresh_lock("opaque-session-one"):
                first_entered.set()
                if not release_first.wait(5):
                    raise AssertionError(
                        "the refresh-lock test did not release worker one"
                    )

        def second_worker():
            second_attempting.set()
            with second.refresh_lock("opaque-session-one"):
                second_entered.set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(first_worker)
            self.assertTrue(first_entered.wait(5))
            following = executor.submit(second_worker)
            self.assertTrue(second_attempting.wait(5))
            try:
                self.assertFalse(
                    second_entered.wait(0.25),
                    "two workers entered one session's refresh boundary",
                )
            finally:
                release_first.set()
            first.result(timeout=5)
            following.result(timeout=5)
        self.assertTrue(second_entered.is_set())

        class RefreshFailed(Exception):
            pass

        with self.assertRaises(RefreshFailed):
            with self.store.refresh_lock("opaque-session-one"):
                raise RefreshFailed
        with second.refresh_lock("opaque-session-one"):
            pass

    def test_refresh_locks_for_independent_sessions_proceed_concurrently(self):
        second = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-a", "key-a")
        )
        first_entered = Event()
        release_first = Event()
        second_entered = Event()

        def first_worker():
            with self.store.refresh_lock("opaque-session-one"):
                first_entered.set()
                if not release_first.wait(5):
                    raise AssertionError(
                        "the refresh-lock test did not release worker one"
                    )

        def second_worker():
            with second.refresh_lock("opaque-session-two"):
                second_entered.set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(first_worker)
            self.assertTrue(first_entered.wait(5))
            following = executor.submit(second_worker)
            try:
                self.assertTrue(
                    second_entered.wait(2),
                    "an unrelated session waited on another session's refresh lock",
                )
            finally:
                release_first.set()
            first.result(timeout=5)
            following.result(timeout=5)

    def test_key_rotation_is_atomic_and_old_key_can_be_removed(self):
        first = pending("state-one", "chain-one")
        second = pending("state-two", "chain-two")
        self.assertTrue(self.store.put_pending(first))
        self.assertTrue(self.store.put_pending(second))
        rotating = portal_postgres.PostgresSessionStore(
            self.connect,
            encryption_keys("key-b", "key-b", "key-a"),
        )

        self.assertEqual(rotating.rotate_encryption(), 2)
        self.assertEqual(
            {row[0] for row in self.raw_rows("pending")},
            {"key-b"},
        )
        replacement = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-b", "key-b")
        )
        self.assertEqual(replacement.consume_pending(first.state), first)
        old_only = portal_postgres.PostgresSessionStore(
            self.connect, encryption_keys("key-a", "key-a")
        )
        with self.assertRaises(portal_postgres.SessionStateError):
            old_only.consume_pending(second.state)

    def test_unreadable_state_fails_visibly_and_delete_still_invalidates_it(self):
        item = pending()
        self.assertTrue(self.store.put_pending(item))
        self.assertIsNotNone(self.store.consume_pending(item.state))
        complete = session()
        self.assertTrue(self.store.create_session(item.chain_id, complete))
        with self.connect() as connection:
            connection.execute(
                "UPDATE registry_client_portal.sessions "
                "SET ciphertext = decode(repeat('00', 29), 'hex')"
            )

        with self.assertRaisesRegex(
            portal_postgres.SessionStateError, "portal session state is unreadable"
        ):
            self.store.get_session(complete.session_id)
        with self.assertRaises(portal_postgres.SessionStateError):
            self.store.delete_session(complete.session_id)
        self.assertIsNone(self.store.get_session(complete.session_id))

    def test_rotation_rolls_back_when_any_row_is_unreadable(self):
        self.assertTrue(self.store.put_pending(pending("state-one", "chain-one")))
        self.assertTrue(self.store.put_pending(pending("state-two", "chain-two")))
        with self.connect() as connection:
            connection.execute(
                "UPDATE registry_client_portal.pending "
                "SET ciphertext = decode(repeat('00', 29), 'hex') "
                "WHERE state_digest = ("
                "SELECT state_digest FROM registry_client_portal.pending LIMIT 1"
                ")"
            )
        rotating = portal_postgres.PostgresSessionStore(
            self.connect,
            encryption_keys("key-b", "key-b", "key-a"),
        )

        with self.assertRaises(portal_postgres.SessionStateError):
            rotating.rotate_encryption()
        self.assertEqual(
            {row[0] for row in self.raw_rows("pending")},
            {"key-a"},
        )

    def test_missing_or_changed_migration_fails_every_operation(self):
        with self.connect() as connection:
            connection.execute(
                "UPDATE registry_client_portal.migrations "
                "SET checksum = repeat('0', 64) WHERE version = 1"
            )
        with self.assertRaisesRegex(
            portal_postgres.SessionStateError, "portal session migration is not current"
        ):
            self.store.put_pending(pending())

        with self.connect() as connection:
            connection.execute("DROP SCHEMA registry_client_portal CASCADE")
        self.store.migrate()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO registry_client_portal.migrations (version, checksum) "
                "VALUES (2, repeat('1', 64))"
            )
        with self.assertRaises(portal_postgres.SessionStateError):
            self.store.get_session("missing")

        with self.connect() as connection:
            connection.execute("DROP SCHEMA registry_client_portal CASCADE")
        with self.assertRaises(portal_postgres.SessionStateError):
            self.store.get_session("missing")


if __name__ == "__main__":
    unittest.main()
