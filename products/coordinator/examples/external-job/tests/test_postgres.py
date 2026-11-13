from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
import uuid


EXAMPLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE))

from service import AdmissionConflict, JobStore  # noqa: E402


DATABASE_URL = os.environ.get("EXTERNAL_JOB_TEST_DATABASE_URL")


@dataclass(frozen=True)
class MachineContext:
    subject: str
    client_id: str = "coordinator-client"
    profile: str = "coordinator-invoker"
    issuer: str = "https://issuer.example.invalid/"
    resource: str = "urn:example:external-job"
    persona: str = "service"


@unittest.skipUnless(
    DATABASE_URL,
    "EXTERNAL_JOB_TEST_DATABASE_URL must name a disposable PostgreSQL database",
)
class PostgreSQLJobStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = f"external_job_test_{uuid.uuid4().hex}"
        self.store = JobStore(DATABASE_URL, schema=self.schema)
        self.store.migrate()
        self.caller = MachineContext("coordinator-a")

    def test_concurrent_duplicate_admission_commits_one_job_and_one_receipt(
        self,
    ) -> None:
        def admit(_: int):
            return self.store.admit(
                self.caller,
                "coordinator-command-001",
                {"reference": "case-001"},
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(admit, range(16)))

        self.assertEqual(len({receipt.job_id for receipt in receipts}), 1)
        self.assertEqual(self._job_count(), 1)

    def test_commit_before_reply_survives_process_restart(self) -> None:
        committed = None

        def stop_after_commit(receipt):
            nonlocal committed
            committed = receipt
            raise RuntimeError("synthetic process stop after commit")

        with self.assertRaisesRegex(RuntimeError, "after commit"):
            self.store.admit(
                self.caller,
                "coordinator-command-001",
                {"reference": "case-001"},
                after_commit=stop_after_commit,
            )

        restarted = JobStore(DATABASE_URL, schema=self.schema)
        recovered = restarted.admit(
            self.caller,
            "coordinator-command-001",
            {"reference": "case-001"},
        )
        self.assertEqual(recovered, committed)
        self.assertEqual(self._job_count(), 1)

    def test_duplicate_key_cannot_select_a_different_job(self) -> None:
        original = self.store.admit(
            self.caller,
            "coordinator-command-001",
            {"reference": "case-001"},
        )
        with self.assertRaises(AdmissionConflict):
            self.store.admit(
                self.caller, "coordinator-command-001", {"reference": "case-002"}
            )

        self.assertEqual(self.store.status(self.caller, original.job_id), "queued")
        self.assertEqual(self._job_count(), 1)

    def test_worker_state_is_durable_and_terminal(self) -> None:
        receipt = self.store.admit(
            self.caller,
            "coordinator-command-001",
            {"reference": "case-001"},
        )
        self.assertEqual(self.store.status(self.caller, receipt.job_id), "queued")
        self.store.transition(receipt.job_id, "running")
        self.assertEqual(self.store.status(self.caller, receipt.job_id), "running")
        self.store.transition(receipt.job_id, "succeeded")
        self.assertEqual(
            JobStore(DATABASE_URL, schema=self.schema).status(
                self.caller, receipt.job_id
            ),
            "succeeded",
        )
        with self.assertRaisesRegex(ValueError, "invalid job transition"):
            self.store.transition(receipt.job_id, "failed")

    def test_verified_callers_have_separate_keys_and_cannot_cross_read(self) -> None:
        first_caller = MachineContext("coordinator-a")
        second_caller = MachineContext("coordinator-b")

        first = self.store.admit(
            first_caller,
            "shared-command",
            {"reference": "case-shared"},
        )
        second = self.store.admit(
            second_caller,
            "shared-command",
            {"reference": "case-shared"},
        )

        self.assertNotEqual(first, second)
        self.assertEqual(self.store.status(first_caller, first.job_id), "queued")
        self.assertIsNone(self.store.status(first_caller, second.job_id))
        self.assertIsNone(self.store.status(second_caller, first.job_id))
        self.assertEqual(self.store.status(second_caller, second.job_id), "queued")
        self.assertEqual(self._job_count(), 2)

    def test_empty_legacy_table_upgrades_without_guessing_an_owner(self) -> None:
        schema = f"external_job_legacy_empty_{uuid.uuid4().hex}"
        self._create_legacy_table(schema)
        store = JobStore(DATABASE_URL, schema=schema)

        store.migrate()
        receipt = store.admit(
            self.caller,
            "coordinator-command-001",
            {"reference": "case-001"},
        )

        self.assertEqual(store.status(self.caller, receipt.job_id), "queued")

    def test_concurrent_empty_legacy_upgrade_rechecks_after_the_table_lock(
        self,
    ) -> None:
        schema = f"external_job_legacy_concurrent_{uuid.uuid4().hex}"
        self._create_legacy_table(schema)
        stores = [
            JobStore(DATABASE_URL, schema=schema),
            JobStore(DATABASE_URL, schema=schema),
        ]
        entered = threading.Barrier(2)
        migrate_legacy = JobStore._migrate_empty_legacy_table

        def synchronized_migration(store, connection):
            entered.wait(timeout=5)
            return migrate_legacy(store, connection)

        with patch.object(
            JobStore,
            "_migrate_empty_legacy_table",
            synchronized_migration,
        ):
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda store: store.migrate(), stores))

        receipt = stores[0].admit(
            self.caller,
            "coordinator-command-001",
            {"reference": "case-001"},
        )
        self.assertEqual(stores[1].status(self.caller, receipt.job_id), "queued")

    def test_populated_legacy_table_fails_closed_without_an_owner_binding(self) -> None:
        schema = f"external_job_legacy_populated_{uuid.uuid4().hex}"
        self._create_legacy_table(schema, populated=True)

        with self.assertRaisesRegex(
            RuntimeError, "rows have no verified caller binding"
        ):
            JobStore(DATABASE_URL, schema=schema).migrate()

    def _job_count(self) -> int:
        import psycopg
        from psycopg import sql

        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("SELECT count(*) FROM {}.jobs").format(
                        sql.Identifier(self.schema)
                    )
                )
                row = cursor.fetchone()
        assert row is not None
        return row[0]

    @staticmethod
    def _create_legacy_table(schema: str, *, populated: bool = False) -> None:
        import psycopg
        from psycopg import sql

        statement = sql.SQL(
            """
            CREATE TABLE {}.jobs (
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
        ).format(sql.Identifier(schema))
        with psycopg.connect(DATABASE_URL) as connection:
            connection.execute(
                sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema))
            )
            connection.execute(statement)
            if populated:
                job_id = uuid.uuid4()
                connection.execute(
                    sql.SQL(
                        """
                        INSERT INTO {}.jobs (
                            job_id, admission_key, request_digest,
                            request_body, receipt
                        ) VALUES (%s, %s, %s, %s::jsonb, %s::jsonb)
                        """
                    ).format(sql.Identifier(schema)),
                    (
                        job_id,
                        "legacy-command",
                        b"legacy-digest",
                        '{"reference":"legacy"}',
                        f'{{"jobId":"{job_id}"}}',
                    ),
                )


if __name__ == "__main__":
    unittest.main()
