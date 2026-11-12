from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sys
import unittest
import uuid


EXAMPLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE))

from service import AdmissionConflict, JobStore  # noqa: E402


DATABASE_URL = os.environ.get("EXTERNAL_JOB_TEST_DATABASE_URL")


@unittest.skipUnless(
    DATABASE_URL,
    "EXTERNAL_JOB_TEST_DATABASE_URL must name a disposable PostgreSQL database",
)
class PostgreSQLJobStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = f"external_job_test_{uuid.uuid4().hex}"
        self.store = JobStore(DATABASE_URL, schema=self.schema)
        self.store.migrate()

    def test_concurrent_duplicate_admission_commits_one_job_and_one_receipt(self) -> None:
        def admit(_: int):
            return self.store.admit(
                "coordinator-command-001", {"reference": "case-001"}
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
                "coordinator-command-001",
                {"reference": "case-001"},
                after_commit=stop_after_commit,
            )

        restarted = JobStore(DATABASE_URL, schema=self.schema)
        recovered = restarted.admit(
            "coordinator-command-001", {"reference": "case-001"}
        )
        self.assertEqual(recovered, committed)
        self.assertEqual(self._job_count(), 1)

    def test_duplicate_key_cannot_select_a_different_job(self) -> None:
        original = self.store.admit(
            "coordinator-command-001", {"reference": "case-001"}
        )
        with self.assertRaises(AdmissionConflict):
            self.store.admit(
                "coordinator-command-001", {"reference": "case-002"}
            )

        self.assertEqual(self.store.status(original.job_id), "queued")
        self.assertEqual(self._job_count(), 1)

    def test_worker_state_is_durable_and_terminal(self) -> None:
        receipt = self.store.admit(
            "coordinator-command-001", {"reference": "case-001"}
        )
        self.assertEqual(self.store.status(receipt.job_id), "queued")
        self.store.transition(receipt.job_id, "running")
        self.assertEqual(self.store.status(receipt.job_id), "running")
        self.store.transition(receipt.job_id, "succeeded")
        self.assertEqual(
            JobStore(DATABASE_URL, schema=self.schema).status(receipt.job_id),
            "succeeded",
        )
        with self.assertRaisesRegex(ValueError, "invalid job transition"):
            self.store.transition(receipt.job_id, "failed")

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


if __name__ == "__main__":
    unittest.main()
