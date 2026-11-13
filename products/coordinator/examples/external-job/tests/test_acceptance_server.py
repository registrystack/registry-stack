from __future__ import annotations

from contextlib import redirect_stderr
from dataclasses import dataclass
from http.client import RemoteDisconnected
from io import StringIO
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))

import acceptance_server  # noqa: E402


@dataclass(frozen=True)
class Caller:
    subject: str


class MemoryStore:
    def __init__(self) -> None:
        self.admissions: dict[tuple[str, str], tuple[dict[str, object], object]] = {}
        self.states: dict[str, str] = {}
        self.owners: dict[str, str] = {}
        self.calls = 0
        self.transition_calls = 0

    def admit(self, caller, key, request, *, after_commit=None):
        self.calls += 1
        owner_key = (caller.subject, key)
        existing = self.admissions.get(owner_key)
        if existing is not None:
            original, receipt = existing
            if original != request:
                raise acceptance_server.AdmissionConflict()
        else:
            receipt = acceptance_server.JobReceipt(
                f"00000000-0000-0000-0000-{len(self.admissions) + 1:012d}"
            )
            self.admissions[owner_key] = (dict(request), receipt)
            self.states[receipt.job_id] = "queued"
            self.owners[receipt.job_id] = caller.subject
        if after_commit is not None:
            after_commit(receipt)
        return receipt

    def status(self, caller, job_id):
        if self.owners.get(job_id) != caller.subject:
            return None
        return self.states.get(job_id)

    def transition(self, job_id, state):
        self.transition_calls += 1
        current = self.states.get(job_id)
        allowed = current == "queued" and state == "running"
        allowed = allowed or current == "running" and state in ("succeeded", "failed")
        if not allowed:
            raise ValueError("invalid job transition")
        self.states[job_id] = state

    def snapshot(self):
        return [
            {
                "key": key,
                "request": request,
                "receipt": receipt.as_json(),
            }
            for (_, key), (request, receipt) in self.admissions.items()
        ]


def request(server, method, path, *, body=None, token=None, key=None):
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    headers = {}
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if key is not None:
        headers["Idempotency-Key"] = key
    outgoing = Request(
        f"{server.base_url}{path}",
        data=encoded,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(outgoing, timeout=2) as response:
            return response.status, response.read()
    except HTTPError as error:
        try:
            return error.code, error.read()
        finally:
            error.close()
    except (RemoteDisconnected, URLError):
        return 0, b""


@unittest.skipUnless(
    acceptance_server.installed_wheel_available(),
    "the assembled registry-stack-client wheel is not installed",
)
class AcceptanceServerTests(unittest.TestCase):
    def start(self, *, fault="none"):
        store = MemoryStore()
        server = acceptance_server.AcceptanceServer(store, fault=fault)
        server.start()
        self.addCleanup(server.stop)
        return store, server

    def post(self, server, *, reference="case-001", token=None):
        return request(
            server,
            "POST",
            "/jobs",
            body={"reference": reference},
            token=token or acceptance_server.SYNTHETIC_TOKEN,
            key="coordinator-command-001",
        )

    def test_uses_machine_admission_from_the_installed_wheel(self):
        module = Path(acceptance_server.MachineAdmission.__module__.replace(".", "/"))
        source = Path(
            sys.modules[acceptance_server.MachineAdmission.__module__].__file__
        ).resolve()

        self.assertEqual(module.as_posix(), "registry_client/machine")
        self.assertIn("site-packages", source.parts)

    def test_machine_admission_precedes_application_work(self):
        store, server = self.start()

        status, body = request(
            server,
            "POST",
            "/jobs",
            body={"reference": "case-001"},
            key="coordinator-command-001",
        )

        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"code": "authentication.refused"})
        self.assertEqual(store.calls, 0)

    def test_admission_and_status_use_the_existing_application(self):
        store, server = self.start()

        first = self.post(server)
        duplicate = self.post(server)
        receipt = json.loads(first[1])
        status = request(
            server,
            "GET",
            f"/jobs/status?id={receipt['jobId']}",
            token=acceptance_server.SYNTHETIC_TOKEN,
        )

        self.assertEqual(first[0], 201)
        self.assertEqual(duplicate, first)
        self.assertEqual(json.loads(status[1]), {**receipt, "state": "queued"})
        self.assertEqual(len(store.admissions), 1)

    def test_authenticated_transition_route_drives_the_existing_store(self):
        store, server = self.start()
        admitted = self.post(server)
        job_id = json.loads(admitted[1])["jobId"]

        running = request(
            server,
            "POST",
            "/test/transition",
            body={"jobId": job_id, "state": "running"},
            token=acceptance_server.SYNTHETIC_TOKEN,
        )
        running_status = request(
            server,
            "GET",
            f"/jobs/status?id={job_id}",
            token=acceptance_server.SYNTHETIC_TOKEN,
        )
        succeeded = request(
            server,
            "POST",
            "/test/transition",
            body={"jobId": job_id, "state": "succeeded"},
            token=acceptance_server.SYNTHETIC_TOKEN,
        )

        self.assertEqual(running, (204, b""))
        self.assertEqual(json.loads(running_status[1])["state"], "running")
        self.assertEqual(succeeded, (204, b""))
        self.assertEqual(store.states[job_id], "succeeded")
        self.assertEqual(store.transition_calls, 2)

    def test_transition_requires_machine_admission_before_parsing_or_mutation(self):
        store, server = self.start()

        status, body = request(
            server,
            "POST",
            "/test/transition",
            body={"jobId": "not-a-job", "state": "running"},
        )

        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"code": "authentication.refused"})
        self.assertEqual(store.transition_calls, 0)

    def test_transition_refuses_invalid_shape_and_state_without_details(self):
        store, server = self.start()
        admitted = self.post(server)
        job_id = json.loads(admitted[1])["jobId"]

        invalid_shape = request(
            server,
            "POST",
            "/test/transition",
            body={"jobId": job_id, "state": "running", "extra": True},
            token=acceptance_server.SYNTHETIC_TOKEN,
        )
        invalid_state = request(
            server,
            "POST",
            "/test/transition",
            body={"jobId": job_id, "state": "succeeded"},
            token=acceptance_server.SYNTHETIC_TOKEN,
        )

        self.assertEqual(invalid_shape[0], 422)
        self.assertEqual(invalid_state[0], 422)
        self.assertEqual(json.loads(invalid_shape[1]), {"reason": "invalid-transition"})
        self.assertEqual(json.loads(invalid_state[1]), {"reason": "invalid-transition"})
        self.assertEqual(store.states[job_id], "queued")

    def test_authenticated_snapshot_reports_one_exact_saved_command(self):
        store, server = self.start()
        admitted = self.post(server)
        duplicate = self.post(server)

        status, body = request(
            server,
            "GET",
            "/test/snapshot",
            token=acceptance_server.SYNTHETIC_TOKEN,
        )

        self.assertEqual(admitted, duplicate)
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body),
            {
                "jobCount": 1,
                "jobs": [
                    {
                        "key": "coordinator-command-001",
                        "request": {"reference": "case-001"},
                        "receipt": json.loads(admitted[1]),
                    }
                ],
            },
        )
        self.assertEqual(store.calls, 2)

    def test_snapshot_requires_machine_admission_before_store_access(self):
        store, server = self.start()

        status, body = request(server, "GET", "/test/snapshot")

        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body), {"code": "authentication.refused"})
        self.assertEqual(store.calls, 0)

    def test_snapshot_refuses_more_than_sixteen_jobs(self):
        store = MemoryStore()
        for index in range(17):
            store.admit(
                Caller("coordinator-service"),
                f"command-{index}",
                {"reference": f"case-{index}"},
            )
        server = acceptance_server.AcceptanceServer(store)
        server.start()
        self.addCleanup(server.stop)

        status, body = request(
            server,
            "GET",
            "/test/snapshot",
            token=acceptance_server.SYNTHETIC_TOKEN,
        )

        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"reason": "snapshot-unavailable"})

    def test_declared_refusal_is_test_only_and_commits_no_job(self):
        store, server = self.start(fault="declared-refusal")

        status, body = self.post(server)

        self.assertEqual(status, 422)
        self.assertEqual(json.loads(body), {"reason": "invalid-job"})
        self.assertEqual(store.admissions, {})

    def test_malformed_response_after_commit_recovers_the_receipt(self):
        store, server = self.start(fault="malformed-response-after-commit")

        first = self.post(server)
        recovered = self.post(server)

        self.assertEqual(first, (201, b"not-json"))
        self.assertEqual(recovered[0], 201)
        self.assertIn("jobId", json.loads(recovered[1]))
        self.assertEqual(len(store.admissions), 1)

    def test_encoding_error_after_commit_recovers_without_a_second_job(self):
        store, server = self.start(fault="encoding-error-after-commit")
        captured = StringIO()

        with redirect_stderr(captured):
            first = self.post(server)
        recovered = self.post(server)

        self.assertIn(first[0], (0, 500))
        self.assertIn("synthetic response encoding failure", captured.getvalue())
        self.assertEqual(recovered[0], 201)
        self.assertEqual(len(store.admissions), 1)

    def test_process_exit_fault_runs_only_after_the_receipt_is_committed(self):
        store, server = self.start(fault="process-exit-after-commit")
        exited = threading.Event()

        def record_exit(code):
            self.assertEqual(code, acceptance_server.POST_COMMIT_EXIT_CODE)
            exited.set()
            raise RuntimeError("synthetic process exit intercepted")

        captured = StringIO()
        with (
            patch.object(acceptance_server.os, "_exit", record_exit),
            redirect_stderr(captured),
        ):
            first = self.post(server)

        self.assertIn(first[0], (0, 500))
        self.assertTrue(exited.is_set())
        self.assertEqual(len(store.admissions), 1)
        self.assertIn("synthetic process exit intercepted", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
