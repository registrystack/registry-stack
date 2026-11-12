from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import sys
import unittest


EXAMPLE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE))

from service import AdmissionConflict, JobApplication, JobReceipt  # noqa: E402


class MemoryStore:
    def __init__(self) -> None:
        self.admissions: dict[str, tuple[dict[str, object], JobReceipt]] = {}
        self.states: dict[str, str] = {}
        self.calls = 0

    def admit(self, key: str, request: dict[str, object]) -> JobReceipt:
        self.calls += 1
        existing = self.admissions.get(key)
        if existing is not None:
            original, receipt = existing
            if original != request:
                raise AdmissionConflict()
            return receipt
        receipt = JobReceipt(job_id=f"job-{len(self.admissions) + 1}")
        self.admissions[key] = (request, receipt)
        self.states[receipt.job_id] = "queued"
        return receipt

    def status(self, job_id: str) -> str | None:
        return self.states.get(job_id)


def request(
    app: JobApplication,
    method: str,
    path: str,
    *,
    body: object | None = None,
    key: str | None = None,
) -> tuple[str, dict[str, str], object]:
    encoded = b"" if body is None else json.dumps(body).encode()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(encoded)),
        "CONTENT_TYPE": "application/json",
        "wsgi.input": BytesIO(encoded),
    }
    if key is not None:
        environ["HTTP_IDEMPOTENCY_KEY"] = key
    captured: dict[str, object] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    payload = b"".join(app(environ, start_response))
    return (
        captured["status"],
        captured["headers"],
        json.loads(payload),
    )


class JobApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = MemoryStore()
        self.app = JobApplication(self.store)

    def test_admission_returns_the_stable_job_receipt(self) -> None:
        first = request(
            self.app,
            "POST",
            "/jobs",
            key="coordinator-command-001",
            body={"reference": "case-001"},
        )
        duplicate = request(
            self.app,
            "POST",
            "/jobs",
            key="coordinator-command-001",
            body={"reference": "case-001"},
        )

        self.assertEqual(first[0], "201 Created")
        self.assertEqual(first, duplicate)
        self.assertEqual(first[2], {"jobId": "job-1"})
        self.assertEqual(self.store.calls, 2)
        self.assertEqual(len(self.store.admissions), 1)

    def test_same_key_with_a_changed_command_is_a_declared_conflict(self) -> None:
        request(
            self.app,
            "POST",
            "/jobs",
            key="coordinator-command-001",
            body={"reference": "case-001"},
        )
        status, _, body = request(
            self.app,
            "POST",
            "/jobs",
            key="coordinator-command-001",
            body={"reference": "case-002"},
        )

        self.assertEqual(status, "409 Conflict")
        self.assertEqual(body, {"reason": "idempotency-conflict"})
        self.assertEqual(len(self.store.admissions), 1)

    def test_status_reads_the_exact_admitted_job(self) -> None:
        _, _, receipt = request(
            self.app,
            "POST",
            "/jobs",
            key="coordinator-command-001",
            body={"reference": "case-001"},
        )
        job_id = receipt["jobId"]
        self.store.states[job_id] = "running"

        environ_path = f"/jobs/status?id={job_id}"
        status, _, body = self._request_url(environ_path)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"jobId": job_id, "state": "running"})

    def test_invalid_work_is_refused_before_admission(self) -> None:
        for key, body in [
            (None, {"reference": "case-001"}),
            ("coordinator-command-001", {}),
            ("coordinator-command-001", {"reference": ""}),
            ("coordinator-command-001", {"reference": "case-001", "extra": True}),
        ]:
            with self.subTest(key=key, body=body):
                status, _, _ = request(
                    self.app, "POST", "/jobs", key=key, body=body
                )
                self.assertIn(status.split(" ", 1)[0], ("400", "422"))
        self.assertEqual(self.store.calls, 0)

    def test_response_encoding_failure_leaves_the_committed_receipt_recoverable(self) -> None:
        def broken_encoder(_: object) -> bytes:
            raise UnicodeError("synthetic response encoding failure")

        broken = JobApplication(self.store, encode_json=broken_encoder)
        with self.assertRaisesRegex(UnicodeError, "synthetic response encoding failure"):
            request(
                broken,
                "POST",
                "/jobs",
                key="coordinator-command-001",
                body={"reference": "case-001"},
            )

        status, _, body = request(
            self.app,
            "POST",
            "/jobs",
            key="coordinator-command-001",
            body={"reference": "case-001"},
        )
        self.assertEqual(status, "201 Created")
        self.assertEqual(body, {"jobId": "job-1"})
        self.assertEqual(len(self.store.admissions), 1)

    def _request_url(self, url: str) -> tuple[str, dict[str, str], object]:
        path, _, query = url.partition("?")
        captured: dict[str, object] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status
            captured["headers"] = dict(headers)

        payload = b"".join(
            self.app(
                {
                    "REQUEST_METHOD": "GET",
                    "PATH_INFO": path,
                    "QUERY_STRING": query,
                    "CONTENT_LENGTH": "0",
                    "wsgi.input": BytesIO(),
                },
                start_response,
            )
        )
        return (
            captured["status"],
            captured["headers"],
            json.loads(payload),
        )


if __name__ == "__main__":
    unittest.main()
