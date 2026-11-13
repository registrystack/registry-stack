from __future__ import annotations

from dataclasses import dataclass
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
        self.admissions: dict[
            tuple[str, str], tuple[dict[str, object], JobReceipt]
        ] = {}
        self.states: dict[tuple[str, str], str] = {}
        self.calls = 0
        self.status_calls = 0

    def admit(self, caller, key: str, request: dict[str, object]) -> JobReceipt:
        self.calls += 1
        owner_key = (caller.subject, key)
        existing = self.admissions.get(owner_key)
        if existing is not None:
            original, receipt = existing
            if original != request:
                raise AdmissionConflict()
            return receipt
        receipt = JobReceipt(job_id=f"job-{len(self.admissions) + 1}")
        self.admissions[owner_key] = (request, receipt)
        self.states[(caller.subject, receipt.job_id)] = "queued"
        return receipt

    def status(self, caller, job_id: str) -> str | None:
        self.status_calls += 1
        return self.states.get((caller.subject, job_id))


class AdmissionFailure(ValueError):
    code = "authentication.refused"


class AdmissionUnavailable(RuntimeError):
    code = "authentication.unavailable"


class MachineAdmission:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def admit(self, values: dict[str, object]) -> object:
        self.calls.append(values)
        authorization = values.get("authorization")
        if authorization == "Bearer coordinator":
            return MachineContext("coordinator")
        if authorization == "Bearer coordinator-a":
            return MachineContext("coordinator-a")
        if authorization == "Bearer coordinator-b":
            return MachineContext("coordinator-b")
        if authorization == "Bearer unavailable-canary":
            raise AdmissionUnavailable()
        raise AdmissionFailure()


@dataclass(frozen=True)
class MachineContext:
    subject: str
    client_id: str = "coordinator-client"
    profile: str = "coordinator-invoker"
    issuer: str = "https://issuer.example.invalid/"
    resource: str = "urn:example:external-job"
    persona: str = "service"


def request(
    app: JobApplication,
    method: str,
    path: str,
    *,
    body: object | None = None,
    key: str | None = None,
    authorization: str | None = "Bearer coordinator",
    cookie: str | None = None,
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
    if authorization is not None:
        environ["HTTP_AUTHORIZATION"] = authorization
    if cookie is not None:
        environ["HTTP_COOKIE"] = cookie
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


def get_url(app, url, *, authorization):
    path, _, query = url.partition("?")
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)

    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_LENGTH": "0",
        "wsgi.input": BytesIO(),
    }
    if authorization is not None:
        environ["HTTP_AUTHORIZATION"] = authorization
    payload = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], json.loads(payload)


class JobApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = MemoryStore()
        self.admission = MachineAdmission()
        self.app = JobApplication(self.store, self.admission)

    def test_post_requires_machine_admission_before_reading_or_storing_work(
        self,
    ) -> None:
        for authorization, cookie in (
            (None, None),
            (None, "session=Bearer coordinator"),
            ("Bearer wrong-token-canary", None),
        ):
            with self.subTest(authorization=authorization, cookie=cookie):
                status, headers, body = request(
                    self.app,
                    "POST",
                    "/jobs",
                    key="coordinator-command-001",
                    body={"reference": "case-001"},
                    authorization=authorization,
                    cookie=cookie,
                )

                self.assertEqual(status, "401 Unauthorized")
                self.assertEqual(body, {"code": "authentication.refused"})
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertNotIn("wrong-token-canary", json.dumps(body))
        self.assertEqual(self.store.calls, 0)
        self.assertEqual(
            self.admission.calls,
            [
                {"authorization": None},
                {"authorization": None},
                {"authorization": "Bearer wrong-token-canary"},
            ],
        )

    def test_get_requires_machine_admission_before_observing_a_job(self) -> None:
        status, _, body = self._request_url("/jobs/status?id=job-1", authorization=None)

        self.assertEqual(status, "401 Unauthorized")
        self.assertEqual(body, {"code": "authentication.refused"})
        self.assertEqual(self.store.status_calls, 0)

    def test_verifier_outage_is_value_free_and_never_reaches_the_store(self) -> None:
        status, _, body = request(
            self.app,
            "POST",
            "/jobs",
            key="coordinator-command-001",
            body={"reference": "case-001"},
            authorization="Bearer unavailable-canary",
        )

        self.assertEqual(status, "503 Service Unavailable")
        self.assertEqual(body, {"code": "authentication.unavailable"})
        self.assertNotIn("unavailable-canary", json.dumps(body))
        self.assertEqual(self.store.calls, 0)

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
        self.assertEqual(
            self.admission.calls,
            [
                {"authorization": "Bearer coordinator"},
                {"authorization": "Bearer coordinator"},
            ],
        )

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
        self.store.states[("coordinator", job_id)] = "running"

        environ_path = f"/jobs/status?id={job_id}"
        status, _, body = self._request_url(environ_path)
        self.assertEqual(status, "200 OK")
        self.assertEqual(body, {"jobId": job_id, "state": "running"})
        self.assertEqual(self.store.status_calls, 1)
        self.assertEqual(
            self.admission.calls[-1], {"authorization": "Bearer coordinator"}
        )

    def test_invalid_work_is_refused_before_admission(self) -> None:
        for key, body in [
            (None, {"reference": "case-001"}),
            ("coordinator-command-001", {}),
            ("coordinator-command-001", {"reference": ""}),
            ("coordinator-command-001", {"reference": "case-001", "extra": True}),
        ]:
            with self.subTest(key=key, body=body):
                status, _, _ = request(self.app, "POST", "/jobs", key=key, body=body)
                self.assertIn(status.split(" ", 1)[0], ("400", "422"))
        self.assertEqual(self.store.calls, 0)

    def test_response_encoding_failure_leaves_the_committed_receipt_recoverable(
        self,
    ) -> None:
        def broken_encoder(_: object) -> bytes:
            raise UnicodeError("synthetic response encoding failure")

        broken = JobApplication(self.store, self.admission, encode_json=broken_encoder)
        with self.assertRaisesRegex(
            UnicodeError, "synthetic response encoding failure"
        ):
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

    def test_verified_caller_namespaces_admission_and_status(self) -> None:
        first = request(
            self.app,
            "POST",
            "/jobs",
            key="shared-command",
            body={"reference": "case-shared"},
            authorization="Bearer coordinator-a",
        )
        second = request(
            self.app,
            "POST",
            "/jobs",
            key="shared-command",
            body={"reference": "case-shared"},
            authorization="Bearer coordinator-b",
        )

        self.assertEqual(first[0], "201 Created")
        self.assertEqual(second[0], "201 Created")
        self.assertNotEqual(first[2], second[2])
        hidden = get_url(
            self.app,
            f"/jobs/status?id={first[2]['jobId']}",
            authorization="Bearer coordinator-b",
        )
        visible = get_url(
            self.app,
            f"/jobs/status?id={first[2]['jobId']}",
            authorization="Bearer coordinator-a",
        )
        self.assertEqual(hidden[0], "404 Not Found")
        self.assertEqual(hidden[2], {"reason": "job-not-found"})
        self.assertEqual(visible[2], {**first[2], "state": "queued"})

    def _request_url(
        self,
        url: str,
        *,
        authorization: str | None = "Bearer coordinator",
    ) -> tuple[str, dict[str, str], object]:
        return get_url(self.app, url, authorization=authorization)


if __name__ == "__main__":
    unittest.main()
