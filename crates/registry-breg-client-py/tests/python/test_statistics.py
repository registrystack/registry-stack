"""Exercise every statistics operation through the native Python binding."""

import base64
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"


def problem(code: str, status: int, detail: str, **extension: str) -> bytes:
    titles = {404: "Not Found", 409: "Conflict", 410: "Gone", 422: "Unprocessable Entity", 500: "Internal Server Error"}
    return json.dumps({
        "type": "https://id.registrystack.org/problems/registry-breg/" + code.replace(".", "/"),
        "title": titles[status], "status": status, "detail": detail,
        "code": code, "traceId": TRACE_ID, **extension,
    }, separators=(",", ":")).encode()


class StatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def exchange(self) -> None:
                size = int(self.headers.get("content-length", "0"))
                requests.append(
                    (
                        self.command,
                        self.path,
                        self.headers.get("accept"),
                        self.headers.get("idempotency-key"),
                        self.rfile.read(size),
                    )
                )
                publish = self.command == "POST" and self.path.endswith(
                    "/versions?accessProfile=publisher"
                )
                failures = (
                    ("/statistics/missing:live", 404, "resource.not_found", "The requested resource was not found.", {}),
                    ("/statistics/release-refused/", 422, "statistical_dataset.release_refused", "The statistical dataset release operation is not eligible.", {"refusalCode": "period-not-ended"}),
                    ("/statistics/version-conflict/", 409, "statistical_dataset.version_conflict", "The statistical dataset computation was superseded or its package changed.", {}),
                    ("/statistics/version-withdrawn/", 410, "statistical_dataset.version_withdrawn", "The statistical dataset version was withdrawn.", {"reasonCode": "source-data-error"}),
                    ("/statistics/domain-violation:live", 500, "statistical_dataset.domain_violation", "A statistical dataset contains a code outside its declared domain.", {"fieldPath": "statisticalDatasets[id=domain-violation].dimensions[id=category]"}),
                )
                failure = next((item for item in failures if item[0] in self.path), None)
                if failure is not None:
                    _, status, code, detail, extension = failure
                    body = problem(code, status, detail, **extension)
                    self.send_response(status)
                    self.send_header("content-type", "application/problem+json")
                    self.send_header("cache-control", "no-store")
                    self.send_header("traceparent", TRACEPARENT)
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                body = (
                    b"period,periodStart,periodEnd,value,status\r\n"
                    if self.headers.get("accept") == "text/csv"
                    else b'{"ok":true}'
                )
                self.send_response(201 if publish else 200)
                self.send_header(
                    "content-type",
                    "text/csv; charset=utf-8" if self.headers["accept"] == "text/csv" else self.headers["accept"],
                )
                self.send_header("traceparent", TRACEPARENT)
                if "/cache-control-missing" not in self.path:
                    cache_control = (
                        "private" if "/cache-control-wrong" in self.path else "no-store"
                    )
                    self.send_header("cache-control", cache_control)
                if "/vary-missing" not in self.path:
                    vary = "accept" if "/vary-wrong" in self.path else "authorization, accept"
                    self.send_header("vary", vary)
                if "/digest-missing/" not in self.path and (
                    self.command == "POST" or "/releases?" not in self.path
                ):
                    represented_body = b'{"wrong":true}' if "/digest-mismatch/" in self.path else body
                    digest = base64.b64encode(hashlib.sha256(represented_body).digest()).decode()
                    self.send_header("repr-digest", f"sha-256=:{digest}:")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = exchange  # noqa: N815
            do_POST = exchange  # noqa: N815

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(f"http://127.0.0.1:{self.server.server_port}")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_all_statistics_methods(self) -> None:
        live = self.client.statistics_live(
            "enrolments", from_period="2025-01", to_period="2025-02",
            access_profile="analyst", format="csv"
        )
        self.assertEqual(live["media_type"], "text/csv; charset=utf-8")
        self.assertTrue(live["repr_digest"].startswith("sha-256=:"))
        self.client.statistics_live("enrolments", from_period="2025-01")
        self.client.statistics_live("enrolments", to_period="2025-02")
        self.client.statistics_releases("enrolments", top=10, skip_token="cursor", access_profile="reader")
        self.client.statistics_latest_release("enrolments", "2025-01", "final", access_profile="reader")
        self.client.statistics_release_version("enrolments", "2025-01", 7, access_profile="reader", format="csv")
        self.client.statistics_release_series("enrolments", "2025-01", "2025-02", "any", access_profile="reader")
        publish = self.client.statistics_publish(
            "enrolments", "2025-01", "final", "publisher", "caller-owned-key"
        )
        withdraw = self.client.statistics_withdraw(
            "enrolments", "2025-01", 7, "disclosure-risk", "publisher", "caller-owned-key"
        )
        self.assertTrue(publish["repr_digest"].startswith("sha-256=:"))
        self.assertTrue(withdraw["repr_digest"].startswith("sha-256=:"))
        self.assertEqual(self.requests[0][1], "/v1/statistics/enrolments:live?from=2025-01&to=2025-02&accessProfile=analyst")
        self.assertEqual(self.requests[1][1], "/v1/statistics/enrolments:live?from=2025-01")
        self.assertEqual(self.requests[2][1], "/v1/statistics/enrolments:live?to=2025-02")
        self.assertEqual(json.loads(self.requests[7][4]), {"status": "final"})
        self.assertEqual(self.requests[7][3], "caller-owned-key")
        self.assertEqual(json.loads(self.requests[8][4]), {"reason": "disclosure-risk"})
        count = len(self.requests)
        with self.assertRaises(BaseRegistryClientError):
            self.client.statistics_release_version("enrolments", "2025-01", 0)
        self.assertEqual(len(self.requests), count)

        self.client.statistics_live("enrolments", from_period="0001", to_period="9998")
        self.client.statistics_latest_release("enrolments", "9999-Q3", "any")
        self.client.statistics_release_version("enrolments", "9999-11", 1)
        self.client.statistics_release_series(
            "enrolments", "2024-02-29", "9999-12-30", "any"
        )
        after_canonical_periods = len(self.requests)
        for invalid_period_call in (
            lambda: self.client.statistics_publish(
                "enrolments", "2025-99", "final", "publisher", "invalid-period-key"
            ),
            lambda: self.client.statistics_withdraw(
                "enrolments", "----", 1, "source-data-error",
                "publisher", "invalid-period-key"
            ),
        ):
            with self.assertRaises(BaseRegistryClientError):
                invalid_period_call()
        self.assertEqual(len(self.requests), after_canonical_periods)

        for invalid_cache_read in (
            lambda: self.client.statistics_live("cache-control-missing"),
            lambda: self.client.statistics_live("vary-wrong", format="csv"),
            lambda: self.client.statistics_releases("vary-missing", top=10),
            lambda: self.client.statistics_releases("cache-control-wrong", top=10),
        ):
            with self.assertRaises(BaseRegistryClientError) as cache_error:
                invalid_cache_read()
            self.assertEqual(cache_error.exception.code, "cache-policy")

        maximum_cursor = "c" * 10_978
        self.client.statistics_releases(
            "d" * 64, top=10, skip_token=maximum_cursor, access_profile="p" * 64
        )
        after_maximum_cursor = len(self.requests)
        with self.assertRaises(BaseRegistryClientError):
            self.client.statistics_releases(
                "d" * 64, top=10, skip_token=maximum_cursor + "c", access_profile="p" * 64
            )
        self.assertEqual(len(self.requests), after_maximum_cursor)

        for version_call in (
            lambda: self.client.statistics_release_version(
                "enrolments", "2025-01", 2**63
            ),
            lambda: self.client.statistics_withdraw(
                "enrolments", "2025-01", 2**63, "source-data-error",
                "publisher", "too-large-version-key"
            ),
        ):
            before_version_call = len(self.requests)
            with self.assertRaises(BaseRegistryClientError):
                version_call()
            self.assertEqual(len(self.requests), before_version_call)

        with self.assertRaises(BaseRegistryClientError) as missing_digest:
            self.client.statistics_publish(
                "digest-missing", "2025-01", "final", "publisher", "digest-missing-key"
            )
        self.assertEqual(missing_digest.exception.code, "representation-digest")

        with self.assertRaises(BaseRegistryClientError) as mismatched_digest:
            self.client.statistics_withdraw(
                "digest-mismatch", "2025-01", 7, "source-data-error",
                "publisher", "digest-mismatch-key"
            )
        self.assertEqual(mismatched_digest.exception.code, "representation-digest")

        with self.assertRaises(BaseRegistryClientError) as missing:
            self.client.statistics_live("missing")
        self.assertEqual(missing.exception.kind, "not-found")
        self.assertEqual(missing.exception.code, "resource.not_found")

        with self.assertRaises(BaseRegistryClientError) as refused:
            self.client.statistics_publish("release-refused", "2025-01", "final", "publisher", "refusal-key")
        self.assertEqual(refused.exception.code, "statistical_dataset.release_refused")
        self.assertEqual(refused.exception.refusal_code, "period-not-ended")

        with self.assertRaises(BaseRegistryClientError) as conflict:
            self.client.statistics_publish("version-conflict", "2025-01", "final", "publisher", "conflict-key")
        self.assertEqual(conflict.exception.code, "statistical_dataset.version_conflict")

        with self.assertRaises(BaseRegistryClientError) as withdrawn:
            self.client.statistics_release_version("version-withdrawn", "2025-01", 7, access_profile="reader")
        self.assertEqual(withdrawn.exception.code, "statistical_dataset.version_withdrawn")
        self.assertEqual(withdrawn.exception.reason_code, "source-data-error")
        self.assertIsNone(withdrawn.exception.refusal_code)

        with self.assertRaises(BaseRegistryClientError) as domain:
            self.client.statistics_live("domain-violation", access_profile="reader")
        self.assertEqual(domain.exception.code, "statistical_dataset.domain_violation")
        self.assertEqual(
            domain.exception.field_path,
            "statisticalDatasets[id=domain-violation].dimensions[id=category]",
        )
        self.assertNotIn("domain-violation", str(domain.exception))


if __name__ == "__main__":
    unittest.main()
