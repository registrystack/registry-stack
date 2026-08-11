from __future__ import annotations

import pathlib
import sys
import unittest
from urllib.parse import urlsplit

TESTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
import bootstrap  # noqa: E402
from relay_server import ETAG, RelayServer, Request, Response  # noqa: E402

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402


class RawBodyTest(unittest.TestCase):
    def test_raw_documents_remain_bytes_and_conditional_requests_are_explicit(self):
        def respond(request: Request) -> Response:
            path = urlsplit(request.target).path
            if path == "/prefix/openapi.json":
                if request.headers.get("if-none-match") == ETAG:
                    return Response(304, headers={"etag": ETAG})
                return Response(200, body=b'{"openapi":"3.1.0"}', headers={"etag": ETAG})
            if path == "/prefix/v2/artifacts/context":
                return Response(200, "application/ld+json", b'{"@context":{}}')
            if path.endswith("/KEY"):
                return Response(
                    200,
                    "application/vnd.sdmx.data+csv;version=2.1.0",
                    b"DATAFLOW,OBS_VALUE\nFLOW,1\n",
                )
            raise AssertionError(request.target)

        with RelayServer(respond) as server:
            client = relay.RelayClient(server.base_url)
            first = client.openapi()
            self.assertEqual(first["kind"], "complete")
            self.assertEqual(first["body"], b'{"openapi":"3.1.0"}')
            self.assertEqual(first["etag"], ETAG)
            second = client.openapi(etag=first["etag"])
            self.assertEqual(
                second, {"kind": "not_modified", "etag": ETAG, "trace_id": second["trace_id"]}
            )
            artifact = client.artifact("context")
            self.assertEqual(artifact["media_type"], "application/ld+json")
            self.assertIsInstance(artifact["body"], bytes)
            data = client.sdmx_data(
                "AGENCY", "FLOW", "1.0.0", key="KEY", format="csv"
            )
            self.assertEqual(data["body"], b"DATAFLOW,OBS_VALUE\nFLOW,1\n")

        self.assertEqual(len(server.requests), 4)
        self.assertEqual(server.requests[1].headers["if-none-match"], ETAG)


if __name__ == "__main__":
    unittest.main()
