from __future__ import annotations

import json
import pathlib
import sys
import unittest
from urllib.parse import parse_qs, urlsplit

TESTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
import bootstrap  # noqa: E402
from relay_server import (  # noqa: E402
    RelayServer,
    Request,
    Response,
    json_response,
    record,
    record_collection,
    record_metadata,
    resource_collection,
    resource_document,
    service_metadata,
)

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402


class HappyPathTest(unittest.TestCase):
    def test_every_fixed_method_delegates_one_exchange_and_returns_plain_values(self):
        def respond(request: Request) -> Response:
            target = urlsplit(request.target)
            path = target.path
            if path in {"/prefix/health", "/prefix/ready"}:
                return json_response({"status": "ok"})
            if path == "/prefix/openapi.json":
                return Response(200, body=b'{"openapi":"3.1.0"}')
            if path == "/prefix/v2":
                return json_response(service_metadata())
            if path == "/prefix/v2/resources":
                return json_response(resource_collection(None))
            if path == "/prefix/v2/resources/people":
                return json_response(
                    {
                        "data": resource_document(),
                        "meta": {"registryIdentifier": "urn:example:registry"},
                    }
                )
            if path == "/prefix/v2/resources/people/records":
                self.assertEqual(parse_qs(target.query), {"status": ["active"]})
                return json_response(record_collection(None))
            if path == "/prefix/v2/resources/people/records/one":
                return json_response({"data": record(), "meta": record_metadata()})
            if path == "/prefix/v2/resources/people/lookups/by-code":
                self.assertEqual(request.method, "POST")
                self.assertEqual(json.loads(request.body), {"selectors": {"code": "one"}})
                return json_response({"data": record(), "meta": record_metadata()})
            if path == "/prefix/v2/resources/people/searches/nearby":
                self.assertEqual(parse_qs(target.query), {"bbox": ["10,20,11,21"]})
                return json_response(record_collection(None))
            if path == "/prefix/v2/artifacts/schema":
                return Response(200, "application/schema+json", b'{"type":"object"}')
            if path.startswith("/prefix/sdmx/v2/data/dataflow/AGENCY/FLOW/1.0.0"):
                return Response(
                    200,
                    "application/vnd.sdmx.data+json;version=2.1.0",
                    b'{"dataSets":[]}',
                )
            if path == "/prefix/sdmx/v2/structure/dataflow/AGENCY/FLOW/1.0.0":
                return Response(
                    200,
                    "application/vnd.sdmx.structure+json;version=2.1.0",
                    b'{"data":{"dataflows":[]}}',
                )
            raise AssertionError(f"unexpected request {request.method} {request.target}")

        with RelayServer(respond) as server:
            client = relay.RelayClient(
                server.base_url,
                authorization={"static": "static-token"},
            )
            self.assertEqual(client.health()["value"], {"status": "ok"})
            self.assertEqual(client.ready()["kind"], "complete")
            self.assertIsInstance(client.openapi()["body"], bytes)
            self.assertEqual(client.service_metadata()["value"]["name"], "Example Registry")
            self.assertEqual(client.resources()["value"]["items"][0]["resourceIdentifier"], "people")
            self.assertEqual(client.resource("people")["value"]["data"]["title"], "People")
            self.assertEqual(
                client.list_records("people", filters={"status": "active"})["value"][
                    "items"
                ][0]["recordIdentifier"],
                "one",
            )
            self.assertEqual(client.read_record("people", "one")["value"]["data"]["domainData"]["label"], "Example")
            self.assertEqual(client.lookup("people", "by-code", {"code": "one"})["value"]["data"]["recordIdentifier"], "one")
            self.assertEqual(client.search("people", "nearby", bbox=[10, 20, 11, 21])["value"]["items"][0]["recordIdentifier"], "one")
            artifact = client.artifact("schema")
            self.assertEqual(artifact["body"], b'{"type":"object"}')
            self.assertEqual(artifact["media_type"], "application/schema+json")
            data = client.sdmx_data(
                "AGENCY",
                "FLOW",
                "1.0.0",
                constraints={"TIME_PERIOD": "ge:2020+le:2024"},
                limit=10,
            )
            self.assertEqual(data["body"], b'{"dataSets":[]}')
            structure = client.sdmx_structure("dataflow", "AGENCY", "FLOW", "1.0.0")
            self.assertEqual(structure["media_type"], "application/vnd.sdmx.structure+json;version=2.1.0")

        self.assertEqual(len(server.requests), 13)
        for request in server.requests[:3]:
            self.assertNotIn("authorization", request.headers)
        for request in server.requests[3:]:
            self.assertEqual(request.headers.get("authorization"), "Bearer static-token")


if __name__ == "__main__":
    unittest.main()
