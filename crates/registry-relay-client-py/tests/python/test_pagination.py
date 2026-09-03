from __future__ import annotations

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
    json_response,
    record_collection,
    resource_collection,
)

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402


class PaginationTest(unittest.TestCase):
    def test_resource_and_collection_continuations_round_trip_as_plain_stateless_values(self):
        def respond(request: Request):
            target = urlsplit(request.target)
            query = parse_qs(target.query)
            if target.path == "/prefix/v2/resources":
                return json_response(
                    resource_collection(None if "cursor" in query else "resource_cursor")
                )
            if target.path == "/prefix/v2/resources/people/records":
                return json_response(
                    record_collection(None if "cursor" in query else "record_cursor")
                )
            if target.path == "/prefix/v2/resources/people/searches/nearby":
                response = json_response(
                    record_collection(
                        None if "cursor" in query else "search_cursor", json_ld=True
                    )
                )
                return type(response)(
                    response.status,
                    "application/ld+json",
                    response.body,
                    response.headers,
                )
            raise AssertionError(request.target)

        with RelayServer(respond) as server:
            client = relay.RelayClient(server.base_url)

            first_resources = client.resources(page_size=2)
            self.assertEqual(first_resources["continuation"], {"cursor": "resource_cursor"})
            second_resources = client.continue_resources(first_resources["continuation"])
            self.assertIsNone(second_resources["continuation"])

            first_records = client.list_records(
                "people",
                page_size=5,
                fields=["recordIdentifier"],
                access_profile="public",
                filters={"category": "active"},
            )
            record_continuation = first_records["continuation"]
            self.assertEqual(
                record_continuation,
                {
                    "route": {"kind": "records", "resource": "people"},
                    "cursor": "record_cursor",
                    "format": "json",
                    "accessProfile": "public",
                },
            )
            second_records = client.continue_list_records(record_continuation)
            self.assertIsNone(second_records["continuation"])

            first_search = client.search(
                "people",
                "nearby",
                bbox=[10, 20, 11, 21],
                page_size=3,
                format="json-ld",
            )
            search_continuation = first_search["continuation"]
            self.assertEqual(search_continuation["route"]["kind"], "search")
            self.assertEqual(search_continuation["route"]["search"], "nearby")
            self.assertEqual(search_continuation["format"], "json-ld")
            self.assertNotIn("accessProfile", search_continuation)
            second_search = client.continue_search(search_continuation)
            self.assertIsNone(second_search["continuation"])

        queries = [parse_qs(urlsplit(request.target).query) for request in server.requests]
        self.assertEqual(queries[1], {"cursor": ["resource_cursor"]})
        self.assertEqual(queries[3], {"cursor": ["record_cursor"], "accessProfile": ["public"]})
        self.assertNotIn("fields", queries[3])
        self.assertNotIn("pageSize", queries[3])
        self.assertNotIn("category", queries[3])
        self.assertEqual(
            queries[4], {"bbox": ["10,20,11,21"], "pageSize": ["3"]}
        )
        self.assertEqual(queries[5], {"cursor": ["search_cursor"]})
        self.assertNotIn("bbox", queries[5])

    def test_continuations_are_route_specific_and_exact(self):
        client = relay.RelayClient("http://127.0.0.1:9")
        for continuation in (
            "cursor",
            {"cursor": "cursor", "unexpected": "value"},
        ):
            with self.subTest(resource_continuation=continuation):
                with self.assertRaises(relay.RelayClientError):
                    client.continue_resources(continuation)

        search = {
            "route": {"kind": "search", "resource": "people", "search": "nearby"},
            "cursor": "cursor",
            "format": "json",
        }
        with self.assertRaises(relay.RelayClientError) as wrong_method:
            client.continue_list_records(search)
        self.assertEqual(wrong_method.exception.kind, "invalid_request")

        records = {
            "route": {"kind": "records", "resource": "people"},
            "cursor": "cursor",
            "format": "json",
            "unexpected": "value",
        }
        with self.assertRaises(relay.RelayClientError):
            client.continue_list_records(records)

        records = {
            "route": {"kind": "records", "resource": "people"},
            "cursor": "cursor",
            "format": "json",
            "accessProfile": None,
        }
        with self.assertRaises(relay.RelayClientError):
            client.continue_list_records(records)

        records = {
            "route": {
                "kind": "records",
                "resource": "people",
                "unexpected": "value",
            },
            "cursor": "cursor",
            "format": "json",
        }
        with self.assertRaises(relay.RelayClientError):
            client.continue_list_records(records)


if __name__ == "__main__":
    unittest.main()
