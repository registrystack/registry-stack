from __future__ import annotations

import inspect
import pathlib
import sys
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
import bootstrap  # noqa: E402

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402


class RequestShapeTest(unittest.TestCase):
    def setUp(self):
        self.client = relay.RelayClient("http://127.0.0.1:9")

    def test_native_list_signature_has_filters_and_no_bbox(self):
        parameters = inspect.signature(relay.RelayClient.list_records).parameters
        self.assertIn("filters", parameters)
        self.assertNotIn("bbox", parameters)

        with self.assertRaises(TypeError):
            self.client.list_records("people", bbox=[10, 20, 11, 21])

    def test_native_search_signature_requires_bbox_and_has_no_filters(self):
        parameters = inspect.signature(relay.RelayClient.search).parameters
        self.assertNotIn("filters", parameters)
        self.assertEqual(parameters["bbox"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameters["bbox"].default, inspect.Parameter.empty)

        with self.assertRaises(TypeError):
            self.client.search("people", "nearby")
        with self.assertRaises(TypeError):
            self.client.search(
                "people",
                "nearby",
                bbox=[10, 20, 11, 21],
                filters={"status": "active"},
            )

    def test_search_rejects_invalid_bbox_without_exposing_values(self):
        canary = "canary-bbox-value"
        for bbox in (None, [10, 20, 11], [canary, 20, 11, 21]):
            with self.subTest(bbox=bbox):
                with self.assertRaises(relay.RelayClientError) as raised:
                    self.client.search("people", "nearby", bbox=bbox)
                self.assertEqual(raised.exception.kind, "invalid_request")
                self.assertEqual(
                    str(raised.exception), "bbox must be a four-number sequence"
                )
                self.assertNotIn(canary, str(raised.exception))
                self.assertNotIn(canary, repr(raised.exception))

        cyclic: list[object] = []
        cyclic.append(cyclic)
        with self.assertRaises(relay.RelayClientError) as cycle:
            self.client.search("people", "nearby", bbox=cyclic)
        self.assertEqual(cycle.exception.kind, "invalid_request")


if __name__ == "__main__":
    unittest.main()
