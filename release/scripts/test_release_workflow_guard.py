#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("release_workflow_guard.py")


def load_module():
    spec = importlib.util.spec_from_file_location("release_workflow_guard", SCRIPT)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module spec from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseWorkflowGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_http_status_uses_the_final_valid_response_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            response = Path(temporary) / "response"
            response.write_bytes(
                b"HTTP/1.1 301 Moved Permanently\r\n"
                b"location: elsewhere\r\n\r\n"
                b"HTTP/2 404\r\ncontent-type: application/json\r\n\r\n{}\n"
            )
            self.assertEqual(self.module.final_http_status(response), "404")
            response.write_text("request failed without headers\n", encoding="utf-8")
            with self.assertRaisesRegex(
                self.module.GuardError,
                "no valid HTTP status",
            ):
                self.module.final_http_status(response)

    def test_public_image_destination_is_closed_and_exact(self) -> None:
        self.assertEqual(
            self.module.public_image_destination(
                "ghcr.io/registrystack/registry-relay:v1.2.3",
                "registrystack",
            ),
            ("registry-relay", "v1.2.3"),
        )
        for value in [
            "ghcr.io/registrystack/registry-relay@sha256:" + "a" * 64,
            "ghcr.io/other/registry-relay:v1.2.3",
            "ghcr.io/registrystack/registry-relay:latest",
        ]:
            with self.subTest(value=value):
                with self.assertRaises(self.module.GuardError):
                    self.module.public_image_destination(value, "registrystack")

    def test_image_tag_absence_burns_any_existing_version(self) -> None:
        digest = "sha256:" + "a" * 64
        document = [
            [
                {
                    "name": digest,
                    "metadata": {
                        "container": {"tags": ["v1.2.3", "supported"]}
                    },
                }
            ]
        ]
        self.assertIsNone(
            self.module.require_image_tag_absent(document, tag="v1.2.4")
        )
        with self.assertRaisesRegex(self.module.GuardError, "already exists"):
            self.module.require_image_tag_absent(document, tag="v1.2.3")

    def test_image_tag_absence_rejects_ambiguous_or_malformed_api_results(
        self,
    ) -> None:
        digest = "sha256:" + "a" * 64
        version = {
            "name": digest,
            "metadata": {"container": {"tags": ["v1.2.3"]}},
        }
        with self.assertRaisesRegex(self.module.GuardError, "multiple"):
            self.module.require_image_tag_absent(
                [[version, dict(version)]],
                tag="v1.2.3",
            )
        for malformed in [
            {},
            [{}],
            [[{}]],
            [[{"metadata": {}}]],
            [[{"metadata": {"container": {"tags": 1}}}]],
        ]:
            with self.subTest(document=json.dumps(malformed)):
                with self.assertRaises(self.module.GuardError):
                    self.module.require_image_tag_absent(
                        malformed,
                        tag="v1.2.3",
                    )


if __name__ == "__main__":
    unittest.main()
