#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "products" / "platform" / "scripts" / "check-client-contract.py"

GENERATOR = "const inputs = {\n  casework: 'casework/generated/casework.openapi.json',\n}\n"
CLEAN_DOCUMENT = {
    "paths": {
        "/v1/items": {
            "get": {"responses": {"200": {"description": "ok"}, "304": {"description": "not modified"}}},
        },
    },
    "components": {"schemas": {"Problem": {"properties": {"code": {"enum": ["item.missing"]}}}}},
}


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["python3", str(SCRIPT), str(root)], check=False, capture_output=True, text=True)


class CheckClientContract(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)
        self.write("clients/typescript/generate-all.ts", GENERATOR)
        self.document(CLEAN_DOCUMENT)

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def document(self, value: dict) -> None:
        self.write("products/casework/generated/casework.openapi.json", json.dumps(value))

    def assert_refused(self, text: str) -> None:
        result = run(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(text, result.stdout)

    def test_clean_documents_pass_and_304_is_allowed(self) -> None:
        result = run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok", result.stdout)

    def test_session_code_in_an_enum_fails(self) -> None:
        document = json.loads(json.dumps(CLEAN_DOCUMENT))
        document["components"]["schemas"]["Problem"]["properties"]["code"]["enum"].append("session.expired")
        self.document(document)
        self.assert_refused("session.expired")

    def test_session_code_as_a_const_or_example_fails(self) -> None:
        for member, value in (("const", "session.unavailable"), ("example", "session.expired"), ("examples", ["session.x"])):
            document = json.loads(json.dumps(CLEAN_DOCUMENT))
            document["components"]["schemas"]["Problem"]["properties"]["code"] = {member: value}
            self.document(document)
            self.assert_refused("session.")

    def test_a_code_that_only_mentions_session_passes(self) -> None:
        document = json.loads(json.dumps(CLEAN_DOCUMENT))
        document["components"]["schemas"]["Problem"]["properties"]["code"]["enum"] = ["sessions.listed", "case.session.x"]
        self.document(document)
        self.assertEqual(run(self.root).returncode, 0)

    def test_a_redirect_answer_fails(self) -> None:
        for status in ("301", "302", "303", "307", "308", "3XX"):
            document = json.loads(json.dumps(CLEAN_DOCUMENT))
            document["paths"]["/v1/items"]["get"]["responses"][status] = {"description": "moved"}
            self.document(document)
            self.assert_refused(f"GET /v1/items declares {status}")

    def test_a_missing_generator_or_document_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(run(Path(empty)).returncode, 2)
        (self.root / "products/casework/generated/casework.openapi.json").unlink()
        self.assertEqual(run(self.root).returncode, 2)

    def test_the_repository_documents_pass(self) -> None:
        result = run(ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
