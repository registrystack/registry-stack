from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate.py")
SPEC = importlib.util.spec_from_file_location("identifier_catalog_generate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
generate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate)


class CatalogGeneratorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "schemas").mkdir()
        (self.root / "src").mkdir()
        (self.root / "src" / "problem.rs").write_text("problem source\n")
        (self.root / "src" / "vocab.rs").write_text("vocabulary source\n")
        self.schema_uri = f"{generate.BASE_URL}/schemas/example/v1.json"
        (self.root / "schemas" / "v1.json").write_text(
            json.dumps({"$id": self.schema_uri, "title": "Example schema"})
        )
        self.problem_catalog = self.root / "problems.json"
        self.problem_catalog.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "uri": f"{generate.BASE_URL}/problems/registry-relay/example/failed",
                            "code": "example.failed",
                            "title": "Example failed",
                            "description": "the example failed",
                            "httpStatuses": [400],
                        }
                    ]
                }
            )
        )
        self.config = self.root / "source.json"
        self.write_config()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.track(".")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, records=None, exclusions=None) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "baseUrl": generate.BASE_URL,
                    "referenceExclusions": exclusions or [],
                    "schemaSources": [
                        {
                            "glob": "schemas/*.json",
                            "owner": "example",
                            "status": "active",
                            "compatibilityLine": "v1",
                            "description": "Example schema.",
                        }
                    ],
                    "records": records
                    if records is not None
                    else [
                        {
                            "uri": f"{generate.BASE_URL}/vocab/example",
                            "kind": "vocabulary",
                            "status": "active",
                            "compatibilityLine": "v1",
                            "owner": "example",
                            "title": "Example vocabulary",
                            "description": "Example terms.",
                            "sourcePath": "src/vocab.rs",
                        }
                    ],
                }
            )
        )

    def track(self, *paths: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), "add", "--", *paths],
            check=True,
        )

    def build(self):
        original = generate.PROBLEM_SOURCE
        generate.PROBLEM_SOURCE = Path("src/problem.rs")
        try:
            return generate.build_catalog(self.root, self.config, self.problem_catalog)
        finally:
            generate.PROBLEM_SOURCE = original

    def test_catalog_binds_problem_schema_and_vocabulary_sources(self) -> None:
        catalog = self.build()
        self.assertEqual(catalog["version"], 1)
        self.assertEqual([entry["uri"] for entry in catalog["entries"]], sorted(
            entry["uri"] for entry in catalog["entries"]
        ))
        schema = next(entry for entry in catalog["entries"] if entry["kind"] == "schema")
        self.assertEqual(schema["uri"], self.schema_uri)
        self.assertEqual(schema["compatibilityLine"], "v1")
        self.assertEqual(schema["source"]["sha256"], schema["artifact"]["sha256"])

    def test_schema_outside_closed_groups_is_rejected(self) -> None:
        outside = self.root / "outside.json"
        outside.write_text(
            json.dumps({"$id": f"{generate.BASE_URL}/schemas/outside.json"})
        )
        self.track("outside.json")
        with self.assertRaisesRegex(generate.CatalogError, "outside the closed source groups"):
            self.build()

    def test_generated_schema_binds_distinct_source_and_artifact(self) -> None:
        document = json.loads(self.config.read_text())
        document["schemaSources"][0]["sourcePath"] = "src/vocab.rs"
        self.config.write_text(json.dumps(document))
        schema = next(
            entry for entry in self.build()["entries"] if entry["kind"] == "schema"
        )
        self.assertEqual(schema["source"]["path"], "src/vocab.rs")
        self.assertEqual(schema["artifact"]["path"], "schemas/v1.json")
        self.assertNotEqual(schema["source"]["sha256"], schema["artifact"]["sha256"])

    def test_duplicate_identifier_is_rejected(self) -> None:
        self.write_config(
            [
                {
                    "uri": self.schema_uri,
                    "kind": "vocabulary",
                    "status": "active",
                    "compatibilityLine": "v1",
                    "owner": "example",
                    "title": "Duplicate",
                    "description": "Duplicate identifier.",
                    "sourcePath": "src/vocab.rs",
                }
            ]
        )
        with self.assertRaisesRegex(generate.CatalogError, "duplicated"):
            self.build()

    def test_problem_code_must_match_its_uri(self) -> None:
        document = json.loads(self.problem_catalog.read_text())
        document["entries"][0]["uri"] = f"{generate.BASE_URL}/problems/wrong"
        self.problem_catalog.write_text(json.dumps(document))
        with self.assertRaisesRegex(generate.CatalogError, "URI and code disagree"):
            self.build()

    def test_retired_source_group_is_rejected(self) -> None:
        document = json.loads(self.config.read_text())
        document["schemaSources"][0]["status"] = "retired"
        self.config.write_text(json.dumps(document))
        with self.assertRaisesRegex(generate.CatalogError, "invalid status"):
            self.build()

    def test_catalog_contract_rejects_blank_owner(self) -> None:
        document = json.loads(self.config.read_text())
        document["schemaSources"][0]["owner"] = ""
        self.config.write_text(json.dumps(document))
        with self.assertRaisesRegex(generate.CatalogError, "invalid owner"):
            self.build()

    def test_catalog_contract_rejects_invalid_problem_statuses(self) -> None:
        document = json.loads(self.problem_catalog.read_text())
        document["entries"][0]["httpStatuses"] = [99, 99]
        self.problem_catalog.write_text(json.dumps(document))
        with self.assertRaisesRegex(generate.CatalogError, "invalid HTTP statuses"):
            self.build()

    def test_unclassified_identifier_reference_is_rejected(self) -> None:
        (self.root / "src" / "unclassified.rs").write_text(
            f'const URI: &str = "{generate.BASE_URL}/unclassified/value";\n'
        )
        self.track("src/unclassified.rs")
        with self.assertRaisesRegex(generate.CatalogError, "outside the active catalog"):
            self.build()

    def test_reviewed_identifier_reference_exclusion_is_accepted(self) -> None:
        (self.root / "src" / "legacy.rs").write_text(
            f'const URI: &str = "{generate.BASE_URL}/legacy/value";\n'
        )
        self.track("src/legacy.rs")
        self.write_config(
            exclusions=[
                {
                    "glob": "src/legacy.rs",
                    "classification": "legacy-source",
                    "reason": "Legacy fixture retained for compatibility tests.",
                }
            ]
        )
        catalog = self.build()
        self.assertNotIn(
            f"{generate.BASE_URL}/legacy/value",
            {entry["uri"] for entry in catalog["entries"]},
        )

    def test_untracked_identifier_reference_is_ignored(self) -> None:
        (self.root / "src" / "scratch.rs").write_text(
            f'const URI: &str = "{generate.BASE_URL}/scratch/value";\n'
        )
        self.build()

    def test_reference_exclusion_must_match_a_tracked_file(self) -> None:
        self.write_config(
            exclusions=[
                {
                    "glob": "src/missing.rs",
                    "classification": "legacy-source",
                    "reason": "A stale exclusion must not survive silently.",
                }
            ]
        )
        with self.assertRaisesRegex(generate.CatalogError, "matched no tracked files"):
            self.build()


if __name__ == "__main__":
    unittest.main()
