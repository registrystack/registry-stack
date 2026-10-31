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
        (self.root / "src" / "fixture-problem.rs").write_text("fixture problem source\n")
        (self.root / "src" / "evidence-problem.rs").write_text(
            "evidence problem source\n"
        )
        (self.root / "src" / "vocab.rs").write_text("vocabulary source\n")
        self.schema_uri = f"{generate.BASE_URL}/schemas/example/v1.json"
        (self.root / "schemas" / "v1.json").write_text(
            json.dumps({"$id": self.schema_uri, "title": "Example schema"})
        )
        self.fixture_problem_catalog = self.root / "fixture-problems.json"
        self.fixture_problem_catalog.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "uri": f"{generate.BASE_URL}/problems/registry-fixture/example/failed",
                            "code": "example.failed",
                            "title": "Example failed",
                            "description": "the example failed",
                            "httpStatuses": [400],
                        }
                    ]
                }
            )
        )
        self.evidence_problem_catalog = self.root / "evidence-problems.json"
        self.config = self.root / "source.json"
        self.write_config()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.track(".")

    def write_evidence_problem_catalog(self) -> None:
        self.evidence_problem_catalog.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "uri": f"{generate.BASE_URL}/problems/registry-evidence/example/failed",
                            "code": "example.failed",
                            "title": "Evidence example failed",
                            "description": "the Evidence example failed",
                            "httpStatuses": [422],
                        }
                    ]
                }
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_config(self, records=None, exclusions=None, problem_sources=None) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "version": 1,
                    "baseUrl": generate.BASE_URL,
                    "problemSources": problem_sources
                    if problem_sources is not None
                    else [
                        {
                            "owner": "fixture-product",
                            "status": "active",
                            "compatibilityLine": "v2",
                            "uriPrefix": f"{generate.BASE_URL}/problems/registry-fixture/",
                            "sourcePath": "src/fixture-problem.rs",
                            "exporterPath": "examples/fixture-problem-catalog.rs",
                            "cargoPackage": "fixture-example",
                            "cargoExample": "problem-catalog",
                        }
                    ],
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
        return generate.build_catalog(
            self.root,
            self.config,
            {"src/fixture-problem.rs": self.fixture_problem_catalog},
        )

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

    def test_yaml_schema_outside_closed_groups_is_rejected(self) -> None:
        outside = self.root / "outside.schema.yaml"
        outside.write_text(
            "$schema: https://json-schema.org/draft/2020-12/schema\n"
            f"$id: {generate.BASE_URL}/schemas/outside/yaml.schema.json\n"
            "title: Outside YAML schema\n"
            "properties:\n"
            "  $id:\n"
            "    type: string\n"
        )
        self.track("outside.schema.yaml")
        with self.assertRaisesRegex(generate.CatalogError, "outside.schema.yaml"):
            self.build()

    def test_yaml_schema_in_a_closed_group_is_catalogued(self) -> None:
        (self.root / "yaml-schemas").mkdir()
        uri = f"{generate.BASE_URL}/schemas/example/yaml.schema.json"
        (self.root / "yaml-schemas" / "one.schema.yaml").write_text(
            f"$schema: https://json-schema.org/draft/2020-12/schema\n$id: {uri}\n"
            'title: "Example YAML schema"\n'
        )
        self.track("yaml-schemas/one.schema.yaml")
        document = json.loads(self.config.read_text())
        document["schemaSources"].append(
            {
                "glob": "yaml-schemas/*.schema.yaml",
                "owner": "example",
                "status": "active",
                "compatibilityLine": "v1",
                "description": "Example YAML schema.",
            }
        )
        self.config.write_text(json.dumps(document))
        entry = next(e for e in self.build()["entries"] if e["uri"] == uri)
        self.assertEqual(entry["title"], "Example YAML schema")
        self.assertEqual(entry["artifact"]["mediaType"], "application/yaml")

    def test_a_yaml_schema_identifier_nested_below_the_top_level_is_not_read(self) -> None:
        nested = self.root / "nested.schema.yaml"
        nested.write_text(
            "properties:\n"
            "  $id: https://example.org/nested.json\n"
            "  title: Nested\n"
        )
        self.assertEqual(generate.read_schema_header(nested), {})

    def test_a_yaml_file_that_is_not_text_is_ignored(self) -> None:
        (self.root / "binary.yaml").write_bytes(b"\xff\xfe\x00")
        self.track("binary.yaml")
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

    def test_profile_record_binds_source_and_artifact(self) -> None:
        profile = self.root / "profile.md"
        profile.write_text("Registry Record profile source\n")
        self.track("profile.md")
        self.write_config(
            [
                {
                    "uri": f"{generate.BASE_URL}/profiles/example/v1",
                    "kind": "profile",
                    "status": "active",
                    "compatibilityLine": "v1",
                    "owner": "example",
                    "title": "Example profile",
                    "description": "Example profile artifact.",
                    "sourcePath": "src/vocab.rs",
                    "artifactPath": "profile.md",
                    "mediaType": "text/markdown",
                }
            ]
        )
        entry = next(
            entry
            for entry in self.build()["entries"]
            if entry["kind"] == "profile"
        )
        self.assertEqual(entry["source"]["path"], "src/vocab.rs")
        self.assertEqual(entry["artifact"]["path"], "profile.md")
        self.assertNotEqual(entry["source"]["sha256"], entry["artifact"]["sha256"])

    def test_profile_record_requires_an_artifact(self) -> None:
        self.write_config(
            [
                {
                    "uri": f"{generate.BASE_URL}/profiles/example/v1",
                    "kind": "profile",
                    "status": "active",
                    "compatibilityLine": "v1",
                    "owner": "example",
                    "title": "Example profile",
                    "description": "Example profile artifact.",
                    "sourcePath": "src/vocab.rs",
                }
            ]
        )
        with self.assertRaisesRegex(generate.CatalogError, "requires an artifact"):
            self.build()

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
        document = json.loads(self.fixture_problem_catalog.read_text())
        document["entries"][0]["uri"] = f"{generate.BASE_URL}/problems/wrong"
        self.fixture_problem_catalog.write_text(json.dumps(document))
        with self.assertRaisesRegex(generate.CatalogError, "URI and code disagree"):
            self.build()

    def test_discovery_qualified_codes_keep_the_published_problem_uris(self) -> None:
        prefix = f"{generate.BASE_URL}/problems/registry-discovery/"
        spellings = {
            "request.invalid": "invalid-request",
            "request.not-found": "not-found",
            "request.result-bound-exceeded": "result-bound-exceeded",
            "service.unavailable": "unavailable",
        }
        config = json.loads(self.config.read_text())
        config["problemSources"][0]["uriPrefix"] = prefix
        self.config.write_text(json.dumps(config))
        template = json.loads(self.fixture_problem_catalog.read_text())["entries"][0]
        self.fixture_problem_catalog.write_text(
            json.dumps({
                "entries": [
                    {**template, "uri": prefix + suffix, "code": code}
                    for code, suffix in spellings.items()
                ]
            })
        )
        problems = {
            entry["problem"]["code"]: entry["uri"]
            for entry in self.build()["entries"]
            if entry["kind"] == "problem"
        }
        self.assertEqual(
            problems, {code: prefix + suffix for code, suffix in spellings.items()}
        )

    def test_discovery_mapping_rejects_uri_drift_and_does_not_relax_other_products(self) -> None:
        for namespace, code, suffix in [
            ("registry-discovery", "request.invalid", "request/invalid"),
            ("registry-discovery", "invalid-request", "invalid-request"),
            ("registry-fixture", "request.invalid", "invalid-request"),
        ]:
            with self.subTest(namespace=namespace, code=code):
                prefix = f"{generate.BASE_URL}/problems/{namespace}/"
                config = json.loads(self.config.read_text())
                config["problemSources"][0]["uriPrefix"] = prefix
                self.config.write_text(json.dumps(config))
                document = json.loads(self.fixture_problem_catalog.read_text())
                document["entries"][0].update(uri=prefix + suffix, code=code)
                self.fixture_problem_catalog.write_text(json.dumps(document))
                with self.assertRaisesRegex(generate.CatalogError, "URI and code disagree"):
                    self.build()

    def test_two_problem_sources_are_merged(self) -> None:
        self.write_evidence_problem_catalog()
        document = json.loads(self.config.read_text())
        document["problemSources"].append(
            {
                "owner": "evidence",
                "status": "active",
                "compatibilityLine": "v1",
                "uriPrefix": f"{generate.BASE_URL}/problems/registry-evidence/",
                "sourcePath": "src/evidence-problem.rs",
                "exporterPath": "examples/evidence-problem-catalog.rs",
                "cargoPackage": "evidence-example",
                "cargoExample": "problem-catalog",
            }
        )
        self.config.write_text(json.dumps(document))
        catalog = generate.build_catalog(
            self.root,
            self.config,
            {
                "src/fixture-problem.rs": self.fixture_problem_catalog,
                "src/evidence-problem.rs": self.evidence_problem_catalog,
            },
        )
        problems = [entry for entry in catalog["entries"] if entry["kind"] == "problem"]
        self.assertEqual([entry["owner"] for entry in problems], ["evidence", "fixture-product"])

    def test_problem_source_prefix_must_match_its_catalog(self) -> None:
        document = json.loads(self.fixture_problem_catalog.read_text())
        document["entries"][0]["uri"] = (
            f"{generate.BASE_URL}/problems/registry-evidence/example/failed"
        )
        self.fixture_problem_catalog.write_text(json.dumps(document))
        with self.assertRaisesRegex(generate.CatalogError, "URI and code disagree"):
            self.build()

    def test_exact_problem_source_prefix_is_an_allowed_reference(self) -> None:
        (self.root / "src" / "prefix.rs").write_text(
            f'const PREFIX: &str = "^{generate.BASE_URL}/problems/registry-fixture/$";\n'
        )
        self.track("src/prefix.rs")
        self.build()

    def test_duplicate_problem_identifier_is_rejected_across_sources(self) -> None:
        self.write_evidence_problem_catalog()
        document = json.loads(self.config.read_text())
        document["problemSources"].append(
            {
                "owner": "evidence",
                "status": "active",
                "compatibilityLine": "v1",
                "uriPrefix": f"{generate.BASE_URL}/problems/registry-fixture/",
                "sourcePath": "src/evidence-problem.rs",
                "exporterPath": "examples/evidence-problem-catalog.rs",
                "cargoPackage": "evidence-example",
                "cargoExample": "problem-catalog",
            }
        )
        self.config.write_text(json.dumps(document))
        duplicate = json.loads(self.evidence_problem_catalog.read_text())
        duplicate["entries"][0]["uri"] = (
            f"{generate.BASE_URL}/problems/registry-fixture/example/failed"
        )
        self.evidence_problem_catalog.write_text(json.dumps(duplicate))
        with self.assertRaisesRegex(generate.CatalogError, "duplicated"):
            generate.build_catalog(
                self.root,
                self.config,
                {
                    "src/fixture-problem.rs": self.fixture_problem_catalog,
                    "src/evidence-problem.rs": self.evidence_problem_catalog,
                },
            )

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
        document = json.loads(self.fixture_problem_catalog.read_text())
        document["entries"][0]["httpStatuses"] = [99, 99]
        self.fixture_problem_catalog.write_text(json.dumps(document))
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
        uri = f"{generate.BASE_URL}/legacy/value"
        (self.root / "src" / "legacy.rs").write_text(
            f'const URI: &str = "{uri}";\n'
        )
        self.track("src/legacy.rs")
        self.write_config(
            exclusions=[
                {
                    "path": "src/legacy.rs",
                    "uri": uri,
                    "classification": "legacy-source",
                    "reason": "Legacy fixture retained for compatibility tests.",
                }
            ]
        )
        catalog = self.build()
        self.assertNotIn(
            uri,
            {entry["uri"] for entry in catalog["entries"]},
        )

    def test_exact_reference_exclusion_does_not_hide_another_uri_in_the_file(self) -> None:
        excluded = f"{generate.BASE_URL}/legacy/value"
        unclassified = f"{generate.BASE_URL}/legacy/other"
        (self.root / "src" / "legacy.rs").write_text(
            f'const EXCLUDED: &str = "{excluded}";\n'
            f'const UNCLASSIFIED: &str = "{unclassified}";\n'
        )
        self.track("src/legacy.rs")
        self.write_config(
            exclusions=[
                {
                    "path": "src/legacy.rs",
                    "uri": excluded,
                    "classification": "fixture",
                    "reason": "One synthetic negative reference is retained.",
                }
            ]
        )
        with self.assertRaisesRegex(generate.CatalogError, "legacy/other"):
            self.build()

    def test_exact_reference_exclusion_must_match_the_uri_in_its_path(self) -> None:
        (self.root / "src" / "legacy.rs").write_text("no identifier here\n")
        self.track("src/legacy.rs")
        self.write_config(
            exclusions=[
                {
                    "path": "src/legacy.rs",
                    "uri": f"{generate.BASE_URL}/legacy/missing",
                    "classification": "fixture",
                    "reason": "A stale exact exclusion must not survive silently.",
                }
            ]
        )
        with self.assertRaisesRegex(generate.CatalogError, "matched no identifier reference"):
            self.build()

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


class RepositoryCatalogSourceTest(unittest.TestCase):
    """The repository's own catalog source, read as it is committed."""

    def test_external_adapter_profile_fixture_has_one_exact_reference_exclusion(self) -> None:
        source = generate.load_source_config(
            SCRIPT.parents[3] / "products/identifiers/contracts/catalog-source.json"
        )
        path = "crates/registry-mcp/tests/fixtures/adapter/optional-pagination/profile.yaml"
        uri = f"{generate.BASE_URL}/schemas/adapter/profile/profile.v1alpha1.schema.json"
        matches = [entry for entry in source["referenceExclusions"] if entry.get("path") == path]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["uri"], uri)
        self.assertEqual(matches[0]["classification"], "fixture")
        self.assertNotIn("glob", matches[0])
    def test_configurable_mcp_schema_has_an_active_catalog_owner(self) -> None:
        repo_root = SCRIPT.parents[3]
        source = generate.load_source_config(
            repo_root / "products/identifiers/contracts/catalog-source.json"
        )
        entries = generate.schema_entries(
            repo_root,
            source["schemaSources"],
            generate.repository_files(repo_root),
            source["referenceExclusions"],
        )
        identifier = (
            f"{generate.BASE_URL}/schemas/platform/mcp-runtime/mcp-runtime.v1alpha1.schema.json"
        )
        matching = [entry for entry in entries if entry["uri"] == identifier]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["owner"], "platform")
        self.assertEqual(matching[0]["source"]["path"], "crates/registry-mcp/src/schema.rs")
        self.assertEqual(
            matching[0]["artifact"]["path"],
            "products/platform/generated/mcp-runtime/mcp-runtime.schema.json",
        )

    def test_breg_explain_groups_name_each_schemas_own_compatibility_line(self) -> None:
        repo_root = SCRIPT.parents[3]
        source = json.loads(
            (repo_root / "products/identifiers/contracts/catalog-source.json").read_text()
        )
        groups = [
            group
            for group in source["schemaSources"]
            if group["glob"].startswith("products/breg/contracts/explain/")
        ]
        schemas = sorted(repo_root.glob("products/breg/contracts/explain/*.schema.json"))
        self.assertTrue(schemas)
        for path in schemas:
            with self.subTest(schema=path.name):
                matching = [group for group in groups if path in repo_root.glob(group["glob"])]
                self.assertEqual(len(matching), 1, "each schema has exactly one catalog owner")
                group = matching[0]
                identifier = json.loads(path.read_text())["$id"]
                self.assertTrue(
                    identifier.endswith(f".{group['compatibilityLine']}.schema.json"),
                    f"{identifier} is not on line {group['compatibilityLine']}",
                )


if __name__ == "__main__":
    unittest.main()
