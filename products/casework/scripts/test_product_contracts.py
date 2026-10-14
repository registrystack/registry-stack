#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check current examples, generated authorities and executable proof inventory."""
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PRODUCT = ROOT / "products/casework"
MATRIX = PRODUCT / "contracts/security-invariant-matrix.yaml"
TRACE = PRODUCT / "contracts/security-test-traceability.yaml"

def references(text: str) -> set[tuple[str, str]]:
    return set(re.findall(r"(?:path|file): ([^,}]+), name: ([A-Za-z0-9_]+)", text))


def rust_test_attributes(source: str, name: str) -> str | None:
    """Return the attribute block that makes `name` a selectable Rust test.

    A private helper called from another test carries no attribute block, so it
    cannot be selected by `cargo test -- <name>` and cannot fail on its own.
    """
    match = re.search(
        rf"((?:^[ \t]*#\[[^\n]*\]\n)+)[ \t]*(?:pub(?:\([^)]*\))?\s+)?"
        rf"(?:async\s+)?fn\s+{re.escape(name)}\b",
        source,
        re.M,
    )
    if match is None:
        return None
    block = match.group(1)
    selectable = any(
        line.strip().startswith(("#[test]", "#[tokio::test", "#[rstest"))
        for line in block.splitlines()
    )
    return block if selectable else None


class ProductContractTests(unittest.TestCase):
    def test_standalone_example_has_one_submitted_review_policy(self):
        project = (PRODUCT / "examples/standalone-decision/casework.yaml").read_text()
        fixture = (PRODUCT / "examples/standalone-decision/fixtures/standalone-decision.yaml").read_text()
        self.assertRegex(project, r"(?m)^reviewPolicies:")
        self.assertRegex(project, r"(?m)^trustedProducers:")
        self.assertIn("mode: submitted", project)
        self.assertNotRegex(project, r"(?m)^(sources|reviewKinds|reviewProducers):")
        self.assertIn("policy: decision", fixture)
        self.assertIn("outcomes: [confirmed, rejected]", fixture)

    def test_canonical_native_context_schema_is_exact_and_local(self):
        directory = PRODUCT / "examples/canonical-review"
        project = (directory / "casework.yaml").read_text()
        self.assertIn("mode: current-source", project)
        self.assertIn("mode: submitted", project)
        self.assertIn("capabilities: [human-display, service-status]", project)
        self.assertIn("service-status: casework-review-status", project)
        self.assertIn("decidingProfiles: [staff]", project)
        self.assertNotIn("sourceProfile:", project)
        reference = re.search(r"\$ref: (schemas/[^\s]+)", project).group(1)
        schema_bytes = (directory / reference).read_bytes()
        digest = "sha256:" + hashlib.sha256(schema_bytes).hexdigest()
        self.assertIn("schemaDigest: " + digest, project)
        schema = json.loads(schema_bytes)
        self.assertEqual(schema["type"], "object")
        self.assertFalse(schema["additionalProperties"])
        runtime = (directory / "runtime.example.yaml").read_text()
        self.assertRegex(runtime, r"(?m)^contextProviders:")
        self.assertIn("casework-review-status", runtime)
        self.assertNotRegex(runtime, r"(?m)^sources:")

    def test_advanced_example_keeps_two_stages_routing_and_clocks(self):
        project = (PRODUCT / "examples/multi-stage-routing-clocks/casework.yaml").read_text()
        fixture = (PRODUCT / "examples/multi-stage-routing-clocks/fixtures/multi-stage-policy.yaml").read_text()
        self.assertIn("mode: submitted", project)
        self.assertIn("stage: technical", project)
        self.assertIn("queue: northern-review", project)
        self.assertIn("excludePreviousStageReviewers: true", project)
        self.assertIn("clocks: [review-deadline, response-budget]", project)
        self.assertIn("policy: regional-review", fixture)
        self.assertNotRegex(project, r"(?m)^(sources|reviewKinds|reviewProducers):")

    def test_project_schema_exposes_one_review_authoring_model(self):
        schema = json.loads((PRODUCT / "generated/project/project.schema.json").read_text())
        properties = schema["properties"]
        for field in ("reviewPolicies", "contextProviders", "trustedProducers", "teams", "queues", "clocks"):
            self.assertIn(field, properties)
        for retired in ("reviewKinds", "reviewProducers", "hostedKinds", "sources", "itemKinds"):
            self.assertNotIn(retired, properties)
        policy = schema["$defs"]["ReviewPolicy"]
        for field in ("context", "stages", "outcomes", "clocks", "displaySchema", "resultSchema"):
            self.assertIn(field, policy["properties"])
        self.assertNotIn("sourceProfile", schema["$defs"]["ReviewContextProviderPolicy"]["properties"])

    def test_http_contract_has_policy_binding_and_review_staffing(self):
        document = json.loads((PRODUCT / "generated/registry-casework.openapi.json").read_text())
        paths = document["paths"]
        for path in ("/v1/review-policies", "/v1/review-tasks/next", "/v1/review-tasks/holdings", "/v1/directory/caseload/preview", "/v1/directory/clocks/recompute/preview"):
            self.assertIn(path, paths)
        self.assertFalse(any("work-items" in path or "events/sources" in path for path in paths))
        create = document["components"]["schemas"]["ReviewCreateRequest"]
        self.assertIn("policy", create["required"])
        self.assertNotIn("kind", create["properties"])
        self.assertIn("ReviewStaffingQuery", document["components"]["schemas"])

    def test_cli_report_contract_is_generated_from_one_typed_union(self):
        schemas = sorted(path.name for path in (PRODUCT / "contracts/cli").glob("*.schema.json"))
        self.assertEqual(schemas, ["report.schema.json"])
        schema = json.loads((PRODUCT / "contracts/cli/report.schema.json").read_text())
        self.assertEqual(schema["properties"]["kind"]["const"], "CaseworkReport")
        self.assertTrue(schema["oneOf"])
        self.assertIn("ExplainPolicy", schema["$defs"])
        for field in ("purpose", "context", "displaySchema", "resultSchema", "stages", "outcomes", "clocks", "dependencies"):
            self.assertIn(field, schema["$defs"]["ExplainPolicy"]["properties"])
        generator = (PRODUCT / "scripts/generate_cli_schemas.py").read_text()
        self.assertIn('"report-schemas"', generator)
        self.assertNotIn("ACTIVATION_DEFS", generator)

    def test_review_runner_selects_all_current_transaction_boundaries(self):
        runner = (PRODUCT / "scripts/check-review-examples.sh").read_text()
        for target in ("review_acceptance_postgres", "review_migration_postgres", "review_directory_postgres", "review_postgres", "review_http", "task_grants::", "review_context_package"):
            self.assertIn(target, runner)
        self.assertIn("CASEWORK_REVIEW_TEST_DATABASE_URL", runner)
        self.assertIn("check-checkpoint.sh", runner)
        self.assertIn("check-review-journeys.sh", runner)
        checkpoint = (PRODUCT / "scripts/check-checkpoint.sh").read_text()
        self.assertIn("examples/canonical-review", checkpoint)
        self.assertIn("examples/standalone-decision", checkpoint)
        self.assertIn("examples/multi-stage-routing-clocks", checkpoint)
        self.assertNotIn('" simulate "', checkpoint)
        self.assertNotIn("source add", checkpoint)

    def test_security_contracts_are_scoped_and_do_not_claim_execution(self):
        matrix, trace = MATRIX.read_text(), TRACE.read_text()
        scope = re.search(r"(?m)^scope: (.+)$", matrix)
        self.assertIsNotNone(scope)
        self.assertIn("scope: " + scope.group(1), trace)
        self.assertIn("evidenceStatus: source-mapped-not-executed", matrix)
        self.assertIn("executionStatus: not-recorded", trace)
        self.assertNotIn("executionStatus: passed", matrix + trace)
        matrix_ids = re.findall(r"id: (CASEWORK-SEC-[0-9]+)", matrix)
        trace_ids = re.findall(r"id: (CASEWORK-SEC-[0-9]+)", trace)
        self.assertTrue(matrix_ids)
        self.assertEqual(len(matrix_ids), len(set(matrix_ids)))
        self.assertEqual(set(matrix_ids), set(trace_ids))
        self.assertTrue(references(matrix))

    def test_every_mapped_test_exists_and_is_selectable(self):
        mapped = references(MATRIX.read_text()) | references(TRACE.read_text())
        self.assertTrue(mapped)
        for relative, name in sorted(mapped):
            with self.subTest(test=f"{relative}:{name}"):
                path = ROOT / relative
                self.assertTrue(path.is_file(), relative)
                source = path.read_text()
                if relative.endswith(".rs"):
                    self.assertIsNotNone(rust_test_attributes(source, name), f"{relative}:{name} must be an attributed test, not a helper")
                else:
                    self.assertTrue(name.startswith("test_"))
                    self.assertIn(f"def {name}(", source)

    def test_readme_documents_every_operator_supplied_test_database(self):
        variables = {variable for path in (ROOT / "crates/registry-casework").rglob("*.rs") for variable in re.findall(r'"(CASEWORK_[A-Z_]*DATABASE_URL)"', path.read_text())}
        self.assertTrue(variables)
        readme = (PRODUCT / "README.md").read_text()
        for variable in sorted(variables):
            with self.subTest(variable=variable):
                self.assertIn(variable, readme)

    def test_deployment_uses_explicit_package_activation(self):
        readme = (PRODUCT / "README.md").read_text()
        self.assertIn("caseworkctl apply --runtime-config /etc/registry-casework/runtime.yaml", readme)
        self.assertIn("casework --runtime-config /etc/registry-casework/runtime.yaml serve", readme)
        self.assertNotIn("runtime.yaml migrate", readme)


if __name__ == "__main__":
    unittest.main()
