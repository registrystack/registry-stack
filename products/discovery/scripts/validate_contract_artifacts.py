#!/usr/bin/env python3
"""Validate Registry Discovery's pinned profile and security traceability."""
from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parents[1]
CONTEXT_URL = "https://registrystack.org/discovery/context/v1alpha1"
PROFILE = "registry-discovery-v1alpha1"
MATRIX = ROOT / "contracts/security-invariant-matrix.yaml"
TRACEABILITY = ROOT / "contracts/security-test-traceability.yaml"
SCHEMA = ROOT / "profile/schema/registry-discovery-v1alpha1.schema.json"
CONTEXT = ROOT / "profile/context/registry-discovery-v1alpha1.jsonld"
SCHEDULE = ROOT / "contracts/implementation-schedule.yaml"
DEFINITION_OF_DONE = ROOT / "contracts/definition-of-done.yaml"
STANDARDS = ROOT / "contracts/standards-profile.yaml"
RDF_PROVENANCE = ROOT / "profile/rdf/provenance.json"
SHACL = ROOT / "profile/shapes/registry-discovery-v1alpha1.shacl.ttl"
PRODUCT_SCHEMAS = {
    "origins": ROOT / "schemas/origins.schema.json",
    "evidence-mapping": ROOT / "schemas/evidence-mapping.schema.json",
    "runtime": ROOT / "schemas/runtime.schema.json",
    "index": ROOT / "schemas/index.schema.json",
}
AUTHORING_FIXTURE = ROOT / "fixtures/project"
REQUIRED_INVARIANTS = {
    "sec-provider-public-projection", "sec-origin-target-confinement",
    "sec-profile-parser-confinement", "sec-build-resource-bounds",
    "sec-origin-record-isolation", "sec-atomic-index-build",
    "sec-discovery-not-trust", "sec-query-and-log-minimization",
}
REQUIRED_DOD_IDS = {
    "discovery-dod-16-1-product-scope", "discovery-dod-16-2-standards-profile",
    "discovery-dod-16-3-provider-publication", "discovery-dod-16-4-origin-build",
    "discovery-dod-16-5-evidence-resolver", "discovery-dod-16-6-runtime-query-api",
    "discovery-dod-16-7-client-trust-invocation", "discovery-dod-16-8-adopter-maintenance-ux",
    "discovery-dod-16-9-acceptance-journeys", "discovery-dod-16-10-security-ci",
    "discovery-dod-16-11-pr-reduction",
}


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def fail(message: str) -> None:
    raise ValueError(message)


def require_executable_test(source: str, name: str, binding: str) -> None:
    if binding.endswith(".py"):
        if not name.startswith("test_") or re.search(
            rf"(?m)^[ \t]+def[ \t]+{re.escape(name)}[ \t]*\(", source
        ) is None:
            fail(f"executable Python test binding is not discoverable: {binding}::{name}")
        return
    if binding.endswith(".js"):
        function = re.search(
            rf"(?m)^[ \t]*test\([ \t]*(['\"]){re.escape(name)}\1[ \t]*,",
            source,
        )
        if function is None:
            fail(f"executable JavaScript test binding is not discoverable: {binding}::{name}")
        return
    function = re.compile(
        rf"(?m)(?P<attributes>(?:^[ \t]*#\[[^\n]+\]\n)+)"
        rf"^[ \t]*(?:async[ \t]+)?fn[ \t]+{re.escape(name)}\b"
    ).search(source)
    if function is None or re.search(
        r"(?m)^[ \t]*#\[(?:tokio::)?test(?:\([^\]]*\))?\][ \t]*$",
        function.group("attributes"),
    ) is None:
        fail(f"executable test binding lacks a test attribute: {binding}::{name}")


def check_profile() -> None:
    context = load(CONTEXT)
    if set(context) != {"@context"} or not isinstance(context["@context"], dict):
        fail("pinned JSON-LD context must contain exactly one local context object")
    schema = load(SCHEMA)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("profile schema must use JSON Schema 2020-12")
    if schema.get("properties", {}).get("@context", {}).get("const") != CONTEXT_URL:
        fail("profile schema must pin the exact context URL")
    if schema.get("properties", {}).get("profile", {}).get("const") != PROFILE:
        fail("profile schema must pin the exact profile identifier")
    service = schema.get("$defs", {}).get("service", {})
    if service.get("additionalProperties") is not False:
        fail("profile service schema must be closed")
    for fixture in sorted((ROOT / "fixtures/descriptions").glob("*.jsonld")):
        document = load(fixture)
        if document.get("@context") != CONTEXT_URL or document.get("profile") != PROFILE:
            fail(f"{fixture.relative_to(ROOT)} is not the pinned profile")


def check_product_schemas_and_fixture() -> None:
    expected_ids = {
        "origins": "https://registrystack.org/discovery/schema/origins-v1alpha1.json",
        "evidence-mapping": "https://registrystack.org/discovery/schema/evidence-mapping-v1alpha1.json",
        "runtime": "https://registrystack.org/discovery/schema/runtime-v1alpha1.json",
        "index": "https://registrystack.org/discovery/schema/index-v1alpha1.json",
    }
    for name, path in PRODUCT_SCHEMAS.items():
        schema = load(path)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            fail(f"{name} schema must use JSON Schema 2020-12")
        if schema.get("$id") != expected_ids[name]:
            fail(f"{name} schema has the wrong stable identifier")
        if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
            fail(f"{name} schema must close its root object")
    origins = PRODUCT_SCHEMAS["origins"]
    if load(origins)["properties"]["origins"].get("maxItems") != 128:
        fail("origins schema must carry the authored-origin hard bound")
    mapping = load(PRODUCT_SCHEMAS["evidence-mapping"])
    if mapping["properties"]["alternatives"].get("maxItems") != 32:
        fail("mapping schema must carry the authored-alternative hard bound")
    if mapping.get("x-maximumDocumentBytes") != 20 * 1024 * 1024:
        fail("mapping schema must publish the aggregate authored-file byte bound")
    runtime = load(PRODUCT_SCHEMAS["runtime"])
    if runtime["properties"]["limits"].get("additionalProperties") is not False:
        fail("runtime limit schema must be closed")
    index = load(PRODUCT_SCHEMAS["index"])
    if index["properties"]["services"].get("maxItems") != 100000:
        fail("index schema must carry the runtime service hard bound")
    for relative in (
        "origins.yaml",
        "mappings/adult-status.yaml",
        "runtime.yaml",
        "discovery-index.json",
        "README.md",
    ):
        if not (AUTHORING_FIXTURE / relative).is_file():
            fail(f"offline authoring fixture is incomplete: {relative}")
    if not (ROOT / "fixtures/schema-negative-corpus.json").is_file():
        fail("shared schema negative corpus is missing")


def check_standards_and_offline_rdf() -> None:
    standards = load(STANDARDS)
    if standards.get("conformanceClaim") != {
        "dcatAp": False,
        "bregDcatAp": False,
        "reason": "Registry Discovery implements a closed selected-term application profile, not the complete mandatory class and constraint sets of either application profile.",
    }:
        fail("standards contract must refuse full DCAT-AP and BRegDCAT-AP claims")
    expected_standards = {
        ("DCAT", "3", "W3C Recommendation 2024-08-22", "https://www.w3.org/TR/2024/REC-vocab-dcat-3-20240822/"),
        ("DCAT-AP", "3.0.1", "Recommendation targeted for selected alignment", "https://semiceu.github.io/DCAT-AP/releases/3.0.1/"),
        ("BRegDCAT-AP", "3.0.0", "Working Draft", "https://semiceu.github.io/BRegDCAT-AP/releases/3.0.0/"),
        ("BRegDCAT-AP", "2.1.0", "Latest published release", "https://github.com/SEMICeu/BregDCAT-AP/tree/main/releases/2.1.0"),
    }
    actual_standards = {
        (item.get("name"), item.get("version"), item.get("status"), item.get("url"))
        for item in standards.get("standards", [])
    }
    if actual_standards != expected_standards:
        fail("standards contract has an inaccurate version or status")
    selected = standards.get("selectedTerms", {})
    if selected.get("dcat") != ["dcat:Catalog", "dcat:DataService", "dcat:endpointURL", "dcat:service"]:
        fail("standards contract has an unexpected selected DCAT subset")
    provenance = load(RDF_PROVENANCE)
    execution = provenance.get("execution", {})
    if (
        execution.get("network") != "forbidden"
        or execution.get("remoteResolution") != "forbidden"
        or execution.get("jsonLdExpansion")
        != "RDFLib 7.1.4 with the pinned local context injected before JSON-LD expansion"
        or execution.get("shacl")
        != "pySHACL 0.30.1 in-memory validation over the selected local shapes"
        or execution.get("dependencyInstallation")
        != "uv 0.11.16 installs only the fully locked test environment; oracle execution is --offline --no-sync and denies socket connects"
    ):
        fail("offline RDF tooling must allow only pinned local context expansion")
    resources = provenance.get("resources", [])
    expected_paths = {
        "profile/context/registry-discovery-v1alpha1.jsonld",
        "profile/schema/registry-discovery-v1alpha1.schema.json",
        "profile/shapes/registry-discovery-v1alpha1.shacl.ttl",
        "schemas/origins.schema.json",
        "schemas/evidence-mapping.schema.json",
        "schemas/runtime.schema.json",
        "schemas/index.schema.json",
        "scripts/test_standards_oracle.py",
        "standards-oracle/pyproject.toml",
        "standards-oracle/uv.lock",
    }
    if {resource.get("path") for resource in resources} != expected_paths:
        fail("RDF provenance resource inventory is incomplete")
    for resource in resources:
        path = ROOT / resource["path"]
        if not path.is_file() or resource.get("sha256") != sha256(path.read_bytes()).hexdigest():
            fail(f"RDF provenance digest drift: {resource.get('path')}")
    fixtures = provenance.get("fixtures", [])
    expected_fixtures = {
        "fixtures/schema-negative-corpus.json",
        "fixtures/descriptions/repeated-service-bindings.jsonld",
        "fixtures/rdf/repeated-service-bindings.nt",
    }
    if {fixture.get("path") for fixture in fixtures} != expected_fixtures:
        fail("standards-oracle fixture provenance is incomplete")
    for fixture in fixtures:
        path = ROOT / fixture["path"]
        if not path.is_file() or fixture.get("sha256") != sha256(path.read_bytes()).hexdigest():
            fail(f"standards-oracle fixture digest drift: {fixture.get('path')}")
    expected_oracles = {
        (
            "crates/registry-discoveryctl/tests/schema_contract.rs",
            "every_positive_fixture_satisfies_draft_2020_12_and_the_closed_rust_parser",
            "jsonschema",
            "0.18.3",
        ),
        (
            "products/discovery/scripts/test_standards_oracle.py",
            "test_json_ld_and_shacl_oracles_validate_every_profile_fixture",
            "rdflib",
            "7.1.4",
        ),
        (
            "products/discovery/scripts/test_standards_oracle.py",
            "test_shacl_oracle_rejects_missing_endpoint",
            "pyshacl",
            "0.30.1",
        ),
        (
            "products/discovery/scripts/test_standards_oracle.py",
            "test_distinct_binding_nodes_preserve_repeated_service_id_capability_correlation",
            "rdflib",
            "7.1.4",
        ),
        (
            "products/discovery/scripts/test_standards_oracle.py",
            "test_json_ld_oracle_preserves_fragment_iris",
            "rdflib",
            "7.1.4",
        ),
    }
    oracles = provenance.get("oracles", [])
    actual_oracles = {
        (oracle.get("path"), oracle.get("test"), oracle.get("implementation"), oracle.get("version"))
        for oracle in oracles
    }
    if actual_oracles != expected_oracles:
        fail("independent standards-oracle inventory is incomplete")
    for path_text, test, _, _ in actual_oracles:
        source_path = REPOSITORY / path_text
        if not source_path.is_file():
            fail(f"standards oracle does not resolve: {path_text}::{test}")
        require_executable_test(
            source_path.read_text(encoding="utf-8"), test, path_text
        )
    shape = SHACL.read_text(encoding="utf-8")
    if "owl:imports" in shape or "sh:select" in shape:
        fail("selected SHACL resource must not import or execute SPARQL")
    for required in ("registry:CatalogShape", "registry:DataServiceShape", "sh:targetClass"):
        if required not in shape:
            fail("selected SHACL resource is incomplete")


def check_traceability() -> None:
    matrix = load(MATRIX)
    rows = matrix.get("invariants")
    if not isinstance(rows, list) or {row.get("id") for row in rows} != REQUIRED_INVARIANTS:
        fail("security invariant inventory is incomplete or duplicated")
    by_id = {row["id"]: row for row in rows}
    traceability = load(TRACEABILITY)
    requirements = traceability.get("requirements")
    if not isinstance(requirements, list):
        fail("security traceability requirements must be a list")
    traced = {entry.get("id"): entry for entry in requirements}
    enforced = {row["id"] for row in rows if row.get("status") == "enforced"}
    if set(traced) != enforced:
        fail("traceability must contain all and only enforced invariants")
    for identifier, row in by_id.items():
        if not isinstance(row.get("threat"), str) or not isinstance(row.get("enforcementPoint"), str):
            fail(f"{identifier} lacks threat or enforcement point")
        if not isinstance(row.get("requiredNegativeBehavior"), str) or not isinstance(row.get("negativeTest"), str):
            fail(f"{identifier} lacks refusal or negative test")
        if row.get("status") == "enforced":
            tests = traced[identifier].get("tests")
            if not isinstance(tests, list) or not tests:
                fail(f"{identifier} lacks executable bindings")
            for test in tests:
                path = REPOSITORY / test["path"]
                if not path.is_file():
                    fail(f"{identifier} test path does not exist: {test['path']}")
                source = path.read_text(encoding="utf-8")
                require_executable_test(source, test["name"], test["path"])
            if row.get("binding") != tests[0]:
                fail(f"{identifier} matrix binding must equal its first exact traceability binding")
        elif row.get("status") != "integration-required" or not isinstance(row.get("integrationOwner"), str):
            fail(f"{identifier} must be enforced or name its integration owner")


def check_schedule() -> None:
    schedule = load(SCHEDULE)
    phases = schedule.get("phases")
    expected = ["phase-0", "phase-1", "phase-2", "phase-3", "phase-4"]
    if not isinstance(phases, list) or [phase.get("id") for phase in phases] != expected:
        fail("implementation schedule must retain the five ordered delivery phases")
    if any(not isinstance(phase.get("exit"), str) for phase in phases):
        fail("every implementation phase needs an exit condition")
    if any("status" in phase or "complete" in phase for phase in phases):
        fail("schedule phases must not make a misleading partial-complete claim")


def check_definition_of_done() -> None:
    document = load(DEFINITION_OF_DONE)
    requirements = document.get("requirements")
    if document.get("status") != "required" or not isinstance(requirements, list):
        fail("Definition of Done must be a required machine contract")
    by_id = {item.get("id"): item for item in requirements}
    if set(by_id) != REQUIRED_DOD_IDS or len(by_id) != len(requirements):
        fail("Definition of Done must cover sections 16.1 through 16.11 exactly once")
    for identifier, item in by_id.items():
        if not isinstance(item.get("requirement"), str) or not isinstance(item.get("section"), str):
            fail(f"{identifier} lacks requirement or section")
        evidence = item.get("requiredEvidence")
        if not isinstance(evidence, list) or not evidence:
            fail(f"{identifier} lacks concrete evidence")
        for proof in evidence:
            path = REPOSITORY / proof.get("path", "")
            if not path.is_file():
                fail(f"{identifier} evidence path does not exist: {proof.get('path')}")
            if "name" in proof:
                source = path.read_text(encoding="utf-8")
                require_executable_test(source, proof["name"], proof["path"])


def main() -> int:
    check_profile()
    check_product_schemas_and_fixture()
    check_standards_and_offline_rdf()
    check_traceability()
    check_schedule()
    check_definition_of_done()
    print("Registry Discovery profile and security contracts are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
