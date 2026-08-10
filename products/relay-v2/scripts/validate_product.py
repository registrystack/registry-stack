#!/usr/bin/env python3
"""Validate Relay V2 product catalogs and cross-file traceability.

Contract, runtime, source-schema, generation, fixture, and packaging semantics
belong to the shared Rust tooling. This script deliberately checks only the
tracked product catalog and the references that join those catalogs together.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - environment failure
    raise SystemExit("PyYAML is required to validate Relay V2 product catalogs") from exc


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PRODUCT_ROOT.parents[1]
PROJECTS = (
    "social-assistance",
    "business-registry",
    "civil-event",
    "labour-statistics",
)
INVALID_SOURCE_ROW_CLASSES = {
    "wrong-type",
    "missing-required",
    "unexpected-value",
    "excessive-size",
}
TRANSFORM_FAILURE_SCENARIOS = {
    "social-invalid-transform",
    "civil-invalid-transform",
}
ACCESS_PROFILE_CONCEALMENT_STEPS = {
    "social-assistance": {"unauthorized-access-profile", "unknown-access-profile"},
    "business-registry": {
        "registrar-access-profile-denied",
        "public-access-profile-unknown",
        "premises-search-access-profile-denied",
        "premises-search-access-profile-unknown",
    },
    "civil-event": {"supervisory-access-profile-denied", "invalid-access-profile"},
}
SECURITY_INVARIANT_IDS = {
    "sec-contract-runtime-separation",
    "sec-package-activation-integrity",
    "sec-one-registry-boundary",
    "sec-sqlite-read-only",
    "sec-sqlite-connection-recovery",
    "sec-token-profile-closed",
    "sec-resource-existence-concealment",
    "sec-operation-confinement",
    "sec-classification-review-binding",
    "sec-finite-access-profile-authorization",
    "sec-public-access-profile-processing-floor",
    "sec-closed-mask-and-date-transforms",
    "sec-access-profile-state-and-metadata-binding",
    "sec-operation-quota",
    "sec-trusted-context",
    "sec-disclosure-monotonic",
    "sec-lookup-non-enumeration",
    "sec-malformed-row-atomicity",
    "sec-reference-visibility",
    "sec-audit-release-gate",
    "sec-audit-correlation-and-minimization",
    "sec-cursor-integrity",
    "sec-spatial-disclosure-confinement",
    "sec-spatial-query-confinement",
    "sec-statistical-binding-inherits-access",
    "sec-statistical-query-closed-and-bounded",
    "sec-statistical-audit-and-wire-binding",
    "sec-source-truthfulness",
    "sec-value-free-diagnostics",
    "sec-value-free-operational-logs",
    "sec-value-free-trace-context",
    "sec-unsigned-family-boundary",
}
SIMPLE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RUST_TEST = re.compile(
    r"#\[(?:tokio::)?test(?:\([^\]]*\))?\]"
    r"(?:\s*#\[[^\]]+\])*\s*(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def mapping(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label}: expected mapping")
        return {}
    return value


def sequence(value: Any, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label}: expected sequence")
        return []
    return value


def require_exact_keys(
    value: dict[str, Any], expected: set[str], label: str, errors: list[str]
) -> None:
    missing = sorted(expected - value.keys())
    unknown = sorted(value.keys() - expected)
    if missing:
        errors.append(f"{label}: missing keys {', '.join(missing)}")
    if unknown:
        errors.append(f"{label}: unknown keys {', '.join(unknown)}")


def executable_test_resolves(reference: Any, label: str, errors: list[str]) -> None:
    test = mapping(reference, label, errors)
    require_exact_keys(test, {"path", "name"}, label, errors)
    raw_path = test.get("path")
    name = test.get("name")
    if not isinstance(raw_path, str) or not raw_path.startswith("crates/"):
        errors.append(f"{label}: path must be a repository-relative crate source path")
        return
    if not isinstance(name, str) or not SIMPLE_IDENTIFIER.fullmatch(name):
        errors.append(f"{label}: name must be one exact Rust test function")
        return
    path = (REPOSITORY_ROOT / raw_path).resolve()
    try:
        path.relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        errors.append(f"{label}: path escapes the repository")
        return
    if not path.is_file():
        errors.append(f"{label}: test source does not exist: {raw_path}")
        return
    names = RUST_TEST.findall(path.read_text(encoding="utf-8"))
    if names.count(name) != 1:
        errors.append(f"{label}: exact executable test does not resolve: {raw_path}::{name}")


def journey_steps(errors: list[str]) -> dict[str, dict[str, tuple[Any, Any]]]:
    result: dict[str, dict[str, tuple[Any, Any]]] = {}
    for project_name in PROJECTS:
        project = PRODUCT_ROOT / "acceptance" / project_name
        for required in (
            "registry.yaml",
            "runtime.yaml",
            "fixture.sql",
            "expected-http.yaml",
            "governance/classification-review.yaml",
        ):
            if not (project / required).is_file():
                errors.append(f"{project_name}: missing required project file {required}")
        journey = mapping(load_yaml(project / "expected-http.yaml"), f"{project_name} journey", errors)
        authorizations = mapping(
            journey.get("authorizations"), f"{project_name} journey authorizations", errors
        )
        identifiers: dict[str, tuple[Any, Any]] = {}
        for index, raw in enumerate(
            sequence(journey.get("steps"), f"{project_name} journey steps", errors)
        ):
            step = mapping(raw, f"{project_name} journey step[{index}]", errors)
            identifier = step.get("id")
            if not isinstance(identifier, str) or not identifier or identifier in identifiers:
                errors.append(f"{project_name}: journey step ids must be unique and non-empty")
                continue
            expectation = mapping(
                step.get("expect"), f"{project_name} journey step[{index}].expect", errors
            )
            identifiers[identifier] = (expectation.get("status"), expectation.get("code"))
            authorization = step.get("authorizationFixture")
            if authorization is not None and authorization not in authorizations:
                errors.append(
                    f"{project_name}: {identifier} references unknown authorization fixture {authorization}"
                )
        result[project_name] = identifiers
    return result


def validate_review_sidecar(
    project: Path, registry: dict[str, Any], expected_method: str, errors: list[str]
) -> None:
    classifications = mapping(registry.get("classifications"), f"{project.name} classifications", errors)
    reference = classifications.get("provenanceRef")
    if not isinstance(reference, str) or not reference:
        errors.append(f"{project.name}: classifications.provenanceRef must name the review sidecar")
        return
    sidecar = project / reference
    if not sidecar.is_file():
        errors.append(f"{project.name}: classification review sidecar is missing")
        return
    review = mapping(load_yaml(sidecar), f"{project.name} classification review", errors)
    require_exact_keys(
        review,
        {
            "apiVersion",
            "kind",
            "registryIdentifier",
            "classificationInventoryDigest",
            "method",
            "reviewer",
            "reviewDate",
            "status",
            "rationaleRef",
        }
        | ({"generatedIdentification"} if expected_method == "generated" else set()),
        f"{project.name} classification review",
        errors,
    )
    if review.get("apiVersion") != "relay.registrystack.org/classification-review/v1":
        errors.append(f"{project.name}: classification review apiVersion is not frozen")
    if review.get("kind") != "ClassificationReview":
        errors.append(f"{project.name}: classification review kind is not frozen")
    if review.get("registryIdentifier") != registry.get("registry", {}).get("registryIdentifier"):
        errors.append(f"{project.name}: classification review binds another Registry")
    if review.get("method") != expected_method or review.get("status") != "reviewed":
        errors.append(f"{project.name}: classification review does not use the required reviewed method")
    if not SHA256.fullmatch(str(review.get("classificationInventoryDigest", ""))):
        errors.append(f"{project.name}: classification review inventory digest is invalid")
    generated = review.get("generatedIdentification")
    if expected_method == "generated":
        generated_binding = mapping(generated, f"{project.name} generated review binding", errors)
        require_exact_keys(
            generated_binding,
            {"reportRef", "reportDigest", "rulePack"},
            f"{project.name} generated review binding",
            errors,
        )
        report_ref = generated_binding.get("reportRef")
        if report_ref != "reports/identification-report.json" or not (project / str(report_ref)).is_file():
            errors.append(f"{project.name}: generated review must bind the accepted identification report")
        if not SHA256.fullmatch(str(generated_binding.get("reportDigest", ""))):
            errors.append(f"{project.name}: generated review report digest is invalid")
        rule_pack = mapping(generated_binding.get("rulePack"), f"{project.name} rule pack", errors)
        require_exact_keys(rule_pack, {"id", "version", "digest"}, f"{project.name} rule pack", errors)
        if not SHA256.fullmatch(str(rule_pack.get("digest", ""))):
            errors.append(f"{project.name}: generated review rule-pack digest is invalid")
    elif generated is not None:
        errors.append(f"{project.name}: imported or manual review must not carry generated binding")


def validate_acceptance_access_profile_contracts(errors: list[str]) -> None:
    expected_methods = {
        "social-assistance": "generated",
        "business-registry": "imported",
        "civil-event": "manual",
        "labour-statistics": "manual",
    }
    expected_access_profiles = {
        "social-assistance": {"limited", "caseworker"},
        "business-registry": {
            "public-register",
            "registrar",
            "public-premises",
            "registrar-premises",
        },
        "civil-event": {"registrar", "supervisory"},
        "labour-statistics": set(),
    }
    for project_name in PROJECTS:
        project = PRODUCT_ROOT / "acceptance" / project_name
        registry = mapping(load_yaml(project / "registry.yaml"), f"{project_name} registry", errors)
        validate_review_sidecar(project, registry, expected_methods[project_name], errors)
        resources = sequence(registry.get("resources"), f"{project_name} resources", errors)
        access_profiles: set[str] = set()
        primary_operations: dict[str, Any] = {}
        operation_definitions: list[Any] = []
        for resource_index, raw_resource in enumerate(resources):
            resource = mapping(
                raw_resource,
                f"{project_name} resource[{resource_index}]",
                errors,
            )
            operations = mapping(
                resource.get("operations"),
                f"{project_name} resource[{resource_index}] operations",
                errors,
            )
            if resource_index == 0:
                primary_operations = operations
            operation_definitions.extend([operations.get("list"), operations.get("read")])
            for collection_name in ("lookups", "searches"):
                collection = operations.get(collection_name, [])
                if isinstance(collection, list):
                    operation_definitions.extend(collection)
        for index, operation in enumerate(operation_definitions):
            if operation is None:
                continue
            operation = mapping(operation, f"{project_name} operation[{index}]", errors)
            profiles = mapping(
                operation.get("accessProfiles"),
                f"{project_name} operation[{index}] access profiles",
                errors,
            )
            default = operation.get("defaultAccessProfile")
            if not isinstance(default, str) or default not in profiles or not profiles:
                errors.append(
                    f"{project_name}: every declared operation needs one declared default access profile"
                )
            for identifier, access_profile in profiles.items():
                access_profiles.add(identifier)
                access_profile = mapping(
                    access_profile,
                    f"{project_name} access profile {identifier}",
                    errors,
                )
                require_exact_keys(
                    access_profile,
                    {"access", "disclosureProfile"},
                    f"{project_name} access profile {identifier}",
                    errors,
                )
        if not expected_access_profiles[project_name].issubset(access_profiles):
            errors.append(f"{project_name}: required acceptance access profiles are missing")
        if project_name == "social-assistance":
            properties = resources[0].get("properties", {}) if resources else {}
            transform = mapping(properties.get("maskedEnrolmentReference", {}).get("transform"), "social partial-string transform", errors)
            if transform != {"kind": "partial-string", "reveal": "suffix", "characters": 4}:
                errors.append("social-assistance: limited access profile must use the frozen partial-string transform")
            runtime = mapping(
                load_yaml(project / "runtime.yaml"), "social-assistance runtime", errors
            )
            quotas = mapping(runtime.get("quotas"), "social-assistance quotas", errors)
            if quotas != {"requestsPerMinute": 1, "burst": 12}:
                errors.append(
                    "social-assistance: quota fixture must admit exactly the twelve "
                    "pre-quota lookup executions before the named rate-limit proof"
                )
        if project_name == "business-registry":
            premises = next(
                (
                    resource
                    for resource in resources
                    if isinstance(resource, dict)
                    and resource.get("id") == "registered-premises"
                ),
                None,
            )
            premises = mapping(premises, "business-registry registered premises", errors)
            properties = mapping(
                premises.get("properties"),
                "business-registry registered premises properties",
                errors,
            )
            location = mapping(
                properties.get("location"),
                "business-registry location property",
                errors,
            )
            expected_location = {
                "type": "point",
                "crs": "http://www.opengis.net/def/crs/OGC/0/CRS84",
                "source": {
                    "longitudeColumn": "longitude",
                    "latitudeColumn": "latitude",
                },
                "sourceRequired": True,
                "semanticTerm": "local:location",
                "label": "Premises location",
                "description": (
                    "Reviewed Point location of the registered premises in CRS84 "
                    "longitude-latitude order."
                ),
                "classification": {
                    "privacy": "non-personal",
                    "institutional": "public",
                    "handling": "public",
                    "status": "reviewed",
                },
            }
            if location != expected_location or premises.get("primaryGeometry") != "location":
                errors.append(
                    "business-registry: registered premises must keep the strict additive "
                    "Point property and primaryGeometry reference"
                )

            premises_operations = mapping(
                premises.get("operations"),
                "business-registry registered premises operations",
                errors,
            )
            list_operation = mapping(
                premises_operations.get("list"),
                "business-registry registered premises list",
                errors,
            )
            if "spatialQuery" in list_operation:
                errors.append(
                    "business-registry: bbox must remain a named search, not a list option"
                )
            searches = sequence(
                premises_operations.get("searches"),
                "business-registry registered premises searches",
                errors,
            )
            bbox_search = next(
                (
                    search
                    for search in searches
                    if isinstance(search, dict) and search.get("id") == "within-bbox"
                ),
                None,
            )
            bbox_search = mapping(
                bbox_search,
                "business-registry within-bbox search",
                errors,
            )
            if bbox_search.get("query") != {
                "kind": "point-bbox",
                "maximumLongitudeSpanDegrees": 2,
                "maximumLatitudeSpanDegrees": 2,
            }:
                errors.append(
                    "business-registry: within-bbox must keep the bounded point-bbox query"
                )
            list_profiles = mapping(
                list_operation.get("accessProfiles"),
                "business-registry registered premises list access profiles",
                errors,
            )
            search_profiles = mapping(
                bbox_search.get("accessProfiles"),
                "business-registry within-bbox access profiles",
                errors,
            )
            list_scope = (
                list_profiles.get("registrar-premises", {}).get("access", {}).get("scope")
                if isinstance(list_profiles.get("registrar-premises"), dict)
                else None
            )
            search_scope = (
                search_profiles.get("registrar-premises", {}).get("access", {}).get("scope")
                if isinstance(search_profiles.get("registrar-premises"), dict)
                else None
            )
            if (
                not isinstance(list_scope, str)
                or not isinstance(search_scope, str)
                or list_scope == search_scope
            ):
                errors.append(
                    "business-registry: protected list and bbox search scopes must be distinct"
                )
        if project_name == "civil-event":
            properties = resources[0].get("properties", {}) if resources else {}
            transform = mapping(properties.get("registrationYear", {}).get("transform"), "civil date-precision transform", errors)
            if transform != {"kind": "date-precision", "sourceType": "date", "precision": "year"}:
                errors.append("civil-event: supervisory access profile must use the frozen date-precision transform")
            if primary_operations.get("list") is not None:
                errors.append("civil-event: collection list remains out of scope")
            runtime = mapping(
                load_yaml(project / "runtime.yaml"), "civil-event runtime", errors
            )
            quotas = mapping(runtime.get("quotas"), "civil-event quotas", errors)
            if quotas != {"requestsPerMinute": 1, "burst": 8}:
                errors.append(
                    "civil-event: lookup quota fixture must admit exactly the eight "
                    "pre-quota lookup executions before the named rate-limit proof"
                )


def validate_statistical_acceptance(errors: list[str]) -> None:
    project = PRODUCT_ROOT / "acceptance" / "labour-statistics"
    registry = mapping(load_yaml(project / "registry.yaml"), "labour-statistics registry", errors)
    if registry.get("resources") != []:
        errors.append("labour-statistics: statisticalDatasets must remain separate from resources")
    sources = mapping(registry.get("sources"), "labour-statistics sources", errors)
    if not sources or any(
        not isinstance(source, dict) or source.get("profile") != "snapshot"
        for source in sources.values()
    ):
        errors.append("labour-statistics: every statistical dataset source must be snapshot-only")
    metadata = mapping(
        registry.get("metadataVisibility"),
        "labour-statistics metadata visibility",
        errors,
    )
    if metadata.get("statisticalDatasets") != "public":
        errors.append(
            "labour-statistics: metadataVisibility.statisticalDatasets must be explicit"
        )
    alignment_targets = registry.get("registry", {}).get("alignmentTargets", [])
    if not isinstance(alignment_targets, list) or not alignment_targets:
        errors.append(
            "labour-statistics: at least one authored directional alignmentTarget is required"
        )
    if any("sdmx" in str(target).lower() for target in alignment_targets):
        errors.append(
            "labour-statistics: compiler-owned SDMX profile versions must not be authored alignmentTargets"
        )

    datasets = sequence(
        registry.get("statisticalDatasets"),
        "labour-statistics statistical datasets",
        errors,
    )
    if {item.get("id") for item in datasets if isinstance(item, dict)} != {
        "labour-force-participation",
        "labour-force-authority",
    }:
        errors.append("labour-statistics: the two acceptance dataflows are required")
    granularities = {"annual", "quarterly", "monthly", "daily"}
    for index, raw_dataset in enumerate(datasets):
        dataset = mapping(raw_dataset, f"labour-statistics dataset[{index}]", errors)
        if "accessProfiles" in dataset or "defaultAccessProfile" in dataset:
            errors.append(
                "labour-statistics: each statistical dataset has one fixed access and no accessProfiles"
            )
        if "access" not in dataset:
            errors.append(f"labour-statistics dataset[{index}]: access is required")
        bindings = mapping(
            dataset.get("bindings"), f"labour-statistics dataset[{index}] bindings", errors
        )
        require_exact_keys(
            bindings,
            {"sdmx"},
            f"labour-statistics dataset[{index}] bindings",
            errors,
        )
        mapping(
            bindings.get("sdmx"),
            f"labour-statistics dataset[{index}] bindings.sdmx",
            errors,
        )
        time = mapping(
            dataset.get("time"), f"labour-statistics dataset[{index}] time", errors
        )
        granularity = time.get("granularity")
        if granularity not in granularities:
            errors.append(
                f"labour-statistics dataset[{index}]: time.granularity must be annual, quarterly, monthly, or daily"
            )
        if granularity != "quarterly":
            errors.append(
                f"labour-statistics dataset[{index}]: the acceptance fixture remains quarterly"
            )

    journey = mapping(
        load_yaml(project / "expected-http.yaml"), "labour-statistics journey", errors
    )
    steps = {
        step.get("id"): step
        for step in sequence(journey.get("steps"), "labour-statistics journey steps", errors)
        if isinstance(step, dict)
    }
    for step in steps.values():
        path = str(step.get("request", {}).get("path", ""))
        allowed = (
            path == "/v2"
            or re.fullmatch(
                r"/sdmx/v2/data/dataflow/[^/]+/[^/]+/[^/]+(?:/[^/]+)?", path
            )
            or re.fullmatch(
                r"/sdmx/v2/structure/(?:dataflow|datastructure)/[^/]+/[^/]+/[^/]+",
                path,
            )
        )
        if not allowed:
            errors.append(
                "labour-statistics: only dataflow data and dataflow/datastructure structure routes are allowed"
            )
    expected_media = {
        "dataflow-structure": "application/vnd.sdmx.structure+json;version=2.1.0",
        "dsd-structure": "application/vnd.sdmx.structure+json;version=2.1.0",
        "public-keyed-json": "application/vnd.sdmx.data+json;version=2.1.0",
        "public-omitted-key-alias": "application/vnd.sdmx.data+json;version=2.1.0",
        "public-csv": "application/vnd.sdmx.data+csv;version=2.1.0",
    }
    for identifier, media_type in expected_media.items():
        if steps.get(identifier, {}).get("expect", {}).get("mediaType") != media_type:
            errors.append(
                f"labour-statistics: {identifier} must retain the frozen SDMX 2.1.0 media type"
            )
    denial_mapping = {
        "protected-missing-credential": (401, "auth.missing_credential"),
        "protected-scope-denied": (404, "resource.not_found"),
        "protected-purpose-denied": (403, "aggregate-data.denied"),
        "protected-binding-denied": (403, "aggregate-data.denied"),
        "protected-structure-concealed": (404, "resource.not_found"),
        "unknown-dataflow-concealed": (404, "resource.not_found"),
    }
    for identifier, expected in denial_mapping.items():
        expectation = steps.get(identifier, {}).get("expect", {})
        if (expectation.get("status"), expectation.get("code")) != expected:
            errors.append(
                f"labour-statistics: {identifier} does not use the fixed denial mapping"
            )
    if steps.get("unsupported-format", {}).get("expect") != {
        "status": 406,
        "code": "format.unsupported",
    }:
        errors.append("labour-statistics: unsupported Accept must use format.unsupported")
    expected_types = {
        "dimensions": {"REF_AREA": "string", "SEX": "string", "TIME_PERIOD": "string"},
        "measures": {"PARTICIPATION_RATE": "number"},
        "attributes": {"UNIT_MEASURE": "string"},
    }
    if steps.get("public-keyed-json", {}).get("expect", {}).get("sdmxJsonTypes") != expected_types:
        errors.append("labour-statistics: typed SDMX-JSON acceptance is incomplete")


def validate_sdmx_profile_contract(errors: list[str]) -> None:
    path = PRODUCT_ROOT / "contracts" / "sdmx-profile-lock.yaml"
    lock = mapping(load_yaml(path), "SDMX profile lock", errors)
    require_exact_keys(
        lock,
        {"schemaVersion", "upstreamBytesCommitted", "profiles", "validation"},
        "SDMX profile lock",
        errors,
    )
    if lock.get("schemaVersion") != "relay.registrystack.org/sdmx-profile-lock/v1alpha1":
        errors.append("SDMX profile lock: schemaVersion is not supported")
    if lock.get("upstreamBytesCommitted") is not False:
        errors.append("SDMX profile lock: upstream schema bytes must remain external")
    profiles = mapping(lock.get("profiles"), "SDMX profiles", errors)
    if set(profiles) != {"rest", "dataJson", "dataCsv", "structureJson"}:
        errors.append("SDMX profile lock: the profile set is closed")
    if mapping(profiles.get("rest"), "SDMX REST profile", errors).get("version") != "2.2.2":
        errors.append("SDMX profile lock: REST subset must remain 2.2.2")
    for profile in ("dataJson", "dataCsv", "structureJson"):
        if mapping(profiles.get(profile), f"SDMX {profile} profile", errors).get("version") != "2.1.0":
            errors.append(f"SDMX profile lock: {profile} must remain 2.1.0")
    for profile in ("dataJson", "structureJson"):
        schema = mapping(
            mapping(profiles.get(profile), f"SDMX {profile} profile", errors).get("schema"),
            f"SDMX {profile} schema",
            errors,
        )
        require_exact_keys(
            schema,
            {"url", "id", "sha256", "cacheFile"},
            f"SDMX {profile} schema",
            errors,
        )
        if not SHA256.fullmatch(str(schema.get("sha256", ""))):
            errors.append(f"SDMX profile lock: {profile} schema digest is invalid")
    expected_profile_pins = {
        "rest": {
            "commit": "19b14e39b78fe6dacf20a8f97e971ab29c3c83e2",
        },
        "dataJson": {
            "commit": "faa661d2247b9914052c76a5dabafd5990493f5a",
            "sha256": "sha256:ca1c85c7693a2d9d0602a1ca8e5a8b1cc56437fcb05e25cce15165ee75dcd80d",
        },
        "dataCsv": {
            "commit": "9a65b133ec99622a04701f1ff09e7c0777afedbf",
        },
        "structureJson": {
            "commit": "faa661d2247b9914052c76a5dabafd5990493f5a",
            "sha256": "sha256:0f502a347cb463aee7664283ec53d79b6993bf5b503dc76151bb597d10ae3e32",
        },
    }
    for name, expected in expected_profile_pins.items():
        profile = mapping(profiles.get(name), f"SDMX {name} profile", errors)
        if profile.get("commit") != expected["commit"]:
            errors.append(f"SDMX profile lock: {name} official revision changed")
        if "sha256" in expected and profile.get("schema", {}).get("sha256") != expected["sha256"]:
            errors.append(f"SDMX profile lock: {name} official schema digest changed")
    validation = mapping(lock.get("validation"), "SDMX profile validation", errors)
    require_exact_keys(
        validation,
        {
            "script",
            "networkByDefault",
            "explicitFetchOption",
            "schemaCacheEnvironment",
            "packageArtifactSuffixes",
        },
        "SDMX profile validation",
        errors,
    )
    script = validation.get("script")
    if script != "scripts/validate-sdmx-profile.py":
        errors.append("SDMX profile lock: canonical script path changed")
    if validation.get("networkByDefault") is not False or validation.get("explicitFetchOption") != "--fetch-official-schemas":
        errors.append("SDMX profile lock: official schema fetch must remain explicit")
    script_path = PRODUCT_ROOT / str(script)
    if not script_path.is_file() or not os.access(script_path, os.X_OK):
        errors.append("SDMX profile lock: executable profile validation script is missing")


def validate_catalogs(errors: list[str]) -> None:
    validate_acceptance_access_profile_contracts(errors)
    validate_statistical_acceptance(errors)
    validate_sdmx_profile_contract(errors)
    layout = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/package-layout.yaml"), "package layout", errors
    )
    require_exact_keys(
        layout,
        {
            "schemaVersion",
            "product",
            "requiredDocuments",
            "requiredContracts",
            "acceptanceProjects",
            "projectFiles",
            "generatedFilesCommitted",
            "semanticHashSnapshotsCommitted",
            "generatedFilePolicy",
            "excludedInputs",
        },
        "package layout",
        errors,
    )
    expected_projects = {name: f"acceptance/{name}" for name in PROJECTS}
    actual_projects = {
        item.get("id"): item.get("path")
        for item in sequence(layout.get("acceptanceProjects"), "acceptance projects", errors)
        if isinstance(item, dict)
    }
    if actual_projects != expected_projects:
        errors.append(
            f"package layout: expected acceptance projects {expected_projects}, got {actual_projects}"
        )
    required_documents = set(
        sequence(layout.get("requiredDocuments"), "required documents", errors)
    )
    for required in {
        "CONCEPT.md",
        "DEFINITION-OF-DONE.md",
        "CONFIGURATION-EXAMPLES.md",
        "IMPLEMENTATION.md",
        "STANDARDS-ALIGNMENT.md",
    }:
        if required not in required_documents or not (PRODUCT_ROOT / required).is_file():
            errors.append(f"package layout: missing maintained document {required}")
    if layout.get("generatedFilesCommitted") is not False:
        errors.append("package layout: generated runtime files must not be committed")
    if layout.get("semanticHashSnapshotsCommitted") is not True:
        errors.append("package layout: reviewed semantic hash snapshots must be committed")

    inventory = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/artifact-inventory.yaml"),
        "artifact inventory",
        errors,
    )
    artifact_ids: set[str] = set()
    for index, raw in enumerate(
        sequence(inventory.get("artifacts"), "artifact inventory", errors)
    ):
        artifact = mapping(raw, f"artifact[{index}]", errors)
        required = {"id", "mediaType", "visibility", "source", "generated"}
        missing = required - artifact.keys()
        if missing:
            errors.append(f"artifact[{index}]: missing keys {', '.join(sorted(missing))}")
        identifier = artifact.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in artifact_ids:
            errors.append(f"artifact[{index}]: id must be unique and non-empty")
        else:
            artifact_ids.add(identifier)
    for required in {
        "openapi-full",
        "openapi-public",
        "access-profile-schema",
        "geojson-response-schema",
        "sdmx-dataflow-structure",
        "sdmx-datastructure-structure",
        "access-profile-shacl",
        "full-record-schema",
        "full-record-shacl",
        "semantic-model",
        "jsonld-context",
        "shacl-shape",
        "codelists",
        "capability-inventory",
        "audit-event-schema",
        "identification-report",
        "classification-inventory",
        "access-profile-report",
        "contextual-review-findings",
        "classification-review",
        "sdmx-profile-lock",
    }:
        if required not in artifact_ids:
            errors.append(f"artifact inventory: missing {required}")

    steps = journey_steps(errors)
    for project, concealed_steps in ACCESS_PROFILE_CONCEALMENT_STEPS.items():
        for step in concealed_steps:
            if steps.get(project, {}).get(step) != (404, "resource.not_found"):
                errors.append(
                    f"{project}: {step} must conceal access-profile existence as 404 resource.not_found"
                )
    scenarios = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/acceptance-scenario-matrix.yaml"),
        "scenario matrix",
        errors,
    )
    expected_runner = "products/relay-v2/scripts/test-http.sh"
    if scenarios.get("execution") != expected_runner:
        errors.append(f"scenario matrix: execution must be {expected_runner}")
    runner = REPOSITORY_ROOT / expected_runner
    if not runner.is_file() or not os.access(runner, os.X_OK):
        errors.append("scenario matrix: executable HTTP journey runner is missing")
    scenario_ids: set[str] = set()
    covered: dict[str, set[str]] = {project: set() for project in PROJECTS}
    invalid_classes: dict[str, set[str]] = {project: set() for project in PROJECTS}
    for index, raw in enumerate(sequence(scenarios.get("scenarios"), "scenarios", errors)):
        scenario = mapping(raw, f"scenario[{index}]", errors)
        expected_keys = {"id", "project", "journeyStep", "assertion"}
        if "invalidSourceRowClass" in scenario:
            expected_keys.update({"invalidSourceRowClass", "expectedStatus", "expectedCode"})
        require_exact_keys(scenario, expected_keys, f"scenario[{index}]", errors)
        identifier = scenario.get("id")
        project = scenario.get("project")
        step = scenario.get("journeyStep")
        if not isinstance(identifier, str) or not identifier or identifier in scenario_ids:
            errors.append(f"scenario[{index}]: id must be unique and non-empty")
        else:
            scenario_ids.add(identifier)
        if project not in steps or step not in steps.get(project, {}):
            errors.append(f"scenario[{index}]: does not resolve to an exact journey step")
        elif isinstance(step, str):
            covered[project].add(step)
        invalid_class = scenario.get("invalidSourceRowClass")
        if invalid_class is not None:
            if invalid_class not in INVALID_SOURCE_ROW_CLASSES:
                errors.append(f"scenario[{index}]: unknown invalid source-row class")
            elif project in invalid_classes:
                invalid_classes[project].add(invalid_class)
            if (
                scenario.get("expectedStatus") != 503
                or scenario.get("expectedCode") != "source.unavailable"
            ):
                errors.append(
                    f"scenario[{index}]: an invalid source row must expect 503 source.unavailable"
                )
            if project in steps and isinstance(step, str):
                journey_status, journey_code = steps[project].get(step, (None, None))
                if (
                    scenario.get("expectedStatus"),
                    scenario.get("expectedCode"),
                ) != (journey_status, journey_code):
                    errors.append(
                        f"scenario[{index}]: invalid source-row expectation disagrees with the journey"
                    )
    for project in PROJECTS:
        if covered[project] != set(steps[project]):
            errors.append(f"scenario matrix: {project} journey coverage is not exact")
        if not invalid_classes[project]:
            errors.append(f"{project}: at least one invalid source-row refusal is required")
    covered_invalid_classes = set().union(*invalid_classes.values())
    if covered_invalid_classes != INVALID_SOURCE_ROW_CLASSES:
        errors.append(
            "acceptance journeys: invalid source-row classes must cover "
            + ", ".join(sorted(INVALID_SOURCE_ROW_CLASSES))
        )
    if not TRANSFORM_FAILURE_SCENARIOS.issubset(scenario_ids):
        errors.append(
            "acceptance journeys: both bounded transforms require an atomic source-failure scenario"
        )

    matrix = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/security-invariant-matrix.yaml"),
        "security invariant matrix",
        errors,
    )
    require_exact_keys(
        matrix,
        {"schemaVersion", "product", "status", "invariants"},
        "security invariant matrix",
        errors,
    )
    if matrix.get("schemaVersion") != "relay.registrystack.org/security-invariants/v1alpha1":
        errors.append("security invariant matrix: schemaVersion is not supported")
    if matrix.get("product") != "relay-v2" or matrix.get("status") != "enforced":
        errors.append("security invariant matrix: product and enforced status are fixed")
    invariant_ids: set[str] = set()
    for index, raw in enumerate(
        sequence(matrix.get("invariants"), "security invariants", errors)
    ):
        invariant = mapping(raw, f"security invariant[{index}]", errors)
        require_exact_keys(
            invariant,
            {
                "id",
                "threat",
                "enforcementPoint",
                "expected",
                "evidence",
                "negativeTest",
                "tests",
            },
            f"security invariant[{index}]",
            errors,
        )
        identifier = invariant.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in invariant_ids:
            errors.append(f"security invariant[{index}]: id must be unique and non-empty")
        else:
            invariant_ids.add(identifier)
        for field in ("threat", "enforcementPoint", "expected", "evidence"):
            value = invariant.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"security invariant[{index}].{field}: a non-empty value is required"
                )
        tests = sequence(invariant.get("tests"), f"security invariant[{index}].tests", errors)
        if not tests:
            errors.append(f"security invariant[{index}]: exact executable tests are required")
        test_names: set[str] = set()
        for test_index, test in enumerate(tests):
            executable_test_resolves(
                test, f"security invariant[{index}].tests[{test_index}]", errors
            )
            if isinstance(test, dict) and isinstance(test.get("name"), str):
                test_names.add(test["name"])
        negative_test = invariant.get("negativeTest")
        if (
            not isinstance(negative_test, str)
            or not SIMPLE_IDENTIFIER.fullmatch(negative_test)
            or negative_test not in test_names
        ):
            errors.append(
                f"security invariant[{index}].negativeTest: must select one exact listed negative test"
            )
        if any(str(value).strip().lower() in {"todo", "tbd"} for value in invariant.values()):
            errors.append(f"security invariant[{index}]: placeholder value is prohibited")
    if invariant_ids != SECURITY_INVARIANT_IDS:
        errors.append("security invariant matrix: the closed invariant inventory is incomplete")

    baselines = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/generated-baselines.yaml"),
        "generated baselines",
        errors,
    )
    if set(mapping(baselines.get("projects"), "generated baseline projects", errors)) != set(
        PROJECTS
    ):
        errors.append("generated baselines: every acceptance project must be present")


def validate_all() -> list[str]:
    errors: list[str] = []
    validate_catalogs(errors)
    return errors


def main() -> int:
    errors = validate_all()
    if errors:
        for error in errors:
            print(f"relay-v2 validation: {error}", file=sys.stderr)
        return 1
    print("relay-v2 product catalog validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
