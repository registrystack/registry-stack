#!/usr/bin/env python3
"""Run the complete Relay V2 adopter workflow and verify reviewed outputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PRODUCT_ROOT.parents[1]
PROJECTS = (
    "social-assistance",
    "business-registry",
    "civil-event",
    "labour-statistics",
)
STATISTICAL_INSPECTIONS = {
    "labour-statistics": {
        "view": "relay_labour_force_rates",
        "timeColumn": "time_period",
        "measureColumn": "obs_value",
        "attributeColumns": ("unit_measure",),
    }
}
BASELINE_PATH = PRODUCT_ROOT / "contracts/generated-baselines.yaml"
CONFIGURATION_REFERENCE = PRODUCT_ROOT / "CONFIGURATION-EXAMPLES.md"
CONFIGURATION_MARKERS = {
    "registry": "relay-v2-registry-key-paths",
    "runtime": "relay-v2-runtime-key-paths",
}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class GateFailure(Exception):
    pass


def run(relayctl: Path, arguments: list[str], *, expected: int = 0) -> tuple[dict[str, Any], bytes]:
    completed = subprocess.run(
        [str(relayctl), "--json", *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != expected:
        raise GateFailure(
            f"relayctl {' '.join(arguments[:1])} returned {completed.returncode}, expected {expected}"
        )
    if completed.stderr:
        raise GateFailure(f"relayctl {' '.join(arguments[:1])} wrote to stderr")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise GateFailure(f"relayctl {' '.join(arguments[:1])} did not emit JSON") from error
    return report, completed.stdout


def materialize(project: Path) -> None:
    database = project / "fixture.sqlite"
    connection = sqlite3.connect(database)
    try:
        connection.executescript((project / "fixture.sql").read_text(encoding="utf-8"))
    finally:
        connection.close()
    database.chmod(0o444)


def protected_canaries(project: Path) -> set[bytes]:
    sql = (project / "fixture.sql").read_text(encoding="utf-8")
    values = {match.replace("''", "'") for match in re.findall(r"'((?:''|[^'])*)'", sql)}
    journey = yaml.safe_load((project / "expected-http.yaml").read_text(encoding="utf-8"))
    for authorization in journey.get("authorizations", {}).values():
        values.add(str(authorization.get("principal", "")))
        values.update(str(value) for value in authorization.get("claims", {}).values())
    for step in journey.get("steps", []):
        values.update(str(value) for value in step.get("request", {}).get("body", {}).values())
    return {value.encode() for value in values if len(value) >= 4}


def assert_value_free(outputs: list[bytes], canaries: set[bytes], project: str) -> None:
    for output in outputs:
        for canary in canaries:
            if canary in output:
                raise GateFailure(f"{project}: adopter output exposed a protected fixture value")


def file_sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def openapi_operations(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    if document.get("openapi") != "3.1.0" or not isinstance(document.get("paths"), dict):
        raise GateFailure("generated OpenAPI is not a valid 3.1 path document")
    for path, path_item in document["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            raise GateFailure("generated OpenAPI path inventory is malformed")
        for method, operation in path_item.items():
            if method not in {"get", "post"} or not isinstance(operation, dict):
                raise GateFailure("generated OpenAPI contains an unsupported path item")
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise GateFailure("generated OpenAPI operation has no operationId")
            result[(path, method)] = operation
    operation_ids = [operation["operationId"] for operation in result.values()]
    if len(operation_ids) != len(set(operation_ids)):
        raise GateFailure("generated OpenAPI operation identifiers are not unique")
    return result


def access_profile_identifiers(operation: dict[str, Any], label: str) -> set[str]:
    profiles = operation.get("x-registry-access-profiles")
    if not isinstance(profiles, list) or not profiles:
        raise GateFailure(f"{label} has no finite access profiles")
    identifiers: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(
            profile.get("accessProfileIdentifier"), str
        ):
            raise GateFailure(f"{label} has a malformed access profile")
        identifier = profile["accessProfileIdentifier"]
        if not identifier or identifier in identifiers:
            raise GateFailure(f"{label} has duplicate or empty access-profile identifiers")
        identifiers.add(identifier)
    return identifiers


def public_access_profile_parameters(operation: dict[str, Any], label: str) -> set[str]:
    parameters = operation.get("parameters")
    if not isinstance(parameters, list):
        raise GateFailure(f"{label} has no parameters")
    matches = [
        parameter
        for parameter in parameters
        if isinstance(parameter, dict)
        and parameter.get("name") == "accessProfile"
        and parameter.get("in") == "query"
    ]
    if len(matches) != 1:
        raise GateFailure(f"{label} has no unique accessProfile parameter")
    identifiers = matches[0].get("schema", {}).get("enum")
    if not isinstance(identifiers, list) or not all(isinstance(item, str) for item in identifiers):
        raise GateFailure(f"{label} has a malformed accessProfile parameter")
    return set(identifiers)


def artifact_identifier(reference: Any) -> str | None:
    if not isinstance(reference, str) or not reference:
        return None
    return reference.rsplit("/", 1)[-1]


def validate_public_operation(
    public: dict[str, Any], full: dict[str, Any], public_artifact_ids: set[str]
) -> None:
    if public.get("operationId") != full.get("operationId"):
        raise GateFailure("public OpenAPI operation identifier does not match full OpenAPI")
    public_ids = access_profile_identifiers(public, "public OpenAPI operation")
    full_ids = access_profile_identifiers(full, "full OpenAPI operation")
    if not public_ids.issubset(full_ids):
        raise GateFailure("public OpenAPI access profile is absent from full OpenAPI")
    if public_access_profile_parameters(public, "public OpenAPI operation") != public_ids:
        raise GateFailure("public OpenAPI access profile parameter does not match public profiles")
    if public.get("security") != [] or "x-registry-required-scopes" in public:
        raise GateFailure("public OpenAPI operation carries protected access or security")
    full_profiles = {
        profile["accessProfileIdentifier"]: profile
        for profile in full["x-registry-access-profiles"]
    }
    protected_ids = {
        entry.get("accessProfileIdentifier")
        for entry in full.get("x-registry-required-scopes", [])
        if isinstance(entry, dict)
        and isinstance(entry.get("accessProfileIdentifier"), str)
    }
    for profile in public["x-registry-access-profiles"]:
        identifier = profile["accessProfileIdentifier"]
        if identifier in protected_ids:
            raise GateFailure("public OpenAPI exposes a protected access profile")
        if profile != full_profiles[identifier]:
            raise GateFailure("public OpenAPI access profile differs from its full profile")
        for reference_key in (
            "schemaReference",
            "semanticModelReference",
            "contextReference",
        ):
            if artifact_identifier(profile.get(reference_key)) not in public_artifact_ids:
                raise GateFailure("public OpenAPI references an artifact absent from public output")


def validate_openapi(package: Path, artifacts: list[dict[str, Any]]) -> None:
    full = yaml.safe_load((package / "generated/openapi.full.yaml").read_text(encoding="utf-8"))
    public = json.loads((package / "generated/openapi.public.json").read_text(encoding="utf-8"))
    full_operations = openapi_operations(full)
    public_operations = openapi_operations(public)
    public_artifact_ids = {
        artifact["id"]
        for artifact in artifacts
        if artifact.get("visibility") == "public" and isinstance(artifact.get("id"), str)
    }
    for key, operation in public_operations.items():
        full_operation = full_operations.get(key)
        if full_operation is None:
            raise GateFailure("public OpenAPI path is absent from full OpenAPI")
        if "x-registry-access-profiles" in operation or "x-registry-access-profiles" in full_operation:
            validate_public_operation(operation, full_operation, public_artifact_ids)
        elif operation != full_operation:
            raise GateFailure("public fixed OpenAPI operation differs from full OpenAPI")

    capabilities = json.loads(
        (package / "generated/artifacts/capabilities.full.json").read_text(encoding="utf-8")
    )
    capability_ids = {
        capability["operationIdentifier"] for capability in capabilities["capabilities"]
    }
    fixed_ids = {
        "relay.health",
        "relay.ready",
        "relay.openapi.public",
        "relay.registry.metadata",
        "relay.resources.list",
        "relay.resources.retrieve",
        "relay.artifacts.retrieve",
    }
    full_ids = {operation["operationId"] for operation in full_operations.values()}
    full_capability_ids = {
        operation.get("x-registry-capability-operation", operation["operationId"])
        for operation in full_operations.values()
        if operation["operationId"] not in fixed_ids
    }
    if full_ids & fixed_ids != fixed_ids or full_capability_ids != capability_ids:
        raise GateFailure("full OpenAPI does not exactly cover compiled capabilities and router metadata")

    public_capabilities = json.loads(
        (package / "generated/artifacts/capabilities.json").read_text(encoding="utf-8")
    )
    public_capability_ids = {
        capability["operationIdentifier"]
        for capability in public_capabilities["capabilities"]
    }
    public_ids = {operation["operationId"] for operation in public_operations.values()}
    required_public_ids = {
        "relay.health",
        "relay.ready",
        "relay.openapi.public",
        "relay.registry.metadata",
        "relay.artifacts.retrieve",
    }
    if not required_public_ids.issubset(public_ids):
        raise GateFailure("public OpenAPI omits a required public router operation")
    bound_public_ids = {
        operation.get("x-registry-capability-operation", operation["operationId"])
        for operation in public_operations.values()
        if operation["operationId"] not in fixed_ids
    }
    if bound_public_ids != public_capability_ids:
        raise GateFailure("public OpenAPI capability paths do not match public discovery")


def validate_exposure_and_identity(package: Path, generated: Path) -> dict[str, Any]:
    manifest = json.loads((package / "relay-package.json").read_text(encoding="utf-8"))
    if manifest.get("packageVersion") != "relay.registrystack.org/package/v1alpha3":
        raise GateFailure("sealed package has an unsupported manifest")
    artifacts = manifest.get("artifacts")
    operation_bindings = manifest.get("operationArtifactBindings")
    files = manifest.get("files")
    if (
        not isinstance(artifacts, list)
        or not isinstance(operation_bindings, list)
        or not isinstance(files, list)
    ):
        raise GateFailure("sealed package inventory is incomplete")
    file_inventory = {entry["path"]: entry for entry in files}
    if len(file_inventory) != len(files):
        raise GateFailure("sealed package contains duplicate file inventory paths")
    compiled = file_inventory.get("compiled/registry.json")
    if (
        not compiled
        or not compiled.get("generated")
        or compiled.get("visibility") != "operator-only"
    ):
        raise GateFailure("sealed package omits its operator-only compiled Registry")
    for entry in files:
        path = package / entry["path"]
        if not path.is_file() or file_sha256(path) != entry.get("sha256"):
            raise GateFailure("sealed package file bytes do not match their inventory")
        if not entry.get("generated") and entry.get("visibility") != "operator-only":
            raise GateFailure("an authored governed file is not operator-only")
    artifact_ids: set[str] = set()
    for artifact in artifacts:
        identifier = artifact.get("id")
        path = artifact.get("path")
        if identifier in artifact_ids or path not in file_inventory:
            raise GateFailure("generated artifact inventory is not one-to-one")
        artifact_ids.add(identifier)
        file_entry = file_inventory[path]
        for key in ("mediaType", "visibility", "sha256"):
            if artifact.get(key) != file_entry.get(key):
                raise GateFailure("artifact exposure inventory disagrees with file inventory")
        visibility = artifact.get("visibility")
        operation = artifact.get("operationIdentifier")
        access_binding = artifact.get("accessBinding")
        if "accessProfileIdentifier" in artifact:
            raise GateFailure(
                "package artifact carries the retired accessProfileIdentifier field"
            )
        if (operation is None) != (access_binding is None):
            raise GateFailure("artifact operation identity and access binding disagree")
        if visibility == "operation-bound" and operation is None:
            raise GateFailure("operation-bound artifact has no compiled operation gate")
        if access_binding is not None:
            if not isinstance(access_binding, dict):
                raise GateFailure("artifact has no explicit access binding")
            if access_binding.get("kind") == "access-profile":
                if visibility != "operation-bound":
                    raise GateFailure(
                        "non-operation-bound Record artifact carries an access-profile gate"
                    )
                if set(access_binding) != {"kind", "identifier"} or not isinstance(
                    access_binding.get("identifier"), str
                ) or not access_binding["identifier"]:
                    raise GateFailure("access-profile artifact has a malformed access binding")
            elif access_binding != {"kind": "fixed-operation"}:
                raise GateFailure("artifact has an unknown access binding")
        generated_path = generated / path.removeprefix("generated/")
        if not generated_path.is_file() or generated_path.read_bytes() != (package / path).read_bytes():
            raise GateFailure("generated and packaged artifact bytes differ")
    by_id = {artifact["id"]: artifact for artifact in artifacts}
    if by_id.get("openapi-full", {}).get("visibility") != "operator-only":
        raise GateFailure("full OpenAPI is not package-only")
    if by_id.get("openapi-public", {}).get("visibility") != "public":
        raise GateFailure("public OpenAPI is not explicitly public")
    validate_openapi(package, artifacts)
    return manifest


def baseline(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "packageRevision": manifest["packageRevision"],
        "contractRevision": manifest["contractRevision"],
        "sourceSchemaFingerprints": manifest["sourceSchemaFingerprints"],
        "artifacts": manifest["artifacts"],
        "governedFiles": [entry for entry in manifest["files"] if not entry["generated"]],
    }


def assert_diff_change(report: dict[str, Any], change_class: str, impact: str) -> None:
    changes = report.get("details", {}).get("report", {}).get("changes", [])
    if not any(
        change.get("class") == change_class and change.get("impact") == impact
        for change in changes
        if isinstance(change, dict)
    ):
        raise GateFailure(
            f"relayctl diff did not classify {change_class} as {impact}"
        )


def exercise_nontrivial_diff(
    accepted: Any, project_name: str, project: Path, previous: Path, root: Path
) -> None:
    if project_name != "business-registry":
        return

    def changed_project(name: str) -> tuple[Path, dict[str, Any]]:
        candidate = root / name
        shutil.copytree(project, candidate)
        contract_path = candidate / "registry.yaml"
        contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
        return candidate, contract

    expanded, contract = changed_project("diff-expanded")
    pagination = contract["resources"][0]["operations"]["list"]["pagination"]
    pagination["maximumPageSize"] += 1
    (expanded / "registry.yaml").write_text(
        yaml.safe_dump(contract, sort_keys=False, width=1000), encoding="utf-8"
    )
    report = accepted(["diff", str(previous), str(expanded)])
    assert_diff_change(report, "pagination-expanded", "widening")

    narrowed, contract = changed_project("diff-narrowed")
    contract["resources"][0]["operations"]["list"]["allowUnfiltered"] = False
    (narrowed / "registry.yaml").write_text(
        yaml.safe_dump(contract, sort_keys=False, width=1000), encoding="utf-8"
    )
    report = accepted(["diff", str(previous), str(narrowed)])
    assert_diff_change(report, "unfiltered-disabled", "narrowing")

    breaking, contract = changed_project("diff-breaking")
    contract["resources"][0]["operations"]["list"]["filters"].pop(0)
    (breaking / "registry.yaml").write_text(
        yaml.safe_dump(contract, sort_keys=False, width=1000), encoding="utf-8"
    )
    report = accepted(["diff", str(previous), str(breaking)])
    assert_diff_change(report, "filter-removed", "breaking")


def run_workflow(relayctl: Path, project_name: str, root: Path) -> tuple[list[dict[str, Any]], list[bytes], dict[str, Any]]:
    source = PRODUCT_ROOT / "acceptance" / project_name
    project = root / "project"
    previous = root / "previous"

    reports: list[dict[str, Any]] = []
    outputs: list[bytes] = []

    def accepted(arguments: list[str]) -> dict[str, Any]:
        report, output = run(relayctl, arguments)
        if report.get("status") != "success" or report.get("diagnostics") != []:
            raise GateFailure(f"{project_name}: relayctl {arguments[0]} refused a reviewed project")
        reports.append(report)
        outputs.append(output)
        return report

    accepted(["init", str(project)])
    for starter in project.iterdir():
        if starter.is_dir():
            shutil.rmtree(starter)
        else:
            starter.unlink()
    shutil.copytree(source, project, dirs_exist_ok=True)
    materialize(project)
    shutil.copytree(project, previous)
    inspect_arguments = [
        "inspect",
        str(project / "fixture.sqlite"),
        "--starters",
        str(root / "inspection"),
    ]
    statistical = STATISTICAL_INSPECTIONS.get(project_name)
    if statistical is not None:
        inspect_arguments.extend(
            [
                "--statistical-view",
                statistical["view"],
                "--time-column",
                statistical["timeColumn"],
                "--measure-column",
                statistical["measureColumn"],
            ]
        )
        for attribute_column in statistical["attributeColumns"]:
            inspect_arguments.extend(["--attribute-column", attribute_column])
    inspection = accepted(inspect_arguments)
    if statistical is not None:
        starter_path = root / "inspection" / "statistical-dataset-starter.yaml"
        starter = yaml.safe_load(starter_path.read_text(encoding="utf-8"))
        datasets = starter.get("statisticalDatasets") if isinstance(starter, dict) else None
        if not isinstance(datasets, list) or len(datasets) != 1:
            raise GateFailure(
                f"{project_name}: inspect did not create one statistical starter"
            )
        dataset = datasets[0]
        attributes = dataset.get("attributes", {})
        if (
            inspection["details"].get("statistical_starter_file")
            != "statistical-dataset-starter.yaml"
            or dataset.get("publication", {}).get("releaseAt") != "REVIEW_REQUIRED"
            or dataset.get("classificationDefaults", {}).get("status") != "suggested"
            or dataset.get("bindings", {}).get("sdmx") != {}
            or dataset.get("time", {}).get("column") != statistical["timeColumn"]
            or dataset.get("time", {}).get("granularity") != "REVIEW_REQUIRED"
            or dataset.get("measure", {}).get("column") != statistical["measureColumn"]
            or sorted(
                attribute.get("column")
                for attribute in attributes.values()
                if isinstance(attribute, dict)
            )
            != sorted(statistical["attributeColumns"])
        ):
            raise GateFailure(
                f"{project_name}: statistical starter is not review-gated and format-neutral"
            )
    check = accepted(["check", str(project), "--production"])
    accepted(["generate", str(project), "--output", str(root / "generated")])
    accepted(["test", str(project)])
    no_op_diff = accepted(["diff", str(previous), str(project)])
    if no_op_diff.get("details", {}).get("report", {}).get("changes") != []:
        raise GateFailure(f"{project_name}: byte-identical projects produced a diff")
    exercise_nontrivial_diff(accepted, project_name, project, previous, root)
    package_report = accepted(["package", str(project), "--output", str(root / "package")])

    manifest = validate_exposure_and_identity(root / "package", root / "generated")
    if package_report["details"]["manifest"] != manifest:
        raise GateFailure(f"{project_name}: package report bytes and sealed manifest differ")

    drift = root / "schema-drift"
    shutil.copytree(project, drift)
    database = drift / "fixture.sqlite"
    database.chmod(0o644)
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE drift_probe (identifier TEXT NOT NULL)")
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o444)
    refusal, refusal_output = run(
        relayctl, ["check", str(drift), "--production"], expected=1
    )
    if refusal.get("status") != "refused" or not refusal.get("diagnostics"):
        raise GateFailure(f"{project_name}: schema change did not fail closed")
    outputs.append(refusal_output)

    key_paths = check["details"].get("configuration_key_paths")
    if not isinstance(key_paths, dict):
        raise GateFailure(f"{project_name}: shared check report omitted configuration key paths")
    return reports + [refusal], outputs, {"manifest": manifest, "keyPaths": key_paths}


def documented_key_paths(text: str, marker: str) -> set[str]:
    start = f"<!-- {marker}:start -->"
    end = f"<!-- {marker}:end -->"
    _, separator, tail = text.partition(start)
    if not separator:
        raise GateFailure(f"configuration reference is missing {start}")
    block, separator, _ = tail.partition(end)
    if not separator:
        raise GateFailure(f"configuration reference is missing {end}")
    paths = [
        line.strip()
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith("```")
    ]
    if paths != sorted(set(paths)):
        raise GateFailure(f"{marker} key paths are not unique and sorted")
    return set(paths)


def rewrite_key_paths(text: str, marker: str, paths: set[str]) -> str:
    start = f"<!-- {marker}:start -->"
    end = f"<!-- {marker}:end -->"
    head, separator, tail = text.partition(start)
    if not separator:
        raise GateFailure(f"configuration reference is missing {start}")
    _, separator, rest = tail.partition(end)
    if not separator:
        raise GateFailure(f"configuration reference is missing {end}")
    body = "\n".join(sorted(paths))
    return f"{head}{start}\n```text\n{body}\n```\n{end}{rest}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--relayctl", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    relayctl = args.relayctl.resolve()
    if not relayctl.is_file():
        print("relay-v2 adopter workflow: relayctl binary is missing", file=sys.stderr)
        return 1

    try:
        snapshots: dict[str, Any] = {}
        key_paths = {"registry": set(), "runtime": set()}
        for project_name in PROJECTS:
            with tempfile.TemporaryDirectory(prefix=f"relay-v2-{project_name}-") as raw:
                try:
                    _, outputs, result = run_workflow(relayctl, project_name, Path(raw))
                except GateFailure as error:
                    raise GateFailure(f"{project_name}: {error}") from error
                canaries = protected_canaries(PRODUCT_ROOT / "acceptance" / project_name)
                assert_value_free(outputs, canaries, project_name)
                snapshots[project_name] = baseline(result["manifest"])
                for kind in key_paths:
                    key_paths[kind].update(result["keyPaths"][kind])

        baseline_document = {
            "schemaVersion": "relay.registrystack.org/generated-baselines/v1alpha1",
            "product": "relay-v2",
            "projects": snapshots,
        }
        reference = CONFIGURATION_REFERENCE.read_text(encoding="utf-8")
        if args.write:
            BASELINE_PATH.write_text(
                yaml.safe_dump(baseline_document, sort_keys=False, width=1000),
                encoding="utf-8",
            )
            for kind, paths in key_paths.items():
                reference = rewrite_key_paths(
                    reference, CONFIGURATION_MARKERS[kind], paths
                )
            CONFIGURATION_REFERENCE.write_text(reference, encoding="utf-8")
            print("relay-v2 reviewed baselines and configuration key paths updated")
            return 0

        committed = yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))
        if committed != baseline_document:
            raise GateFailure(
                "generated semantic hashes or exposure inventory drifted; "
                "run products/relay-v2/scripts/check-generated.sh --write "
                f"to refresh {BASELINE_PATH.relative_to(REPOSITORY_ROOT)}"
            )
        for kind, paths in key_paths.items():
            documented = documented_key_paths(reference, CONFIGURATION_MARKERS[kind])
            if documented != paths:
                raise GateFailure(
                    f"{kind} configuration key-path reference drifted; "
                    "run products/relay-v2/scripts/check-generated.sh --write "
                    f"to refresh {CONFIGURATION_REFERENCE.relative_to(REPOSITORY_ROOT)}"
                )
    except (GateFailure, OSError, KeyError, TypeError, yaml.YAMLError) as error:
        print(f"relay-v2 adopter workflow: {error}", file=sys.stderr)
        return 1

    print("relay-v2 complete adopter workflow, exposure inventory, and baselines passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
