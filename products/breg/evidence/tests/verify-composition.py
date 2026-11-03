#!/usr/bin/env python3
"""Offline native BReg-to-Evidence composition proof with matching binaries.

Requires bregctl, evidencectl, evidence and PyYAML. Starts no services. The
adopter flow uses ordinary authored files and public CLIs, not this harness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import yaml

INPUTS = Path(__file__).resolve().parents[1]
BREG_DEFINITIONS = {"record-active", "record-status-pair"}
OFFLINE_REQUESTER_HEADER = "b2ZmbGluZS1maXh0dXJlLXByaW5jaXBhbA"
OFFLINE_PURPOSE_HEADER = "cmVjb3JkLXZlcmlmaWNhdGlvbg"


def run(binary: Path, *args: object, environment: dict[str, str], refused: bool = False) -> str:
    result = subprocess.run(
        [str(binary), *map(str, args)], env=environment, capture_output=True,
        text=True, timeout=120, check=False,
    )
    if refused:
        assert result.returncode, f"{binary.name} {args[0]} unexpectedly succeeded"
        return result.stderr + result.stdout
    if result.returncode:
        raise RuntimeError(
            f"{binary.name} {args[0]} failed ({result.returncode}):\n"
            + result.stderr[-8192:] + result.stdout[-8192:]
        )
    return result.stdout


def read(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def write(path: Path, value: dict) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False))


def authored_snapshot(project: Path) -> dict[str, bytes]:
    """Ignore the importer's private lock/state; compare all authored bytes."""
    return {
        str(path.relative_to(project)): path.read_bytes()
        for path in project.rglob("*")
        if path.is_file() and not set(path.relative_to(project).parts) & {".evidence", ".generated"}
    }


def check_fixtures(project: Path, binaries: dict[str, Path], environment: dict[str, str],
                   *, target: Path, expected: dict[str, int]) -> dict:
    report = json.loads(run(
        binaries["evidencectl"], "--format", "json", "test", project,
        "--target", target, environment=environment,
    ))
    assert report["passed"], report
    actual = {item["path"]: item["evaluatedCases"] for item in report["fixtures"]}
    assert actual == expected, report
    assert all(item["passed"] for item in report["fixtures"]), report
    return report


def bind_logged_fixture_headers(project: Path) -> None:
    """Record the fixed host-owned attribution used by offline fixture replay."""
    for name in ["record-active.yaml", "record-status-pair.yaml"]:
        path = project / "fixtures" / name
        fixture = read(path)
        for case in fixture["cases"]:
            acquisition = case.get("acquisition")
            if acquisition is None:
                continue
            for exchange in acquisition["exchanges"]:
                headers = exchange["request"].setdefault("headers", {})
                assert "registry-access-requester" not in headers
                assert "registry-access-purpose" not in headers
                headers["registry-access-requester"] = OFFLINE_REQUESTER_HEADER
                headers["registry-access-purpose"] = OFFLINE_PURPOSE_HEADER
        write(path, fixture)


def verify(workspace: Path, binaries: dict[str, Path]) -> dict:
    environment = dict(os.environ)
    environment.pop("REGISTRY_EVIDENCE_RUNTIME", None)
    environment.pop("BREGCTL_BIN", None)
    environment["EVIDENCE_BIN"] = str(binaries["evidence"])
    environment["PATH"] = os.pathsep.join([
        *(str(binaries[name].parent) for name in ["bregctl", "evidencectl", "evidence"]),
        environment.get("PATH", ""),
    ])
    registry, project = workspace / "registry", workspace / "evidence"
    target, candidate = workspace / "target", workspace / "candidate"
    shutil.copytree(INPUTS / "registry", registry)

    # A complete independent native project precedes the optional BReg source.
    run(binaries["evidencectl"], "init", project, "--starter", INPUTS / "offline-starter",
        "--profile", "local", environment=environment)
    run(binaries["evidencectl"], "check", project, environment=environment)
    offline_cases = {"fixtures/extract-record-active.yaml": 13}
    check_fixtures(project, binaries, environment, target=project / "local-target.yaml",
                   expected=offline_cases)

    export_arguments = (
        "generate", "evidence-source", registry,
        "--access-profile", "evidence-source", "--record-type", "record",
        "--selector", "by-code", "--selector", "by-registration-number",
        "--fields", "status", "--source-id", "registry-status", "--connection", "registry",
        # The pack declares the authentication the target below selects; the
        # runtime refuses a pack and target that name different types.
        "--authentication", "oauth2-private-key-jwt",
    )
    for name in ["export", "repeated-export"]:
        run(binaries["bregctl"], *export_arguments, "--output", workspace / name,
            environment=environment)
    exported = workspace / "export"
    manifest = json.loads((exported / "source-export.json").read_text())
    assert (exported / "source-export.json").read_bytes() == (
        workspace / "repeated-export/source-export.json"
    ).read_bytes(), "same compiled inputs must yield the same export"
    for artifact in manifest["artifacts"]:
        content = (exported / artifact["path"]).read_bytes()
        assert "sha256:" + hashlib.sha256(content).hexdigest() == artifact["digest"]
        assert content == (workspace / "repeated-export" / artifact["path"]).read_bytes()
    original_registry = authored_snapshot(registry)
    denied_export = workspace / "denied-export"
    denied_arguments = tuple("label" if arg == "status" else arg for arg in export_arguments)
    refused = run(binaries["bregctl"], *denied_arguments, "--output", denied_export,
                  environment=environment, refused=True)
    assert "breg.evidence-source.refused" in refused, refused
    assert not denied_export.exists()
    assert authored_snapshot(registry) == original_registry, "export grants no Registry authority"

    # A modified export must fail its inventory before changing authored files.
    tampered = workspace / "tampered-export"
    shutil.copytree(exported, tampered)
    damaged = tampered / manifest["artifacts"][0]["path"]
    damaged.write_bytes(damaged.read_bytes() + b"\n# altered after export\n")
    before = authored_snapshot(project)
    refused = run(binaries["evidencectl"], "source", "import", tampered,
                  "--project", project, environment=environment, refused=True)
    assert "checksum" in refused, refused
    assert authored_snapshot(project) == before, "refused import must preserve authored files"
    run(binaries["evidencectl"], "source", "import", exported, "--project", project,
        environment=environment)
    imported = read(project / "evidence.yaml")
    assert set(imported["sources"]) == {"record-status", "registry-status"}
    assert set(imported["assertionDefinitions"]) == {"extract-record-active"}, (
        "source import must create no assertion meaning or caller grant"
    )
    assert not (project / "sources").exists(), "Sources belong to EvidenceProject"
    imported_functions = {item["id"]: item for item in imported["functions"]}
    assert not any(name.startswith("registry-status-") for name in imported_functions), (
        "source preparation and extraction remain in the pinned pack closure"
    )
    assert (project / "adapter-packs/registry-status/pack.yaml").is_file()
    assert (project / "adapter-packs/registry-status/scripts/lookup.rhai").is_file()

    # Ordinary authoring follows import. This fragment is never passed as a project.
    fragment = read(INPUTS / "starter/definitions.yaml.fragment")
    imported["functions"].extend(fragment["functions"])
    imported["assertionDefinitions"].update(fragment["assertionDefinitions"])
    write(project / "evidence.yaml", imported)
    for directory in ["functions", "fixtures"]:
        shutil.copytree(INPUTS / "starter" / directory, project / directory, dirs_exist_ok=True)
    run(binaries["evidencectl"], "target", "new", target, "--local", "--project", project,
        environment=environment)
    settings = read(target / "target.yaml")
    settings["connections"]["record-status-extract"] = {"endpoints": {}}
    settings["connections"]["registry"] = {
        "endpoints": {
            "registry": {
                "origin": "http://127.0.0.1:8090",
                "authentication": {
                    "type": "oauth2-private-key-jwt",
                    "tokenEndpoint": "http://127.0.0.1:8091/oauth2/token",
                    "clientIdRef": "secret:file/registry-client-id",
                    "clientAssertionKeyRef": "secret:file/registry-client-key",
                    "clientAssertionAudience": "http://127.0.0.1:8091",
                    "scope": "registry:evidence:lookup", "maximumCacheSeconds": 60,
                },
            },
        },
    }
    # A target binds every extract profile its Sources use; `target new` leaves
    # the file path to the operator.
    settings["extracts"] = {"record-status-extract": {"path": "extracts/record-status.sqlite"}}
    write(target / "target.yaml", settings)
    run(binaries["evidencectl"], "check", project, "--target", target,
        environment=environment)
    fixtures = check_fixtures(project, binaries, environment, target=target, expected={
        **offline_cases, "fixtures/record-active.yaml": 12,
        "fixtures/record-status-pair.yaml": 12,
    })
    run(binaries["evidencectl"], "package", project, "--target", target,
        "--output", candidate, environment=environment)
    bundle_path = candidate / "bundle"
    bundle = read(bundle_path / "evidence.yaml")
    assert set(bundle["sources"]) == {"record-status", "registry-status"}
    assert list(bundle["sourceConnections"]) == ["record-status-extract", "registry"]
    assert bundle["sourceConnections"]["record-status-extract"]["endpoints"] == []
    source = bundle["sources"]["registry-status"]
    owner = bundle["sourceConnections"]["registry"]
    assert source["connection"] == "registry"
    assert "baseUrl" not in source and "authentication" not in source
    assert len(owner["endpoints"]) == 1
    reviewed_endpoint = owner["endpoints"][0]
    assert reviewed_endpoint["endpoint"] == "registry"
    assert reviewed_endpoint["authentication"]["type"] == "oauth2-private-key-jwt"
    requirements = {item["handle"]: item for item in bundle["requirements"]}
    assert len(requirements) == 3
    assert all(requirements[name]["acquisition"]["source"] == "registry-status"
               for name in BREG_DEFINITIONS)
    assert source["pack"]["version"] == manifest["provenance"]["behaviorRevision"]
    assert source["pack"]["digest"].startswith("sha256:")
    pack_root = bundle_path / source["pack"]["artifactPrefix"]
    pack = read(pack_root / "pack.yaml")
    assert pack["id"] == "registry-status"
    assert pack["version"] == source["pack"]["version"]
    assert pack["sourceRoutes"][0]["id"] == source["route"] == "lookup"
    assert pack["sourceRoutes"][0]["evidence"]["acquisitionPosture"] == "field-projected"
    assert pack["endpoints"][0]["hostProtocol"]["id"] == "registry-lookup-v1"
    facts = read(
        pack_root
        / pack["sourceRoutes"][0]["evidence"]["factsSchema"]["path"]
    )
    assert list(facts["properties"]) == ["status"], "identity must not become a fact"
    assert source["posture"] == "field-projected"
    assert len(source["inputs"]) == 2
    assert {item["selector"]["profile"] for item in source["inputs"].values()} == {
        "breg-8-registry-6-record-7-by-code",
        "breg-8-registry-6-record-22-by-registration-number",
    }
    report = json.loads(run(binaries["evidence"], "bundle-check", "--bundle", bundle_path,
                            "--json", environment=environment))
    assert len(report["requirements"]) == 3

    # The same generated pack must execute when the Registry model requires
    # host-owned access attribution. A copied project keeps this proof isolated
    # from the unlogged source and records only the fixed synthetic host values.
    logged_registry = workspace / "logged-registry"
    shutil.copytree(registry, logged_registry)
    logged_model_path = logged_registry / "registry.yaml"
    logged_model = read(logged_model_path)
    logged_model["recordTypes"][0]["accessLog"] = {
        "subjectField": "code",
        "retentionDays": 90,
        "trustedIntermediaries": ["evidence-service"],
    }
    write(logged_model_path, logged_model)
    logged_export = workspace / "logged-export"
    logged_arguments = list(export_arguments)
    logged_arguments[2] = logged_registry
    run(binaries["bregctl"], *logged_arguments, "--output", logged_export,
        environment=environment)
    logged_protocol = json.loads(
        (logged_export / "adapter-packs/registry-status/protocols/registry-lookup.json")
        .read_text()
    )
    assert logged_protocol["forwardAccessAttribution"] is True
    logged_project, logged_target = workspace / "logged-evidence", workspace / "logged-target"
    shutil.copytree(project, logged_project)
    shutil.copytree(target, logged_target)
    bind_logged_fixture_headers(logged_project)
    run(binaries["evidencectl"], "source", "update", logged_export,
        "--project", logged_project, "--target", logged_target, environment=environment)
    logged_fixtures = check_fixtures(
        logged_project, binaries, environment, target=logged_target,
        expected={
            **offline_cases, "fixtures/record-active.yaml": 12,
            "fixtures/record-status-pair.yaml": 12,
        },
    )

    # An unrelated Registry field changes provenance only, never assertion meaning.
    model_path = registry / "registry.yaml"
    model = read(model_path)
    fields = model["recordTypes"][0]["fields"]
    fields.append({"id": "operator-note", "type": "string", "maximumLength": 32,
                   "classification": "internal"})
    write(model_path, model)
    unrelated_export = workspace / "unrelated-export"
    run(binaries["bregctl"], *export_arguments, "--output", unrelated_export,
        environment=environment)
    unrelated_manifest = json.loads((unrelated_export / "source-export.json").read_text())
    assert unrelated_manifest["provenance"]["registryRevision"] != manifest["provenance"]["registryRevision"]
    assert unrelated_manifest["provenance"]["behaviorRevision"] == source["pack"]["version"]
    unrelated = json.loads(run(binaries["evidencectl"], "--format", "json", "source", "diff",
        unrelated_export, "--project", project, "--target", target, environment=environment))
    assert unrelated["provenanceChanged"] == ["registry-status"]
    assert not unrelated["affectedDefinitions"]
    assert len(unrelated["definitionRevisions"]) == 3
    assert all(item["change"] == "unchanged" for item in unrelated["definitionRevisions"])

    # A consumed identity bound changes only the two definitions sharing that Source.
    next(field for field in fields if field["id"] == "code")["maximumLength"] = 63
    write(model_path, model)
    changed_export = workspace / "changed-export"
    run(binaries["bregctl"], *export_arguments, "--output", changed_export,
        environment=environment)
    for command in ["diff", "update"]:
        changed = json.loads(run(binaries["evidencectl"], "--format", "json", "source", command,
            changed_export, "--project", project, "--target", target, environment=environment))
        assert not changed["conflicts"]
        assert set(changed["affectedDefinitions"]) == BREG_DEFINITIONS
        changes = {item["requirement"]: item["change"] for item in changed["definitionRevisions"]}
        assert changes == {
            "urn:example:requirement:extract-record-active:v1": "unchanged",
            "urn:example:requirement:record-active:v1": "changed",
            "urn:example:requirement:record-status-pair:v1": "changed",
        }, changes

    # A renamed consumed fact refuses before changing any authored input.
    field = next(field for field in fields if field["id"] == "status")
    field.update(id="lifecycle-status", apiName="lifecycleStatus")
    for profile in model["accessProfiles"]:
        for permission in profile["permissions"]["records"]:
            for key in ["readableFields", "writableFields"]:
                if key in permission:
                    permission[key] = ["lifecycle-status" if name == "status" else name
                                       for name in permission[key]]
    write(model_path, model)
    renamed_export = workspace / "renamed-export"
    renamed_arguments = tuple("lifecycle-status" if arg == "status" else arg for arg in export_arguments)
    run(binaries["bregctl"], *renamed_arguments, "--output", renamed_export, environment=environment)
    before = authored_snapshot(project)
    for command in ["diff", "update"]:
        refused = run(binaries["evidencectl"], "source", command, renamed_export,
                      "--project", project, "--target", target, environment=environment, refused=True)
        assert "reads fact `status`" in refused, refused
        assert authored_snapshot(project) == before
    guided = verify_source_add_review(workspace / "source-add", binaries, environment)
    return {
        "proofBoundary": "offline export/import, fixtures and package; no live services",
        "exportArtifacts": len(manifest["artifacts"]),
        "fixtureCases": sum(item["evaluatedCases"] for item in fixtures["fixtures"]),
        "definitions": 3, "sources": 2, "behaviorRevision": source["pack"]["version"],
        "packageDigest": report["packageDigest"], "tamperedImport": "refused without authored changes",
        "unreadableFactExport": "refused", "provenanceOnlyRevisions": "unchanged",
        "consumedChangeRevisions": "both BReg definitions changed; offline definition unchanged",
        "nativeSourceUpdate": "passed", "renamedFactUpdate": "refused without authored changes",
        "loggedFixtureCases": sum(item["evaluatedCases"] for item in logged_fixtures["fixtures"]),
        "sourceAddReview": guided,
    }


def verify_source_add_review(workspace: Path, binaries: dict[str, Path], environment: dict[str, str]) -> dict:
    """Guided setup names its prerequisites and leaves refused projects untouched."""
    workspace.mkdir(mode=0o700)
    registry, project = workspace / "registry", workspace / "evidence"
    shutil.copytree(INPUTS / "registry", registry)
    add_arguments = ("source", "add", registry, project, "--entity", "record",
                     "--selector-field", "code", "--fields", "status", "--all-records")
    version = run(binaries["bregctl"], "--version", environment=environment).strip()
    help_text = run(binaries["evidencectl"], "source", "add", "--help", environment=environment)
    assert all(word in help_text for word in ["bregctl", "PATH", "--apply"])
    refused = run(binaries["evidencectl"], *add_arguments, "--dry-run",
                  environment=environment, refused=True)
    assert "evidencectl.usage" in refused, refused
    mismatched = run(binaries["evidencectl"], *add_arguments, "--bregctl-bin", binaries["evidence"],
                     environment=environment, refused=True)
    assert version in mismatched and "BREGCTL_BIN" in mismatched, mismatched
    before = authored_snapshot(registry)
    for apply in [(), ("--apply",)]:
        refused = run(binaries["evidencectl"], *add_arguments, *apply,
                      environment=environment, refused=True)
        assert "dev prepare-source" in refused, refused
        assert not project.exists()
        assert not (registry / ".breg").exists()
        assert authored_snapshot(registry) == before
    return {"reviewByDefault": True, "bregctlRequirement": version,
            "missingRetainedSession": "refused without project changes",
            "successfulLiveConnection": "not exercised by offline proof"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["bregctl", "evidencectl", "evidence"]:
        parser.add_argument(f"--{name}", type=Path, default=shutil.which(name))
    parser.add_argument("--work-dir", type=Path, help="new private directory retaining synthetic outputs")
    args = parser.parse_args()
    binaries = {}
    for name in ["bregctl", "evidencectl", "evidence"]:
        path = getattr(args, name)
        if path is None or not path.is_file():
            parser.error(f"provide --{name} with a matching native executable")
        binaries[name] = path.resolve()
    if args.work_dir:
        workspace = args.work_dir.resolve()
        workspace.mkdir(mode=0o700)
        report = verify(workspace, binaries)
    else:
        with tempfile.TemporaryDirectory(prefix="breg-evidence-composition-") as directory:
            report = verify(Path(directory).resolve(), binaries)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
