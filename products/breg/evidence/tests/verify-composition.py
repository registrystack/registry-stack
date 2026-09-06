#!/usr/bin/env python3
"""Maintainer-only offline proof of the native BReg to Evidence composition.

Requires matching bregctl, evidencectl and evidence binaries plus PyYAML. The
adopter workflow uses the native commands directly, not this test harness.
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


def run(binary: Path, *args: object, environment: dict[str, str]) -> str:
    result = subprocess.run(
        [str(binary), *(str(arg) for arg in args)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"{binary.name} {args[0]} failed ({result.returncode}):\n"
            + result.stderr[-8192:] + result.stdout[-8192:]
        )
    return result.stdout


def verify(workspace: Path, binaries: dict[str, Path]) -> dict[str, object]:
    environment = dict(os.environ)
    environment.pop("REGISTRY_EVIDENCE_RUNTIME", None)
    environment["PATH"] = os.pathsep.join(
        [str(binaries["evidence"].parent), environment.get("PATH", "")]
    )
    registry = workspace / "registry"
    project = workspace / "evidence"
    target = workspace / "target"
    candidate = workspace / "candidate"
    shutil.copytree(INPUTS / "registry", registry)
    export_arguments = (
        "generate", "evidence-source", registry,
        "--access-profile", "evidence-source", "--entity", "record",
        "--selector", "by-code", "--selector", "by-registration-number",
        "--fields", "status", "--source-id", "registry-status", "--connection", "registry",
    )
    for name in ["export", "repeated-export"]:
        run(binaries["bregctl"], *export_arguments, "--output", workspace / name,
            environment=environment)
    exported = workspace / "export"
    manifest = json.loads((exported / "source-export.json").read_text())
    assert (exported / "source-export.json").read_bytes() == (
        workspace / "repeated-export/source-export.json"
    ).read_bytes(), "same compiled BReg inputs must yield the same export"
    for artifact in manifest["artifacts"]:
        content = (exported / artifact["path"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == artifact["sha256"]
        assert content == (workspace / "repeated-export" / artifact["path"]).read_bytes()
    run(binaries["evidencectl"], "new", project, "--starter", INPUTS / "starter",
        "--profile", "local", environment=environment)
    assert not list((project / "sources").iterdir()), "starter must not hold a generated copy"
    settings = yaml.safe_load((project / "targets/local/settings.yaml").read_text())
    settings["runtime"]["bundleDirectory"] = str(candidate / "bundle")
    settings["runtime"]["secretProviders"]["file"]["root"] = str(project / "secrets")
    settings["runtime"]["auditStorage"]["path"] = str(workspace / "audit/evidence.jsonl")
    settings_path = workspace / "resolved-settings.json"
    settings_path.write_text(json.dumps(settings))
    run(binaries["evidencectl"], "target", "new", target, "--settings", settings_path,
        "--signing-public-key", project / "secrets/signing-p256-public.jwk.json",
        environment=environment)
    run(binaries["evidencectl"], "source", "import", exported, "--project", project,
        "--target", target, environment=environment)
    fixtures = json.loads(run(
        binaries["evidencectl"], "fixtures", "run", "--project", project,
        "--target", target, "--json", environment=environment,
    ))
    assert len(fixtures["fixtures"]) == 2, "both questions need their own executed fixture"
    assert all(fixture["passed"] and fixture["evaluated_cases"] == 11
               for fixture in fixtures["fixtures"]), fixtures
    run(binaries["evidencectl"], "build", "--project", project, "--target", target,
        "--output", candidate, environment=environment)
    bundle = yaml.safe_load((candidate / "bundle/evidence.yaml").read_text())
    assert list(bundle["sources"]) == ["registry-status"], "questions must reuse one source"
    assert list(bundle["sourceConnections"]) == ["registry"]
    source = bundle["sources"]["registry-status"]
    owner = bundle["sourceConnections"]["registry"]
    assert source["connection"] == "registry"
    assert source["baseUrl"] == owner["baseUrl"]
    assert source["authentication"] == owner["authentication"]
    assert source["request"]["concurrencyLimit"] == owner["concurrencyLimit"]
    assert len(bundle["requirements"]) == 2
    assert all(requirement["acquisition"]["source"] == "registry-status"
               for requirement in bundle["requirements"])
    assert source["behaviorRevision"] == manifest["provenance"]["behaviorRevision"]
    fact_schema = yaml.safe_load((candidate / "bundle" / source["factSchema"]).read_text())
    assert list(fact_schema["properties"]) == ["status"], "identity must not become a fact"
    report = json.loads(run(binaries["evidence"], "bundle-check", "--bundle",
                            candidate / "bundle", "--json", environment=environment))
    assert len(report["requirements"]) == 2
    # Full package provenance can move without changing the consumed lookup.
    model_path = registry / "registry.yaml"
    model = yaml.safe_load(model_path.read_text())
    model["entities"][0]["fields"].append({
        "id": "operator-note", "type": "string", "maxLength": 32,
        "classification": "internal",
    })
    model_path.write_text(yaml.safe_dump(model, sort_keys=False))
    unrelated_export = workspace / "unrelated-export"
    run(binaries["bregctl"], *export_arguments, "--output", unrelated_export,
        environment=environment)
    unrelated_manifest = json.loads((unrelated_export / "source-export.json").read_text())
    assert unrelated_manifest["provenance"]["packageRevision"] != manifest["provenance"]["packageRevision"]
    assert unrelated_manifest["provenance"]["behaviorRevision"] == source["behaviorRevision"]
    unrelated = json.loads(run(
        binaries["evidencectl"], "source", "diff", unrelated_export,
        "--project", project, "--target", target, environment=environment,
    ))
    assert unrelated["provenanceChanged"] == ["registry-status"]
    assert not unrelated["affectedQuestions"]
    assert len(unrelated["questionRevisions"]) == 2
    assert all(item["change"] == "unchanged" for item in unrelated["questionRevisions"])
    # A consumed identity bound changes both questions that share this source.
    model["entities"][0]["fields"][0]["maxLength"] = 63
    model_path.write_text(yaml.safe_dump(model, sort_keys=False))
    changed_export = workspace / "changed-export"
    run(binaries["bregctl"], *export_arguments, "--output", changed_export,
        environment=environment)
    changed = json.loads(run(
        binaries["evidencectl"], "source", "diff", changed_export,
        "--project", project, "--target", target, environment=environment,
    ))
    assert len(changed["questionRevisions"]) == 2
    assert all(item["change"] == "changed" for item in changed["questionRevisions"])
    updated = json.loads(run(
        binaries["evidencectl"], "source", "update", changed_export,
        "--project", project, "--target", target, environment=environment,
    ))
    assert not updated["conflicts"]
    assert all(item["change"] == "changed" for item in updated["questionRevisions"])
    return {
        "exportArtifacts": len(manifest["artifacts"]),
        "fixtureCases": sum(item["evaluated_cases"] for item in fixtures["fixtures"]),
        "behaviorRevision": source["behaviorRevision"],
        "bundleRevision": report["bundleRevision"],
        "questions": len(report["requirements"]),
        "provenanceOnlyRevisions": "unchanged",
        "consumedChangeRevisions": "both changed",
        "nativeSourceUpdate": "passed",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["bregctl", "evidencectl", "evidence"]:
        parser.add_argument(f"--{name}", type=Path, default=shutil.which(name))
    parser.add_argument("--work-dir", type=Path, help="new private directory to retain test outputs")
    args = parser.parse_args()
    binaries = {}
    for name in ["bregctl", "evidencectl", "evidence"]:
        path = getattr(args, name)
        if path is None or not path.is_file():
            parser.error(f"provide --{name} with a matching native executable")
        binaries[name] = path.resolve()
    if args.work_dir is not None:
        workspace = args.work_dir.resolve()
        workspace.mkdir(mode=0o700)
        report = verify(workspace, binaries)
    else:
        with tempfile.TemporaryDirectory(prefix="breg-evidence-composition-") as directory:
            workspace = Path(directory).resolve()
            try:
                report = verify(workspace, binaries)
            finally:
                # The native build deliberately seals its candidate. Only this
                # newly created disposable test tree is made removable.
                for path in workspace.rglob("*"):
                    if path.is_dir() and not path.is_symlink():
                        path.chmod(0o700)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
