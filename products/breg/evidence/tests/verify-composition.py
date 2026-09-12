#!/usr/bin/env python3
"""Maintainer-only native proof of the native BReg to Evidence composition.

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


def verify_default_init(workspace: Path, binaries: dict[str, Path]) -> dict[str, object]:
    """The unmodified init model composes with its one-selector teaching starter."""
    workspace.mkdir()
    environment = dict(os.environ)
    environment.pop("REGISTRY_EVIDENCE_RUNTIME", None)
    environment["PATH"] = os.pathsep.join(
        [str(binaries["evidence"].parent), environment.get("PATH", "")]
    )
    registry = workspace / "registry"
    project = workspace / "evidence"
    candidate = workspace / "candidate"
    target = project / "targets/configured"
    exported = workspace / "export"
    run(binaries["bregctl"], "init", registry, environment=environment)
    clients = yaml.safe_load((registry / "dev-clients.yaml").read_text())["clients"]
    source = next(client for client in clients if client["id"] == "source")
    assert source["accessProfiles"] == ["evidence-source"]
    assert source["scopes"] == ["registry:evidence:lookup"]
    assert source["claims"]["registry_purpose"] == "evidence-source-read"
    assert "clientIdFile" not in source and "assertionKeyFile" not in source
    assert len({client["claims"]["registry_principal"] for client in clients}) == len(clients)
    run(binaries["evidencectl"], "new", project, "--starter", INPUTS / "default-starter",
        "--profile", "local", environment=environment)
    settings = yaml.safe_load((project / "targets/local/settings.yaml").read_text())
    settings["runtime"]["bundleDirectory"] = str(candidate / "bundle")
    settings["runtime"]["secretProviders"]["file"]["root"] = str(project / "secrets")
    settings["runtime"]["auditStorage"]["path"] = str(project / "audit/evidence.jsonl")
    settings_path = workspace / "resolved-settings.json"
    settings_path.write_text(json.dumps(settings))
    run(binaries["evidencectl"], "target", "new", target, "--settings", settings_path,
        "--signing-public-key", project / "secrets/signing-p256-public.jwk.json",
        environment=environment)
    run(binaries["bregctl"], "generate", "evidence-source", registry,
        "--access-profile", "evidence-source", "--entity", "record",
        "--selector", "by-code", "--fields", "status", "--source-id", "registry-status",
        "--connection", "registry", "--output", exported, environment=environment)
    run(binaries["evidencectl"], "source", "import", exported, "--project", project,
        "--target", target, environment=environment)
    fixtures = json.loads(run(binaries["evidencectl"], "fixtures", "run",
        "--project", project, "--target", target, "--json", environment=environment))
    assert len(fixtures["fixtures"]) == 1
    assert fixtures["fixtures"][0]["passed"]
    assert fixtures["fixtures"][0]["evaluated_cases"] == 11
    run(binaries["evidencectl"], "build", "--project", project, "--target", target,
        "--output", candidate, environment=environment)
    return {"questions": 1, "fixtureCases": 11, "defaultSourceClient": "dedicated"}


def verify_source_add_review(workspace: Path, binaries: dict[str, Path]) -> dict[str, object]:
    """source add reviews by default and refuses before it changes either project.

    The public preparation it drives needs the retained session only the live
    proof starts, so this offline path proves the command surface, the matching
    tooling requirement, and that a refused connection leaves nothing behind.
    """
    workspace.mkdir()
    environment = dict(os.environ)
    environment.pop("REGISTRY_EVIDENCE_RUNTIME", None)
    environment["PATH"] = os.pathsep.join(
        [str(binaries["bregctl"].parent), environment.get("PATH", "")]
    )
    registry = workspace / "registry"
    project = workspace / "evidence"
    run(binaries["bregctl"], "init", registry, environment=environment)

    def refuse(*args: object) -> str:
        result = subprocess.run(
            [str(binaries["evidencectl"]), *(str(arg) for arg in args)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode, f"evidencectl {args} must refuse:\n{result.stdout[-4096:]}"
        return result.stderr[-8192:]

    add_arguments = ("source", "add", registry, "--project", project, "--entity", "record",
                     "--selector-field", "code", "--fields", "status", "--all-records")
    version = run(binaries["bregctl"], "--version", environment=environment).strip()
    help_text = run(binaries["evidencectl"], "source", "add", "--help", environment=environment)
    assert "bregctl" in help_text and "PATH" in help_text and "--apply" in help_text
    # The withdrawn review flag must not survive as an accepted argument.
    assert "evidencectl.usage" in refuse(*add_arguments, "--dry-run")
    mismatched = refuse(*add_arguments, "--bregctl-bin", binaries["evidence"])
    assert version in mismatched and "BREGCTL_BIN" in mismatched, mismatched
    # A review and an apply both stop at the one public preparation this
    # command drives, naming the operation an adopter can inspect by hand.
    for consent in [(), ("--apply",)]:
        refused = refuse(*add_arguments, *consent)
        assert "dev prepare-source" in refused, refused
        assert not project.exists(), "a refused connection creates no Evidence project"
        assert not (registry / ".breg").exists(), "a refused connection starts no session"
    return {
        "reviewFlag": "withdrawn",
        "bregctlRequirement": version,
        "publicPreparation": "refused without a retained session",
    }


def verify_live(workspace: Path, binaries: dict[str, Path], *, late: bool = False) -> dict[str, object]:
    """Opt-in retained-record proof; cleans up only the services it creates."""
    import socket
    import urllib.error
    import urllib.request

    workspace.mkdir(mode=0o700)
    environment = dict(os.environ)
    environment.pop("REGISTRY_EVIDENCE_RUNTIME", None)
    environment["PATH"] = os.pathsep.join(
        [str(binaries["breg"].parent), str(binaries["evidence"].parent),
         environment.get("PATH", "")]
    )
    registry, project = workspace / "registry", workspace / "evidence"
    candidate, target = workspace / "candidate", project / "targets/configured"
    # Reserve distinct available numeric-loopback ports, releasing just before start.
    reservations = [socket.socket() for _ in range(5)]
    for reservation in reservations:
        reservation.bind(("127.0.0.1", 0))
    ports = [reservation.getsockname()[1] for reservation in reservations]
    for reservation in reservations:
        reservation.close()

    def command(name: str, *args: object, cwd: Path | None = None) -> str:
        result = subprocess.run([str(binaries[name]), *map(str, args)], cwd=cwd,
                                env=environment, capture_output=True, text=True,
                                timeout=600, check=False)
        if result.returncode:
            # Native diagnostics are already secret-free. Never include token stdout.
            details = result.stderr
            if not details:
                try:
                    details = json.dumps(json.loads(result.stdout).get("diagnostics", []))
                except (ValueError, AttributeError):
                    details = "native command returned no structured diagnostic"
            raise RuntimeError(f"{name} {args[0]} failed: {details[-4096:]}")
        return result.stdout

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(method: str, url: str, token: str, body: object = None,
                headers: dict[str, str] | None = None) -> tuple[int, object, object]:
        sent_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        sent_headers.update(headers or {})
        sent = urllib.request.Request(url, method=method, headers=sent_headers,
                                      data=None if body is None else json.dumps(body).encode())
        try:
            response = opener.open(sent, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read()), response.headers

    def token(session: dict[str, object], client_name: str) -> str:
        report = json.loads(command("bregctl", "--format", "json", "dev", "token",
                                    client_name, registry))
        header = Path(report["headerFile"]).read_text().strip()
        prefix = "Authorization: Bearer "
        assert header.startswith(prefix), "BREG dev token header is malformed"
        return header[len(prefix):]

    fact, answer = ("name", "named") if late else ("status", "active")
    value = "Synthetic Works" if late else "active"
    source_id = "registry-name" if late else "registry-status"
    source_client = "registry-name" if late else "source"
    source_profile = "registry-name" if late else "evidence-source"
    question = "record-named" if late else "record-active"
    selector_profile = "breg-8-registry-6-record-7-by-code"
    if late:
        target = project / "targets/local"
        command("bregctl", "init", registry, "--from", "publicschema", "--selection",
                INPUTS / "organization-selection.yaml")
        authored = yaml.safe_load((registry / "registry.yaml").read_text())
        assert all(profile["id"] != "evidence-source" for profile in authored["accessProfiles"])
        assert all(not entity.get("selectorProfiles") for entity in authored["entities"])
        # Private test-only field, prepared before first start to prove disclosure denial.
        entity = next(entity for entity in authored["entities"] if entity["id"] == "record")
        entity["fields"].append({"id": "operator-note", "type": "string", "maxLength": 64,
                                 "classification": "internal"})
        operator_profile = next(profile for profile in authored["accessProfiles"] if profile["id"] == "operator")
        permission = next(
            permission
            for permission in operator_profile["permissions"]
            if permission["entity"] == "record"
        )
        for field_list in ["readableFields", "writableFields"]:
            permission[field_list].append("operator-note")
        (registry / "registry.yaml").write_text(yaml.safe_dump(authored, sort_keys=False))
    else:
        command("bregctl", "init", registry)
    breg_started = evidence_started = False
    try:
        breg_started = True  # Also clean up a partially started owned session.
        session = json.loads(command("bregctl", "dev", registry, "--breg-port", ports[0],
                                     "--issuer-port", ports[1], "--database-port", ports[2],
                                     "--format", "json"))
        assert not project.exists(), "record must precede Evidence creation"
        operator = token(session, "operator")
        route = f'{session["bregUrl"]}/v1/records/records'
        code = "SYNTHETIC-ORGANIZATION" if late else "SYNTHETIC-ACTIVE"
        domain = ({"code": code, "name": "Earlier name", "operatorNote": "PRIVATE-SYNTHETIC-CANARY"} if late else
                  {"code": code, "label": "Synthetic record", "status": "retired"})
        status, created, _ = request("POST", route + "?accessProfile=operator", operator,
            {"data": domain},
            {"Idempotency-Key": "composition-create-1"})
        assert status == 201, f"create returned {status}"
        record_id = created["data"]["recordIdentifier"]
        record_url = f"{route}/{record_id}?accessProfile=operator"
        status, before, headers = request("GET", record_url, operator)
        assert status == 200
        status, edited, _ = request("PATCH", record_url, operator,
            [{"op": "replace", "path": f"/data/{fact}", "value": value}],
            {"Idempotency-Key": "composition-edit-1", "If-Match": headers["ETag"],
             "Content-Type": "application/json-patch+json"})
        assert status == 200, f"edit returned {status}"
        status, retained, _ = request("GET", record_url, operator)
        assert status == 200 and retained["data"]["domainData"][fact] == value
        assert retained["data"]["recordIdentifier"] == before["data"]["recordIdentifier"]
        assert retained["data"]["revisionIdentifier"] != before["data"]["revisionIdentifier"]
        state_root = registry / ".breg/dev"
        prior_keys = {str(path.relative_to(state_root)): path.read_bytes()
                      for path in (state_root / "credentials").rglob("*") if path.is_file()}
        prior_registrations = {str(path.relative_to(state_root)): path.read_bytes()
                               for path in (state_root / "issuer/registry-schema/agents").glob("*")
                               if path.is_file()}
        prior_clients = json.loads((state_root / "clients.json").read_text())

        def history() -> bytes:
            state = json.loads((state_root / "state.json").read_text())
            result = subprocess.run(["docker", "exec", "-i", state["containerId"], "psql",
                "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "breg_dev"],
                input="SELECT row_to_json(r)::text FROM registry_internal.registry_revisions r "
                      "ORDER BY entity_id, record_id, record_revision;", text=True,
                capture_output=True, timeout=30, check=False)
            assert result.returncode == 0, "owned retained history query must succeed"
            return result.stdout.encode()

        if late:
            status, _, _ = request("POST", route + "?accessProfile=operator", operator,
                {"data": {**domain, "code": "SYNTHETIC-OUTSIDE", "name": "Other synthetic organization"}},
                {"Idempotency-Key": "composition-outside-1"})
            assert status == 201, "out-of-scope control record must exist"
        prior_history = history() if late else None
        if late:
            assert retained["data"]["domainData"]["operatorNote"] == "PRIVATE-SYNTHETIC-CANARY"
        if late:
            assert {client["id"] for client in session["clients"]} == {"operator", "reader"}
            assert len(prior_history.splitlines()) >= 2, "create and edit must leave revisions"
            command("bregctl", "dev", "stop", registry)
            # Arbitrary authored edits must remain outside the bounded source transition.
            model_path = registry / "registry.yaml"
            original_model = model_path.read_bytes()
            for change in ["source", "schema"]:
                model = yaml.safe_load(original_model)
                if change == "source":
                    model["registry"]["canonicalBaseIri"] += "/unexpected"
                else:
                    entity = next(entity for entity in model["entities"] if entity["id"] == "record")
                    next(field for field in entity["fields"] if field["id"] == "name")["maxLength"] = 254
                model_path.write_text(yaml.safe_dump(model, sort_keys=False))
                try:
                    refused = subprocess.run([str(binaries["bregctl"]), "dev", "start", str(registry)],
                                             env=environment, capture_output=True, text=True, timeout=60)
                    assert refused.returncode != 0, f"unexpected {change} edit must not start"
                    assert "changed" in refused.stderr or "differ" in refused.stderr, (
                        "refusal must identify changed retained inputs"
                    )
                finally:
                    model_path.write_bytes(original_model)
            row_value_file = workspace / "row-value.json"
            row_value_file.write_text(json.dumps(value))
            row_value_file.chmod(0o600)
            add_arguments = ("source", "add", registry, "--project", project, "--entity", "record",
                             "--selector-field", "code", "--fields", fact,
                             "--row-field", "name", "--row-value-file", row_value_file,
                             "--source-id", source_id, "--selector-profile", "by-code")
            state_before_preview = {path: path.read_bytes() for path in
                [state_root / "state.json", registry / "registry.yaml", registry / "dev-clients.yaml"]}
            preview = json.loads(command("evidencectl", *add_arguments[:-2], "--format", "json"))
            assert preview["status"] == "preview"
            assert all("--apply" in step for step in preview["next"])
            assert all(preview[key] == source_id for key in ["client", "accessProfile", "selectorProfile"])
            assert not project.exists()
            assert all(path.read_bytes() == content for path, content in state_before_preview.items())
            assert {str(path.relative_to(state_root)): path.read_bytes()
                    for path in (state_root / "credentials").rglob("*") if path.is_file()} == prior_keys
            command("evidencectl", *add_arguments, "--apply")
            retry_paths = [registry / "registry.yaml", registry / "dev-clients.yaml",
                           state_root / "clients.json", state_root / "state.json",
                           state_root / "credentials" / source_client / "assertion-key.jwk"]
            before_retry = {path: path.read_bytes() for path in retry_paths}
            # An identical attachment is retryable.
            command("evidencectl", *add_arguments, "--apply")
            assert all(path.read_bytes() == content for path, content in before_retry.items()), (
                "identical source attachment must not evolve or rotate the retained session"
            )
            for relative, content in {**prior_keys, **prior_registrations}.items():
                assert (state_root / relative).read_bytes() == content
            current_clients = json.loads((state_root / "clients.json").read_text())
            assert current_clients["clients"][:-1] == prior_clients["clients"]
            source_root = state_root / "credentials" / source_client
            pair = [(source_root / name).read_bytes() for name in ["client-id", "assertion-key.jwk"]]
            assert pair[1] not in prior_keys.values(), "late source key must be distinct"
            private_scalar = json.loads(pair[1])["d"].encode()
            assert private_scalar not in {
                json.loads(content)["d"].encode() for relative, content in prior_keys.items()
                if relative.endswith("assertion-key.jwk")
            }, "late source must not reuse an existing private scalar"
            for directory in ["adapters", "schemas", "selectors", "sources"]:
                for artifact in (project / directory).rglob("*"):
                    if artifact.is_file():
                        content = artifact.read_bytes()
                        assert pair[1].strip() not in content and private_scalar not in content, (
                            "imported source contract must contain no source private key"
                        )
            source = {"clientIdFile": str(source_root / "client-id"),
                      "assertionKeyFile": str(source_root / "assertion-key.jwk")}
            assert pair == [(project / "secrets" / name).read_bytes()
                            for name in ["registry-client-id", "registry-client-key"]]
            assert not list((project / "questions").glob("*.yaml")), "source add precedes question authoring"
            for directory in ["questions", "derivations", "fixtures"]:
                shutil.copytree(INPUTS / "named-starter" / directory, project / directory, dirs_exist_ok=True)
            fixtures = json.loads(command("evidencectl", "fixtures", "run", "--local", "--project", project,
                                          "--target", target, "--json"))
            assert len(fixtures["fixtures"]) == 1 and fixtures["fixtures"][0]["passed"]
            assert fixtures["fixtures"][0]["evaluated_cases"] == 11
        else:
            source = next(item for item in session["clients"] if item["id"] == "source")
            pair = [Path(source[key]).read_bytes() for key in ["clientIdFile", "assertionKeyFile"]]
            keys = [Path(item["assertionKeyFile"]).read_bytes() for item in session["clients"]]
            assert len(set(keys)) == len(keys), "each client needs its own key"
            state_root = registry / ".breg/dev"
            registrations = (state_root / "clients.json").read_bytes()
            command("bregctl", "dev", "stop", registry)
            state_before_preview = {path: path.read_bytes() for path in
                [state_root / "state.json", registry / "registry.yaml", registry / "dev-clients.yaml"]}
            preview = json.loads(command("evidencectl", "source", "add", registry, "--project", project,
                "--entity", "record", "--selector-field", "code", "--fields", "status",
                "--all-records", "--format", "json"))
            assert preview["status"] == "preview"
            assert all("--apply" in step for step in preview["next"])
            assert all(preview[key] == "registry-record"
                       for key in ["sourceId", "client", "accessProfile", "selectorProfile"])
            assert not project.exists()
            assert all(path.read_bytes() == content for path, content in state_before_preview.items())
            assert {str(path.relative_to(state_root)): path.read_bytes()
                    for path in (state_root / "credentials").rglob("*") if path.is_file()} == prior_keys
            command("evidencectl", "new", project, "--starter", INPUTS / "default-starter", "--profile", "local")
            exported = workspace / "export"
            command("bregctl", "generate", "evidence-source", registry,
                    "--access-profile", "evidence-source", "--entity", "record", "--selector", "by-code",
                    "--fields", "status", "--source-id", "registry-status", "--connection", "registry",
                    "--output", exported)
            private_scalar = json.loads(pair[1])["d"].encode()
            for artifact in exported.rglob("*"):
                if artifact.is_file():
                    content = artifact.read_bytes()
                    assert all(secret.strip() not in content for secret in [pair[1], private_scalar]), (
                        "portable export must exclude actual retained credentials"
                    )
            command("bregctl", "dev", "export-client", registry, "--client", "source",
                    "--client-id-file", project / "secrets/registry-client-id",
                    "--assertion-key-file", project / "secrets/registry-client-key")
            assert pair == [(project / "secrets" / name).read_bytes()
                            for name in ["registry-client-id", "registry-client-key"]]
            assert registrations == (state_root / "clients.json").read_bytes()
            settings = yaml.safe_load((project / "targets/local/settings.yaml").read_text())
            settings["governance"]["sourceConnections"]["registry"]["baseUrl"] = session["bregUrl"]
            settings["governance"]["sourceConnections"]["registry"]["authentication"]["tokenEndpoint"] = session["tokenEndpoint"]
            settings["runtime"]["bundleDirectory"] = str(candidate / "bundle")
            settings["runtime"]["secretProviders"]["file"]["root"] = str(project / "secrets")
            settings["runtime"]["auditStorage"]["path"] = str(project / "audit/evidence.jsonl")
            settings_path = workspace / "settings.json"
            settings_path.write_text(json.dumps(settings))
            command("evidencectl", "target", "new", target, "--settings", settings_path,
                    "--signing-public-key", project / "secrets/signing-p256-public.jwk.json")
            command("evidencectl", "source", "import", exported, "--project", project, "--target", target)
            command("evidencectl", "fixtures", "run", "--project", project, "--target", target)
            command("evidencectl", "build", "--project", project, "--target", target, "--output", candidate)
        restarted = json.loads(command("bregctl", "dev", "start", registry, "--format", "json"))
        if late:
            assert restarted["packageRevision"] != session["packageRevision"], "source needs a successor"
            assert history() == prior_history, "policy successor must preserve all revision history"
            for relative, content in {**prior_keys, **prior_registrations}.items():
                assert (state_root / relative).read_bytes() == content
        else:
            assert restarted["packageRevision"] == session["packageRevision"]
        assert pair == [Path(source[key]).read_bytes() for key in ["clientIdFile", "assertionKeyFile"]]
        status, after, _ = request("GET", record_url, token(restarted, "operator"))
        assert status == 200 and after["data"] == retained["data"], "setup must preserve complete record"
        source_token = token(restarted, source_client)
        lookup = route + f":lookup?accessProfile={source_profile}&$select=code,{fact}"
        selector = {"selector": "by-code", "values": {"code": code}}
        status, found, _ = request("POST", lookup, source_token, selector)
        assert status == 200 and found["data"]["domainData"][fact] == value
        assert set(found["data"]["domainData"]) == {"code", fact}
        denied = {}
        if late:
            status, problem, _ = request("POST", lookup, source_token,
                {"selector": "by-code", "values": {"code": "SYNTHETIC-OUTSIDE"}})
            assert (status, problem.get("code")) == (404, "lookup.unresolved"), (
                "existing out-of-scope record must remain unresolved"
            )
            denied["outsideRowScope"] = {"status": status, "code": problem["code"]}
        for name, method, url, body in [
            ("list", "GET", route + f"?accessProfile={source_profile}", None),
            ("mutation", "POST", route + f"?accessProfile={source_profile}", {"data": {**domain, "code": "DENIED"}}),
            ("ungrantedField", "POST", lookup + (",operatorNote" if late else ",label"), selector),
        ]:
            status, problem, _ = request(method, url, source_token, body,
                                   {"Idempotency-Key": "composition-denied"})
            assert (status, problem.get("code")) == (404, "resource.not_found"), (
                f"{name} must return the concealed authority refusal, got {status}"
            )
            denied[name] = {"status": status, "code": problem["code"]}
        evidence_started = True
        command("evidencectl", "dev", "--target", target, "--detach", "--evidence-port", ports[3],
                "--issuer-port", ports[4], cwd=project)
        command("evidencectl", "request", "prepare", question, "--purpose", "record-verification",
                "--subject", f"subject@{selector_profile}:code={code}",
                "--name", "by-code", cwd=project)
        prepared = project / ".evidence/requests/by-code"
        response_path, verified_path = project / "response.json", project / "verified.json"
        result = subprocess.run(["curl", "--silent", "--show-error", "--fail-with-body",
            "--config", str(prepared / "authorization.curl"), "--request", "POST",
            "--url", f"http://127.0.0.1:{ports[3]}/v1/evidence", "--header", "Content-Type: application/json",
            "--header", "Accept: application/jose+json", "--data-binary", "@" + str(prepared / "request.json"),
            "--output", str(response_path)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, f"Evidence request failed: {result.stderr}"
        command("evidencectl", "verify", response_path, "--context", prepared / "verification.json",
                "--output", verified_path, cwd=project)
        verified = json.loads(verified_path.read_text())
        assert all(hidden not in json.dumps(verified) for hidden in
                   [code, "Synthetic record", "Synthetic Works", "PRIVATE-SYNTHETIC-CANARY"])
        assert verified["supportedValues"] == [{
            "providesValueFor": f"urn:example:concept:{question}:{answer}", "value": True,
        }], "verified answer must assert active"
        report = {"retainedRecord": "id, revision and content unchanged",
                  "sourcePairRetained": True, "distinctClientKeys": True, "sourceLookup": "passed",
                  "sourceDenied": denied, "signedAnswer": f"verified {answer}=true"}
        if late:
            report.update({"policySuccessor": True, "historyRetained": True, "fixtureCases": 11,
                           "priorClientsAndIssuerPreserved": True, "identicalRetry": "passed",
                           "defaultNamespaces": "source ID; preview unchanged",
                           "unexpectedSourceAndSchemaEdits": "refused"})
        else:
            report["packageRetained"] = True
            report["plainInitDefaultSourcePreview"] = "collision-free; unchanged"
        return report
    finally:
        try:
            if evidence_started:
                command("evidencectl", "dev", "stop", cwd=project)
        finally:
            if breg_started:
                # Reclamation happens only after proof, never during Evidence setup.
                command("bregctl", "dev", "stop", registry, "--remove")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["bregctl", "evidencectl", "evidence"]:
        parser.add_argument(f"--{name}", type=Path, default=shutil.which(name))
    parser.add_argument("--work-dir", type=Path, help="new private directory to retain test outputs")
    parser.add_argument("--live", action="store_true", help="also run retained-record proof with Docker, breg and the stock issuer")
    for name in ["breg"]:
        parser.add_argument(f"--{name}", type=Path, default=shutil.which(name))
    args = parser.parse_args()
    binaries = {}
    for name in ["bregctl", "evidencectl", "evidence"] + (["breg"] if args.live else []):
        path = getattr(args, name)
        if path is None or not path.is_file():
            parser.error(f"provide --{name} with a matching native executable")
        binaries[name] = path.resolve()
    if args.work_dir is not None:
        workspace = args.work_dir.resolve()
        workspace.mkdir(mode=0o700)
        report = verify(workspace, binaries)
        report["defaultInit"] = verify_default_init(workspace / "default-init", binaries)
        report["sourceAddReview"] = verify_source_add_review(workspace / "source-add", binaries)
        if args.live:
            report["live"] = verify_live(workspace / "live", binaries)
            report["lateAdoption"] = verify_live(workspace / "late-adoption", binaries, late=True)
    else:
        with tempfile.TemporaryDirectory(prefix="breg-evidence-composition-") as directory:
            workspace = Path(directory).resolve()
            try:
                report = verify(workspace, binaries)
                report["defaultInit"] = verify_default_init(workspace / "default-init", binaries)
                report["sourceAddReview"] = verify_source_add_review(workspace / "source-add", binaries)
                if args.live:
                    report["live"] = verify_live(workspace / "live", binaries)
                    report["lateAdoption"] = verify_live(workspace / "late-adoption", binaries, late=True)
            finally:
                # The native build deliberately seals its candidate. Only this
                # newly created disposable test tree is made removable.
                for path in workspace.rglob("*"):
                    if path.is_dir() and not path.is_symlink():
                        path.chmod(0o700)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
