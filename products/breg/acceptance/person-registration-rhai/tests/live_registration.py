#!/usr/bin/env python3
"""Exercise an externally signed candidate through the ordinary BREG CLI and HTTP API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import shutil
import subprocess
import time
import urllib.error
import urllib.request

import yaml


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project", "report", "receipt", "runtime", "credentials", "bregctl", "breg", "signer", "secrets", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    output = args.output
    output.mkdir(mode=0o700)
    runtime = yaml.safe_load(args.runtime.read_text(encoding="utf-8"))
    test_report = json.loads(args.report.read_text(encoding="utf-8"))

    def cli(label: str, *command: str) -> dict:
        result = subprocess.run([str(args.bregctl), "--format", "json", *command], capture_output=True, text=True, check=False)
        (output / f"{label}.json").write_text(result.stdout, encoding="utf-8")
        if result.returncode:
            raise SystemExit(f"person registration lifecycle failed at {label}; no response values printed")
        return json.loads(result.stdout)

    invalid_project = output / "invalid-pattern-project"
    shutil.copytree(args.project, invalid_project)
    invalid_config = yaml.safe_load((invalid_project / "registry.yaml").read_text(encoding="utf-8"))
    for entity in invalid_config["entities"]:
        if entity["id"] == "person":
            for field in entity["fields"]:
                if field["id"] == "identifier":
                    field["pattern"] = "["
    (invalid_project / "registry.yaml").write_text(yaml.safe_dump(invalid_config, sort_keys=False), encoding="utf-8")
    invalid = subprocess.run([
        str(args.bregctl), "--format", "json", "test", str(invalid_project),
        "--runtime-config", str(args.runtime), "--credentials", str(args.credentials),
        "--database-id", runtime["identity"]["databaseId"],
        "--signature-threshold", "1", "--signature-key-id", "change-request-example-package-key",
        "--output", str(output / "invalid-pattern-receipt.json"),
    ], capture_output=True, text=True, check=False)
    (output / "invalid-pattern-report.json").write_text(invalid.stdout, encoding="utf-8")
    diagnostics = json.loads(invalid.stdout).get("diagnostics", [])
    if invalid.returncode == 0 or not any(
        item.get("code") == "field.pattern.syntax_invalid"
        and item.get("path") == "entities[person].fields[identifier].pattern"
        for item in diagnostics
    ):
        raise SystemExit("invalid native pattern did not produce its field-addressed schema-test diagnostic")

    package_output = output / "candidate"
    package_args = [
        "package", str(args.project),
        "--database-id", runtime["identity"]["databaseId"],
        "--schema-fingerprint", test_report["schemaFingerprint"],
        "--test-receipt", str(args.receipt),
        "--signature-threshold", "1",
        "--signature-key-id", "change-request-example-package-key",
        "--output", str(package_output),
    ]
    pending = cli("package-awaiting", *package_args)
    if pending.get("state") != "awaiting_signatures":
        raise SystemExit("candidate did not stop at the external signature boundary")
    signature = subprocess.run([
        "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(args.signer),
        "-in", str(package_output / "signing-input.json"),
    ], capture_output=True, check=True).stdout
    signatures = output / "signatures.json"
    signatures.write_text(json.dumps({"signatures": [{"keyId": "change-request-example-package-key", "signatureHex": signature.hex()}]}), encoding="utf-8")
    published = cli("package-signed", *package_args, "--signatures", str(signatures))
    runtime["package"].update(root=str(package_output / "package"), activeRevision=published["packageRevision"], activeSequence=1)
    # A transient loopback listener serves only this synthetic acceptance journey.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    runtime["listener"]["bind"] = f"127.0.0.1:{port}"
    active_runtime = output / "runtime.yaml"
    active_runtime.write_text(yaml.safe_dump(runtime, sort_keys=False), encoding="utf-8")
    cli("apply", "apply", "--runtime-config", str(active_runtime), "--package", str(package_output / "package"), "--initial")
    cli("verify", "verify", "--runtime-config", str(active_runtime))
    base = f"http://127.0.0.1:{port}"
    tokens = {role: (args.secrets / f"person-{role}-token").read_text(encoding="utf-8").strip() for role in ("registrar", "reader")}

    def request(path: str, role: str, body: dict | None = None, key: str | None = None) -> tuple[int, dict]:
        headers = {"Authorization": f"Bearer {tokens[role]}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if key:
            headers["Idempotency-Key"] = key
        call = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(call, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    with (output / "server.log").open("wb") as log:
        server = subprocess.Popen([str(args.breg), "--config", str(active_runtime)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while True:
                if server.poll() is not None:
                    raise SystemExit("person registration server stopped before readiness")
                try:
                    with urllib.request.urlopen(base + "/ready", timeout=1) as ready:
                        if ready.status == 200:
                            break
                except (urllib.error.URLError, TimeoutError):
                    pass
                if time.monotonic() >= deadline:
                    raise SystemExit("person registration server readiness deadline exceeded")
                time.sleep(0.1)
            status, metadata = request("/v1/registry?accessProfile=person-reader", "reader")
            fields = [field for operation in metadata.get("operations", [])
                      if operation.get("sourceEntity") == "person"
                      for field in operation.get("fields", []) if field.get("id") == "identifier"]
            native_rule = {"kind": "postgresql-are", "pattern": "^[0-9]{13}$"}
            if status != 200 or not fields or any(field.get("storageValidation") != native_rule or "pattern" in field["schema"] for field in fields):
                raise SystemExit("identifier metadata did not separate native storage validation from its JSON schema")
            body = json.loads((args.project / "examples/register-person.http.json").read_text(encoding="utf-8"))
            status, receipt = request("/v1/actions/register-person", "registrar", body, "person-live-001")
            if status != 200:
                raise SystemExit("live person registration did not succeed")
            person = receipt["results"]["person"]
            status, record = request(f'/v1/records/people/{person["recordId"]}?accessProfile=person-reader', "reader")
            if status != 200 or record["data"]["domainData"] != {"identifier": "0123456789012", "displayName": "Mina Example"}:
                raise SystemExit("authorized GET did not match the exact synthetic stored fields")
            for label, inputs, display_name in (
                ("omitted-family", {"identifier": "0123456789016", "givenName": "  Mina  "}, "Mina"),
                ("null-family", {"identifier": "0123456789017", "givenName": "  Mina  ", "familyName": None}, "Mina"),
                ("omitted-given", {"identifier": "0123456789018", "familyName": " Example "}, "Example"),
                ("null-given", {"identifier": "0123456789019", "givenName": None, "familyName": " Example "}, "Example"),
            ):
                status, optional_receipt = request("/v1/actions/register-person", "registrar", {"input": inputs}, f"person-live-{label}")
                if status != 200:
                    raise SystemExit(f"live optional name case failed: {label}")
                optional_person = optional_receipt["results"]["person"]
                status, optional_record = request(f'/v1/records/people/{optional_person["recordId"]}?accessProfile=person-reader', "reader")
                if status != 200 or optional_record["data"]["domainData"] != {"identifier": inputs["identifier"], "displayName": display_name}:
                    raise SystemExit(f"live optional name was not stored as expected: {label}")
            status, denied = request(
                "/v1/records/people?accessProfile=person-registrar", "registrar",
                {"data": {"identifier": "0123456789014", "displayName": "Synthetic direct create"}},
                "person-live-no-crud",
            )
            if status != 404 or denied.get("code") != "resource.not_found":
                raise SystemExit("the action-only registrar unexpectedly obtained ordinary create authority")
            status, replay = request("/v1/actions/register-person", "registrar", body, "person-live-001")
            if status != 200 or replay != receipt:
                raise SystemExit("live receipt replay changed its response")
            for label, names in (
                ("blank", {"givenName": "  ", "familyName": " "}),
                ("omitted", {}),
                ("null", {"givenName": None, "familyName": None}),
            ):
                blank = {"input": {"identifier": "0123456789013", **names}}
                status, refusal = request("/v1/actions/register-person", "registrar", blank, f"person-live-{label}")
                if status != 422 or refusal.get("code") != "action.refused" or refusal.get("refusalCode") != "blank-name" or refusal.get("fieldPath") != "/input/givenName" or refusal.get("detail") != "At least one name part is required.":
                    raise SystemExit(f"live blank-name refusal did not match the public contract: {label}")
            corrected = {"input": {"identifier": "0123456789013", "givenName": "Mina"}}
            status, recovered = request("/v1/actions/register-person", "registrar", corrected, "person-live-blank")
            if status != 200 or "person" not in recovered.get("results", {}):
                raise SystemExit("corrected input could not recover from the declared business refusal")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
    print("person registration invalid-pattern schema test, signed-package apply, verify, metadata, HTTP calculation, optional inputs, GET, replay and refusal recovery passed")


if __name__ == "__main__":
    main()
