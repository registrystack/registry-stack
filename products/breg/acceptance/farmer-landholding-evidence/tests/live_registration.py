#!/usr/bin/env python3
"""Run a real Evidence-backed schema test, external package signing and live BREG journey."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

import yaml


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("project", "test-runtime", "runtime", "credentials", "bregctl", "breg", "signer", "secrets", "output"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--requests", type=Path, help="Synthetic provider source request log for call-count assertions")
    parser.add_argument("--signature-key-id", default="change-request-example-package-key")
    args = parser.parse_args()
    output = args.output
    output.mkdir(mode=0o700)
    runtime = yaml.safe_load(args.runtime.read_text())

    def cli(label: str, *command: str) -> dict:
        result = subprocess.run([str(args.bregctl), "--format", "json", *command], capture_output=True, text=True)
        (output / f"{label}.json").write_text(result.stdout)
        if result.returncode:
            raise SystemExit(f"farmer lifecycle failed at {label}; inspect the owner-only report")
        return json.loads(result.stdout)

    cli("check", "check", str(args.project))
    receipt_path = output / "schema-test-receipt.json"
    test = cli("schema-test", "test", str(args.project), "--runtime-config", str(args.test_runtime),
               "--credentials", str(args.credentials), "--database-id", runtime["identity"]["databaseId"],
               "--signature-threshold", "1", "--signature-key-id", args.signature_key_id,
               "--output", str(receipt_path))
    if "farmer-evidence-registration" not in test.get("successfulJourneyIds", []):
        raise SystemExit("schema test did not attest the complete farmer journey")
    candidate = output / "candidate"
    package_args = ["package", str(args.project), "--database-id", runtime["identity"]["databaseId"],
                    "--schema-fingerprint", test["schemaFingerprint"], "--test-receipt", str(receipt_path),
                    "--signature-threshold", "1", "--signature-key-id", args.signature_key_id,
                    "--output", str(candidate)]
    pending = cli("package-awaiting", *package_args)
    if pending.get("state") != "awaiting_signatures":
        raise SystemExit("package did not require its external signature")
    signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(args.signer),
                                "-in", str(candidate / "signing-input.json")], capture_output=True, check=True).stdout
    signatures = output / "signatures.json"
    signatures.write_text(json.dumps({"signatures": [{"keyId": args.signature_key_id, "signatureHex": signature.hex()}]}))
    signed = cli("package-signed", *package_args, "--signatures", str(signatures))
    runtime["package"].update(root=str(candidate / "package"), activeRevision=signed["packageRevision"], activeSequence=1)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    runtime["listener"]["bind"] = f"127.0.0.1:{port}"
    active_runtime = output / "runtime.yaml"
    active_runtime.write_text(yaml.safe_dump(runtime, sort_keys=False))
    cli("apply", "apply", "--runtime-config", str(active_runtime), "--package", str(candidate / "package"), "--initial")
    cli("verify", "verify", "--runtime-config", str(active_runtime))
    base = f"http://127.0.0.1:{port}"
    tokens = {role: (args.secrets / f"landholding-{role}-token").read_text().strip() for role in ("registrar", "reader")}

    def request(path: str, role: str, body: dict | None = None, key: str | None = None) -> tuple[int, dict]:
        headers = {"Authorization": f"Bearer {tokens[role]}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if key:
            headers["Idempotency-Key"] = key
        call = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(call, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def call_count() -> int | None:
        if args.requests is None:
            return None
        return len(args.requests.read_text().splitlines()) if args.requests.exists() else 0

    with (output / "server.log").open("wb") as log:
        server = subprocess.Popen([str(args.breg), "--config", str(active_runtime)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while True:
                if server.poll() is not None:
                    raise SystemExit("farmer BREG process stopped before readiness")
                try:
                    with urllib.request.urlopen(base + "/ready", timeout=1) as ready:
                        readiness_failure = f"HTTP {ready.status}"
                        if ready.status == 200:
                            break
                except urllib.error.HTTPError as error:
                    readiness_failure = f"HTTP {error.code}"
                    error.close()
                except (urllib.error.URLError, TimeoutError):
                    readiness_failure = "connection unavailable or timed out"
                if time.monotonic() >= deadline:
                    raise SystemExit(f"farmer BREG readiness deadline exceeded ({readiness_failure})")
                time.sleep(0.1)
            inputs = {"farmerPrefix": " TH ", "farmerNumber": " 00042 ", "parcelCode": "LIVE-P-001", "includeCategory": True}
            body = {"input": inputs}
            calls_before_registration = call_count()
            action_started = time.monotonic()
            status, receipt = request("/v1/actions/register-landholding", "registrar", body, "farmer-live-001")
            action_milliseconds = round((time.monotonic() - action_started) * 1000, 3)
            (output / "action-cost.json").write_text(json.dumps({"twoCallActionMilliseconds": action_milliseconds}) + "\n")
            if status != 200:
                raise SystemExit("real Evidence-backed registration did not succeed")
            if calls_before_registration is not None and call_count() != calls_before_registration + 2:
                raise SystemExit("conditional category registration did not make exactly two source requests")
            identifier = receipt["results"]["landholding"]["recordId"]
            status, record = request(f"/v1/records/landholdings/{identifier}?accessProfile=landholding-reader", "reader")
            if status != 200 or record["data"]["domainData"] != {"farmerNumber": "TH-00042", "parcelCode": "LIVE-P-001", "farmerCategory": "smallholder"}:
                raise SystemExit("live GET did not match canonical selector and verified category")
            calls_before_replay = call_count()
            status, replay = request("/v1/actions/register-landholding", "registrar", body, "farmer-live-001")
            if status != 200 or replay != receipt or call_count() != calls_before_replay:
                raise SystemExit("receipt replay changed the committed response")
            for label, number, code in [("inactive", "00043", "farmer-inactive"), ("blank", " ", "invalid-farmer-number")]:
                calls_before_refusal = call_count()
                status, refusal = request("/v1/actions/register-landholding", "registrar", {"input": {**inputs, "farmerNumber": number, "parcelCode": f"LIVE-{label}"}}, f"farmer-live-{label}")
                if status != 422 or refusal.get("code") != "action.refused" or refusal.get("refusalCode") != code:
                    raise SystemExit(f"live {label} refusal did not match its declared contract")
                expected_calls = 1 if label == "inactive" else 0
                if calls_before_refusal is not None and call_count() != calls_before_refusal + expected_calls:
                    raise SystemExit(f"live {label} refusal made an unexpected source request")
            status, denied = request("/v1/records/landholdings?accessProfile=landholding-registrar", "registrar", {"data": {"farmerNumber": "TH-00043", "parcelCode": "BYPASS"}}, "farmer-no-crud")
            if status != 404 or denied.get("code") != "resource.not_found":
                raise SystemExit("action-only profile gained direct create authority")
            # Fresh retained evidence must survive an ordinary expiry maintenance run.
            erased = cli("retention", "evidence-retention", "erase-expired", "--runtime-config", str(active_runtime), "--before", datetime.now(timezone.utc).isoformat())
            if erased.get("erased") != 0:
                raise SystemExit("expiry maintenance removed fresh evidence")
            calls_before_replay = call_count()
            status, replay = request("/v1/actions/register-landholding", "registrar", body, "farmer-live-001")
            if status != 200 or replay != receipt or call_count() != calls_before_replay:
                raise SystemExit("maintenance changed receipt replay")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
    print("farmer real Evidence schema-test, external signing, activation, HTTP registration, GET, refusal, replay and retention passed")


if __name__ == "__main__":
    main()
