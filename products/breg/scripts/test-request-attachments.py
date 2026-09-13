#!/usr/bin/env python3
"""Prove authored request attachments through native dev, HTTP and operator retention."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "products/breg/acceptance/request-attachments"
PDF = b"%PDF-1.4\nSynthetic attachment acceptance evidence.\n%%EOF\n"
SLOT = "supporting-file"


def free_ports() -> list[int]:
    sockets = [socket.socket() for _ in range(3)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def read_runtime_yaml(path: str) -> dict:
    try:
        import yaml
    except ImportError:
        raise RuntimeError("--verification requires PyYAML") from None
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def test_request_attachment_journey() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target/debug",
                        help="Directory containing matching bregctl and breg binaries")
    parser.add_argument("--project", type=Path, default=FIXTURE)
    parser.add_argument("--verification", action="store_true",
                        help="Exercise asynchronous external verification and quarantine (requires PyYAML)")
    parser.add_argument("--keep", action="store_true", help="Keep owner-only reports after success")
    args = parser.parse_args()
    binaries = args.bin_dir.resolve()
    for name in ("bregctl", "breg"):
        require((binaries / name).is_file(), f"Build the matching {name} binary first")
    docker = shutil.which("docker")
    require(docker is not None, "Docker is required by the native development lifecycle")
    os.umask(0o077)
    temporary = Path(tempfile.mkdtemp(prefix="breg-request-attachments-")).resolve()
    project = temporary / "project"
    shutil.copytree(args.project, project, ignore=shutil.ignore_patterns(".breg"))
    environment = dict(os.environ)
    environment["PATH"] = str(binaries) + os.pathsep + environment.get("PATH", "")
    environment["SSL_CERT_FILE"] = str(project / ".breg/dev/tls/ca.pem")
    bregctl = str(binaries / "bregctl")
    started = False
    passed = False
    configured_process = None
    configured_log = None
    verifier = None
    verifier_thread = None
    verifier_release = threading.Event()
    verifier_seen = threading.Event()
    verifier_mode = {"value": "held", "errors": [], "hashes": []}

    def cli(label: str, *arguments: str) -> dict:
        result = subprocess.run([bregctl, "--format", "json", *arguments], env=environment,
                                capture_output=True, text=True, timeout=300, check=False)
        (temporary / f"{label}.json").write_text(result.stdout, encoding="utf-8")
        (temporary / f"{label}.stderr").write_text(result.stderr, encoding="utf-8")
        try:
            report = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError(f"{label} returned no JSON report") from None
        if result.returncode or report.get("ok") is not True:
            codes = ", ".join(str(d.get("code", "unknown")) for d in report.get("diagnostics", []))
            raise RuntimeError(f"{label} failed ({codes or 'private report available'})")
        return report

    try:
        cli("check", "check", str(project))
        breg_port, issuer_port, database_port = free_ports()
        # Native dev owns separate TLS PostgreSQL test/live databases, exact
        # runtime/migration roles, rehearsal receipt, signed package and activation.
        started = True
        state = cli("dev-start", "dev", str(project), "--breg-port", str(breg_port),
                    "--issuer-port", str(issuer_port), "--database-port", str(database_port),
                    "--docker-bin", str(docker))
        require(state.get("status") == "ready" and not state.get("activationPending"),
                "Native dev did not finish schema rehearsal and activation")
        runtime = str(Path(state["runtimeConfig"]).resolve())
        cli("verify", "verify", "--runtime-config", runtime)
        print("Native schema-test, package activation and verify passed.", flush=True)
        base = state["bregUrl"]
        tokens = {}
        for role in ("operator", "owner", "other-owner", "reviewer", "applier"):
            token_report = cli(f"token-{role}", "dev", "token", role, str(project))
            header = Path(token_report["headerFile"]).read_text(encoding="utf-8").strip()
            prefix = "Authorization: Bearer "
            require(header.startswith(prefix), f"{role} token header is malformed")
            tokens[role] = header[len(prefix):]

        if args.verification:
            verifier_secret = uuid.uuid4().hex
            environment["BREG_ACCEPTANCE_VERIFIER_AUTHORIZATION"] = verifier_secret

            class VerifierHandler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

                def do_POST(self):
                    content = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    digest = hashlib.sha256(content).hexdigest()
                    valid = (self.path == "/verify" and self.headers.get("Content-Type") == "application/pdf"
                             and self.headers.get("X-Content-SHA256") == digest
                             and self.headers.get("Authorization") == "Bearer " + verifier_secret)
                    if not valid:
                        verifier_mode["errors"].append("Verifier received invalid authentication or integrity context")
                    verifier_mode["hashes"].append(digest)
                    mode = verifier_mode["value"]
                    verifier_seen.set()
                    if mode == "held":
                        verifier_release.wait(15)
                    verdict = {"verdict": "approved" if mode == "approved" else "rejected"}
                    raw = json.dumps(verdict).encode()
                    try:
                        self.send_response(200 if valid and mode in ("approved", "rejected") else 503)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw)
                    except (BrokenPipeError, ConnectionResetError):
                        # Holding the verdict deliberately lets the worker time out.
                        # Close that abandoned response without logging its request.
                        self.close_connection = True

            verifier = http.server.ThreadingHTTPServer(("127.0.0.1", 0), VerifierHandler)
            verifier_thread = threading.Thread(target=verifier.serve_forever, daemon=True)
            verifier_thread.start()
            configured = read_runtime_yaml(runtime)
            configured["secretProviders"]["environment"] = {}
            configured_port = free_ports()[0]
            configured["listener"]["bind"] = f"127.0.0.1:{configured_port}"
            configured["attachmentVerification"] = {
                "kind": "http", "endpoint": f"http://127.0.0.1:{verifier.server_port}/verify",
                "authorizationRef": "secret:env/BREG_ACCEPTANCE_VERIFIER_AUTHORIZATION",
                "policyId": "acceptance-v1",
                "timeoutMilliseconds": 1000}
            runtime = str(temporary / "verified-runtime.json")
            Path(runtime).write_text(json.dumps(configured), encoding="utf-8")
            configured_log = (temporary / "verified-runtime.log").open("wb")
            configured_process = subprocess.Popen([str(binaries / "breg"), "--config", runtime],
                                                  env=environment, stdout=configured_log, stderr=subprocess.STDOUT)
            base = f"http://127.0.0.1:{configured_port}"
            deadline = time.monotonic() + 30
            while True:
                require(configured_process.poll() is None, "Configured attachment runtime stopped during startup")
                try:
                    with socket.create_connection(("127.0.0.1", configured_port), timeout=0.2):
                        break
                except OSError:
                    require(time.monotonic() < deadline, "Configured attachment runtime did not become ready")
                    time.sleep(0.1)
            cli("verify-configured", "verify", "--runtime-config", runtime)

        def request(method: str, path: str, role: str | None, body=None,
                    *, profile: str | None = None, etag: str | None = None,
                    key: str | None = None, content_type: str | None = None,
                    version: int | None = None) -> tuple[int, dict, bytes]:
            parsed_path = urllib.parse.urlsplit(path)
            require(not parsed_path.scheme and not parsed_path.netloc, "Expected a local API action path")
            query = dict(urllib.parse.parse_qsl(parsed_path.query))
            if profile or role:
                query["accessProfile"] = profile or role
            if version is not None:
                query["proposalVersion"] = str(version)
            headers = {}
            if role:
                headers["Authorization"] = "Bearer " + tokens[role]
            if etag:
                headers["If-Match"] = etag
            if key:
                headers["Idempotency-Key"] = key
            if isinstance(body, dict):
                body = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
            elif content_type:
                headers["Content-Type"] = content_type
            url = base + parsed_path.path + ("?" + urllib.parse.urlencode(query) if query else "")
            call = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                response = urllib.request.urlopen(call, timeout=20)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, {name.lower(): value for name, value in response.headers.items()}, response.read()

        def document(result, expected: int, label: str) -> tuple[dict, dict]:
            status, headers, raw = result
            if status != expected:
                try:
                    code = json.loads(raw).get("code", "unknown")
                except ValueError:
                    code = "non-JSON refusal"
                raise RuntimeError(f"{label}: expected HTTP {expected}, received {status} ({code})")
            return json.loads(raw), headers

        record, _ = document(request("POST", "/v1/records/records", "operator",
                                    {"data": {"label": "Original label"}}, key="attachment-record"),
                             201, "Create record")
        record_id = record["data"]["recordIdentifier"]
        draft, _ = document(request("POST", "/v1/records/correction-requests", "owner",
                                   {"data": {"record": record_id, "label": "Corrected label"}},
                                   key="attachment-draft"), 201, "Create incomplete draft")
        request_id = draft["data"]["recordIdentifier"]
        path = f"/v1/records/correction-requests/{request_id}"
        attachment_path = path + "/attachments/" + SLOT

        def get(role: str = "owner") -> tuple[dict, dict]:
            return document(request("GET", path, role), 200, f"Read request as {role}")

        def action(operation: str, role: str, *, key: str):
            current, _ = get(role)
            state = current["data"]["request"]
            candidates = [entry for entry in state["actions"] if entry["operation"] == operation]
            require(len(candidates) == 1, f"{operation} needs one discovered action")
            selected = candidates[0]
            body = {} if operation in ("submit_request", "cancel_request") else {
                "proposalVersion": state["proposalVersion"], "effectDigest": state["effectDigest"]}
            return request("POST", selected["href"], role, body, etag=selected["ifMatch"], key=key)

        missing = action("submit_request", "owner", key="attachment-submit-missing")
        require(missing[0] == 412, f"Missing required slot expected HTTP 412, received {missing[0]}")
        current, headers = get()
        require(current["data"]["request"]["bregState"] == "draft", "Refusal changed draft state")
        initial_etag = headers["etag"]
        require(request("GET", path, "other-owner", profile="owner")[0] == 404,
                "A different owner obtained the request")
        denied = request("PATCH", attachment_path, "other-owner", PDF, profile="owner",
                         etag=initial_etag, key="attachment-other-owner", content_type="application/pdf")
        require(denied[0] == 412, f"Different-owner upload expected HTTP 412, received {denied[0]}")
        absent_path = f"/v1/records/correction-requests/{uuid.uuid4()}/attachments/{SLOT}"
        absent = request("PATCH", absent_path, "other-owner", PDF, profile="owner",
                         etag=initial_etag, key="attachment-absent", content_type="application/pdf")
        require(absent[0] == denied[0], "Upload refusal disclosed whether the protected request exists")

        owned_state = json.loads(Path(state["stateFile"]).read_text(encoding="utf-8"))
        container_id = owned_state["containerId"]
        require(isinstance(container_id, str) and len(container_id) == 64,
                "Native dev did not identify its owned database container")

        def storage_permission(grant: bool) -> None:
            sql = ("GRANT INSERT ON registry_internal.registry_attachment_blobs TO breg_dev_runtime;"
                   if grant else "REVOKE INSERT ON registry_internal.registry_attachment_blobs FROM breg_dev_runtime;")
            result = subprocess.run([str(docker), "exec", "-i", container_id, "psql", "-X", "-q",
                                     "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "breg_dev"],
                                    input=sql.encode(), capture_output=True, timeout=20, check=False)
            require(result.returncode == 0, "Could not set disposable storage failure condition")

        print("Required-slot and protected-owner refusals passed.", flush=True)
        storage_permission(False)
        try:
            failure = request("PATCH", attachment_path, "owner", PDF, etag=initial_etag,
                              key="attachment-upload", content_type="application/pdf")
            require(failure[0] in (500, 503), "Unavailable database storage did not fail upload")
        finally:
            storage_permission(True)
        recovered, _ = get()
        require(recovered["data"]["domainData"].get(SLOT) is None,
                "Failed upload retained successful metadata")
        document(request("PATCH", attachment_path, "owner", PDF, etag=initial_etag,
                         key="attachment-upload", content_type="application/pdf"), 200, "Recover upload")
        uploaded, uploaded_headers = get()
        metadata = uploaded["data"]["domainData"][SLOT]
        require(metadata["sha256"] == hashlib.sha256(PDF).hexdigest() and metadata["byteSize"] == len(PDF),
                "Server-computed integrity metadata differs from uploaded bytes")
        require(uploaded_headers["etag"] != initial_etag, "Upload did not advance request concurrency")
        print("Database storage refusal and same-key upload recovery passed.", flush=True)
        evidence = PDF
        if args.verification:
            require(metadata["verificationStatus"] == "pending", "Configured upload bypassed quarantine")
            # The acknowledgement arrived while the verifier is still held. The
            # worker can start later, so wait for its independent request here.
            require(verifier_seen.wait(10), "Background verifier did not receive the acknowledged upload")
            require(not verifier_release.is_set(), "Verifier was released before upload acknowledgement")
            pending_version = uploaded["data"]["request"]["proposalVersion"]
            pending_revision = uploaded["data"]["revisionIdentifier"]
            pending_etag = uploaded_headers["etag"]
            pending_status = request("GET", attachment_path, "owner", version=pending_version)[0]
            require(pending_status == 404, f"Pending evidence expected HTTP 404, received {pending_status}")
            require(action("submit_request", "owner", key="attachment-submit-pending")[0] == 412,
                    "Pending evidence allowed submission")
            print("Acknowledged upload stayed quarantined while the verifier was held.", flush=True)
            verifier_mode["value"] = "approved"
            verifier_release.set()

            def await_verdict(expected: str):
                deadline = time.monotonic() + 75
                while True:
                    value, response_headers = get()
                    if value["data"]["domainData"][SLOT]["verificationStatus"] == expected:
                        require(not verifier_mode["errors"], "External verifier contract was violated")
                        return value, response_headers
                    require(time.monotonic() < deadline, f"External verification did not reach {expected}")
                    time.sleep(0.25)

            uploaded, uploaded_headers = await_verdict("approved")
            require(uploaded_headers["etag"] != pending_etag,
                    "Verification changed response metadata without advancing its ETag")
            require(uploaded["data"]["revisionIdentifier"] == pending_revision,
                    "Verification unexpectedly rewrote the request record revision")
            require(verifier_mode["hashes"].count(hashlib.sha256(PDF).hexdigest()) >= 2,
                    "Unavailable verification was not retried for the same content")
            print("Held verifier acknowledged upload; quarantined reads/submission and retry approval passed.", flush=True)
            # A prior approval cannot release different replacement bytes.
            verifier_mode["value"] = "rejected"
            rejected_pdf = PDF + b"Rejected replacement.\n"
            document(request("PATCH", attachment_path, "owner", rejected_pdf,
                             etag=uploaded_headers["etag"], key="attachment-rejected-replacement",
                             content_type="application/pdf"), 200, "Upload rejected replacement")
            rejected, rejected_headers = await_verdict("rejected")
            rejected_metadata = rejected["data"]["domainData"][SLOT]
            require(rejected_metadata["sha256"] == hashlib.sha256(rejected_pdf).hexdigest()
                    and rejected_metadata["sha256"] in verifier_mode["hashes"],
                    "Replacement verdict did not bind the replacement hash")
            rejected_status = request("GET", attachment_path, "owner",
                                      version=rejected["data"]["request"]["proposalVersion"])[0]
            require(rejected_status == 404, f"Rejected evidence expected HTTP 404, received {rejected_status}")
            require(action("submit_request", "owner", key="attachment-submit-rejected")[0] == 412,
                    "Rejected evidence allowed submission")
            verifier_mode["value"] = "approved"
            evidence = PDF + b"Approved replacement.\n"
            document(request("PATCH", attachment_path, "owner", evidence,
                             etag=rejected_headers["etag"], key="attachment-approved-replacement",
                             content_type="application/pdf"), 200, "Upload approved replacement")
            uploaded, uploaded_headers = await_verdict("approved")
            metadata = uploaded["data"]["domainData"][SLOT]
            require(metadata["sha256"] == hashlib.sha256(evidence).hexdigest()
                    and metadata["sha256"] in verifier_mode["hashes"],
                    "Approval was not obtained for exact replacement bytes")
            print("Replacement evidence required its own verdict; rejected content remained unavailable.", flush=True)
        document(action("submit_request", "owner", key="attachment-submit"), 200, "Submit complete draft")
        submitted, _ = get("reviewer")
        version = submitted["data"]["request"]["proposalVersion"]
        require(submitted["data"]["domainData"][SLOT]["sha256"] == metadata["sha256"],
                "Reviewer received different evidence metadata")
        for role in ("owner", "reviewer", "applier"):
            status, download_headers, content = request("GET", attachment_path, role, version=version)
            require(status == 200 and content == evidence, f"Exact {role} download expected HTTP 200 and evidence bytes, received {status}")
            require(download_headers.get("x-content-type-options") == "nosniff"
                    and "no-store" in download_headers.get("cache-control", "")
                    and download_headers.get("content-disposition", "").split(";", 1)[0] == "attachment",
                    "Download response lacks safe binary headers")
        for role, profile, requested_version in [(None, "owner", version),
                                                 ("other-owner", "owner", version),
                                                 ("reviewer", "reviewer", version + 1)]:
            require(request("GET", attachment_path, role, profile=profile, version=requested_version)[0] == 404,
                    "Unauthorized or wrong-version download revealed attachment content")
        document(action("approve_request", "reviewer", key="attachment-review"), 200, "Approve evidence")
        document(action("apply_request", "applier", key="attachment-apply"), 200, "Apply reviewed request")
        applied, _ = document(request("GET", f"/v1/records/records/{record_id}", "operator"), 200, "Read applied record")
        require(applied["data"]["domainData"]["label"] == "Corrected label", "Reviewed correction was not applied")
        print("Exact submitted evidence downloads, review and application passed.", flush=True)
        listing = cli("retention-list", "request-retention", "list", "--runtime-config", runtime,
                      "--request-entity", "correction-request")
        require(any(item["requestId"] == request_id and item["eligibleForErasure"] for item in listing["requests"]),
                "Applied request was not eligible for operator retention")
        exact = ("--runtime-config", runtime, "--request-entity", "correction-request",
                 "--request-id", request_id, "--proposal-version", str(version))
        dry = cli("retention-dry-run", "request-retention", "dry-run", *exact)
        require(dry["erasure"]["attachmentReferences"] == 1, "Dry run did not count the exact attachment reference")
        erased = cli("retention-erase", "request-retention", "erase", *exact)
        require(erased["erasure"]["attachmentReferences"] == 1, "Erasure did not remove the attachment reference")
        require(request("GET", attachment_path, "reviewer", version=version)[0] == 404,
                "Erased attachment remained downloadable")
        repeat = cli("retention-dry-run-after", "request-retention", "dry-run", *exact)
        require(repeat["erasure"]["attachmentReferences"] == 0, "Erased attachment reference remained retained")
        cleanup = cli("attachment-cleanup", "request-retention", "cleanup-attachments",
                      "--runtime-config", runtime)
        require(cleanup["pendingExternalDeletions"] == 0
                and cleanup["externalDeletionTombstones"] == 0,
                "Database storage unexpectedly retained external cleanup work")
        passed = True
        mode = " with asynchronous verification" if args.verification else ""
        print(f"Request attachments{mode}: authoring, native schema-test/package/activation, draft refusal, storage failure recovery, HTTP upload, owner/reviewer/applier reads, review/apply and exact operator erasure passed.")
    finally:
        verifier_release.set()
        if configured_process is not None:
            configured_process.terminate()
            try:
                configured_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                configured_process.kill()
                configured_process.wait(timeout=10)
        if configured_log is not None:
            configured_log.close()
        if verifier is not None:
            verifier.shutdown()
            verifier.server_close()
        if verifier_thread is not None:
            verifier_thread.join(timeout=5)
        if started:
            try:
                cli("dev-remove", "dev", "stop", str(project), "--remove", "--docker-bin", str(docker))
            except Exception:
                print(f"Owned development cleanup failed; private state: {temporary}")
                raise
        if passed and not args.keep:
            shutil.rmtree(temporary)
        else:
            print(f"Owner-only acceptance reports: {temporary}")


if __name__ == "__main__":
    test_request_attachment_journey()
