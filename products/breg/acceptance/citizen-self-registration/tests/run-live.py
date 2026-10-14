#!/usr/bin/env python3
"""Historical native SMS signup runner for the retired Casework integration."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml


def free_port(used: set[int]) -> int:
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in used:
            used.add(port)
            return port


class SmsDelivery:
    """A test SMS transport. OTPs stay in memory and never enter logs."""

    def __init__(self) -> None:
        self.messages: deque[str] = deque()
        self.condition = threading.Condition()
        self.deliveries = 0
        path = "/sms/" + secrets.token_urlsafe(24)
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                pass

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != path or not 0 < length <= 16384:
                    self.send_error(400)
                    return
                try:
                    message = self.rfile.read(length).decode("utf-8")
                    otp = re.search(r"(?<!\d)\d{6}(?!\d)", message)
                    if otp is None:
                        raise ValueError("invalid SMS transport payload")
                except (ValueError, KeyError, TypeError):
                    self.send_error(400)
                    return
                with sink.condition:
                    sink.messages.append(otp.group())
                    sink.deliveries += 1
                    sink.condition.notify_all()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"sent"}')

        self.server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.url = f"http://host.docker.internal:{self.server.server_port}{path}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def otp_for(self, _phone: str) -> str:
        # ThunderID's custom sender carries only the rendered message body.
        # Run user flows sequentially and consume each native delivery once.
        deadline = time.monotonic() + 15
        with self.condition:
            while not self.messages:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("native issuer did not deliver an SMS")
                self.condition.wait(remaining)
            return self.messages.popleft()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("acceptance helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Commands:
    def __init__(self, root: Path, environment: dict[str, str]) -> None:
        self.root = root
        self.environment = environment
        self.sequence = 0

    def run(self, arguments: list[str | Path], *, json_output: bool = False, timeout: int = 240):
        self.sequence += 1
        result = subprocess.run([str(arg) for arg in arguments], capture_output=True,
                                env=self.environment, timeout=timeout, check=False)
        log = self.root / f"command-{self.sequence:02}.log"
        log.write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{Path(arguments[0]).name} failed; inspect {log.name}")
        return json.loads(result.stdout) if json_output else result.stdout.decode().strip()


def issuer_error_excerpt(project: Path, environment: dict[str, str]) -> str:
    """Keep bounded, redacted native errors before the owned issuer stops."""
    session = json.loads((project / ".breg/dev/issuer/session.json").read_text())
    name = session.get("containerName")
    if not isinstance(name, str) or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,159}", name) is None:
        return ""
    logs = subprocess.run(["docker", "logs", "--tail", "100", name], capture_output=True,
                          env=environment, timeout=10, check=False)
    if logs.returncode:
        return ""
    excerpt = "\n".join(line for line in (logs.stdout + logs.stderr).decode(errors="replace").splitlines()
                        if "ERROR" in line or '"level":"error"' in line)
    for key, value in environment.items():
        if key.startswith("REGISTRATION_") and value:
            excerpt = excerpt.replace(value, "[secret]")
    excerpt = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[token]", excerpt)
    excerpt = re.sub(r"[A-Za-z0-9_-]{24,}", "[opaque]", excerpt)
    excerpt = re.sub(r"\d{4,}", "[number]", excerpt)
    return excerpt[:65536]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("breg", "bregctl", "casework", "caseworkctl"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="An absent absolute private state directory")
    parser.add_argument("--library-directory", type=Path, help="FIPS dylib directory for a local macOS build")
    parser.add_argument("--keep-state", action="store_true", help="Keep stopped disposable databases for diagnosis")
    args = parser.parse_args()
    os.umask(0o077)
    if args.output:
        if not args.output.is_absolute():
            parser.error("--output must be an absent absolute path")
        root = args.output
        root.mkdir(mode=0o700)
    else:
        root = Path(tempfile.mkdtemp(prefix="citizen-registration-"))
    source = Path(__file__).resolve().parents[1]
    project = root / "registry"
    casework_project = root / "casework"
    shutil.copytree(source, project, ignore=shutil.ignore_patterns("__pycache__", ".breg", ".casework"))
    shutil.copytree(source / "casework", casework_project, ignore=shutil.ignore_patterns("__pycache__", ".casework"))
    environment = dict(os.environ)
    binaries = {name: getattr(args, name).resolve() for name in ("breg", "bregctl", "casework", "caseworkctl")}
    environment["PATH"] = os.pathsep.join(dict.fromkeys([str(path.parent) for path in binaries.values()])) + os.pathsep + environment.get("PATH", "")
    if args.library_directory:
        environment["DYLD_FALLBACK_LIBRARY_PATH"] = str(args.library_directory.resolve())
    for name in ("REGISTRATION_CITIZEN_CLIENT_SECRET", "REGISTRATION_STAFF_CLIENT_SECRET", "REGISTRATION_STAFF_PASSWORD", "REGISTRATION_CASEWORK_WEBHOOK_KEY"):
        environment[name] = secrets.token_urlsafe(32)
    commands = Commands(root, environment)
    used: set[int] = set()
    breg_port, issuer_port, database_port, casework_port, casework_database_port = [free_port(used) for _ in range(5)]
    clients = yaml.safe_load((project / "dev-clients.yaml").read_text())
    clients["reviewAuthorities"]["casework"]["endpoint"] = f"http://127.0.0.1:{casework_port}/"
    clients["eventDestinations"]["casework"]["origin"] = f"http://127.0.0.1:{casework_port}"
    (project / "dev-clients.yaml").write_text(yaml.safe_dump(clients, sort_keys=False))
    result = {"outcome": "running", "checks": [], "smsTransport": "test-delivery", "protocol": "native-public-apis"}

    def checkpoint(name: str, facts: dict | None = None) -> None:
        result["checks"].append({"name": name, **(facts or {})})
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"Passed: {name}", flush=True)

    identity_module = load_module("citizen_identity", source / "identity/helper.py")
    journey_module = load_module("citizen_journey", source / "tests/live_journey.py")
    sms = SmsDelivery()
    started_breg = False
    started_casework = False
    try:
        result["binaries"] = {name: commands.run([path, "--version"]) for name, path in binaries.items()}
        result["binarySha256"] = {}
        for name, path in binaries.items():
            digest = hashlib.sha256()
            with path.open("rb") as binary:
                for block in iter(lambda: binary.read(1024 * 1024), b""):
                    digest.update(block)
            result["binarySha256"][name] = digest.hexdigest()
        result["issuerPin"] = json.loads((source.parents[3] / "crates/registry-thunderid-tooling/thunderid-version.json").read_text())
        result["sourceCommit"] = commands.run(["git", "-C", source.parents[3], "rev-parse", "HEAD"])
        result["workingTreeHasChanges"] = bool(commands.run(["git", "-C", source.parents[3], "status", "--porcelain"]))
        commands.run([binaries["bregctl"], "check", project])
        started_breg = True
        status = commands.run([binaries["bregctl"], "--format", "json", "dev", "start", project,
                               "--breg-port", str(breg_port), "--issuer-port", str(issuer_port),
                               "--database-port", str(database_port)], json_output=True)
        commands.run([binaries["bregctl"], "dev", "stop", project])
        identity = identity_module.NativeIdentity(status["issuer"], project, project / ".breg/dev/issuer/secrets", sms.url, status["audience"])
        identity.bootstrap()
        status = commands.run([binaries["bregctl"], "--format", "json", "dev", "start", project], json_output=True)
        checkpoint("native issuer and BReg activated", {"packageDigest": status["packageDigest"]})

        state = json.loads(Path(status["stateFile"]).read_text())
        dev_root = project / ".breg/dev"
        casework_clients = yaml.safe_load((casework_project / "dev-clients.example.yaml").read_text())
        integration = casework_clients["integrations"]
        integration["resource"] = status["audience"]
        binding = integration["sources"]["citizen-self-registration"]
        binding.update(baseUrl=status["bregUrl"], tokenEndpoint=status["tokenEndpoint"],
                       clientAssertionAudience=status["clientAssertionAudience"], resource=status["audience"],
                       eventSource=f"urn:registrystack:registry:citizen-self-registration:instance:{state['instanceId']}")
        integration["secretFiles"]["source-breg-casework-webhook"] = str(dev_root / "secrets/webhook-casework")
        (casework_project / "dev-clients.yaml").write_text(yaml.safe_dump(casework_clients, sort_keys=False))
        policy = yaml.safe_load((casework_project / "casework.yaml").read_text())
        for producer in policy["reviewProducers"]:
            producer["issuer"] = status["issuer"]
            producer["trustedInitiatorIssuer"] = status["issuer"]
        (casework_project / "casework.yaml").write_text(yaml.safe_dump(policy, sort_keys=False))
        commands.run([binaries["caseworkctl"], "check", casework_project,
                      "--against-breg-package", dev_root / "build/package",
                      "--source-id", "citizen-self-registration", "--bregctl-bin", binaries["bregctl"]])
        commands.run([binaries["caseworkctl"], "test", casework_project])
        started_casework = True
        commands.run([binaries["caseworkctl"], "--format", "json", "dev", "start", casework_project,
                      "--issuer-project", project, "--casework-port", str(casework_port),
                      "--database-port", str(casework_database_port)], json_output=True)
        checkpoint("real Casework policy and separate database activated")
        reviewer = identity.staff_login("registration-reviewer", environment["REGISTRATION_STAFF_PASSWORD"],
                                        ["registration:review", "registry:steward", "registration:casework-admin"])
        casework_url = f"http://127.0.0.1:{casework_port}"
        journey_module.replace_directory(casework_url, status["issuer"], reviewer, "registration-reviewer")
        checkpoint("native reviewer owns the review queue")
        # Reserved fictional NANP numbers; no actual SMS leaves this fixture.
        phone_a, phone_b = "+12025550101", "+12025550102"

        def wrong_otp(phone: str) -> str:
            valid = sms.otp_for(phone)
            return "000000" if valid != "000000" else "111111"

        try:
            identity.signup("+12025550103", wrong_otp)
        except identity_module.IdentityFlowError as error:
            step = error.step or {}
            if step.get("flowStatus") != "INCOMPLETE" or step.get("assertion") or step.get("error", {}).get("code") != "FET-1008":
                raise RuntimeError(f"wrong OTP did not produce the native assertion-free refusal: {error}") from error
        else:
            raise RuntimeError("native signup accepted an incorrect OTP")
        checkpoint("wrong SMS OTP refused before account provisioning")
        applicant_a = identity.signup(phone_a, sms.otp_for)
        applicant_b = identity.signup(phone_b, sms.otp_for)
        checkpoint("two previously unknown accounts registered through SMS OTP")
        if not identity.refuses_staff_scope(phone_a, sms.otp_for):
            raise RuntimeError("native citizen signup granted a staff scope")
        checkpoint("citizen cannot acquire the staff review scope")

        def restart_breg() -> None:
            commands.run([binaries["bregctl"], "dev", "stop", project])
            commands.run([binaries["bregctl"], "--format", "json", "dev", "start", project], json_output=True)

        journey_module.run_journey(status["bregUrl"], casework_url, applicant_a, applicant_b,
                                   reviewer, lambda phone: identity.login(phone, sms.otp_for),
                                   phone_a, phone_b, checkpoint, restart_breg)
        result["outcome"] = "passed"
        result["smsDeliveries"] = sms.deliveries
        checkpoint("complete signup-to-automatic-enrollment journey")
    # Any failed checkpoint must retain its result and reach owned-service cleanup.
    except Exception as error:  # noqa: BLE001
        result["outcome"] = "failed"
        result["failure"] = str(error)
        try:
            excerpt = issuer_error_excerpt(project, environment)
            if excerpt:
                (root / "issuer-errors.log").write_text(excerpt + "\n")
        except (OSError, ValueError, subprocess.TimeoutExpired):
            # Optional issuer diagnostics must not mask the failed checkpoint or stop cleanup.
            pass
        print(f"Acceptance run failed. Private diagnostics: {root}", file=sys.stderr)
    finally:
        cleanup_errors = []
        for started, tool, local_project in ((started_casework, binaries["caseworkctl"], casework_project),
                                             (started_breg, binaries["bregctl"], project)):
            state_directory = ".casework" if tool == binaries["caseworkctl"] else ".breg"
            if started and (local_project / state_directory / "dev/state.json").exists():
                try:
                    removal = [] if args.keep_state else ["--remove"]
                    commands.run([tool, "dev", "stop", *removal, local_project])
                # One cleanup failure must not prevent stopping the other service.
                except Exception as error:  # noqa: BLE001
                    cleanup_errors.append(str(error))
        sms.close()
        if cleanup_errors:
            result["cleanupErrors"] = cleanup_errors
            result["outcome"] = "failed"
        (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"Private result: {root / 'result.json'}", flush=True)
    return 0 if result["outcome"] == "passed" else 1


if __name__ == "__main__":
    print(
        "This historical runner uses the retired Casework source-sync and "
        "automatic-apply model. Use products/casework/examples/canonical-review/README.md "
        "and products/casework/DEV-SOURCES.md for current review setup and "
        "read-only native provider pairing.",
        file=sys.stderr,
    )
    raise SystemExit(2)
