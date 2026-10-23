#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic native-CLI composition proof. Never connect it to operated services."""
import argparse
import base64
import datetime as dt
import hashlib
import http.server as http_server
import importlib.util
import threading
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from real_service_fixtures import (write_breg, write_casework, write_messaging, write_review_casework,
                                   write_scheduling, CASEWORK_PRINCIPALS, SCHEDULING_RESOURCE,
                                   COORDINATOR_RESOURCE)

REPO = Path(__file__).resolve().parents[3]
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                "scripts/cargo_runtime_library_path.py")
SOURCE_PREFIXES = ("crates/", "products/", ".cargo/")
NATIVE_BINARIES = ("breg", "bregctl", "casework", "caseworkctl", "messaging", "messagingctl",
                   "scheduling", "schedulingctl", "coordinator", "coordinatorctl")
NATIVE_PACKAGES = ("registry-breg", "registry-bregctl", "registry-casework", "registry-caseworkctl",
                   "registry-messaging", "registry-messagingctl", "registry-scheduling",
                   "registry-schedulingctl", "registry-coordinator")
NATIVE_FEATURES = ",".join((
    "registry-breg/runtime", "registry-breg/postgres-test", "registry-breg/tooling", "registry-breg/schema",
    "registry-bregctl/schema", "registry-casework/schema", "registry-casework/postgres-test",
    "registry-caseworkctl/schema", "registry-caseworkctl/postgres-test", "registry-messaging/schema",
    "registry-messaging/postgres-test", "registry-messagingctl/postgres-test", "registry-scheduling/schema",
    "registry-scheduling/postgres-test", "registry-schedulingctl/postgres-test",
    "registry-coordinator/schema", "registry-coordinator/postgres-test",
))
_cargo_spec = importlib.util.spec_from_file_location("cargo_runtime_library_path", REPO / "scripts/cargo_runtime_library_path.py")
cargo_runtime = importlib.util.module_from_spec(_cargo_spec)
_cargo_spec.loader.exec_module(cargo_runtime)


AUTHORITY = "https://casework.local.example"
SOURCE = "coordinator-source"
# The PostgreSQL image caseworkctl's dev sessions pin, for the one database
# this journey owns directly.
POSTGRES_IMAGE = ("public.ecr.aws/docker/library/postgres:17.11"
                  "@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675")
MAILPIT_IMAGE = ("ghcr.io/axllent/mailpit:v1.31.2"
                 "@sha256:74d609a42ec279aa63c6b4622a6fa9b5408d1ad5b1d76a1c4be40a265ce0863d")
# Synthetic server and root certificate extensions for that database. Casework
# verifies the server by its IP address against the pinned root.
DATABASE_TLS = """[req]
distinguished_name = name
prompt = no
[name]
CN = Coordinator journey database
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1, DNS:localhost
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def free_ports(count):
    listeners = [socket.socket() for _ in range(count)]
    for listener in listeners:
        listener.bind(("127.0.0.1", 0))
    ports = [listener.getsockname()[1] for listener in listeners]
    for listener in listeners:
        listener.close()
    return ports


def stamp(seconds=0):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)).isoformat()


def http(method, url, token=None, body=None, headers=None, expected=(200,)):
    fields = dict(headers or {})
    if token:
        fields["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        fields["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=fields, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read(1_048_577)
    assert len(raw) <= 1_048_576, "response exceeds fixture bound"
    assert response.status in expected, f"{method} {urllib.parse.urlparse(url).path}: HTTP {response.status}"
    return json.loads(raw) if raw else None


def exported_context_schema(artifacts, action):
    """Read and verify exact bytes published by the owning BReg generator."""
    artifacts = Path(artifacts).resolve()
    index = json.loads((artifacts / "generated/review-context-schemas/index.json").read_text())
    entry = index[action]
    path = (artifacts / entry["path"]).resolve()
    assert path.is_relative_to(artifacts), "the owning artifact path must remain in its export"
    raw = path.read_bytes()
    assert "sha256:" + hashlib.sha256(raw).hexdigest() == entry["digest"]
    schema = json.loads(raw)
    assert schema["$id"] == entry["id"]
    assert schema["x-registry-definition-revision"] == entry["revision"]
    return {"bytes": raw, "contract": {"id": entry["id"], "revision": entry["revision"], "schemaDigest": entry["digest"]}}


def bind_review_policy(project, binding):
    """Pin one task-owned authored request to the owning compiled PolicyBinding."""
    assert set(binding) == {"id", "version", "digest"}, "require an exact owning PolicyBinding"
    assert binding["id"] == "application-review" and binding["version"] == "1"
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", binding["digest"])
    path = Path(project) / "functions.rhai"
    source = path.read_text()
    pattern = r'policy:\s*#\{id:\s*"application-review",\s*version:\s*"1",\s*digest:\s*"sha256:[0-9a-f]{64}"\}'
    replacement = 'policy: #{id: "application-review", version: "1", digest: ' + json.dumps(binding["digest"]) + '}'
    source, changed = re.subn(pattern, lambda _: replacement, source)
    assert changed == 1, "the native copy must contain one exact review-policy request binding"
    private(path, source)


def subject(token):
    # Display data from our own dev fixture. Products still verify signatures.
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sub"]


def database_environment(database, base):
    parts = urllib.parse.urlsplit(database)
    parameters = {"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT",
                  "sslkey": "PGSSLKEY", "connect_timeout": "PGCONNECT_TIMEOUT", "application_name": "PGAPPNAME"}
    query = urllib.parse.parse_qsl(parts.query)
    assert all(key in parameters for key, _ in query), "disposable URLs cannot override search_path"
    env = {key: value for key, value in base.items() if not key.startswith("PG")}
    env.update(PGHOST=parts.hostname, PGPORT=str(parts.port or 5432),
               PGDATABASE=urllib.parse.unquote(parts.path.lstrip("/")), PGCONNECT_TIMEOUT="5")
    if parts.username is not None:
        env["PGUSER"] = urllib.parse.unquote(parts.username)
    if parts.password is not None:
        env["PGPASSWORD"] = urllib.parse.unquote(parts.password)
    env.update({parameters[key]: value for key, value in query})
    return env


class LostResponseProxy:
    """Forward exact private fixture commands, dropping the first committed reply."""
    def __init__(self, origin, mutation_path):
        try:
            parts = urllib.parse.urlsplit(origin)
            valid_origin = (parts.scheme == "http" and parts.username is None
                and parts.password is None and parts.port is not None
                and 1 <= parts.port <= 65535 and not parts.path
                and not parts.query and not parts.fragment
                and "?" not in origin and "#" not in origin
                and not any(ord(char) <= 32 or ord(char) == 127 for char in origin)
                and ipaddress.ip_address(parts.hostname).is_loopback)
        except ValueError:
            valid_origin = False
        if not valid_origin:
            raise ValueError("fixture proxy origin must be an HTTP numeric loopback origin with an explicit port")
        self.commands = []
        self.lost = False
        proxy = self
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        class Handler(http_server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                self.forward()
            def do_POST(self):
                self.forward()
            def forward(self):
                # BaseHTTPRequestHandler normalizes leading // in self.path.
                target = self.requestline.split()[1]
                if (not target.startswith("/") or target.startswith("//")
                    or "#" in target
                    or any(ord(char) <= 32 or ord(char) == 127 for char in target)):
                    self.send_error(400, "fixture proxy requires an origin-form request target")
                    self.close_connection = True
                    return
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 <= length <= 131_072
                body = self.rfile.read(length) if length else None
                fields = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "content-length")}
                request = urllib.request.Request(origin + target, data=body, headers=fields, method=self.command)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                try:
                    response = opener.open(request, timeout=10)
                except urllib.error.HTTPError as error:
                    response = error
                raw = response.read(1_048_577)
                assert len(raw) <= 1_048_576
                mutation = self.command == "POST" and self.path == mutation_path
                if mutation:
                    bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
                    encoded = bearer.split(".")[1]
                    claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
                    proxy.commands.append({"key": self.headers.get("Idempotency-Key"),
                        "bodyHash": hashlib.sha256(body or b"").hexdigest(), "responseStatus": response.status,
                        "issuedAt": claims.get("iat"), "accessTokenExpiresAt": claims.get("exp"),
                        "subject": claims.get("sub"),
                        "issuer": claims.get("iss"), "audience": claims.get("aud"), "clientId": claims.get("client_id"),
                        "scopes": claims.get("scope", "").split(),
                        "signedIdentityObject": isinstance(claims.get("identity"), dict),
                        "signedIdentityClaims": sorted(claims["identity"]) if isinstance(claims.get("identity"), dict) else None,
                        "boundsHash": hashlib.sha256(json.dumps(claims.get("registry_grant_bounds"), sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                        "grantId": claims.get("registry_grant_id"), "grantExpiresAt": claims.get("registry_grant_exp")})
                if mutation and 200 <= response.status < 300 and not proxy.lost:
                    proxy.lost = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                self.send_response(response.status)
                for key, value in response.headers.items():
                    if key.lower() not in ("connection", "transfer-encoding", "content-length", "server", "date"):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        self.server = http_server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest():
    # Working bytes, including untracked source files, identify this build.
    if (REPO / ".git").exists():
        paths = subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=REPO,
        ).split(b"\0")
    else:
        # The docs reader deliberately copies source without Git metadata.
        # Its checkout already excludes ignored build output, so enumerate the
        # same bounded source roots directly.
        candidates = [REPO / name for name in SOURCE_FILES]
        for root in (REPO / "crates", REPO / "products", REPO / ".cargo"):
            candidates.extend(root.rglob("*"))
        paths = [os.fsencode(path.relative_to(REPO)) for path in sorted(candidates)]
    manifest = {}
    for encoded in paths:
        if not encoded:
            continue
        name = os.fsdecode(encoded)
        if name in SOURCE_FILES or name.startswith(SOURCE_PREFIXES):
            path = REPO / name
            if path.is_file() and not path.is_symlink():
                manifest[name] = file_digest(path)
    return manifest


def source_digest():
    return hashlib.sha256(json.dumps(source_manifest(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_snapshot(inventory_path=None):
    manifest = source_manifest()
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    snapshot = {"sourceInventorySha256": hashlib.sha256(encoded.encode()).hexdigest(),
        "capturedAt": stamp()}
    if inventory_path is not None:
        private(inventory_path, encoded)
        snapshot["sourceInventoryFile"] = inventory_path.name
    if (REPO / ".git").exists():
        snapshot["gitHead"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip()
        snapshot["workingDiffSha256"] = hashlib.sha256(subprocess.check_output(
            ["git", "diff", "--binary", "HEAD"], cwd=REPO)).hexdigest()
        untracked = subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=REPO).split(b"\0")
        snapshot["untrackedSourceSha256"] = {os.fsdecode(name): manifest[os.fsdecode(name)]
            for name in untracked if name and os.fsdecode(name) in manifest}
    return snapshot


def cargo_metadata(environment):
    return json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=REPO, env=environment))


def cargo_build(command, log_path, environment):
    with log_path.open("w") as log:
        result = subprocess.run(command, cwd=REPO, env=environment, stdout=log)
    lines = log_path.read_text().splitlines()
    if result.returncode:
        # Cargo's JSON stream contains rendered rustc diagnostics. Replay them
        # before a temporary build directory can be removed by its owner.
        sys.stderr.write(cargo_runtime.rendered_diagnostics(lines))
        raise SystemExit("native Cargo build failed; see compiler diagnostics above")
    return [json.loads(line) for line in lines if line.strip()]


def exact_fips_library(messages):
    directory = cargo_runtime.resolve_aws_lc_fips_artifacts(
        [json.dumps(message) for message in messages])
    build = next(message for message in messages if message.get("reason") == "build-script-executed"
        and "aws-lc-fips-sys@" in message.get("package_id", ""))
    library = next(name.removeprefix("dylib=") for name in build["linked_libs"]
        if name.startswith("dylib=aws_lc_fips_") and name.endswith("_crypto"))
    return directory / ("lib" + library + ".dylib")


def prepare_native(destination, environment=None):
    """Build explicitly, then retain exact executables and their runtime library."""
    destination = destination.resolve()
    destination.mkdir(mode=0o700)
    environment = dict(os.environ if environment is None else environment)
    for key in ("CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"):
        environment.setdefault(key, "0")
    before = source_snapshot(destination / "source-before-build.inventory.json")
    private(destination / "source-before-build.json", before)
    metadata = cargo_metadata(environment)
    command = ["cargo", "build", "--locked"]
    for package in NATIVE_PACKAGES:
        command += ["-p", package]
    command += ["--features", NATIVE_FEATURES]
    for binary in NATIVE_BINARIES:
        command += ["--bin", binary]
    command += ["--example", "reviewed-notice-input", "--message-format", "json-render-diagnostics"]
    messages = cargo_build(command, destination / "build.jsonl", environment)
    artifacts = {message["target"]["name"]: Path(message["executable"]) for message in messages
        if message.get("reason") == "compiler-artifact" and message.get("executable")}
    binaries = destination / "bin"
    binaries.mkdir(mode=0o700)
    for name in (*NATIVE_BINARIES, "reviewed-notice-input"):
        if name not in artifacts:
            raise SystemExit("Cargo did not report the required executable: " + name)
        shutil.copy2(artifacts[name], binaries / name)
        (binaries / name).chmod(0o500)
    libraries = {}
    if sys.platform == "darwin":
        library = exact_fips_library(messages)
        library_root = destination / "libraries"
        library_root.mkdir(mode=0o700)
        frozen = library_root / library.name
        shutil.copy2(library, frozen)
        frozen.chmod(0o500)
        libraries[library.name] = {"path": str(frozen), "sha256": file_digest(frozen)}
    after = source_snapshot(destination / "source-after-build.inventory.json")
    private(destination / "source-after-build.json", after)
    if before["sourceInventorySha256"] != after["sourceInventorySha256"]:
        raise SystemExit("source changed during preparation; retry with stable source in a new output directory")
    manifest = {"sourceBeforeBuild": before, "sourceAfterBuild": after, "command": command,
        "cargoTargetDirectory": metadata["target_directory"],
        "buildEnvironment": {key: environment[key] for key in (
            "RUSTC_WRAPPER", "CARGO_TARGET_DIR", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG",
            "CARGO_PROFILE_TEST_DEBUG", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE") if key in environment},
        "binarySha256": {name: file_digest(binaries / name) for name in NATIVE_BINARIES},
        "helperSha256": {"reviewed-notice-input": file_digest(binaries / "reviewed-notice-input")},
        "runtimeLibraries": libraries,
        "fipsBuildScripts": [message for message in messages
            if message.get("reason") == "build-script-executed" and "aws-lc-fips-sys@" in message.get("package_id", "")]}
    private(destination / "build-manifest.json", manifest)
    print(f"Native preparation complete: {destination}", flush=True)
    return binaries, destination / "build-manifest.json"


class Journey:
    def __init__(self, root, binaries, wait_seconds, build_manifest=None, authority_preflight=False,
                 required_binaries=None, require_reviewed_notice_starter=True):
        self.root = root
        self.started_at = stamp()
        self.source_at_start = source_digest()
        self.binary_digests = {}
        self.build_provenance = json.loads(build_manifest.read_text()) if build_manifest else None
        self.wait_seconds = wait_seconds
        self.authority_preflight = authority_preflight
        self.proxies = []
        self.log_index = 0
        self.children = []
        self.sessions = []
        self.containers = []
        self.mailpit_url = None
        self.env = os.environ.copy()
        self.bin = root / "bin"
        self.bin.mkdir(mode=0o700)
        # Freeze executable bytes so a concurrent build cannot change a worker
        # at its restart. Library selection comes from the exact Cargo build.
        frozen_binaries = root / "native-binaries"
        frozen_binaries.mkdir(mode=0o700)
        dylibs = sorted({str(p.parent) for p in (binaries / "build").glob("aws-lc-fips-sys-*/out/build/artifacts/*.dylib")})
        self.library_digests = {}
        if sys.platform == "darwin" and not self.build_provenance:
            # Release archives place their relocated FIPS libraries alongside
            # each executable. Preserve that loader-relative layout on restart.
            for library in sorted(binaries.glob("libaws_lc_fips_*.dylib")):
                assert library.is_file() and not library.is_symlink(), "released runtime library must be a regular file"
                destination = frozen_binaries / library.name
                shutil.copy2(library, destination)
                destination.chmod(0o500)
                self.library_digests[library.name] = file_digest(library)
                assert file_digest(destination) == self.library_digests[library.name]
        if sys.platform == "darwin" and self.build_provenance:
            library_dir = root / "native-libraries"
            library_dir.mkdir(mode=0o700)
            retained = self.build_provenance.get("runtimeLibraries")
            if retained is None:
                libraries = [exact_fips_library(self.build_provenance.get("fipsBuildScripts", []))]
            else:
                libraries = [Path(item["path"]) for item in retained.values()]
                assert all(file_digest(Path(item["path"])) == item["sha256"] for item in retained.values()), "prepared runtime library changed"
            for library in libraries:
                destination = library_dir / library.name
                digest = file_digest(library)
                assert not destination.exists() or file_digest(destination) == digest
                shutil.copy2(library, destination)
                destination.chmod(0o500)
                self.library_digests[library.name] = digest
            assert self.library_digests, "exact Cargo FIPS library evidence is required on macOS"
            dylibs = [str(library_dir)]
        required_binaries = required_binaries or NATIVE_BINARIES
        for name in required_binaries:
            binary = binaries / name
            assert binary.is_file(), f"build {name} before running this journey"
            self.binary_digests[name] = file_digest(binary)
            frozen = frozen_binaries / name
            shutil.copy2(binary, frozen)
            frozen.chmod(0o500)
            assert file_digest(frozen) == self.binary_digests[name]
            wrapper = self.bin / name
            env = f"export DYLD_FALLBACK_LIBRARY_PATH={shlex.quote(':'.join(dylibs))}\n" if sys.platform == "darwin" and dylibs else ""
            private(wrapper, "#!/bin/sh\n" + env + f"exec {shlex.quote(str(frozen))} \"$@\"\n")
            wrapper.chmod(0o700)
        self.reviewed_notice_starter_digest = None
        if require_reviewed_notice_starter:
            starter = binaries / "reviewed-notice-input"
            if not starter.is_file():
                starter = binaries / "examples/reviewed-notice-input"
            assert starter.is_file(), "build the reviewed-notice-input example before running this journey"
            frozen = frozen_binaries / starter.name
            shutil.copy2(starter, frozen)
            frozen.chmod(0o500)
            wrapper = self.bin / starter.name
            private(wrapper, "#!/bin/sh\n" + env + f"exec {shlex.quote(str(frozen))} \"$@\"\n")
            wrapper.chmod(0o700)
            self.reviewed_notice_starter_digest = file_digest(frozen)
        if self.build_provenance:
            assert all(self.build_provenance["binarySha256"].get(name) == digest for name, digest in self.binary_digests.items()), "native binaries differ from build evidence"
            if require_reviewed_notice_starter and "helperSha256" in self.build_provenance:
                assert self.build_provenance["helperSha256"]["reviewed-notice-input"] == self.reviewed_notice_starter_digest, "reviewed-notice-input differs from build evidence"
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env.get("PATH", "")
        self.env["REGISTRY_THUNDERID_TOOLING_DIAGNOSTICS"] = "1"
        listeners = [socket.socket() for _ in range(6)]
        for listener in listeners:
            listener.bind(("127.0.0.1", 0))
        self.ports = dict(zip(["breg", "issuer", "bregdb", "casework", "caseworkdb", "jwks"], [s.getsockname()[1] for s in listeners]))
        for listener in listeners:
            listener.close()
        self.urls = {key: f"http://127.0.0.1:{port}" for key, port in self.ports.items()}

    def ctl(self, binary, *args, success=True):
        self.log_index += 1
        result = subprocess.run([str(self.bin / binary), "--format", "json", *map(str, args)],
                                env=self.env, capture_output=True, timeout=240)
        log = self.root / "logs" / f"command-{self.log_index:03d}.txt"
        private(log, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        if success:
            assert result.returncode == 0, f"{binary} {args[0]} failed; inspect private {log}"
            report = json.loads(result.stdout)
            if report.get("kind") == "CaseworkReport":
                assert report["ok"] and report["status"] == "complete"
                return report["data"]
            return report
        return result.returncode

    def token(self, binary, project, client):
        report = self.ctl(binary, "dev", "token", client, project)
        lines = Path(report["headerFile"]).read_text().splitlines()
        return next(line.removeprefix("Authorization: Bearer ") for line in lines if line.startswith("Authorization: Bearer "))

    def casework_start(self, project, owner):
        return self.ctl("caseworkctl", "dev", "start", project, "--issuer-project", owner,
                        "--casework-port", self.ports["casework"], "--database-port", self.ports["caseworkdb"],
                        "--casework-bin", self.bin / "casework")

    def export(self, owner, client, destination):
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        return self.ctl("bregctl", "dev", "export-client", owner, "--client", client,
                        "--client-id-file", destination / (client + "-id"),
                        "--assertion-key-file", destination / (client + "-key"))

    def spawn(self, binary, runtime, label):
        args = [str(self.bin / binary), "--runtime-config", str(runtime)]
        if binary != "coordinator":
            args.append("serve")
        with open(self.root / "logs" / f"{label}.log", "wb") as log:
            child = subprocess.Popen(args, env=self.env, stdout=log, stderr=log)
            self.children.append((child, log))
        return child

    def stop(self, child):
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            child.wait(timeout=15)

    def ready(self, child, url, path="/ready"):
        for _ in range(300):
            assert child.poll() is None, "fixture service exited; inspect private logs"
            try:
                http("GET", url + path)
                return
            except (OSError, AssertionError):
                time.sleep(0.1)
        raise AssertionError("fixture service failed readiness")

    def producer_request(self, owner, method, url, body=None, headers=None):
        return http(method, url, self.token("bregctl", owner, "coordinator-producer"), body, headers)

    def reviewed_notice_input(self, owner, application):
        """Use the maintained Rust client and protocol digest for one current application."""
        report = self.ctl("bregctl", "dev", "token", "application-reader", owner)
        output = self.root / "reviewed-notice-inputs" / f"{application}.json"
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        result = subprocess.run([
            str(self.bin / "reviewed-notice-input"),
            "--breg-url", self.urls["breg"],
            "--record-id", application,
            "--token-file", report["headerFile"],
            "--output", output,
        ], env=self.env, capture_output=True, timeout=30)
        assert result.returncode == 0, "reviewed-notice input preparation failed"
        prepared = json.loads(output.read_text())
        assert set(prepared) == {"applicationId", "applicationRevision", "applicationDigest"}
        return prepared

    def start_proposal(self, owner, action_id, inputs):
        token = self.token("bregctl", owner, "seed-client")
        metadata = http("GET", self.urls["breg"] + "/v1/registry?accessProfile=seeder", token)
        action = next(action for action in metadata["actions"] if action["id"] == action_id)
        assert action["execution"]["mode"] == "proposal"
        route = action["routes"]["start"]
        assert route["method"] == "POST"
        url = urllib.parse.urljoin(self.urls["breg"], route["path"]) + "?accessProfile=seeder"
        proposal = http("POST", url, token, {"input": inputs},
                        {"Idempotency-Key": str(uuid.uuid4())}, (200, 201))
        assert proposal["state"] == "draft" and proposal["actionId"] == action_id
        assert proposal["actionRevision"] == action["revision"]
        assert "application" not in proposal
        return proposal

    def proposal_transition(self, owner, proposal, operation, body=None):
        link = proposal["links"][operation]
        assert link["method"] == "POST" and link["operation"] == operation
        assert link["availability"]["available"]
        url = urllib.parse.urljoin(self.urls["breg"], link["path"]) + "?" + urllib.parse.urlencode({"accessProfile": link["accessProfile"]})
        return http("POST", url, self.token("bregctl", owner, "seed-client"),
                    {} if body is None else body,
                    {"Idempotency-Key": str(uuid.uuid4()), "If-Match": link["ifMatch"]}, (200, 201))

    def read_proposal(self, owner, proposal):
        link = proposal["links"]["self"]
        assert link["method"] == "GET" and link["operation"] == "get"
        url = urllib.parse.urljoin(self.urls["breg"], link["path"]) + "?" + urllib.parse.urlencode({"accessProfile": link["accessProfile"]})
        return http("GET", url, self.token("bregctl", owner, "seed-client"))

    def patch_application(self, owner, application, field, value):
        """Submit one genuine no-review Proposal and observe its exact application."""
        action, value_field = {
            "requestedAmount": ("correct-amount", "proposedAmount"),
            "noticeAllowed": ("correct-notice-permission", "proposedNoticeAllowed"),
        }[field]
        draft = self.start_proposal(owner, action, {"applicationId": application,
            value_field: value, "reason": "Exercise the reviewed-notice post-review guard"})
        submitted = self.proposal_transition(owner, draft, "submit")
        assert submitted["state"] == "submitted" and submitted["effectDigest"]
        binding = {key: submitted[key] for key in ("id", "actionId", "actionRevision", "submissionVersion", "effectDigest")}
        deadline = time.monotonic() + 30
        while True:
            current = self.read_proposal(owner, submitted)
            assert {key: current[key] for key in binding} == binding, "a successor cannot satisfy exact application observation"
            if current["state"] == "applied":
                assert current["application"]["submissionVersion"] == binding["submissionVersion"]
                assert current["application"]["effectDigest"] == binding["effectDigest"]
                break
            assert current["state"] == "submitted" and time.monotonic() < deadline, "the no-review mutation did not apply"
            time.sleep(0.1)
        return http("GET", self.urls["breg"] +
                    f"/v1/records/applications/{application}?accessProfile=seeder",
                    self.token("bregctl", owner, "seed-client"))

    def start(self, owner, url, label, data, flow="deferred-appointment"):
        contract = self.producer_request(owner, "GET", url + "/v1/workflows/" + urllib.parse.quote(flow, safe=""))
        assert contract["workflow"] == flow, "the served workflow contract must match the selected workflow"
        body = {"workflow": flow, "workflowRevision": contract["workflowRevision"], "input": data}
        first = self.producer_request(owner, "POST", url + "/v1/runs", body, {"Idempotency-Key": label})
        repeat = self.producer_request(owner, "POST", url + "/v1/runs", body, {"Idempotency-Key": label})
        assert repeat["runId"] == first["runId"]
        return first["runId"]

    def inspect(self, owner, url, run):
        return self.producer_request(owner, "GET", url + f"/v1/runs/{run}/inspect")

    def drive(self, owner, url, run):
        deadline = time.monotonic() + 120
        reconciled = []
        while time.monotonic() < deadline:
            result = self.inspect(owner, url, run)
            private(self.root / "native-progress.json", result)
            if (result["run"]["state"] == "attention" and result["run"].get("uncertain")) or result["run"]["state"] == "uncertain":
                step = result["run"]["step"]
                self.producer_request(owner, "POST", url + f"/v1/runs/{run}/reconcile",
                    {"reason": "Synthetic original-command receipt lookup"})
                reconciled.append(step)
            elif result["run"]["state"] != "running":
                return result, reconciled
            time.sleep(0.15)
        raise AssertionError("coordinator did not settle within fixture deadline")

    def cleanup(self, success):
        failures = []
        for proxy in self.proxies:
            proxy.close()
        for child, stream in reversed(self.children):
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            stream.close()
        for binary, project in reversed(self.sessions):
            state = project / (".breg/dev/state.json" if binary == "bregctl" else ".casework/dev/state.json")
            if not state.is_file():
                continue
            args = ["dev", "stop", project]
            if success:
                args.append("--remove")
            code = self.ctl(binary, *args, success=False)
            if code != 0:
                failures.append(binary)
        # The journey's own database holds nothing a diagnosis needs, so it is
        # removed whether or not the journey passed.
        for container in reversed(self.containers):
            result = subprocess.run(["docker", "rm", "--force", "--volumes", container],
                                    env=self.env, capture_output=True, timeout=60)
            if result.returncode != 0:
                failures.append("docker container " + container)
        assert not failures, f"owned cleanup failed for {', '.join(failures)}; inspect private logs in {self.root}"

    def run(self):
        # Start the issuer owner before compiling the task-grant policy. Its
        # exact client subjects and audience are part of that policy binding.
        bootstrap = write_breg(self.root / "breg-schema-bootstrap", self.urls)
        self.ctl("bregctl", "check", bootstrap)
        bootstrap_breg, bootstrap_database = free_ports(2)
        self.sessions.append(("bregctl", bootstrap))
        bootstrap_report = self.ctl("bregctl", "dev", "start", bootstrap,
            "--breg-port", bootstrap_breg, "--issuer-port", self.ports["issuer"],
            "--database-port", bootstrap_database, "--breg-bin", self.bin / "breg")
        resource = bootstrap_report["resource"]
        agent = subject(self.token("bregctl", bootstrap, "task-agent"))
        exported = self.root / "breg-schema-export"
        self.ctl("bregctl", "generate", "schemas", bootstrap, "--output", exported)
        context = exported_context_schema(exported, "correct-email")
        policy_project = write_casework(self.root / "casework-policy-bootstrap", self.urls,
            resource, agent, context)
        self.ctl("caseworkctl", "provider", "pair", policy_project, "--provider-id", "applications",
            "--breg-package", Path(bootstrap_report["stateFile"]).parent / "build/package",
            "--action-id", "correct-email", "--bregctl-bin", self.bin / "bregctl", "--apply")
        checked = self.ctl("caseworkctl", "check", policy_project)
        binding = next(item for item in checked["policyBindings"] if item["id"] == "external-review")
        # A separate disposable source borrows the same issuer and uses the
        # actual compiled consumer policy. The producer schema stays acyclic.
        owner = write_breg(self.root / "breg", self.urls, binding, borrower=True)
        self.ctl("bregctl", "check", owner)
        self.sessions.append(("bregctl", owner))
        report = self.ctl("bregctl", "dev", "start", owner, "--breg-port", self.ports["breg"],
                          "--database-port", self.ports["bregdb"], "--issuer-project", bootstrap,
                          "--breg-bin", self.bin / "breg")
        assert report["resource"] == resource and report["issuer"] == bootstrap_report["issuer"]
        print("BReg and stock issuer ready through native dev tooling.", flush=True)
        casework = self.root / "casework"
        shutil.copytree(policy_project, casework)
        self.ctl("caseworkctl", "provider", "pair", casework, "--provider-id", "applications",
                 "--breg-package", Path(report["stateFile"]).parent / "build/package", "--action-id", "correct-email",
                 "--bregctl-bin", self.bin / "bregctl", "--apply")
        checked = self.ctl("caseworkctl", "check", casework)
        assert next(item for item in checked["policyBindings"] if item["id"] == "external-review") == binding, "pairing cannot silently change the frozen review policy"
        self.sessions.append(("caseworkctl", casework))
        self.casework_start(casework, bootstrap)
        seed = self.token("bregctl", owner, "seed-client")
        def create(collection, data):
            value = http("POST", self.urls["breg"] + f"/v1/records/{collection}?accessProfile=seeder", seed,
                         {"data":data}, {"Idempotency-Key":str(uuid.uuid4())}, (201,))
            return value["data"]["recordIdentifier"]
        application = create("applications", {
            "tenant": "tenant-a", "applicantName": "Amina Example",
            "benefitProgram": "housing-support", "requestedAmount": 1200,
            "email": "synthetic@example.invalid", "noticeAllowed": True,
            "appointmentAllowed": True,
        })
        draft = self.start_proposal(owner, "correct-email", {"applicationId": application,
            "proposedEmail": "updated@example.invalid", "reason": "Synthetic native review"})
        submitted = self.proposal_transition(owner, draft, "submit")
        assert submitted["state"] == "submitted" and submitted["effectDigest"]
        # BReg owns review submission. Casework only observes the exact source
        # binding through its paired, read-only context provider.
        human = self.token("caseworkctl", casework, "staff")
        human_headers = {"Registry-Casework-Profile":"staff","Registry-Source-Profile":"reviewer"}
        deadline = time.monotonic() + 90
        while True:
            page = http("GET", self.urls["casework"] + "/v1/review-tasks?queue=review&limit=25", human, headers=human_headers)
            private(self.root / "native-source-inbox-progress.json", page)
            item = next((row for row in page["items"] if row["state"] == "open" and row["subject"]["id"] == submitted["id"]), None)
            if item is not None:
                break
            assert time.monotonic() < deadline, "BReg's exact review submission never reached Casework"
            time.sleep(0.2)
        task_url = self.urls["casework"] + "/v1/review-tasks/" + item["taskId"]
        http("POST", task_url + "/claim", human, headers={**human_headers,
                       "If-Match":f'"{item["revision"]}"', "Idempotency-Key":str(uuid.uuid4())})
        http("GET", task_url + "/task-templates", human, headers=human_headers)
        def approve(template):
            current = http("GET", task_url, human, headers=human_headers)
            return http("POST", task_url + "/task-grants", human,
                        {"templateId":template,"templateVersion":"1"},
                        {**human_headers,"If-Match":f'"{current["revision"]}"',"Idempotency-Key":str(uuid.uuid4())})
        print("Casework source visibility and human task approval ready.", flush=True)
        messaging_url, messaging_runtime = self.deferred_appointment(bootstrap, resource, application, casework, agent, approve,
            lambda: self.proposal_transition(owner, self.read_proposal(owner, submitted), "cancel"))
        self.reviewed_notice(bootstrap, resource, messaging_url, messaging_runtime)

    def authorization(self, exported, resource, scopes, **extra):
        return {"tokenEndpoint":exported["tokenEndpoint"], "clientAssertionAudience":exported["clientAssertionAudience"],
                "clientId":Path(exported["clientIdFile"]).read_text().strip(),
                "signingKeyRef":"secret:file/" + Path(exported["assertionKeyFile"]).name,
                "resource":resource,"scopes":scopes, **extra}

    def runtime(self, keys, connections):
        return {"apiVersion":"id.registrystack.org/formats/coordinator/runtime/v1alpha1","kind":"CoordinatorRuntimeConfig",
                "secretProviders":{"file":{"root":str(keys)},"environment":{}},
                "database":{"runtimeUrlRef":"secret:env/COORDINATOR_TEST_DATABASE_URL"},
                "namespace":"coordinator_" + uuid.uuid4().hex,"connections":connections}

    def isolated_database(self, variable, prefix):
        database = os.environ[variable]
        schema = prefix + uuid.uuid4().hex
        result = subprocess.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-q"],
            input=f"CREATE SCHEMA {schema};\n".encode(), env=database_environment(database, self.env),
            capture_output=True, timeout=15)
        assert result.returncode == 0, "disposable schema creation failed"
        parts = urllib.parse.urlsplit(database)
        query = urllib.parse.parse_qsl(parts.query) + [("options", "-csearch_path=" + schema)]
        return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))

    def scheduling_service(self, owner, resource, day):
        project = write_scheduling(self.root / "scheduling", day)
        self.ctl("schedulingctl", "check", project)
        package = self.root / "scheduling-package"
        self.ctl("schedulingctl", "package", project, "--output", package)
        secrets = self.root / "scheduling-secrets"
        status = self.export(owner, "scheduling-status", secrets)
        private(secrets / "database", self.isolated_database("COORDINATOR_MESSAGING_TEST_DATABASE_URL", "coordinator_scheduling_"))
        private(secrets / "audit-key", uuid.uuid4().hex + uuid.uuid4().hex)
        private(secrets / "jwks", http("GET", self.urls["issuer"] + "/oauth2/jwks"))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        url = f"http://127.0.0.1:{port}"
        runtime = self.root / "scheduling-runtime.yaml"
        private(runtime, {
            "apiVersion": "id.registrystack.org/formats/scheduling/runtime/v1alpha1", "kind": "SchedulingRuntimeConfig",
            "identity": {"databaseId": "coordinator-scheduling"}, "package": {"root": str(package)},
            "listener": {"bind": f"127.0.0.1:{port}", "tlsTermination": "development-loopback"},
            "secretProviders": {"file": {"root": str(secrets)}},
            "database": {"runtimeUrlRef": "secret:file/database", "migrationUrlRef": "secret:file/database", "testOnlyPlaintext": True},
            "authentication": {"oidc": {"issuer": self.urls["issuer"], "audience": SCHEDULING_RESOURCE,
                "scopeClaim": "scope", "readsScope": "scheduling:read", "allowedClients": ["task-agent", "scheduling-reader"],
                "assertionIssuers": {"task-agent": [AUTHORITY]},
                "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"}}},
            "taskGrantStatus": [{"sourceIssuer": AUTHORITY, "baseUrl": self.urls["casework"],
                "tokenEndpoint": status["tokenEndpoint"], "clientAssertionAudience": status["clientAssertionAudience"],
                "clientId": Path(status["clientIdFile"]).read_text().strip(),
                "privateKeyRef": "secret:file/" + Path(status["assertionKeyFile"]).name, "statusResource": resource}],
            "audit": {"destination": "file", "path": str(self.root / "audit/scheduling.ndjson"), "hashKeyRef": "secret:file/audit-key"},
            "retention": {"receiptRetentionDays": 7},
        })
        self.ctl("schedulingctl", "apply", "--runtime-config", runtime)
        self.ctl("schedulingctl", "records", "apply", "--runtime-config", runtime,
                 project / "records.yaml")
        child = self.spawn("scheduling", runtime, "scheduling")
        self.ready(child, url, "/readyz")
        return url, runtime

    def coordinator_deployment(self, owner, resource, agent, scheduling_url, messaging_url):
        keys = self.root / "coordinator-secrets"
        reader = self.export(owner, "application-reader", keys)
        catalogue = self.export(owner, "scheduling-reader", keys)
        booking = self.export(owner, "task-agent", keys)
        sender = self.export(owner, "case-system", keys)
        task = {"baseUrl": self.urls["casework"], "issuer": AUTHORITY, "subject": agent,
            "exchangeAudience": self.urls["issuer"], "bootstrapResource": resource}
        return self.coordinator_service("deferred-appointment", keys, {
            "applications": {"type": "breg", "baseUrl": self.urls["breg"], "profile": "follow-up-reader",
                "authorization": self.authorization(reader, resource, ["records:get"])},
            "catalogue": {"type": "scheduling", "baseUrl": scheduling_url,
                "authorization": self.authorization(catalogue, SCHEDULING_RESOURCE, ["scheduling:read"])},
            "bookings": {"type": "scheduling", "baseUrl": scheduling_url,
                "authorization": self.authorization(booking, SCHEDULING_RESOURCE, ["scheduling:read", "scheduling:commit"], taskAuthority=task),
                "observationAuthorization": self.authorization(booking, SCHEDULING_RESOURCE, ["scheduling:read"])},
            "notices": {"type": "messaging", "baseUrl": messaging_url,
                "authorization": self.authorization(sender, sender["resource"], ["messaging:send"])},
        }, free_ports(1)[0], "coordinator-before-wait")

    def coordinator_service(self, flow, keys, connections, port, label, additional_projects=(), primary_project=None):
        """Package maintained example flows, apply them with a split role, and serve them."""
        projects = [(flow, primary_project or REPO / "products/coordinator/examples" / flow), *additional_projects]
        packages = []
        for flow_id, project in projects:
            if flow_id.startswith("reviewed-notice"):
                bound_project = self.root / ("bound-" + flow_id)
                shutil.copytree(project, bound_project)
                bind_review_policy(bound_project, self.review_policy_binding)
                project = bound_project
            package = self.root / f"coordinator-{flow_id}-package"
            packaged = self.ctl("coordinatorctl", "package", "--project", project, "--output", package)
            packages.append({"root": str(package), "expectedDigest": packaged["packageDigest"]})
        database = os.environ["COORDINATOR_TEST_DATABASE_URL"]
        role = "coordinator_native_" + uuid.uuid4().hex[:16]
        password = uuid.uuid4().hex + uuid.uuid4().hex
        # The owned disposable role is created through stdin, with no credential
        # in argv or a captured SQL echo. It cannot migrate or activate.
        result = subprocess.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-q"],
            input=f"CREATE ROLE {role} LOGIN NOINHERIT PASSWORD '{password}';\n".encode(),
            env=database_environment(database, self.env), capture_output=True, timeout=15)
        assert result.returncode == 0, "owned split Coordinator role creation failed"
        parts = urllib.parse.urlsplit(database)
        host = parts.hostname
        if ":" in host:
            host = "[" + host + "]"
        runtime_url = urllib.parse.urlunsplit(parts._replace(netloc=f"{role}:{password}@{host}:{parts.port or 5432}"))
        private(keys / "runtime-database", runtime_url)
        private(keys / "migration-database", database)
        private(keys / "jwks", http("GET", self.urls["issuer"] + "/oauth2/jwks"))
        for key_name in ["state-key", "admission-key", "audit-key"]:
            value = b"\0" + os.urandom(31) if key_name == "state-key" else os.urandom(32)
            private(keys / key_name, value)
        config = self.runtime(keys, connections)
        config["database"] = {"runtimeUrlRef": "secret:file/runtime-database", "migrationUrlRef": "secret:file/migration-database"}
        config["deployment"] = {
            "databaseId": "coordinator-native-" + uuid.uuid4().hex,
            "runtimeRole": role,
            "packages": packages,
            "listener": {"bind": f"127.0.0.1:{port}", "tlsTermination": "development-loopback"},
            "authentication": {"issuer": self.urls["issuer"], "audience": COORDINATOR_RESOURCE,
                "scopeClaim": "scope", "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"},
                "policies": {"coordinator-producer": {
                    "requiredScopes": ["coordinator:start", "coordinator:operate"],
                    "workflows": [flow_id for flow_id, _ in projects],
                    "actions": ["start", "status", "inspect", "reconcile", "retry-same", "cancel"], "operator": True}}},
            "auditFile": str(self.root / f"audit/coordinator-{flow}.ndjson"), "auditKeyRef": "secret:file/audit-key",
            "activeStateKey": 1, "stateKeys": {"1": {"keyRef": "secret:file/state-key"}}, "admissionKeyRef": "secret:file/admission-key",
        }
        runtime = self.root / f"coordinator-{flow}-runtime.yaml"
        private(runtime, config)
        self.ctl("coordinatorctl", "--runtime-config", runtime, "plan")
        applied = self.ctl("coordinatorctl", "--runtime-config", runtime, "apply")
        assert applied["activation"]["roleMode"] == "split", "serving role must not migrate or activate"
        assert [(item["workflow"], item["change"]) for item in applied["workflows"]] == sorted(
            (flow_id, "install") for flow_id, _ in projects)
        url = f"http://127.0.0.1:{port}"
        child = self.spawn("coordinator", runtime, label)
        self.ready(child, url)
        return runtime, url, child

    def deferred_appointment(self, owner, resource, application, casework, agent, approve, revoke_source):
        day = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).date().isoformat()
        messaging_url, messaging_runtime = self.messaging_service(owner)
        scheduling_url, _ = self.scheduling_service(owner, resource, day)
        booking_proxy = LostResponseProxy(scheduling_url, "/v1/appointments")
        message_proxy = LostResponseProxy(messaging_url, "/v1/messages")
        self.proxies.extend([booking_proxy, message_proxy])
        runtime, url, worker = self.coordinator_deployment(owner, resource, agent, booking_proxy.url, message_proxy.url)
        expired_grant = approve("book-appointment-expiry-control")
        assert expired_grant["authorizationMode"] == "deferred"
        grant = approve("book-appointment")
        assert grant["authorizationMode"] == "deferred"
        if self.authority_preflight:
            # This real authority preflight diagnoses the fixture without allowing
            # Coordinator to consume an assertion or bearer supplied by its caller.
            bootstrap = self.token("caseworkctl", casework, "task-agent")
            assertion = http("POST", self.urls["casework"] + f'/v1/task-grants/{grant["id"]}/assertion', bootstrap)
            encoded = assertion["assertion"].split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            metadata = {key: claims.get(key) for key in ("iss", "sub", "aud", "scope", "registry_grant_id", "registry_grant_client", "registry_grant_resource", "registry_grant_exp")}
            private(self.root / "native-grant-preflight.json", metadata)
            assert claims["iss"] == AUTHORITY and claims["sub"] == agent and claims["aud"] == self.urls["issuer"]
            assert claims["registry_grant_id"] == grant["id"] and claims["registry_grant_exp"] == grant["expiresAt"]
            assert claims["registry_grant_client"] == "task-agent" and claims["registry_grant_resource"] == SCHEDULING_RESOURCE
            assert set(claims["scope"].split()) == {"scheduling:read", "scheduling:commit"}
            del bootstrap, assertion, claims
        approved_at = time.monotonic()
        due = stamp(self.wait_seconds)
        data = {"applicationId": application, "bookAfter": due, "searchStart": day + "T09:00:00Z",
            "searchEnd": day + "T17:00:00Z", "grant": {"id": grant["id"], "expiresAt": grant["expiresAt"]}}
        run = self.start(owner, url, "native-deferred-appointment", data)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            waiting = self.inspect(owner, url, run)
            if waiting["run"]["step"] == "due" and waiting["run"].get("nextDueAt"):
                break
            assert waiting["run"]["state"] == "running", "workflow failed before its persisted wait"
            time.sleep(0.1)
        else:
            raise AssertionError("workflow never persisted its wait")
        private(self.root / "persisted-wait.json", waiting)
        self.stop(worker)
        print(f"Coordinator persisted its wait and stopped. Waiting {self.wait_seconds}s before restart.", flush=True)
        until = dt.datetime.fromisoformat(due).timestamp()
        while time.time() < until:
            time.sleep(min(30, until - time.time()))
            print(f"Durable wait elapsed: {int(time.monotonic() - approved_at)}s.", flush=True)
        worker = self.spawn("coordinator", runtime, "coordinator-after-wait")
        self.ready(worker, url)
        result, reconciled = self.drive(owner, url, run)
        private(self.root / "native-outcome.json", result)
        private(self.root / "native-commit-observations.json", {"booking": booking_proxy.commands, "messaging": message_proxy.commands})
        assert result["run"]["outcome"] == "appointment-and-message-accepted", "deferred native flow did not complete"
        assert booking_proxy.lost and message_proxy.lost, "both committed responses must be lost deliberately"
        assert set(reconciled) == {"book", "notify"}, "read-only original receipt recovery must settle both effects"
        assert len({item["key"] for item in booking_proxy.commands}) == 1
        assert len({item["bodyHash"] for item in booking_proxy.commands}) == 1
        assert len({item["key"] for item in message_proxy.commands}) == 1
        assert len({item["bodyHash"] for item in message_proxy.commands}) == 1
        assert len(booking_proxy.commands) == len(message_proxy.commands) == 1, "receipt recovery must not resubmit effects"
        command = booking_proxy.commands[0]
        assert command["grantId"] == grant["id"] and command["grantExpiresAt"] == grant["expiresAt"]
        assert command["subject"] == agent and command["issuer"] == self.urls["issuer"]
        assert command["clientId"] == "task-agent" and command["audience"] == SCHEDULING_RESOURCE
        assert set(command["scopes"]) == {"scheduling:read", "scheduling:commit"}
        assert command["boundsHash"] == hashlib.sha256(json.dumps(grant["bounds"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        assert command["issuedAt"] >= dt.datetime.fromisoformat(due).timestamp() - 1, "booking credential must be issued after restart"
        assert command["issuedAt"] < command["accessTokenExpiresAt"] <= grant["expiresAt"], "fresh credentials cannot extend the original approval"
        approval_refusals = self.approval_refusals(owner, url, data, grant, expired_grant,
                                                  booking_proxy, message_proxy)
        messages = self.ctl("messagingctl", "messages", "list", "--runtime-config", messaging_runtime)
        assert len(messages["messages"]) == 1
        assert messages["messages"][0]["id"] == result["run"]["output"]["messageId"]
        connection = self.root / "scheduling-observation.json"
        private(connection, {"apiVersion": "id.registrystack.org/formats/platform/task-connection/v1alpha1",
            "kind": "PlatformTaskConnection", "caseworkUrl": self.urls["casework"],
            "tokenEndpoint": self.urls["issuer"] + "/oauth2/token", "clientAssertionAudience": self.urls["issuer"],
            "bootstrapResource": resource,
            "secretProviders": {"file": {"root": str((casework / ".casework/dev/credentials/task-agent").resolve())}},
            "clients": {"task-agent": {"assertionKeyRef": "secret:file/assertion-key.jwk",
                "resource": SCHEDULING_RESOURCE, "scopes": ["scheduling:read", "scheduling:commit"]}}})
        # Native grant tooling acquires a fresh exact grant for authoritative
        # caller-owned listing, independently of Coordinator's local outcome.
        token_report = self.ctl("caseworkctl", "dev", "grant", "task-agent", "--grant", grant["id"],
            "--connection", connection, casework)
        token_lines = Path(token_report["headerFile"]).read_text().splitlines()
        token = next(line.removeprefix("Authorization: Bearer ") for line in token_lines if line.startswith("Authorization: Bearer "))
        appointments = http("GET", scheduling_url + "/v1/appointments?" + urllib.parse.urlencode({
            "externalReferenceProduct": "breg", "externalReferenceRecordType": "applications",
            "externalReferenceIdentifier": application}), token)
        assert len(appointments["items"]) == 1
        assert appointments["items"][0]["appointmentId"] == result["run"]["output"]["appointmentId"]
        # The same still-unexpired approval loses authority when its exact
        # source Proposal ceases to be reviewable. Recheck through real
        # Casework status before any additional Scheduling command.
        revoke_source()
        mutations = (len(booking_proxy.commands), len(message_proxy.commands))
        refused_run = self.start(owner, url, "native-current-source-no-longer-reviewable", {**data, "bookAfter": stamp(-1)})
        refused, reconciled_again = self.drive(owner, url, refused_run)
        assert refused["run"]["state"] == "failed" and refused["run"]["failureCode"] == "credential-refused"
        assert not reconciled_again and (len(booking_proxy.commands), len(message_proxy.commands)) == mutations
        approval_refusals.append({"control": "current-source-no-longer-reviewable", "state": "failed",
            "failureCode": "credential-refused", "additionalProductMutations": 0})
        private(self.root / "native-approval-refusals.json", approval_refusals)
        elapsed = int(time.monotonic() - approved_at)
        proof = {"proofBoundary": "native_postgres_and_services" if self.wait_seconds >= 901 else "short_smoke_only",
            "actualApprovalElapsedSeconds": elapsed, "configuredWaitSeconds": self.wait_seconds, "authorityPreflight": self.authority_preflight,
            "workerRestart": True, "freshBookingIssuedAt": command["issuedAt"], "originalGrantDeadline": grant["expiresAt"],
            "freshBookingExpiresAt": command["accessTokenExpiresAt"], "approvalRefusals": approval_refusals,
            "bookingAuthority": {key: command[key] for key in ("issuer", "subject", "clientId", "audience", "scopes", "boundsHash")},
            "appointments": len(appointments["items"]), "acceptedMessages": len(messages["messages"]),
            "bookingResponseLost": True, "messageResponseLost": True, "readOnlyReconciliations": reconciled,
            "run": result["run"], "deliveryProven": False,
            "startedAt": self.started_at, "completedAt": stamp(),
            "sourceDigestAtStart": self.source_at_start, "sourceDigestAtEnd": source_digest(),
            "binarySha256": self.binary_digests, "librarySha256": self.library_digests, "buildProvenance": self.build_provenance,
            "runtimeSha256": {str(path.relative_to(self.root)): file_digest(path)
                for path in self.root.rglob("*runtime*") if path.is_file() and path.suffix in (".json", ".yaml")},
            "reviewRequiredAfterSourceChanges": True}
        private(self.root / "native-deferred-proof.json", proof)
        print("Deferred appointment and accepted notice recovered original receipts after response loss.", flush=True)
        return messaging_url, messaging_runtime

    def approval_refusals(self, owner, url, positive_input, grant, expired_grant,
                         booking_proxy, message_proxy):
        # These are actual Casework approvals and native Coordinator requests.
        # The short-lived approval is distinct from the positive journey's grant.
        while time.time() <= expired_grant["expiresAt"]:
            time.sleep(0.1)
        controls = [
            ("expired-original-approval", {"id": expired_grant["id"], "expiresAt": expired_grant["expiresAt"]}),
            ("unknown-approval", {"id": str(uuid.uuid4()), "expiresAt": grant["expiresAt"]}),
            ("mismatched-original-deadline", {"id": grant["id"], "expiresAt": grant["expiresAt"] + 1}),
        ]
        before = (len(booking_proxy.commands), len(message_proxy.commands))
        results = []
        for label, reference in controls:
            data = {**positive_input, "bookAfter": stamp(-1), "grant": reference}
            run = self.start(owner, url, label, data)
            outcome, reconciled = self.drive(owner, url, run)
            assert outcome["run"]["state"] == "failed", "invalid approval must definitely refuse"
            assert outcome["run"]["step"] == "book"
            assert outcome["run"]["failureCode"] == "credential-refused"
            assert not outcome["run"].get("uncertain") and not reconciled
            assert (len(booking_proxy.commands), len(message_proxy.commands)) == before, "invalid approval cannot reach an effect"
            results.append({"control": label, "grantId": reference["id"],
                "suppliedApprovalDeadline": reference["expiresAt"],
                "originalApprovalDeadline": expired_grant["expiresAt"] if label == "expired-original-approval" else grant["expiresAt"],
                "state": outcome["run"]["state"], "step": outcome["run"]["step"],
                "failureCode": outcome["run"]["failureCode"], "additionalProductMutations": 0,
                "reconciliations": reconciled})
        private(self.root / "native-approval-refusals.json", results)
        print("Expired, unknown, and mismatched approvals refused without product effects.", flush=True)
        return results

    def docker(self, *args, stdin=None, redact=None):
        """Run one Docker command, keeping its output with any credential redacted."""
        self.log_index += 1
        result = subprocess.run(["docker", *map(str, args)], input=stdin, env=self.env,
                                capture_output=True, timeout=120)
        output = result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
        if redact:
            output = output.replace(redact, "<redacted>")
        log = self.root / "logs" / f"command-{self.log_index:03d}.txt"
        private(log, output)
        assert result.returncode == 0, f"docker {args[0]} failed; inspect private {log}"
        return result.stdout

    def tls_database(self, name, *, superuser=False):
        """Own one TLS PostgreSQL database for a runtime that refuses plaintext.

        Returns its URL and the root certificate that signed its server
        certificate. The container is named after the work directory.
        """
        container = f"{self.root.name}-{name}"
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container), \
            "the work directory name must also form a Docker container name"
        tls = self.root / f"{name}-tls"
        tls.mkdir(mode=0o700)
        private(tls / "openssl.cnf", DATABASE_TLS)
        def openssl(*args):
            result = subprocess.run(["openssl", *map(str, args)], env=self.env, capture_output=True, timeout=30)
            assert result.returncode == 0, f"openssl {args[0]} failed for the journey database certificate"
        for key in ("root.key", "server.key"):
            openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", tls / key)
        openssl("req", "-new", "-x509", "-key", tls / "root.key", "-out", tls / "root.pem", "-days", "2",
                "-config", tls / "openssl.cnf", "-extensions", "root", "-subj", "/CN=Coordinator journey database root")
        openssl("req", "-new", "-key", tls / "server.key", "-out", tls / "server.csr",
                "-config", tls / "openssl.cnf", "-subj", "/CN=localhost")
        openssl("x509", "-req", "-in", tls / "server.csr", "-CA", tls / "root.pem", "-CAkey", tls / "root.key",
                "-set_serial", "0x" + secrets.token_hex(16), "-days", "2",
                "-extfile", tls / "openssl.cnf", "-extensions", "server", "-out", tls / "server.pem")
        port, = free_ports(1)
        postgres_password = secrets.token_hex(32)
        private(tls / "postgres.env", "POSTGRES_USER=postgres\nPOSTGRES_PASSWORD="
                + postgres_password + "\nPOSTGRES_DB=postgres\n")
        self.docker("create", "--name", container, "--label", "org.registrystack.journey=coordinator-real-services",
                    "--publish", f"127.0.0.1:{port}:5432", "--env-file", tls / "postgres.env", POSTGRES_IMAGE)
        # Only a container this journey created is removed at cleanup.
        self.containers.append(container)
        for source in ("server.pem", "server.key"):
            self.docker("cp", tls / source, f"{container}:/tmp/journey-{source}")
        self.docker("start", container)
        deadline = time.monotonic() + 60
        while subprocess.run(["docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                             env=self.env, capture_output=True, timeout=30).returncode != 0:
            assert time.monotonic() < deadline, "the journey database did not become ready"
            time.sleep(0.5)
        self.docker("exec", "--user", "root", container, "chown", "postgres:postgres",
                    "/tmp/journey-server.pem", "/tmp/journey-server.key")
        self.docker("exec", "--user", "root", container, "chmod", "600", "/tmp/journey-server.key")
        role = "casework_review"
        password = secrets.token_hex(32)
        # The superuser works over the container's local socket. The role's
        # password reaches psql through stdin only and is redacted from its log.
        statements = ("ALTER SYSTEM SET ssl = 'on';\n"
                      "ALTER SYSTEM SET ssl_cert_file = '/tmp/journey-server.pem';\n"
                      "ALTER SYSTEM SET ssl_key_file = '/tmp/journey-server.key';\n"
                      "SELECT pg_reload_conf();\n"
                      f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';\n"
                      f"CREATE DATABASE casework OWNER {role};\n")
        self.docker("exec", "-i", container, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
                    "-d", "postgres", stdin=statements.encode(), redact=password)
        deadline = time.monotonic() + 30
        while self.docker("exec", container, "psql", "-X", "-A", "-t", "-U", "postgres", "-c", "SHOW ssl").strip() != b"on":
            assert time.monotonic() < deadline, "the journey database did not enable TLS"
            time.sleep(0.2)
        username, credential = ("postgres", postgres_password) if superuser else (role, password)
        return f"postgresql://{username}:{credential}@127.0.0.1:{port}/casework", (tls / "root.pem").read_text()

    def mailpit(self):
        """Start the pinned local SMTP sink and return its SMTP port and API."""
        container = f"{self.root.name}-mailpit"
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container), \
            "the work directory name must also form a Docker container name"
        smtp_port, api_port = free_ports(2)
        self.docker("create", "--name", container,
                    "--label", "org.registrystack.journey=coordinator-real-services",
                    "--publish", f"127.0.0.1:{smtp_port}:1025",
                    "--publish", f"127.0.0.1:{api_port}:8025", MAILPIT_IMAGE)
        self.containers.append(container)
        self.docker("start", container)
        api = f"http://127.0.0.1:{api_port}"
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(api + "/readyz", timeout=1) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                # Connection failures are expected while the owned container starts.
                pass
            assert time.monotonic() < deadline, "Mailpit did not become ready"
            time.sleep(0.2)
        return smtp_port, api

    def mailpit_messages(self):
        assert self.mailpit_url, "Mailpit must be started before its mailbox is read"
        with urllib.request.urlopen(self.mailpit_url + "/api/v1/messages", timeout=10) as response:
            return json.load(response)["messages"]

    def review_casework(self, owner, resource, port, completion_url, completion_token):
        """Serve a Casework whose review producer's completions reach the Coordinator."""
        project = write_review_casework(self.root / "review-casework", self.urls)
        checked = self.ctl("caseworkctl", "check", project)
        self.review_policy_binding = next(binding for binding in checked["policyBindings"] if binding["id"] == "application-review")
        package = self.root / "review-casework-package"
        self.ctl("caseworkctl", "package", project, "--output", package)
        database, root_certificate = self.tls_database("review-casework-database")
        keys = self.root / "review-casework-secrets"
        private(keys / "database", database)
        private(keys / "database-root.pem", root_certificate)
        private(keys / "audit-key", secrets.token_hex(32))
        private(keys / "jwks", http("GET", self.urls["issuer"] + "/oauth2/jwks"))
        private(keys / "completion-token", completion_token)
        url = f"http://127.0.0.1:{port}"
        runtime = self.root / "review-casework-runtime.yaml"
        private(runtime, {
            "apiVersion": "id.registrystack.org/formats/casework/runtime/v1alpha1", "kind": "CaseworkRuntimeConfig",
            "identity": {"databaseId": "coordinator-review-casework"}, "package": {"root": str(package)},
            "listener": {"bind": f"127.0.0.1:{port}", "tlsTermination": "development-loopback",
                         "networkExposure": "private-address"},
            "secretProviders": {"file": {"root": str(keys)}},
            "database": {"runtimeUrlRef": "secret:file/database", "migrationUrlRef": "secret:file/database",
                         "trustedRootCertificateRef": "secret:file/database-root.pem"},
            "authentication": {"oidc": {"issuer": self.urls["issuer"], "audience": resource,
                "allowedClients": ["review-producer", "staff", "administrator"], "scopeClaim": "scope",
                "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"},
                "humanIdentity": {"claim": "registry_actor_kind", "value": "human"}}},
            "audit": {"path": str(self.root / "audit/review-casework.ndjson"), "hashKeyRef": "secret:file/audit-key"},
            "contextProviders": {},
            "reviewCompletionDestinations": {"coordinator": {
                "url": completion_url, "bearerTokenRef": "secret:file/completion-token",
                "attemptTimeoutMilliseconds": 5000, "maximumAttempts": 10, "retryDelaySeconds": 1}},
        })
        self.ctl("caseworkctl", "apply", "--runtime-config", runtime)
        child = self.spawn("casework", runtime, "review-casework")
        self.ready(child, url)
        administrator = self.token("bregctl", owner, "administrator")
        headers = {"Registry-Casework-Profile": "administrator"}
        directory = http("GET", url + "/v1/directory", administrator, headers=headers)
        http("POST", url + "/v1/directory/bootstrap", administrator,
             {"teamId": "reviewers", "queueId": "applications", "supervisors": [],
              "staff": [{"issuer": self.urls["issuer"], "subject": CASEWORK_PRINCIPALS["staff"]}]},
             {**headers, "If-Match": f'"{directory["revision"]}"', "Idempotency-Key": str(uuid.uuid4())})
        return url

    def reviewed_notice(self, owner, resource, messaging_url, messaging_runtime):
        """Run the reviewed BReg to Casework to BReg to Messaging journey.

        The fallback result read is 900 seconds away, so a run that settles
        within the fixture deadline was woken by Casework's completion event.
        """
        coordinator_port, casework_port = free_ports(2)
        completion_token = secrets.token_urlsafe(32)
        receiver = f"http://127.0.0.1:{coordinator_port}/v1/review-completions"
        casework_url = self.review_casework(owner, resource, casework_port, receiver, completion_token)
        keys = self.root / "coordinator-review-secrets"
        reviewer = self.export(owner, "review-producer", keys)
        assert reviewer["resource"] == resource, "the review producer must request the Casework audience"
        reader = self.export(owner, "application-reader", keys)
        sender = self.export(owner, "case-system", keys)
        private(keys / "review-completion-token", completion_token)
        production_project = REPO / "products/coordinator/examples/reviewed-notice"
        short_timeout_project = self.root / "reviewed-notice-short-timeout"
        shutil.copytree(production_project, short_timeout_project)
        short_workflow = short_timeout_project / "workflow.yaml"
        source = short_workflow.read_text()
        assert source.count("  id: reviewed-notice\n") == 1
        assert source.count("    timeoutSeconds: 1209600\n") == 1
        private(short_workflow, source.replace("  id: reviewed-notice\n",
            "  id: reviewed-notice-short-timeout\n").replace(
            "    timeoutSeconds: 1209600\n", "    timeoutSeconds: 2\n"))
        short_scenarios = short_timeout_project / "scenarios.yaml"
        scenarios = short_scenarios.read_text()
        assert scenarios.count("workflowElapsedSeconds: 1209600") == 2
        private(short_scenarios, scenarios.replace(
            "workflowElapsedSeconds: 1209600", "workflowElapsedSeconds: 2"))
        runtime, url, worker = self.coordinator_service("reviewed-notice", keys, {
            "applications": {"type": "breg", "baseUrl": self.urls["breg"],
                "profile": "follow-up-reader",
                "authorization": self.authorization(reader, resource, ["records:get"])},
            "review": {"type": "casework-review-producer", "baseUrl": casework_url, "profile": "coordinator-producer",
                "producer": "coordinator", "authorization": self.authorization(reviewer, resource, ["casework:review"]),
                "completion": {"recipientBinding": "coordinator-v1", "bearerTokenRef": "secret:file/review-completion-token"},
                "resultCheckSeconds": 900},
            "notices": {"type": "messaging", "baseUrl": messaging_url,
                "authorization": self.authorization(sender, sender["resource"], ["messaging:send"])},
        }, coordinator_port, "coordinator-reviewed-notice",
            [("reviewed-notice-short-timeout", short_timeout_project)])
        sent_before = {item["id"] for item in self.ctl("messagingctl", "messages", "list", "--runtime-config", messaging_runtime)["messages"]}
        mailbox_before = {item["ID"] for item in self.mailpit_messages()}

        seed = self.token("bregctl", owner, "seed-client")
        def create_application(label):
            response = http("POST", self.urls["breg"] + "/v1/records/applications?accessProfile=seeder", seed, {
                "data": {"tenant": "tenant-a", "applicantName": f"{label.title()} Applicant",
                    "benefitProgram": "housing-support", "requestedAmount": 1200,
                    "email": f"{label}@example.invalid", "noticeAllowed": True,
                    "appointmentAllowed": True}},
                {"Idempotency-Key": str(uuid.uuid4())}, (201,))
            return response["data"]["recordIdentifier"]

        runs = {}
        for outcome in ("approve", "reject", "changed", "permission-gone", "operator-cancel"):
            application = create_application(outcome)
            data = self.reviewed_notice_input(owner, application)
            runs[outcome] = (application, self.start(
                owner, url, "native-reviewed-notice-" + outcome, data, "reviewed-notice"))
        deadline = time.monotonic() + 60
        for _, run in runs.values():
            while (status := self.inspect(owner, url, run)["run"])["step"] != "await-review":
                assert status["state"] == "running", f"a reviewed-notice run stopped before its wait ({status['failureCode']})"
                assert time.monotonic() < deadline, "a reviewed-notice run never reached its wait"
                time.sleep(0.2)
            assert status["state"] == "running"
        print("Reviewed-notice runs submitted current BReg applications and wait for review.", flush=True)

        # The test-owned copy shortens only this one wait. The maintained
        # package above retains the production fourteen-day deadline.
        timeout_application = create_application("timeout")
        timeout_data = self.reviewed_notice_input(owner, timeout_application)
        timeout_run = self.start(owner, url, "native-reviewed-notice-timeout",
                                 timeout_data, "reviewed-notice-short-timeout")
        deadline = time.monotonic() + 30
        while (timeout_status := self.inspect(owner, url, timeout_run)["run"])["step"] != "await-review":
            assert timeout_status["state"] == "running"
            assert time.monotonic() < deadline, "the short-timeout run never reached its review wait"
            time.sleep(0.05)
        timeout_started = time.monotonic()
        timeout_status, _ = self.drive(owner, url, timeout_run)
        timeout_elapsed = time.monotonic() - timeout_started
        assert timeout_status["run"]["outcome"] == "review-timeout-withdrawn"
        assert timeout_elapsed >= 1.5, "the short-timeout package did not wait on the actual clock"
        runs["timeout"] = (timeout_application, timeout_run)

        # Current BReg state changes after the reviewed snapshot. Approval must
        # reread it and suppress both notices.
        self.patch_application(owner, runs["changed"][0], "requestedAmount", 1400)
        self.patch_application(owner, runs["permission-gone"][0], "noticeAllowed", False)

        # Operator cancellation owns a separate withdrawal route. Once it
        # settles, Casework must not retain an open review for that run.
        operator_run = runs["operator-cancel"][1]
        self.producer_request(owner, "POST", url + f"/v1/runs/{operator_run}/cancel",
                              {"reason": "Synthetic operator cancellation"})
        operator_status, _ = self.drive(owner, url, operator_run)
        assert operator_status["run"]["outcome"] == "review-operator-withdrawn"

        # Restart after the waits are durable. The later completion events wake
        # the new worker, which still performs the authoritative result reads.
        self.stop(worker)
        worker = self.spawn("coordinator", runtime, "coordinator-reviewed-notice-restarted")
        self.ready(worker, url)

        staff = self.token("bregctl", owner, "staff")
        headers = {"Registry-Casework-Profile": "staff"}
        page = http("GET", casework_url + "/v1/review-tasks?queue=applications&limit=25", staff, headers=headers)
        tasks = [item for item in page["items"] if item["state"] == "open"]
        assert len(tasks) == len(runs) - 2, "timeout and operator cancellation must close their reviews"
        decided_at = time.monotonic()
        for item in tasks:
            task_url = casework_url + "/v1/review-tasks/" + item["taskId"]
            http("POST", task_url + "/claim", staff, headers={**headers, "If-Match": f'"{item["revision"]}"',
                 "Idempotency-Key": str(uuid.uuid4())})
            context = http("GET", task_url + "/context", staff, headers=headers)
            outcome = next(name for name, (application, _) in runs.items()
                           if application == context["requesterReference"])
            assert set(context["context"]["snapshot"]) == {
                "applicantName", "benefitProgram", "requestedAmount"}
            body = ({"decision": {"type": "reject", "outcome": "missing-evidence"}}
                    if outcome == "reject" else {"decision": {"type": "approve", "outcome": "approved"}})
            current = http("GET", task_url, staff, headers=headers)
            http("POST", task_url + "/decisions", staff, body, {**headers, "If-Match": f'"{current["revision"]}"',
                 "Idempotency-Key": str(uuid.uuid4())}, (204,))
        settled = {"operator-cancel": operator_status["run"], "timeout": timeout_status["run"]}
        deadline = time.monotonic() + 120
        while len(settled) < len(runs):
            assert time.monotonic() < deadline, "a completion event did not wake its run before the fallback read"
            for outcome, (_, run) in runs.items():
                status = self.inspect(owner, url, run)["run"]
                if outcome not in settled and status["state"] != "running":
                    settled[outcome] = status
            time.sleep(0.25)
        elapsed = int(time.monotonic() - decided_at)
        expected = {
            "approve": "notice-accepted",
            "reject": "review-rejected",
            "changed": "application-changed",
            "permission-gone": "notice-permission-gone",
            "operator-cancel": "review-operator-withdrawn",
            "timeout": "review-timeout-withdrawn",
        }
        for outcome, name in expected.items():
            assert (settled[outcome]["state"], settled[outcome]["outcome"]) == ("finished", name)
        approved = settled["approve"]
        sent = [item["id"] for item in self.ctl("messagingctl", "messages", "list", "--runtime-config", messaging_runtime)["messages"]
                if item["id"] not in sent_before]
        assert sent == [approved["output"]["messageId"]], "only the approved review may send a notice"
        deadline = time.monotonic() + 30
        delivered = []
        while not delivered:
            delivered = [item for item in self.mailpit_messages() if item["ID"] not in mailbox_before]
            assert len(delivered) <= 1, "suppressed review outcomes must not deliver mail"
            assert time.monotonic() < deadline, "the accepted notice did not reach local Mailpit"
            if not delivered:
                time.sleep(0.2)
        assert delivered[0]["To"][0]["Address"] == "approve@example.invalid"
        assert delivered[0]["Subject"] == "Application approved"
        open_after = http("GET", casework_url + "/v1/review-tasks?queue=applications&limit=25",
                          staff, headers=headers)
        assert not [item for item in open_after["items"] if item["state"] == "open"]
        # The live receiver refuses an inauthentic event and acknowledges an
        # authentic one for a request it does not know, so the answer reveals
        # nothing about which requests exist.
        event = {"type": "review.completed", "eventId": str(uuid.uuid4()), "requestId": str(uuid.uuid4()),
                 "resultId": str(uuid.uuid4()), "completedAt": stamp()}
        refusals = {}
        for label, token, binding, expected in (
                ("wrongToken", "synthetic-wrong-completion-token", "coordinator-v1", 401),
                ("wrongRecipientBinding", completion_token, "synthetic-other-recipient", 401),
                ("unknownRequest", completion_token, "coordinator-v1", 204)):
            http("POST", receiver, token, event, {"registry-recipient-binding": binding,
                 "idempotency-key": event["eventId"]}, (expected,))
            refusals[label] = expected
        private(self.root / "native-reviewed-notice-proof.json", {
            "proofBoundary": "native_breg_casework_breg_and_messaging",
            "runs": {outcome: {key: status[key] for key in ("state", "step", "outcome", "failureCode")}
                     for outcome, status in settled.items()},
            "decisionToSettledSeconds": elapsed, "resultCheckSeconds": 900,
            "workerRestartWhileWaiting": True,
            "productionTimeoutSeconds": 1209600,
            "testTimeoutSeconds": 2,
            "actualTimeoutElapsedSeconds": timeout_elapsed,
            "reviewedNoticeStarterSha256": self.reviewed_notice_starter_digest,
            "receiver": refusals, "acceptedNotices": len(sent), "localMailboxNotices": len(delivered),
            "deliveryProven": True,
        })
        print(f"Casework completion events woke the restarted worker within {elapsed}s; only the unchanged approval sent its notice.", flush=True)

    def messaging_service(self, owner, test_only_plaintext=True, trusted_root_certificate=None):
        project = write_messaging(self.root / "messaging")
        package = self.root / "messaging-package"
        self.ctl("messagingctl", "package", project, "--output", package)
        keys = self.root / "coordinator-secrets"
        self.export(owner, "application-reader", keys)
        sender = self.export(owner, "case-system", keys)
        assert sender["resource"] == "urn:example:messaging", "client export must use registered Messaging resource"
        secret = self.root / "messaging-secrets"
        database = os.environ["COORDINATOR_MESSAGING_TEST_DATABASE_URL"]
        parts = urllib.parse.urlsplit(database)
        query = urllib.parse.parse_qsl(parts.query)
        # libpq does not expand a URI supplied through PGDATABASE. Pass its
        # parts through private environment values, never credentials in argv.
        parameters = {"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
                      "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY",
                      "connect_timeout": "PGCONNECT_TIMEOUT", "application_name": "PGAPPNAME"}
        assert all(key in parameters for key, _ in query), "use a disposable URL without unsupported query settings or search_path overrides"
        pg_env = {key: value for key, value in self.env.items() if not key.startswith("PG")}
        pg_env.update(PGHOST=parts.hostname, PGPORT=str(parts.port or 5432),
                      PGDATABASE=urllib.parse.unquote(parts.path.lstrip("/")), PGCONNECT_TIMEOUT="5")
        if parts.username is not None:
            pg_env["PGUSER"] = urllib.parse.unquote(parts.username)
        if parts.password is not None:
            pg_env["PGPASSWORD"] = urllib.parse.unquote(parts.password)
        pg_env.update({parameters[key]: value for key, value in query})
        schema = "coordinator_messaging_" + uuid.uuid4().hex
        result = subprocess.run(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-q", "-c", f"CREATE SCHEMA {schema}"],
                                env=pg_env, capture_output=True, timeout=15)
        assert result.returncode == 0, "disposable Messaging schema creation failed"
        query.append(("options", "-csearch_path=" + schema))
        private(secret / "database", urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query))))
        if trusted_root_certificate is not None:
            private(secret / "database-root.pem", trusted_root_certificate)
        private(secret / "audit-key", uuid.uuid4().hex + uuid.uuid4().hex)
        private(secret / "jwks", http("GET", self.urls["issuer"] + "/oauth2/jwks"))
        smtp_port, self.mailpit_url = self.mailpit()
        listener = socket.socket()
        listener.bind(("127.0.0.1",0))
        port = listener.getsockname()[1]
        listener.close()
        runtime = self.root / "messaging-runtime.yaml"
        database_config = {"runtimeUrlRef":"secret:file/database","migrationUrlRef":"secret:file/database"}
        if test_only_plaintext:
            database_config["testOnlyPlaintext"] = True
        if trusted_root_certificate is not None:
            database_config["trustedRootCertificateRef"] = "secret:file/database-root.pem"
        private(runtime, {"apiVersion":"id.registrystack.org/formats/messaging/runtime/v1alpha1","kind":"MessagingRuntimeConfig",
            "identity":{"databaseId":"coordinator-messaging"},"package":{"root":str(package)},
            "listener":{"bind":f"127.0.0.1:{port}","tlsTermination":"development-loopback"},
            "secretProviders":{"file":{"root":str(secret)}},
            "database": database_config,
            "authentication":{"oidc":{"issuer":self.urls["issuer"],"audience":"urn:example:messaging",
                "scopeClaim":"scope","allowedClients":["case-system"],"jwksSource":{"type":"static","documentRef":"secret:file/jwks"}}},
            "providers":{"mail-relay":{"type":"smtp","host":"127.0.0.1","port":smtp_port,
                "tls":"development-loopback"}},
            "audit":{"destination":"file","path":str(self.root / "audit/messaging.ndjson"),"hashKeyRef":"secret:file/audit-key"}})
        self.ctl("messagingctl", "apply", "--runtime-config", runtime)
        with open(self.root / "logs/messaging.log", "wb") as log:
            child = subprocess.Popen([str(self.bin / "messaging"),"--runtime-config",str(runtime),"serve"], env=self.env, stdout=log, stderr=log)
            self.children.append((child, log))
        for _ in range(100):
            assert child.poll() is None, "Messaging exited; inspect its private log"
            try:
                socket.create_connection(("127.0.0.1",port),timeout=0.1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("Messaging did not become ready; inspect its private log")
        return f"http://127.0.0.1:{port}", runtime

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    preparation = parser.add_mutually_exclusive_group()
    preparation.add_argument("--prepare", type=Path, metavar="NEW_DIRECTORY",
        help="Build and freeze all ten native binaries, reviewed-notice-input and a build manifest, then exit; honors CARGO_TARGET_DIR")
    preparation.add_argument("--bin-dir", type=Path,
        help="Use existing native binaries without rebuilding; defaults to Cargo's target_directory/debug")
    parser.add_argument("--authority-preflight", action="store_true", help="Diagnostic real assertion check before the workflow; omitted for first-call proof")
    parser.add_argument("--build-manifest", type=Path, help="Private source and binary digest evidence from the native build")
    parser.add_argument("--work-dir", type=Path, help="New owner-only directory for retained private diagnostics")
    parser.add_argument("--wait-seconds", type=int, default=961,
                        help="Actual durable wait; less than 901 is a smoke check only")
    args = parser.parse_args()
    os.umask(0o077)
    if args.prepare:
        if args.build_manifest or args.work_dir:
            parser.error("--prepare cannot be combined with --build-manifest or --work-dir")
        prepare_native(args.prepare)
        return
    if args.bin_dir is None:
        args.bin_dir = Path(cargo_metadata(os.environ)["target_directory"]) / "debug"
    assert 1 <= args.wait_seconds <= 1800
    for key in ["COORDINATOR_TEST_DATABASE_URL", "COORDINATOR_MESSAGING_TEST_DATABASE_URL"]:
        assert os.environ.get(key), f"set {key} to a disposable local database"
        database = urllib.parse.urlsplit(os.environ[key])
        try:
            local = database.hostname == "localhost" or ipaddress.ip_address(database.hostname).is_loopback
        except ValueError:
            local = False
        assert database.scheme in ("postgres", "postgresql") and local and database.path.strip("/"), \
            f"{key} must identify a disposable database on loopback"
    assert os.environ["COORDINATOR_TEST_DATABASE_URL"] != os.environ["COORDINATOR_MESSAGING_TEST_DATABASE_URL"]
    os.umask(0o077)
    root = args.work_dir
    if root:
        root = root.parent.resolve() / root.name
        root.mkdir(mode=0o700)
    else:
        root = Path(tempfile.mkdtemp(prefix="coordinator-real-services-", dir=Path(tempfile.gettempdir()).resolve()))
    print(f"Private journey state: {root}", flush=True)
    journey = Journey(root, args.bin_dir.resolve(), args.wait_seconds, args.build_manifest, args.authority_preflight)
    success = False
    try:
        journey.run()
        success = True
    finally:
        journey.cleanup(success)
    print("Native service journey passed. Owned dev containers removed; private diagnostics retained.", flush=True)


if __name__ == "__main__":
    main()
