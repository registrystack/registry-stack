#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic native-CLI composition proof. Never connect it to operated services."""
import argparse
import base64
import datetime as dt
import hashlib
import http.server as http_server
import threading
import ipaddress
import json
import os
from pathlib import Path
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

from real_service_fixtures import (write_breg, write_casework, write_messaging, write_scheduling,
                                   SCHEDULING_RESOURCE, COORDINATOR_RESOURCE)

REPO = Path(__file__).resolve().parents[3]
AUTHORITY = "https://casework.local.example"
SOURCE = "coordinator-source"


def private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


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


def subject(token):
    # Display data from our own dev fixture. Products still verify signatures.
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sub"]


def producer_token(exported, directory):
    """Use the exported client and standard private_key_jwt at the stock issuer."""
    def encode(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")
    def decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    key = json.loads(Path(exported["assertionKeyFile"]).read_text())
    assert key["kty"] == "EC" and key["crv"] == "P-256" and key["alg"] == "ES256"
    scalar, x, y = (decode(key[field]) for field in ("d", "x", "y"))
    assert len(scalar) == len(x) == len(y) == 32
    # SEC1 ECPrivateKey with prime256v1 parameters and the registered public key.
    members = bytes.fromhex("0201010420") + scalar + bytes.fromhex("a00a06082a8648ce3d030107a14403420004") + x + y
    der = bytes([0x30, len(members)]) + members
    key_file = directory / "assertion-key.der"
    private(key_file, der)
    client = Path(exported["clientIdFile"]).read_text().strip()
    now = int(time.time())
    header = {"alg": "ES256", "typ": "JWT"}
    if key.get("kid"):
        header["kid"] = key["kid"]
    claims = {"iss": client, "sub": client, "aud": exported["clientAssertionAudience"],
              "iat": now, "exp": now + 60, "jti": str(uuid.uuid4())}
    signing_input = ".".join(encode(json.dumps(value, separators=(",", ":")).encode()) for value in (header, claims))
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key_file), "-keyform", "DER"],
        input=signing_input.encode(), capture_output=True, timeout=10)
    assert signature.returncode == 0, "private fixture assertion signing failed"
    encoded = signature.stdout
    assert len(encoded) <= 72 and encoded[:1] == b"\x30" and encoded[1] == len(encoded) - 2
    offset = 2
    integers = []
    for _ in range(2):
        assert encoded[offset] == 2
        length = encoded[offset + 1]
        value = encoded[offset + 2:offset + 2 + length]
        integers.append(int.from_bytes(value, "big").to_bytes(32, "big"))
        offset += 2 + length
    assert offset == len(encoded)
    assertion = signing_input + "." + encode(b"".join(integers))
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": client,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion, "resource": exported["resource"], "scope": " ".join(exported["scopes"])}).encode()
    request = urllib.request.Request(exported["tokenEndpoint"], data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        raw = response.read(65537)
        assert len(raw) <= 65536
        token = json.loads(raw)["access_token"]
    assert len(token) <= 65536 and token.count(".") == 2
    return token


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
    # Working bytes, including the pilot's new source files, identify this build.
    paths = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=REPO).split(b"\0")
    manifest = {}
    for encoded in paths:
        if not encoded:
            continue
        name = os.fsdecode(encoded)
        if name in ("Cargo.toml", "Cargo.lock") or name.startswith(("crates/", "products/coordinator/")):
            path = REPO / name
            if path.is_file() and not path.is_symlink():
                manifest[name] = file_digest(path)
    return manifest


def source_digest():
    return hashlib.sha256(json.dumps(source_manifest(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Journey:
    def __init__(self, root, binaries, wait_seconds, build_manifest=None, authority_preflight=False):
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
        self.env = os.environ.copy()
        self.bin = root / "bin"
        self.bin.mkdir(mode=0o700)
        # Freeze executable bytes so a concurrent build cannot change a worker
        # at its restart. Library selection comes from the exact Cargo build.
        frozen_binaries = root / "native-binaries"
        frozen_binaries.mkdir(mode=0o700)
        dylibs = sorted({str(p.parent) for p in (binaries / "build").glob("aws-lc-fips-sys-*/out/build/artifacts/*.dylib")})
        self.library_digests = {}
        if sys.platform == "darwin" and self.build_provenance:
            library_dir = root / "native-libraries"
            library_dir.mkdir(mode=0o700)
            for build in self.build_provenance.get("fipsBuildScripts", []):
                artifacts = Path(build["out_dir"]) / "build/artifacts"
                for library in artifacts.glob("*.dylib"):
                    destination = library_dir / library.name
                    digest = file_digest(library)
                    assert not destination.exists() or file_digest(destination) == digest
                    shutil.copy2(library, destination)
                    destination.chmod(0o500)
                    self.library_digests[library.name] = digest
            assert self.library_digests, "exact Cargo FIPS library evidence is required on macOS"
            dylibs = [str(library_dir)]
        for name in ["breg", "bregctl", "casework", "caseworkctl", "messaging", "messagingctl", "scheduling", "schedulingctl", "coordinator", "coordinatorctl"]:
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
        if self.build_provenance:
            assert self.build_provenance["binarySha256"] == self.binary_digests, "native binaries differ from build evidence"
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
            return json.loads(result.stdout)
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
        for _ in range(100):
            assert child.poll() is None, "fixture service exited; inspect private logs"
            try:
                http("GET", url + path)
                return
            except (OSError, AssertionError):
                time.sleep(0.1)
        raise AssertionError("fixture service failed readiness")

    def producer_request(self, owner, method, url, body=None, headers=None):
        return http(method, url, producer_token(self.producer_identity, self.root / "producer-secrets"), body, headers)

    def start(self, owner, url, label, data):
        body = {"flow": "deferred-appointment", "input": data}
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
        assert not failures, f"owned cleanup failed for {', '.join(failures)}; inspect private logs in {self.root}"

    def run(self):
        owner = write_breg(self.root / "breg", self.urls)
        self.ctl("bregctl", "check", owner)
        self.sessions.append(("bregctl", owner))
        report = self.ctl("bregctl", "dev", "start", owner, "--breg-port", self.ports["breg"],
                          "--issuer-port", self.ports["issuer"], "--database-port", self.ports["bregdb"],
                          "--breg-bin", self.bin / "breg")
        resource = report.get("resource", report.get("audience"))
        assert resource, "native owner report must identify resource"
        print("BReg and stock issuer ready through native dev tooling.", flush=True)
        agent = subject(self.token("bregctl", owner, "task-agent"))
        casework = write_casework(self.root / "casework", self.urls, resource, agent)
        explanation = self.ctl("bregctl", "explain", "change-requests", owner)
        request = next(item for item in explanation["explanation"]["requests"] if item["requestEntity"] == "application-change")
        private(casework / "sources/source.json", {
            "apiVersion":"id.registrystack.org/formats/casework/breg-source-description/v1alpha1",
            "kind":"CaseworkBregSourceDescription", "sourceId":SOURCE, "authority":"none",
            "origin":"bregctl explain change-requests", "sourceRevision":explanation["revision"], "requests":[request]})
        self.ctl("caseworkctl", "check", casework)
        self.sessions.append(("caseworkctl", casework))
        self.casework_start(casework, owner)
        seed = self.token("bregctl", owner, "seed-client")
        def create(collection, data):
            value = http("POST", self.urls["breg"] + f"/v1/records/{collection}?accessProfile=seeder", seed,
                         {"data":data}, {"Idempotency-Key":str(uuid.uuid4())}, (201,))
            return value["data"]["recordIdentifier"]
        application = create("applications", {"tenant":"tenant-a","email":"synthetic@example.invalid","noticeAllowed":True,"appointmentAllowed":True})
        change = create("application-changes", {"tenant":"tenant-a","record":application,
                                                "proposedEmail":"updated@example.invalid","reason":"Synthetic review"})
        path = self.urls["breg"] + f"/v1/records/application-changes/{change}?accessProfile=seeder"
        record = http("GET", path, seed)
        action = next(a for a in record["data"]["request"]["actions"] if a["operation"] == "submit-request")
        http("POST", urllib.parse.urljoin(self.urls["breg"], action["href"]), seed, {},
             {"Idempotency-Key":str(uuid.uuid4()), "If-Match":action["ifMatch"]})
        record = http("GET", path, seed)
        http("POST", self.urls["casework"] + "/v1/review-requests", self.token("caseworkctl", casework, "producer"),
             {"kind":"external-review", "subject":{"source":SOURCE,"type":"application-change","id":change,
              "version":str(record["data"]["request"]["proposalVersion"]),"digest":record["data"]["request"]["effectDigest"]},
              "requesterReference":"synthetic-native-journey", "context":{"strategy":"source","binding":{"reference":"synthetic-native-journey"}}},
             {"Registry-Casework-Profile":"producer","Idempotency-Key":str(uuid.uuid4())}, (201,))
        # Native retained restart triggers immediate source reconciliation.
        self.ctl("caseworkctl", "dev", "stop", casework)
        self.casework_start(casework, owner)
        human = self.token("caseworkctl", casework, "staff")
        human_headers = {"Registry-Casework-Profile":"staff","Registry-Source-Profile":"reviewer"}
        page = http("GET", self.urls["casework"] + "/v1/review-tasks?queue=review&limit=25", human, headers=human_headers)
        item = next(row for row in page["items"] if row["state"] == "open")
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
        self.deferred_appointment(owner, resource, application, casework, agent, approve)

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
                "privateKeyRef": "secret:file/" + Path(status["assertionKeyFile"]).name, "caseworkResource": resource}],
            "audit": {"destination": "file", "path": str(self.root / "audit/scheduling.ndjson"), "hashKeyRef": "secret:file/audit-key"},
            "retention": {"attemptReceiptRetentionDays": 7},
        })
        self.ctl("schedulingctl", "apply", "--runtime-config", runtime)
        self.ctl("schedulingctl", "records", "apply", runtime, project / "records.yaml")
        child = self.spawn("scheduling", runtime, "scheduling")
        self.ready(child, url, "/readyz")
        return url, runtime

    def coordinator_deployment(self, owner, resource, agent, scheduling_url, messaging_url):
        self.producer_identity = self.export(owner, "coordinator-producer", self.root / "producer-secrets")
        assert self.producer_identity["resource"] == COORDINATOR_RESOURCE
        keys = self.root / "coordinator-secrets"
        reader = self.export(owner, "application-reader", keys)
        catalogue = self.export(owner, "scheduling-reader", keys)
        booking = self.export(owner, "task-agent", keys)
        sender = self.export(owner, "case-system", keys)
        project = REPO / "products/coordinator/examples/deferred-appointment"
        package = self.root / "coordinator-package"
        packaged = self.ctl("coordinatorctl", "package", "--project", project, "--output", package)
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
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        task = {"baseUrl": self.urls["casework"], "issuer": AUTHORITY, "subject": agent,
            "exchangeAudience": self.urls["issuer"], "bootstrapResource": resource}
        config = self.runtime(keys, {
            "applications": {"product": "breg", "baseUrl": self.urls["breg"], "profile": "follow-up-reader",
                "authorization": self.authorization(reader, resource, ["records:get"])},
            "catalogue": {"product": "scheduling", "baseUrl": scheduling_url,
                "authorization": self.authorization(catalogue, SCHEDULING_RESOURCE, ["scheduling:read"])},
            "bookings": {"product": "scheduling", "baseUrl": scheduling_url,
                "authorization": self.authorization(booking, SCHEDULING_RESOURCE, ["scheduling:read", "scheduling:commit"], taskAuthority=task),
                "observationAuthorization": self.authorization(booking, SCHEDULING_RESOURCE, ["scheduling:read"])},
            "notices": {"product": "messaging", "baseUrl": messaging_url,
                "authorization": self.authorization(sender, sender["resource"], ["messaging:send"])},
        })
        config["database"] = {"runtimeUrlRef": "secret:file/runtime-database", "migrationUrlRef": "secret:file/migration-database"}
        config["deployment"] = {
            "databaseId": "coordinator-native-" + uuid.uuid4().hex,
            "runtimeRole": role,
            "package": {"root": str(package), "expectedDigest": packaged["packageDigest"]},
            "listener": {"bind": f"127.0.0.1:{port}", "tlsTermination": "development-loopback"},
            "authentication": {"issuer": self.urls["issuer"], "audience": COORDINATOR_RESOURCE,
                "scopeClaim": "scope", "jwksSource": {"type": "static", "documentRef": "secret:file/jwks"},
                "allowedClients": ["coordinator-producer"], "policies": [{"clientId": "coordinator-producer",
                    "requiredScopes": ["coordinator:start", "coordinator:operate"], "flows": ["deferred-appointment"],
                    "actions": ["start", "status", "inspect", "reconcile", "retry-same", "cancel", "doctor"], "operator": True}]},
            "auditFile": str(self.root / "audit/coordinator.ndjson"), "auditKeyRef": "secret:file/audit-key",
            "activeStateKey": 1, "stateKeys": {"1": {"keyRef": "secret:file/state-key"}}, "admissionKeyRef": "secret:file/admission-key",
        }
        runtime = self.root / "coordinator-runtime.yaml"
        private(runtime, config)
        self.ctl("coordinatorctl", "--runtime-config", runtime, "plan")
        applied = self.ctl("coordinatorctl", "--runtime-config", runtime, "apply")
        assert applied["roleMode"] == "split", "serving role must not migrate or activate"
        url = f"http://127.0.0.1:{port}"
        child = self.spawn("coordinator", runtime, "coordinator-before-wait")
        self.ready(child, url)
        return runtime, url, child

    def deferred_appointment(self, owner, resource, application, casework, agent, approve):
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

    def messaging_service(self, owner):
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
        private(secret / "audit-key", uuid.uuid4().hex + uuid.uuid4().hex)
        private(secret / "jwks", http("GET", self.urls["issuer"] + "/oauth2/jwks"))
        listener = socket.socket()
        listener.bind(("127.0.0.1",0))
        port = listener.getsockname()[1]
        listener.close()
        runtime = self.root / "messaging-runtime.yaml"
        private(runtime, {"apiVersion":"id.registrystack.org/formats/messaging/runtime/v1alpha1","kind":"MessagingRuntimeConfig",
            "identity":{"databaseId":"coordinator-messaging"},"package":{"root":str(package)},
            "listener":{"bind":f"127.0.0.1:{port}","tlsTermination":"development-loopback"},
            "secretProviders":{"file":{"root":str(secret)}},
            "database":{"runtimeUrlRef":"secret:file/database","migrationUrlRef":"secret:file/database","testOnlyPlaintext":True},
            "authentication":{"oidc":{"issuer":self.urls["issuer"],"audience":"urn:example:messaging",
                "scopeClaim":"scope","allowedClients":["case-system"],"jwksSource":{"type":"static","documentRef":"secret:file/jwks"}}},
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
    parser.add_argument("--bin-dir", type=Path, default=REPO / "target/debug")
    parser.add_argument("--authority-preflight", action="store_true", help="Diagnostic real assertion check before the workflow; omitted for first-call proof")
    parser.add_argument("--build-manifest", type=Path, help="Private source and binary digest evidence from the native build")
    parser.add_argument("--work-dir", type=Path, help="New owner-only directory for retained private diagnostics")
    parser.add_argument("--wait-seconds", type=int, default=961,
                        help="Actual durable wait; less than 901 is a smoke check only")
    args = parser.parse_args()
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
