"""Disposable runtime support; synthetic issuer is the only HTTP test double."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs
from urllib.request import ProxyHandler, Request, build_opener

import yaml

ROOT = Path(__file__).resolve().parents[5]
INPUTS = Path(__file__).resolve().parents[1]
OPEN = build_opener(ProxyHandler({})).open


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def yaml_write(path, value):
    path.write_text(yaml.safe_dump(value, sort_keys=False))


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Harness:
    def __init__(self, output, binaries):
        self.output, self.binaries = output, binaries
        self.env = dict(os.environ, EVIDENCE_BIN=str(binaries["evidence"]))
        self.env["PATH"] = str(binaries["bregctl"].parent) + os.pathsep + os.environ["PATH"]
        self.processes = []
        self.resources = {"databases": [], "roles": []}
        self.container = None
        self.issuer = None
        self.secret_root = output / "secrets"
        self.secret_root.mkdir()
        self.checks = []
        self.http_outcomes = []
        self.sequence = 0
        self.redactions = []

    def run(self, label, command, *, data=None, env=None, refused=False):
        result = subprocess.run(
            list(map(str, command)),
            input=data,
            env=env or self.env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        safe_out, safe_err = result.stdout, result.stderr
        for secret in self.redactions:
            safe_out, safe_err = (
                safe_out.replace(secret, "<redacted>"),
                safe_err.replace(secret, "<redacted>"),
            )
        (self.output / f"{label}.stdout").write_text(safe_out)
        (self.output / f"{label}.stderr").write_text(safe_err)
        if bool(result.returncode) != refused:
            raise RuntimeError(f"{label} failed; inspect owner-only command report")
        return result.stdout

    def ctl(self, binary, label, *args, refused=False):
        value = json.loads(
            self.run(label, [self.binaries[binary], "--format", "json", *args], refused=refused)
        )
        if not refused and value.get("kind") == "CaseworkReport":
            assert value["ok"] and value["status"] == "complete", "Casework command incomplete"
            return value["data"]
        return value

    def check(self, label, condition):
        assert condition, label
        self.checks.append(label)
        write(self.output / "checks.json", self.checks)

    def http(self, origin, path, token=None, profile=None, body=None, method="GET", headers=None):
        request_headers = dict(headers or {})
        if token:
            request_headers["Authorization"] = "Bearer " + token
        if profile:
            request_headers["Registry-Casework-Profile"] = profile
            request_headers["Registry-Review-Profile"] = profile
        if body is not None:
            request_headers.setdefault("Content-Type", "application/json")
        call = Request(
            origin + path,
            method=method,
            headers=request_headers,
            data=None if body is None else json.dumps(body).encode(),
        )
        try:
            response = OPEN(call, timeout=15)
        except HTTPError as error:
            response = error
        with response:
            data = response.read(1024 * 1024 + 1)
            assert len(data) <= 1024 * 1024, "HTTP response exceeded bound"
            value = json.loads(data) if data else None
            self.http_outcomes.append(
                {
                    "method": method,
                    "status": response.status,
                    "problemCode": value.get("code") if isinstance(value, dict) else None,
                }
            )
            write(self.output / "http-outcomes.json", self.http_outcomes)
            return response.status, value, {key.lower(): value for key, value in response.headers.items()}

    def start(self, name, command, origin):
        log = (self.output / f"{name}.log").open("wb")
        process = subprocess.Popen(list(map(str, command)), env=self.env, stdout=log, stderr=log)
        log.close()
        self.processes.append(process)
        deadline = time.monotonic() + 40
        while True:
            if process.poll() is not None:
                raise RuntimeError(f"{name} stopped before readiness; inspect protected log")
            try:
                status = self.http(origin, "/ready")[0]
                if status == 200:
                    return
                last_failure = f"HTTP {status}"
            except (URLError, OSError) as error:
                last_failure = type(error).__name__
            if time.monotonic() > deadline:
                raise RuntimeError(f"{name} readiness deadline expired ({last_failure})")
            time.sleep(0.1)

    def sql(self, database, statement):
        self.sequence += 1
        return self.run(
            f"sql-{self.sequence}",
            ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1"],
            data=statement,
            env=dict(self.pg_env, PGDATABASE=database),
        ).strip()

    def database(self):
        tls = self.output / "tls"
        tls.mkdir()
        for label, command in [
            (
                "ca",
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-nodes",
                    "-newkey",
                    "rsa:2048",
                    "-sha256",
                    "-days",
                    "2",
                    "-subj",
                    "/CN=Synthetic journey CA",
                    "-keyout",
                    tls / "ca.key",
                    "-out",
                    tls / "ca.pem",
                ],
            ),
            (
                "csr",
                [
                    "openssl",
                    "req",
                    "-new",
                    "-nodes",
                    "-newkey",
                    "rsa:2048",
                    "-subj",
                    "/CN=localhost",
                    "-keyout",
                    tls / "server.key",
                    "-out",
                    tls / "server.csr",
                ],
            ),
        ]:
            self.run(label, command)
        (tls / "server.ext").write_text("subjectAltName=DNS:localhost\n")
        self.run(
            "cert",
            [
                "openssl",
                "x509",
                "-req",
                "-sha256",
                "-days",
                "2",
                "-in",
                tls / "server.csr",
                "-CA",
                tls / "ca.pem",
                "-CAkey",
                tls / "ca.key",
                "-CAcreateserial",
                "-extfile",
                tls / "server.ext",
                "-out",
                tls / "server.crt",
            ],
        )
        password = secrets.token_hex(24)
        self.redactions.append(password)
        container = self.run(
            "container-create",
            [
                "docker",
                "run",
                "-d",
                "--name",
                "reviewed-evidence-" + secrets.token_hex(6),
                "-e",
                "POSTGRES_PASSWORD",
                "-p",
                "127.0.0.1::5432",
                "docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675",
            ],
            env=dict(self.env, POSTGRES_PASSWORD=password),
        ).strip()
        self.container = container
        deadline = time.monotonic() + 60
        while True:
            result = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-U", "postgres"], capture_output=True
            )
            logs_result = subprocess.run(["docker", "logs", container], capture_output=True)
            logs = logs_result.stdout + logs_result.stderr
            if result.returncode == 0 and logs.count(b"database system is ready to accept connections") >= 2:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("disposable PostgreSQL initialization deadline expired")
            time.sleep(0.2)
        for name in ("server.crt", "server.key"):
            self.run(
                "copy-" + name, ["docker", "cp", tls / name, container + ":/var/lib/postgresql/data/" + name]
            )
        script = """chown postgres:postgres /var/lib/postgresql/data/server.*
chmod 600 /var/lib/postgresql/data/server.key
printf "\\nssl=on\\nssl_cert_file='server.crt'\\nssl_key_file='server.key'\\n" >> /var/lib/postgresql/data/postgresql.conf
sed -i 's/^host /hostssl /' /var/lib/postgresql/data/pg_hba.conf
"""
        self.run(
            "configure-tls", ["docker", "exec", "-i", "--user", "root", container, "sh", "-eu"], data=script
        )
        self.run(
            "reload-tls",
            [
                "docker",
                "exec",
                "--user",
                "postgres",
                container,
                "pg_ctl",
                "-D",
                "/var/lib/postgresql/data",
                "reload",
            ],
        )
        bound = (
            self.run("container-port", ["docker", "port", container, "5432/tcp"]).strip().rsplit(":", 1)[1]
        )
        self.pg_env = dict(
            self.env,
            PGHOST="localhost",
            PGPORT=bound,
            PGUSER="postgres",
            PGPASSWORD=password,
            PGSSLMODE="verify-full",
            PGSSLROOTCERT=str(tls / "ca.pem"),
        )
        self.env["SSL_CERT_FILE"] = str(tls / "ca.pem")
        (self.secret_root / "postgres-ca").write_bytes((tls / "ca.pem").read_bytes())
        self.check(
            "postgres-tls-verified",
            self.sql("postgres", "COPY (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) TO STDOUT;")
            == "t",
        )
        self.check(
            "postgres-plaintext-refused",
            subprocess.run(
                ["psql", "-X", "-q", "-c", "SELECT 1"],
                env=dict(self.pg_env, PGDATABASE="postgres", PGSSLMODE="disable"),
                capture_output=True,
            ).returncode
            != 0,
        )
        self.db_configs = {}
        for name in ("schema", "source", "casework"):
            database = "journey_" + name
            migration, runtime = name + "_migration", name + "_runtime"
            for role in (migration, runtime):
                self.sql(
                    "postgres",
                    f"CREATE ROLE \"{role}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{password}';",
                )
                self.resources["roles"].append(role)
                (self.secret_root / role).write_text(
                    f"postgresql://{role}:{password}@localhost:{bound}/{database}"
                )
            self.sql("postgres", f'CREATE DATABASE "{database}";')
            self.resources["databases"].append(database)
            self.sql(
                database,
                f'REVOKE ALL ON DATABASE "{database}" FROM PUBLIC; GRANT CONNECT ON DATABASE "{database}" TO "{migration}", "{runtime}";',
            )
            if name == "casework":
                self.sql(database, f'GRANT USAGE, CREATE ON SCHEMA public TO "{migration}";')
            if name != "casework":
                self.sql(
                    database,
                    "CREATE EXTENSION btree_gist;\n"
                    + "\n".join(
                        f'CREATE SCHEMA {schema} AUTHORIZATION "{migration}"; REVOKE ALL ON SCHEMA {schema} FROM PUBLIC;'
                        for schema in (
                            "registry_internal",
                            "registry_data",
                            "registry_source",
                            "registry_derived",
                            "registry_context",
                        )
                    ),
                )
            self.db_configs[name] = {
                "runtimeUrlRef": "secret:file/" + runtime,
                "migrationUrlRef": "secret:file/" + migration,
                "trustedRootCertificateRef": "secret:file/postgres-ca",
            }
            if name != "casework":
                self.db_configs[name].update(
                    roles={"migration": migration, "runtime": runtime},
                    pool={
                        "maximumConnections": 4,
                        "waitTimeoutMilliseconds": 1000,
                        "createTimeoutMilliseconds": 1000,
                        "recycleTimeoutMilliseconds": 1000,
                    },
                )

    def identity(self):
        # Reuse the maintained synthetic fixture's P-256 key and token helpers.
        spec = importlib.util.spec_from_file_location(
            "fixture_crypto",
            ROOT / "products/breg/acceptance/farmer-landholding-evidence/evidence/run-provider.py",
        )
        crypto = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(crypto)
        self.crypto = crypto
        pem, public, self.issuer_private = crypto.make_key(self.secret_root, "issuer")
        self.tokens = {}
        harness = self

        class Issuer(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def send(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/.well-known/jwks.json":
                    self.send(200, {"keys": [public]})
                elif self.path in (
                    "/.well-known/openid-configuration",
                    "/.well-known/oauth-authorization-server",
                ):
                    self.send(
                        200,
                        {
                            "issuer": harness.issuer_url,
                            "jwks_uri": harness.issuer_url + "/.well-known/jwks.json",
                            "token_endpoint": harness.issuer_url + "/oauth2/token",
                            "grant_types_supported": ["client_credentials"],
                            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                        },
                    )
                else:
                    self.send(404, {})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/oauth2/token" or not 0 < length <= 16384:
                    self.send(400, {})
                    return
                form = parse_qs(self.rfile.read(length).decode())
                client = form.get("client_id", [""])[0]
                if (
                    client not in ("context-status", "consumer")
                    or form.get("grant_type") != ["client_credentials"]
                    or not form.get("client_assertion")
                ):
                    self.send(403, {})
                    return
                self.send(
                    200, {"access_token": harness.tokens[client], "token_type": "Bearer", "expires_in": 300}
                )

        self.issuer = ThreadingHTTPServer(("127.0.0.1", 0), Issuer)
        self.issuer_url = f"http://127.0.0.1:{self.issuer.server_port}"
        threading.Thread(target=self.issuer.serve_forever, daemon=True).start()
        write(self.secret_root / "oidc-jwks", {"keys": [public]})
        roles = {
            "operator": ("registry:generic:operate", "registry-operations", "human"),
            "applier": ("registry:apply", "registry-operations", "human"),
            "staff": ("registry:review casework:staff", "registry-operations", "human"),
            "administrator": ("casework:admin", "registry-operations", "human"),
            "producer": ("casework:request", "registry-operations", "service"),
            "context-status": ("registry:review-status", "registry-operations", "service"),
            "source": ("registry:evidence:lookup", "evidence-source-read", "service"),
            "consumer": ("evidence:request", "record-verification", "service"),
            "ungranted": ("evidence:request", "record-verification", "service"),
        }
        for role, (scope, purpose, actor) in roles.items():
            now = int(time.time())
            claims = {
                "iss": self.issuer_url,
                "aud": ["urn:journey:breg", "urn:journey:casework", "urn:example:audience:local-evidence"],
                "sub": role,
                "client_id": role,
                "iat": now - 1,
                "exp": now + 1800,
                "registry_principal": role,
                "registry_purpose": purpose,
                "registry_actor_kind": actor,
                "scope": scope,
                "evidence_tags": [role],
                "evidence_audience": "urn:example:audience:local-evidence",
            }
            self.tokens[role] = crypto.sign_token(pem, public, claims)
            self.redactions.append(self.tokens[role])
            (self.secret_root / (role + "-token")).write_text(self.tokens[role])
        for name in ("audit-key", "cursor-key", "subject-binding-hmac-key"):
            (self.secret_root / name).write_text(secrets.token_hex(32))
        _, self.signer_public, signer = crypto.make_key(self.secret_root, "signer")
        write(self.secret_root / "signing-p256-private-jwk", signer)
        write(self.secret_root / "signing-p256-public.jwk.json", self.signer_public)
        write(self.secret_root / "client-key", self.issuer_private)
        (self.secret_root / "context-client-id").write_text("context-status")

    def cleanup(self):
        failures = []
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        if self.issuer:
            self.issuer.shutdown()
            self.issuer.server_close()
        if hasattr(self, "pg_env"):
            for database in reversed(self.resources["databases"]):
                try:
                    self.sql("postgres", f'DROP DATABASE "{database}" WITH (FORCE);')
                except (RuntimeError, subprocess.TimeoutExpired):
                    failures.append("database cleanup failed")
            for role in reversed(self.resources["roles"]):
                try:
                    self.sql("postgres", f'DROP ROLE "{role}";')
                except (RuntimeError, subprocess.TimeoutExpired):
                    failures.append("role cleanup failed")
            try:
                remaining_dbs = int(
                    self.sql(
                        "postgres",
                        "COPY (SELECT count(*) FROM pg_database WHERE datname IN ('journey_schema','journey_source','journey_casework')) TO STDOUT;",
                    )
                )
                remaining_roles = int(
                    self.sql(
                        "postgres",
                        "COPY (SELECT count(*) FROM pg_roles WHERE rolname IN ('schema_migration','schema_runtime','source_migration','source_runtime','casework_migration','casework_runtime')) TO STDOUT;",
                    )
                )
            except (RuntimeError, ValueError, subprocess.TimeoutExpired):
                remaining_dbs = remaining_roles = None
                failures.append("database inventory unavailable")
        else:
            remaining_dbs, remaining_roles = len(self.resources["databases"]), len(self.resources["roles"])
        container_removed = False
        if self.container:
            try:
                self.run("postgres-log", ["docker", "logs", self.container])
            except (RuntimeError, subprocess.TimeoutExpired):
                failures.append("database log unavailable")
            try:
                self.run("container-remove", ["docker", "rm", "-f", self.container])
                assert (
                    self.container
                    not in subprocess.run(
                        ["docker", "ps", "-aq", "--no-trunc"], capture_output=True, text=True, check=True
                    ).stdout.splitlines()
                )
                container_removed = True
            except (RuntimeError, AssertionError, subprocess.CalledProcessError):
                failures.append("container cleanup failed")
        receipt = {
            "processesStopped": all(p.poll() is not None for p in self.processes),
            "databasesRemaining": remaining_dbs,
            "rolesRemaining": remaining_roles,
        }
        write(
            self.output / "cleanup.json",
            dict(receipt, errors=failures, containerRemoved=container_removed),
        )
        assert not failures, "cleanup failed; inspect owner-only receipt"
        return receipt


def hashes(paths):
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
