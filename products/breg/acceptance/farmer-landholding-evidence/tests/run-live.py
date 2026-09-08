#!/usr/bin/env python3
"""Provision disposable databases and run the real Evidence/BREG adopter journey."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import yaml


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bregctl", "breg", "evidence"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="Fresh owner-only evidence directory; defaults to a temporary directory")
    args = parser.parse_args()
    os.umask(0o077)
    project_source = Path(__file__).resolve().parents[1]
    root = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="breg-farmer-live-", dir="/private/tmp" if Path("/private/tmp").exists() else None))
    if args.output:
        root.mkdir(mode=0o700)
    secret_root = root / "secrets"
    secret_root.mkdir()
    admin = urlsplit(os.environ.get("BREG_TEST_DATABASE_URL", ""))
    ca = Path(os.environ.get("BREG_TEST_TLS_CA_PEM_PATH", "")).resolve()
    if admin.scheme not in {"postgres", "postgresql"} or not admin.hostname or not ca.is_file():
        raise SystemExit("Provide BREG_TEST_DATABASE_URL and BREG_TEST_TLS_CA_PEM_PATH for a disposable TLS PostgreSQL service")
    psql = shutil.which("psql")
    if not psql:
        raise SystemExit("psql must be on PATH")
    child_env = dict(os.environ, SSL_CERT_FILE=str(ca))
    admin_env = dict(child_env, PGHOST=admin.hostname, PGPORT=str(admin.port or 5432), PGUSER=unquote(admin.username or "postgres"), PGPASSWORD=unquote(admin.password or ""), PGSSLMODE="verify-full", PGSSLROOTCERT=str(ca))
    suffix = secrets.token_hex(4)
    migration, runtime_role = f"farmer_migration_{suffix}", f"farmer_runtime_{suffix}"
    databases = [f"farmer_test_{suffix}", f"farmer_live_{suffix}"]
    password = secrets.token_hex(24)
    created_databases: list[str] = []
    created_roles: list[str] = []
    provider = None

    def sql(database: str, text: str) -> str:
        result = subprocess.run([psql, "-X", "-q", "-v", "ON_ERROR_STOP=1"], input=text, text=True, capture_output=True, env=dict(admin_env, PGDATABASE=database))
        if result.returncode:
            (root / "database-error.log").write_text(result.stderr)
            raise RuntimeError("disposable database provisioning failed; inspect owner-only evidence")
        return result.stdout.strip()

    def write(path: Path, value: object, *, canonical: bool = False) -> None:
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) if canonical else json.dumps(value, indent=2) + "\n")

    def b64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    def key(name: str, kid: str) -> tuple[Path, dict]:
        private = root / f"{name}.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
        return private, {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid, "x": b64(der[-32:])}

    def token(private: Path, kid: str, role: str, purpose: str, scope: str) -> str:
        now = int(time.time())
        claims = {"aud": "urn:breg:change-request-example", "client_id": "registry-change-request-example", "exp": now + 3600, "iat": now,
                  "iss": "https://issuer.example/change-request-example", "jti": f"farmer-{suffix}-{role}", "registry_principal": f"synthetic-landholding-{role}",
                  "sub": f"synthetic-landholding-{role}", "registry_purpose": purpose, "scope": scope}
        body = b64(json.dumps({"alg": "EdDSA", "kid": kid, "typ": "JWT"}, separators=(",", ":")).encode()) + "." + b64(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = root / "token-signing-input"
        signing_input.write_text(body)
        sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private), "-in", str(signing_input)], capture_output=True, check=True).stdout
        signing_input.unlink()
        return body + "." + b64(sig)

    try:
        with (root / "provider.log").open("wb") as log:
            provider = subprocess.Popen([sys.executable, str(project_source / "evidence/run-provider.py"), "--evidence", str(args.evidence.resolve()), "--output", str(root / "provider")], stdin=subprocess.PIPE, stdout=log, stderr=log, env=child_env)
        ready_path = root / "provider/ready.json"
        deadline = time.monotonic() + 30
        while not ready_path.is_file():
            if provider.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("real Evidence provider did not become ready; inspect owner-only provider.log")
            time.sleep(0.1)
        ready = json.loads(ready_path.read_text())
        project = root / "project"
        shutil.copytree(project_source, project, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(ready["contractsFile"], project / "evidence/farmer-contracts.json")
        shutil.copyfile(ready["tokenFile"], secret_root / "evidence-token")
        shutil.copyfile(ready["jwksFile"], secret_root / "evidence-jwks")
        config = yaml.safe_load((project / "registry.yaml").read_text())
        package = config["package"]
        oidc_key, oidc_jwk = key("oidc-signer", "change-request-example-oidc-key")
        signer, signer_jwk = key("package-signer", "change-request-example-package-key")
        write(secret_root / "oidc-jwks", {"keys": [oidc_jwk]})
        for role, purpose, scope in [("registrar", "land-registration", "registry:landholding:register"), ("reader", "land-registration-audit", "registry:landholding:read")]:
            (secret_root / f"landholding-{role}-token").write_text(token(oidc_key, oidc_jwk["kid"], role, purpose, scope))
        (secret_root / "audit-key").write_text(secrets.token_hex(32))
        (secret_root / "cursor-key").write_text(secrets.token_hex(32))
        database_id = "farmer-evidence-local-db"
        anchor = root / "trust-anchor.json"
        write(anchor, {"apiVersion": "registry.registrystack.org/package-trust/v1", "databaseId": database_id, "environment": package["environment"], "instanceId": package["instanceId"], "keys": [{"jwk": signer_jwk, "keyId": signer_jwk["kid"]}], "threshold": 1}, canonical=True)
        for role in (migration, runtime_role):
            sql(admin.path.lstrip("/") or "postgres", f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD \'{password}\';')
            created_roles.append(role)
        for index, database in enumerate(databases):
            sql(admin.path.lstrip("/") or "postgres", f'CREATE DATABASE "{database}";')
            created_databases.append(database)
            statements = ["CREATE EXTENSION IF NOT EXISTS btree_gist;", f'REVOKE ALL ON DATABASE "{database}" FROM PUBLIC;', f'GRANT CONNECT ON DATABASE "{database}" TO "{migration}", "{runtime_role}";']
            for schema in ("registry_internal", "registry_data", "registry_source", "registry_derived", "registry_context"):
                statements += [f'CREATE SCHEMA {schema} AUTHORIZATION "{migration}";', f'REVOKE ALL ON SCHEMA {schema} FROM PUBLIC;']
            sql(database, "\n".join(statements))
            for role, label in [(migration, "migration"), (runtime_role, "runtime")]:
                url = urlunsplit((admin.scheme, f"{quote(role)}:{password}@{admin.hostname}:{admin.port or 5432}", f"/{database}", "", ""))
                (secret_root / f"{label}-{index}").write_text(url)
            runtime = {
                "apiVersion": "registry.registrystack.org/breg-runtime/v1alpha1", "kind": "BRegRuntimeConfig", "listener": {"bind": "127.0.0.1:0"},
                "identity": {"environment": package["environment"], "instanceId": package["instanceId"], "databaseId": database_id, "databaseInitializationEnvironment": package["environment"]},
                "secretProviders": {"file": {"root": str(secret_root)}},
                "database": {"runtimeUrlRef": f"secret:file/runtime-{index}", "migrationUrlRef": f"secret:file/migration-{index}", "pool": {"maxSize": 4, "waitTimeoutMilliseconds": 1000, "createTimeoutMilliseconds": 1000, "recycleTimeoutMilliseconds": 1000}, "roles": {"migration": migration, "runtime": runtime_role}},
                "package": {"root": str(root / "empty-package"), "trustAnchorPath": str(anchor), "compilerSourceRevision": package["sourceRevision"], "activeRevision": "sha256:" + "1" * 64, "activeSequence": 1},
                "authentication": {"oidc": {"issuer": "https://issuer.example/change-request-example", "audience": "urn:breg:change-request-example", "allowedAlgorithm": "EdDSA", "accessTokenType": "JWT", "scopeClaim": "scope", "scopeSeparator": " ", "allowedClients": ["registry-change-request-example"], "deniedKids": [], "maxTokenLifetimeSeconds": 3600, "leewayMilliseconds": 60000, "jwksCache": {"cacheTtlSeconds": 600, "negativeCacheTtlSeconds": 60, "refreshCooldownSeconds": 30, "maxDocumentBytes": 65536, "requestTimeoutMilliseconds": 5000, "outageToleranceSeconds": 0}, "jwksSource": {"kind": "static", "documentRef": "secret:file/oidc-jwks"}}, "authorityClaims": {"principal": "registry_principal", "purpose": "registry_purpose"}},
                "audit": {"hashKeyRef": "secret:file/audit-key"}, "cursor": {"secretRef": "secret:file/cursor-key", "maxAgeSeconds": 300}, "eventDestinations": {},
                "evidenceProviders": {"farmer-registry": {"baseUrl": ready["baseUrl"], "trustBindingId": "synthetic-farmer-live", "tokenRef": "secret:file/evidence-token", "trustedJwksRef": "secret:file/evidence-jwks", "revokedKeyIds": []}},
                "operationalTimeouts": {"httpRequestMilliseconds": 10000, "shutdownGraceMilliseconds": 30000, "recordLockMilliseconds": 5000, "migrationLockMilliseconds": 30000, "migrationStatementMilliseconds": 60000},
            }
            (root / f"runtime-{index}.yaml").write_text(yaml.safe_dump(runtime, sort_keys=False))
        (root / "empty-package").mkdir()
        journeys = yaml.safe_load((project / "tests/journeys.yaml").read_text())
        bindings = [{"journeyId": journey["id"], "stepId": step["id"], "credential": {"type": "bearer", "tokenRef": f'secret:file/{step["accessProfile"]}-token'}} for journey in journeys["journeys"] for step in journey["steps"]]
        credentials = root / "credentials.json"
        write(credentials, {"apiVersion": "registry.registrystack.org/breg-schema-test-credentials/v1", "kind": "SchemaTestCredentials", "bindings": bindings})
        command = [sys.executable, str(project_source / "tests/live_registration.py"), "--project", str(project), "--test-runtime", str(root / "runtime-0.yaml"), "--runtime", str(root / "runtime-1.yaml"), "--credentials", str(credentials), "--signer", str(signer), "--secrets", str(secret_root), "--output", str(root / "journey"), "--bregctl", str(args.bregctl.resolve()), "--breg", str(args.breg.resolve()), "--requests", ready["requestsFile"]]
        subprocess.run(command, env=child_env, check=True)
        # Only committed acquisitions are retained. Inactive and blank refusals
        # cannot silently become an assertion archive.
        retained = sql(databases[1], "COPY (SELECT count(*) FROM registry_internal.registry_action_evidence_uses) TO STDOUT;")
        if retained != "2":
            raise RuntimeError("live action did not retain exactly its two committed acquisitions")
        acl = sql(databases[1], f"COPY (SELECT has_table_privilege('{runtime_role}', 'registry_internal.registry_action_evidence_uses', 'SELECT'), has_table_privilege('{runtime_role}', 'registry_internal.registry_action_evidence_uses', 'INSERT'), has_table_privilege('{runtime_role}', 'registry_internal.registry_action_evidence_uses', 'DELETE')) TO STDOUT;")
        if acl != "f\tt\tf":
            raise RuntimeError("runtime evidence retention privileges are not INSERT-only")
        retained_bytes = int(sql(databases[1], "COPY (SELECT coalesce(sum(octet_length(retained::text)),0) FROM registry_internal.registry_action_evidence_uses) TO STDOUT;"))
        action_cost = json.loads((root / "journey/action-cost.json").read_text())
        write(root / "retention-proof.json", {"committedAcquisitions": 2, "retainedJsonBytes": retained_bytes, **action_cost, "runtimeSelect": False, "runtimeInsert": True, "runtimeDelete": False})
        print(f"Synthetic two-call action: {action_cost['twoCallActionMilliseconds']} ms; retained acquisitions: 2; retained JSON bytes: {retained_bytes}")
    finally:
        if provider:
            provider.terminate()
            try:
                provider.wait(timeout=10)
            except subprocess.TimeoutExpired:
                provider.kill()
                provider.wait()
        for database in reversed(created_databases):
            sql(admin.path.lstrip("/") or "postgres", f'DROP DATABASE "{database}" WITH (FORCE);')
        for role in reversed(created_roles):
            sql(admin.path.lstrip("/") or "postgres", f'DROP ROLE "{role}";')
    print(f"Owner-only trial evidence: {root}")


if __name__ == "__main__":
    main()
