#!/usr/bin/env python3
"""Build synthetic authoring inputs for the minimal BReg Kubernetes smoke."""

import argparse
import base64
import copy
import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

ISSUER = "https://issuer.stack.example.test"
AUDIENCE = "urn:breg:local-directory"
CLIENT = "directory-client"
STEPS = {
    "create-contact": "editor",
    "read-contact": "editor",
    "conceal-contact-outside-jurisdiction": "foreign-editor",
    "obtain-email-condition": "editor",
    "update-contact-email": "editor",
    "read-updated-contact": "editor",
    "start-registration": "editor",
    "submit-registration": "editor",
}


def base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def token(key, role, zone):
    now = int(time.time())
    principal = "synthetic-directory-editor" if role == "editor" else "synthetic-foreign-editor"
    header = {"alg": "EdDSA", "typ": "at+jwt", "kid": "registry-lab"}
    claims = {
        "aud": AUDIENCE, "iss": ISSUER, "client_id": CLIENT, "sub": principal,
        "iat": now, "exp": now + 1800, "scope": "registry:directory:write",
        "registry_actor_kind": "service", "registry_principal": principal,
        "registry_purpose": "directory-administration", "jurisdiction": zone,
    }
    signing_input = ".".join(base64url(json.dumps(value).encode()) for value in (header, claims))
    with tempfile.NamedTemporaryFile() as message:
        message.write(signing_input.encode())
        message.flush()
        signature = subprocess.check_output(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", message.name]
        )
    return signing_input + "." + base64url(signature)


def build_inputs(root, host, database, test_database, public_origin, migration_password, runtime_password, ca):
    root.mkdir(mode=0o700)
    secret_root = root / "secrets"
    secret_root.mkdir(mode=0o700)
    key = root / "issuer.key"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True)
    public_key = subprocess.check_output(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"])
    write_json(secret_root / "issuer-jwks", {"keys": [{
        "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "kid": "registry-lab",
        "x": base64url(public_key[-32:]),
    }]})
    for name, zone in (("editor", "zone-a"), ("foreign-editor", "zone-b")):
        (secret_root / f"{name}-token").write_text(token(key, name, zone))
    for name in ("audit-key", "cursor-key"):
        (secret_root / name).write_text(secrets.token_hex(32))
    (secret_root / "database-ca").write_bytes(ca.read_bytes())
    for role, password in (("runtime", runtime_password), ("migration", migration_password)):
        username = f"registry_{role}"
        for prefix, database_name in (("", database), ("test-", test_database)):
            url = f"postgresql://{username}:{quote(password.read_text().strip(), safe='')}@{host}:5432/{database_name}"
            (secret_root / f"{prefix}{role}-database-url").write_text(url)

    runtime = {
        "apiVersion": "id.registrystack.org/formats/breg/runtime/v1alpha1",
        "kind": "BRegRuntimeConfig",
        "listener": {"bind": "0.0.0.0:8080", "publicOrigin": public_origin},
        "identity": {
            "environment": "production", "instanceId": "local-directory",
            "databaseId": "registry-lab-db", "databaseInitializationEnvironment": "production",
        },
        "secretProviders": {"file": {"root": "/etc/breg-secrets"}},
        "database": {
            "runtimeUrlRef": "secret:file/runtime-database-url",
            "migrationUrlRef": "secret:file/migration-database-url",
            "trustedRootCertificateRef": "secret:file/database-ca",
            "pool": {"maximumConnections": 4},
            "roles": {"migration": "registry_migration", "runtime": "registry_runtime"},
        },
        "package": {"root": "/var/lib/breg/package"},
        "authentication": {
            "oidc": {
                "issuer": ISSUER, "audience": AUDIENCE, "allowedAlgorithm": "EdDSA",
                "accessTokenType": "at+jwt", "scopeClaim": "scope", "scopeSeparator": " ",
                "allowedClients": [CLIENT], "maximumTokenLifetimeSeconds": 3600,
                "leewayMilliseconds": 30000,
                "jwksSource": {"type": "static", "documentRef": "secret:file/issuer-jwks"},
            },
            "authorityClaims": {"principal": "registry_principal", "purpose": "registry_purpose"},
        },
        "audit": {"hashKeyRef": "secret:file/audit-key", "destination": "file", "path": "/var/log/breg/audit.jsonl"},
        "cursor": {"secretRef": "secret:file/cursor-key"},
    }
    write_json(root / "runtime.json", runtime)
    test = copy.deepcopy(runtime)
    test["listener"] = {"bind": "127.0.0.1:8180"}
    test["secretProviders"]["file"]["root"] = "/proof/secrets"
    test["database"]["runtimeUrlRef"] = "secret:file/test-runtime-database-url"
    test["database"]["migrationUrlRef"] = "secret:file/test-migration-database-url"
    test["package"]["root"] = "/proof/empty-package"
    test["audit"]["path"] = "/proof/test-audit/audit.jsonl"
    write_json(root / "test-runtime.json", test)
    write_json(root / "credentials.json", {
        "apiVersion": "id.registrystack.org/formats/breg/schema-test-credentials/v1",
        "kind": "BRegSchemaTestCredentials",
        "bindings": [
            {"journeyId": "directory-contact", "stepId": step, "credential": {
                "type": "bearer", "tokenRef": f"secret:file/{role}-token",
            }} for step, role in STEPS.items()
        ],
    })
    (root / "empty-package").mkdir(mode=0o700)
    (root / "test-audit").mkdir(mode=0o700)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--database-host", required=True)
    parser.add_argument("--database-name", default="registry_breg")
    parser.add_argument("--test-database-name", default="registry_breg_test")
    parser.add_argument("--public-origin", required=True)
    parser.add_argument("--migration-password", type=Path, required=True)
    parser.add_argument("--runtime-password", type=Path, required=True)
    parser.add_argument("--database-ca", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    build_inputs(
        args.output, args.database_host, args.database_name, args.test_database_name, args.public_origin,
        args.migration_password, args.runtime_password, args.database_ca,
    )


if __name__ == "__main__":
    main()
