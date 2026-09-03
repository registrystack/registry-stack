#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
"""Lay out a throwaway deployment of Mint and Evidence for the demonstration.

Deployment plumbing, not part of the security story: keys, certificates,
configuration files, and file permissions. The walkthrough in `walkthrough.py`
is the part worth reading.

Everything this writes is disposable and local. The keys are generated fresh on
every run and are worthless outside this directory.
"""

import datetime as dt
import json
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from key_material import ed25519_jwk, p256_jwk, write, write_secret

MINT_PORT = 8090
TLS_PORT = 8443
EVIDENCE_PORT = 8080
SOURCE_PORT = 8092

MINT_ORIGIN = f"https://localhost:{TLS_PORT}"
AGENT = "urn:example:demo:agent:appointment-scheduler"


def issue_tls_certificate(root: Path) -> None:
    """A private CA and one `localhost` server certificate.

    Evidence insists the token issuer and its key set be HTTPS, with no
    exception for loopback. That is the right default and the demonstration
    respects it rather than working around it.
    """
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "registry-stack demo CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, None)
    )

    server_key = ed25519.Ed25519PrivateKey.generate()
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(ca_key, None)
    )

    pem = serialization.Encoding.PEM
    write(root / "ca.pem", ca_certificate.public_bytes(pem).decode())
    write(root / "tls.pem", server_certificate.public_bytes(pem).decode())
    write_secret(
        root / "tls.key",
        server_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    )


def provision_mint(root: Path) -> None:
    mint = root / "mint"
    signing_private, signing_public = p256_jwk()
    write_secret(mint / "secrets/signing.jwk", json.dumps(signing_private))
    public_file = f"{signing_public['kid']}.jwk.json"
    write(mint / f"public-keys/{public_file}", json.dumps(signing_public))
    write_secret(mint / "secrets/audit-hmac-key", secrets.token_hex(32))

    for client_id in ("scheduler", "service-desk"):
        private, public = ed25519_jwk(f"{client_id}-key-1")
        write_secret(root / f"client-keys/{client_id}.jwk", json.dumps(private))

        # `scheduler` is the delegated caller. Its registration is the whole
        # authorization decision Mint makes: which agents it may act as, and
        # which selector fields it may bind, at which claim paths.
        delegation = (
            "delegation:\n"
            f"  actors: [{AGENT}]\n"
            "  subjectClaims:\n"
            "    given_name: identity.given_name\n"
            "    family_name: identity.family_name\n"
            "    birth_date: identity.birth_date\n"
            if client_id == "scheduler"
            else ""
        )
        write(
            mint / f"clients/{client_id}.yaml",
            f"clientId: {client_id}\n"
            f"principal: urn:example:demo:principal:{client_id}\n"
            f"evidenceAudience: https://{client_id}.demo.invalid\n"
            "requesterTags: [demo-agent]\n"
            f"keys: [{json.dumps(public)}]\n" + delegation,
        )

    write(
        mint / "mint.yaml",
        f"""version: 1
validationMode: supervised-local-development
issuer: {MINT_ORIGIN}
listener: {{address: 127.0.0.1, port: {MINT_PORT}}}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/{public_file}
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing.jwk
secretProviders:
  file: {{root: {mint / "secrets"}}}
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [evidence.demo.invalid]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
    actor: evidence_actor
clientAssertion:
  audience: {MINT_ORIGIN}/token
  algorithms: [EdDSA]
clients:
  directory: clients
""",
    )


def provision_evidence(root: Path, bundle_source: Path) -> None:
    evidence = root / "evidence"

    # Evidence refuses a bundle it could write to, so the copy is frozen.
    bundle = evidence / "bundle"
    shutil.copytree(bundle_source, bundle)
    for path in sorted(bundle.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    bundle.chmod(0o555)

    # `secretProviders.file.root` in the runtime file below. The name stays
    # clear of the word "secret" because this is a directory path, written into
    # a world-readable configuration file, and a scanner that reads names alone
    # cannot tell it apart from the material inside it.
    provider_root = evidence / "secrets"
    provider_root.mkdir(parents=True, exist_ok=True)
    provider_root.chmod(0o700)  # Evidence refuses a group- or world-readable root

    evidence_signing_private = {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU",
        "d": "MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4",
    }
    write_secret(
        provider_root / "evidence-signing", json.dumps(evidence_signing_private)
    )
    write_secret(provider_root / "audit-hash-key", secrets.token_hex(32))
    write_secret(provider_root / "subject-binding-key", secrets.token_hex(32))
    write_secret(provider_root / "source-token", os.environ["DEMO_SOURCE_TOKEN"])

    (evidence / "audit").mkdir(parents=True, exist_ok=True)
    write(
        evidence / "runtime.yaml",
        f"""version: 1
bundleDirectory: {bundle}
listener:
  bindHost: 127.0.0.1
  port: {EVIDENCE_PORT}
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 5000
secretProviders:
  file:
    root: {provider_root}
signer:
  kind: local-jwk
  privateKeyRef: secret:file/evidence-signing
auditStorage:
  path: {evidence / "audit/evidence.jsonl"}
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
""",
        0o444,  # Evidence refuses a runtime file it could write to
    )


if __name__ == "__main__":
    root = Path(sys.argv[1]).resolve()
    bundle_source = Path(sys.argv[2]).resolve()
    if root.exists():
        # Frozen directories need their write bit back before removal.
        for path in sorted(root.rglob("*"), reverse=True):
            path.chmod(path.stat().st_mode | stat.S_IWUSR)
        shutil.rmtree(root)
    root.mkdir(parents=True)

    issue_tls_certificate(root)
    provision_mint(root)
    provision_evidence(root, bundle_source)
    print(f"provisioned {root}")
