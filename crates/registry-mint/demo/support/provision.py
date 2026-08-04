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

import base64
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

MINT_PORT = 8090
TLS_PORT = 8443
EVIDENCE_PORT = 8080
SOURCE_PORT = 8092

MINT_ORIGIN = f"https://localhost:{TLS_PORT}"
AGENT = "urn:example:demo:agent:appointment-scheduler"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def ed25519_jwk(kid: str) -> tuple[dict, dict]:
    """Return (private JWK, public JWK) for a fresh Ed25519 key."""
    private = ed25519.Ed25519PrivateKey.generate()
    x = b64(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    d = b64(
        private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x}
    return {**public_jwk, "d": d}, public_jwk


def write(path: Path, text: str, mode: int = 0o644) -> Path:
    """Write a file everyone on the machine may read: certificates, configuration."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def write_secret(path: Path, text: str) -> Path:
    """Write a file that is never wider than owner read/write, not even briefly.

    Creating the file and then narrowing it would leave a freshly generated
    signing key readable by anyone on the machine for the length of the write.
    `os.open` carries the mode into the creation; the `chmod` after it only
    undoes the umask.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    path.chmod(0o600)
    return path


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
    signing_private, _ = ed25519_jwk("mint-key-1")
    write_secret(mint / "secrets/signing.jwk", json.dumps(signing_private))
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
issuer: {MINT_ORIGIN}
listener: {{address: 127.0.0.1, port: {MINT_PORT}}}
signing:
  algorithm: EdDSA
  activeKeyId: mint-key-1
  activeKeyFile: secrets/signing.jwk
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyFile: secrets/audit-hmac-key
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

    signing_private, _ = ed25519_jwk("demo-evidence-key")
    write_secret(provider_root / "signing-key", json.dumps(signing_private))
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
