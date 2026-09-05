#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
# SPDX-License-Identifier: Apache-2.0
"""Exercise real disposable issuers through BREG's authenticated router.

Uses the maintained Mint key helper and an ordinary Cargo integration test.
No existing containers, databases, or identity-provider accounts are touched.
Tokens, generated credentials, and private keys live only in a temporary directory.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import importlib.util
import json
import os
import secrets
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
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
KEYCLOAK = "quay.io/keycloak/keycloak:26.7.3@sha256:ff4257d0d64efbe99ed1ddfaf07765cc3c36dc7518bf8324d41961327f441c54"
AUDIENCE = "urn:breg:issuer-portability"
PRINCIPAL = "urn:institution:service-clerk"
HUMAN_PRINCIPAL = "urn:institution:human-clerk"
PURPOSE = "registry-administration"
POSTGRES_TEST = "mint_to_keycloak_continues_persisted_review_with_stable_principal"
ROUTER_TEST = "mint_and_keycloak_preserve_authority_and_cutover_rejects_the_old_issuer"


def write(path: Path, value: object, *, container_readable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = value if isinstance(value, str) else json.dumps(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(content)
    if container_readable:
        path.chmod(0o644)


def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
    # Keep subprocess output private: an issuer may include sensitive details
    # in an error. Failures expose only the step's executable and status.
    result = subprocess.run(args, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} step failed (exit {result.returncode})")
    return result


def build_test(target: str, features: str, test_name: str) -> str:
    result = subprocess.run(
        ["cargo", "test", "--locked", "-p", "registry-breg", "--features", features,
         "--test", target, "--no-run", "--message-format=json-render-diagnostics"],
        cwd=ROOT, stdout=subprocess.PIPE, check=True)
    executables = []
    for line in result.stdout.splitlines():
        event = json.loads(line)
        if (event.get("reason") == "compiler-artifact" and event["target"]["name"] == target
                and event.get("executable")):
            executables.append(event["executable"])
    if len(executables) != 1:
        raise RuntimeError(f"Cargo did not return one {target} test executable")
    executable = executables[0]
    listed = run([executable, test_name, "--ignored", "--exact", "--list"]).stdout.decode()
    if f"{test_name}: test" not in listed.splitlines():
        raise RuntimeError(f"the exact {target} test is absent; refusing an empty test run")
    return executable


def port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(url: str, data: dict | None = None, headers: dict | None = None, opener=None):
    body = None if data is None else urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, body, headers or {})
    return (opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))).open(req, timeout=10)


def wait_ready(url: str, deadline_seconds: int = 120, process=None) -> None:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("Mint exited before becoming ready; check its generated configuration")
        try:
            with request(url) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.5)
    raise RuntimeError("disposable issuer did not become ready")


def mapper(name: str, kind: str, config: dict) -> dict:
    return {"name": name, "protocol": "openid-connect", "protocolMapper": kind,
            "config": {"access.token.claim": "true", "id.token.claim": "false",
                       "userinfo.token.claim": "false", **config}}


def realm(client_secret: str, password: str, callback: str) -> dict:
    authority = [
        mapper("stable principal", "oidc-usermodel-attribute-mapper", {
            "user.attribute": "registry_principal", "claim.name": "registry_principal",
            "jsonType.label": "String"}),
        mapper("district assignments", "oidc-usermodel-attribute-mapper", {
            "user.attribute": "districts", "claim.name": "districts",
            "jsonType.label": "String", "multivalued": "true"}),
        mapper("tenant assignment", "oidc-hardcoded-claim-mapper", {
            "claim.name": "tenant_claim", "claim.value": "tenant-a", "jsonType.label": "String"}),
        mapper("purpose", "oidc-hardcoded-claim-mapper", {
            "claim.name": "purpose", "claim.value": PURPOSE, "jsonType.label": "String"}),
        mapper("BREG resource", "oidc-audience-mapper", {"included.custom.audience": AUDIENCE}),
    ]
    client = {"protocol": "openid-connect", "enabled": True,
              "defaultClientScopes": [], "optionalClientScopes": ["registry.read"],
              "protocolMappers": authority, "directAccessGrantsEnabled": False,
              "fullScopeAllowed": False}
    assignments = {"registry_principal": [PRINCIPAL], "districts": ["district-a"]}
    return {
        "realm": "breg-issuer-journey", "enabled": True, "sslRequired": "none",
        "accessTokenLifespan": 300,
        "clientScopes": [{"name": "registry.read", "protocol": "openid-connect",
                          "attributes": {"include.in.token.scope": "true"}}],
        "clients": [
            {**client, "clientId": "clerk-service", "secret": client_secret,
             "publicClient": False, "serviceAccountsEnabled": True, "standardFlowEnabled": False},
            {**client, "clientId": "clerk-browser", "publicClient": True,
             "standardFlowEnabled": True, "serviceAccountsEnabled": False,
             "redirectUris": [callback], "attributes": {"pkce.code.challenge.method": "S256"}},
        ],
        "users": [
            {"username": "service-account-clerk-service", "enabled": True,
             "serviceAccountClientId": "clerk-service", "attributes": assignments},
            {"username": "synthetic-clerk", "enabled": True,
             "email": "clerk@example.test", "emailVerified": True,
             "firstName": "Synthetic", "lastName": "Clerk",
             "attributes": {**assignments, "registry_principal": [HUMAN_PRINCIPAL]},
             "credentials": [{"type": "password", "value": password, "temporary": False}]},
        ],
    }


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form" and attributes.get("id") == "kc-form-login":
            self.action = attributes.get("action")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LoopbackBrowserCookies(http.cookiejar.DefaultCookiePolicy):
    """Match browsers' trustworthy-loopback handling for this exact test origin."""

    def __init__(self, issuer: str):
        super().__init__()
        self.origin = urllib.parse.urlsplit(issuer)

    def return_ok_secure(self, cookie, req):
        target = urllib.parse.urlsplit(req.full_url)
        if (target.scheme, target.netloc) == (self.origin.scheme, self.origin.netloc) and target.hostname == "127.0.0.1":
            return True
        return super().return_ok_secure(cookie, req)


def human_token(issuer: str, password: str, callback: str) -> str:
    # Follow the actual interactive authorization endpoint and its login form.
    # The callback redirect is intercepted locally; no password-grant shortcut.
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    authorization = issuer + "/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": "clerk-browser", "redirect_uri": callback, "response_type": "code",
        "scope": "openid registry.read", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256"})
    browser = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(LoopbackBrowserCookies(issuer))), NoRedirect())
    with request(authorization, opener=browser) as response:
        form = LoginForm()
        form.feed(response.read().decode())
    if not form.action or not form.action.startswith(issuer + "/"):
        raise RuntimeError("Keycloak did not return the expected issuer login form")
    try:
        with request(form.action, {"username": "synthetic-clerk", "password": password,
                                  "credentialId": ""}, opener=browser):
            raise RuntimeError("interactive login did not redirect with an authorization code")
    except urllib.error.HTTPError as response:
        if response.code != 302:
            error_page = response.read().decode()
            hint = ""
            for expected in ["Cookie not found", "Invalid username or password", "Invalid request", "Session not active", "Invalid code"]:
                if expected.lower() in error_page.lower():
                    hint = ": " + expected
                    break
            raise RuntimeError(f"interactive login failed (HTTP status {response.code}){hint}") from None
        location = response.headers.get("Location", "")
    parsed = urllib.parse.urlsplit(location)
    if urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")) != callback:
        raise RuntimeError("unexpected login callback")
    query = urllib.parse.parse_qs(parsed.query)
    if query.get("state") != [state] or len(query.get("code", [])) != 1:
        raise RuntimeError("authorization callback failed state/code validation")
    with request(issuer + "/protocol/openid-connect/token", {
        "grant_type": "authorization_code", "client_id": "clerk-browser",
        "redirect_uri": callback, "code": query["code"][0], "code_verifier": verifier,
    }) as response:
        return json.load(response)["access_token"]


def journey(root: Path, mint: str, docker: str, test_binaries: dict[str, str]) -> None:
    mint_origin = f"http://127.0.0.1:{port()}"
    keycloak_port = port()
    keycloak_origin = f"http://127.0.0.1:{keycloak_port}"
    issuer = keycloak_origin + "/realms/breg-issuer-journey"
    callback = f"http://127.0.0.1:{port()}/callback"
    key_helper = ROOT / "crates/registry-mint/demo/support/key_material.py"
    spec = importlib.util.spec_from_file_location("mint_key_material", key_helper)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    private, public = helper.p256_jwk()
    write(root / "keys/signing-p256-private-jwk", private)
    write(root / "keys/audit-hmac-key", secrets.token_hex(32))
    public_path = f"public-keys/{public['kid']}.jwk.json"
    write(root / public_path, public)
    fingerprint = run([mint, "client-secret", "generate", "--out", str(root / "client-secret")]).stdout.decode().strip()
    write(root / "clients/clerk.yaml", {
        "clientId": "clerk-service", "principal": PRINCIPAL,
        "authorization": {"scopes": ["registry.read"], "claims": {
            "registry_principal": PRINCIPAL, "purpose": PURPOSE, "districts": ["district-a"],
            "tenant_claim": "tenant-a"}},
        "clientAuthentication": {"method": "client-secret", "secretFingerprints": [fingerprint]}})
    write(root / "mint.json", {
        "version": 1, "validationMode": "supervised-local-development", "issuer": mint_origin,
        "listener": {"address": "127.0.0.1", "port": int(mint_origin.rsplit(":", 1)[1])},
        "signing": {"algorithm": "ES256", "activePublicJwkFile": public_path,
                    "publishedPublicJwkFiles": [], "revokedKeyIds": []},
        "signer": {"kind": "local-jwk", "privateKeyRef": "secret:file/signing-p256-private-jwk"},
        "secretProviders": {"file": {"root": str(root / "keys")}},
        "audit": {"path": "mint-audit.jsonl", "maximumFileBytes": 10485760,
                  "hashKeyRef": "secret:file/audit-hmac-key", "hashKeyVersion": 1},
        "accessTokens": {"audiences": [AUDIENCE], "lifetimeSeconds": 300},
        "clientAssertion": {"audience": mint_origin + "/token", "maximumLifetimeSeconds": 120,
                            "algorithms": ["ES256"]}, "clients": {"directory": "clients"}})
    client_secret, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    write(root / "import/realm.json", realm(client_secret, password, callback), container_readable=True)
    # Only the mounted import directory is traversable by the container user;
    # its owner-only host ancestor keeps generated login credentials private.
    (root / "import").chmod(0o755)
    name = "breg-issuer-journey-" + secrets.token_hex(6)
    process = None
    try:
        print("Starting disposable Mint and Keycloak issuers", flush=True)
        process = subprocess.Popen([mint, "serve", "--config", str(root / "mint.json")],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run([docker, "run", "--detach", "--name", name,
             "--publish", f"127.0.0.1:{keycloak_port}:8080",
             "--mount", f"type=bind,src={root / 'import'},dst=/opt/keycloak/data/import,readonly",
             KEYCLOAK, "start-dev", "--import-realm", "--hostname", keycloak_origin])
        wait_ready(mint_origin + "/ready", process=process)
        wait_ready(issuer + "/.well-known/openid-configuration")
        print("Obtaining the registered Mint machine token", flush=True)
        basic = base64.b64encode(("clerk-service:" + (root / "client-secret").read_text().strip()).encode()).decode()
        with request(mint_origin + "/token", {"grant_type": "client_credentials"},
                     {"Authorization": "Basic " + basic}) as response:
            write(root / "mint.token", json.load(response)["access_token"])
        for name_suffix, scope in [("service", "registry.read"), ("no-scope", "")]:
            print(f"Obtaining Keycloak {name_suffix} token", flush=True)
            with request(issuer + "/protocol/openid-connect/token", {
                "grant_type": "client_credentials", "client_id": "clerk-service",
                "client_secret": client_secret, **({"scope": scope} if scope else {})}) as response:
                write(root / f"{name_suffix}.token", json.load(response)["access_token"])
        print("Exercising human authorization-code login with PKCE", flush=True)
        write(root / "human.token", human_token(issuer, password, callback))
        with request(mint_origin + "/.well-known/openid-configuration") as response:
            mint_metadata = json.load(response)
        for provider, jwks_uri in [("mint", mint_metadata["jwks_uri"]),
                                   ("keycloak", issuer + "/protocol/openid-connect/certs")]:
            with request(jwks_uri) as response:
                write(root / f"{provider}-jwks.json", json.load(response))
        write(root / "journey.json", {
            "mint": {"issuer": mint_origin, "algorithm": "ES256", "token_type": "at+jwt", "jwks_file": "mint-jwks.json"},
            "keycloak": {"issuer": issuer, "algorithm": "RS256", "token_type": "JWT", "jwks_file": "keycloak-jwks.json"}})
        print("Verifying issued tokens, authority and issuer cutover in the real BREG router", flush=True)
        environment = dict(os.environ, BREG_ISSUER_JOURNEY_DIR=str(root))
        subprocess.run([test_binaries["router"], ROUTER_TEST, "--ignored", "--exact", "--nocapture"],
                       cwd=ROOT / "crates/registry-breg", env=environment, check=True)
        if "postgres" in test_binaries:
            print("Continuing a persisted PostgreSQL approval across the issuer change", flush=True)
            subprocess.run([test_binaries["postgres"], POSTGRES_TEST, "--ignored", "--exact", "--nocapture"],
                           cwd=ROOT / "crates/registry-breg", env=environment, check=True)
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        removed = subprocess.run([docker, "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if removed.returncode:
            print(f"Could not remove the disposable container {name}; inspect it with Docker", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mint", type=Path, help="matching built Mint executable; default: Cargo target debug/mint")
    parser.add_argument("--with-postgres", action="store_true",
                        help="also exercise persisted approval cutover against an explicitly disposable BREG_TEST_DATABASE_URL")
    args = parser.parse_args()
    docker = shutil.which("docker")
    if not docker:
        raise SystemExit("Docker is required for the disposable Keycloak service")
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    mint = (args.mint or target / "debug/mint").resolve()
    if not mint.is_file():
        raise SystemExit("Build Mint first: cargo build --locked -p registry-mint --bin mint")
    if args.with_postgres and not os.environ.get("BREG_TEST_DATABASE_URL"):
        raise SystemExit("--with-postgres requires BREG_TEST_DATABASE_URL pointing to a disposable test database")
    os.umask(0o077)
    # Compile before issuance: a first build must not consume token lifetime.
    print("Building the focused BREG router test before issuing short-lived tokens", flush=True)
    test_binaries = {"router": build_test("issuer_portability", "runtime", ROUTER_TEST)}
    if args.with_postgres:
        test_binaries["postgres"] = build_test("postgres_change_requests", "postgres-test,tooling", POSTGRES_TEST)
    def stop(signum, _frame):
        raise SystemExit(128 + signum)
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stop)
    with tempfile.TemporaryDirectory(prefix="breg-issuer-journey-") as temporary:
        journey(Path(temporary).resolve(), str(mint), docker, test_binaries)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, urllib.error.URLError, subprocess.CalledProcessError) as error:
        # Never print HTTP response bodies, redirect URLs/codes, or credentials.
        detail = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        if isinstance(error, urllib.error.HTTPError):
            detail = f"HTTP status {error.code}"
        raise SystemExit(f"Issuer journey failed: {detail}") from None
