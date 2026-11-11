#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Rehearse, package, activate and exercise the licensing example with candidate binaries."""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
from secrets import token_hex
import shutil
import socket
import subprocess
from threading import Thread
import time
from urllib.error import URLError
from urllib.parse import unquote, urlsplit
from uuid import UUID

import fixture_path
fixture_path.ensure_importable()
from journey import HTTP, Journey, JourneyError, expect, request
from recovery import ScopeRecovery
from synthetic_source import Fixture, handler, runtime_fragment

PROJECT = Path(__file__).resolve().parents[2] / "examples/external-views"
ISSUER = "https://fixture-issuer.example.test/licensing"
AUDIENCE = "urn:breg:external-views-fixture"
KEY_ID = "external-views-fixture"
IDENTITIES = {
    "officer": ("officer", "human", "read"),
    "restricted": ("restricted", "human", "read"),
    "licensing-refresh": ("refresh", "service", "refresh"),
    "fixture-editor": ("editor", "service", "write"),
}
MANAGED_NOTIFIER = {"population-change-notifier": ("notifier", "service", "person-change-hint")}
URL_FILES = ("rehearsal-migration-url", "rehearsal-runtime-url", "migration-url", "runtime-url")


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def write_json(path, data):
    private_write(path, json.dumps(data, indent=2).encode("utf-8") + b"\n")


def database_urls(directory, destination):
    databases = []
    for name in URL_FILES:
        with (directory / name).open("rb") as stream:
            data = stream.read(4097).strip()
        expect(0 < len(data) <= 4096, "a fixture database URL file has an invalid size")
        try:
            target = urlsplit(data.decode("ascii"))
            port = target.port
        except (UnicodeError, ValueError):
            raise JourneyError("a fixture database URL is malformed") from None
        role = unquote(target.username or "")
        database = target.path.removeprefix("/")
        expect(
            target.scheme in ("postgresql", "postgres")
            and target.hostname in ("localhost", "127.0.0.1", "::1")
            and port is not None
            and re.fullmatch(r"breg_ext_[a-z0-9_]{1,45}", database)
            and re.fullmatch(r"[_a-z][_a-z0-9]{0,62}", role)
            and target.query == "sslmode=require"
            and not target.fragment,
            "use explicit loopback TLS URLs for fresh breg_ext_ fixture databases",
        )
        databases.append((target.hostname, port, database, role, data))
    rm, rr, dm, dr = databases
    expect(rm[:3] == rr[:3] and dm[:3] == dr[:3] and rm[:2] == dm[:2] and rm[2] != dm[2]
           and rm[3] == dm[3] and rr[3] == dr[3] and dm[3] != dr[3],
           "the rehearsal and deployment must be separate databases using the same split roles")
    for name, (*_, data) in zip(URL_FILES, databases):
        private_write(destination / name, data)
    return {"migration": dm[3], "runtime": dr[3]}


def command(work, name, args, report=False):
    with (work / f"{name}.stderr").open("xb") as error:
        result = subprocess.run(args, cwd=work, stdout=subprocess.PIPE, stderr=error, timeout=180,
                                check=False)
    if report:
        private_write(work / f"{name}.json", result.stdout)
    expect(result.returncode == 0, f"{name} failed. See the owner-only fixture logs.")
    return result.stdout


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def create_fixture_identity(work, keys, identities=IDENTITIES, token_lifetime=1800):
    signer = work / "fixture-signing-key.pem"
    command(work, "generate-fixture-key", ["openssl", "genpkey", "-algorithm", "ED25519", "-out", signer])
    signer.chmod(0o600)
    public = command(work, "derive-fixture-jwk", ["openssl", "pkey", "-in", signer, "-pubout", "-outform", "DER"])
    ed25519_prefix = bytes.fromhex("302a300506032b6570032100")
    expect(len(public) == len(ed25519_prefix) + 32 and public.startswith(ed25519_prefix),
           "OpenSSL did not produce the expected Ed25519 public key")
    write_json(keys / "oidc-jwks", {"keys": [{
        "alg": "EdDSA", "crv": "Ed25519", "kid": KEY_ID, "kty": "OKP",
        "x": b64(public[len(ed25519_prefix):]).decode("ascii"),
    }]})
    tokens = {}
    now = int(time.time())
    for client, (person, actor, scope) in identities.items():
        principal = f"synthetic-licensing-{person}"
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "sub": principal, "client_id": client,
            "iat": now, "exp": now + token_lifetime, "jti": token_hex(12),
            "scope": f"registry:licensing:{scope}", "registry_actor_kind": actor,
            "registry_principal": principal, "registry_purpose": "licensing", "jurisdiction": "zone-a",
        }
        signed = b".".join(
            b64(json.dumps(value, separators=(",", ":")).encode("utf-8"))
            for value in ({"alg": "EdDSA", "kid": KEY_ID, "typ": "JWT"}, claims)
        )
        input_file = work / f"{client}.signing-input"
        private_write(input_file, signed)
        signature = command(work, f"sign-{client}", [
            "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", signer, "-in", input_file,
        ])
        token = keys / f"{client}-token"
        private_write(token, signed + b"." + b64(signature))
        tokens[client] = token
    return tokens


def runtime_config(work, roles, pack, listener, prefix="", identities=IDENTITIES, token_lifetime=1800, **source):
    return {
        "apiVersion": "id.registrystack.org/formats/breg/runtime/v1alpha1", "kind": "BRegRuntimeConfig",
        "listener": {"bind": listener},
        "identity": {
            "environment": "acceptance", "instanceId": "external-views-fixture",
            "databaseId": prefix + "external-views-fixture", "databaseInitializationEnvironment": "acceptance",
        },
        "secretProviders": {"file": {"root": str(work / "secrets")}},
        "database": {
            "migrationUrlRef": f"secret:file/{prefix}migration-url",
            "runtimeUrlRef": f"secret:file/{prefix}runtime-url",
            "trustedRootCertificateRef": "secret:file/postgres-ca",
            "pool": {"maximumConnections": 4}, "roles": roles,
        },
        "package": {"root": str(pack)},
        "authentication": {
            "oidc": {
                "issuer": ISSUER, "audience": AUDIENCE, "allowedAlgorithm": "EdDSA",
                "accessTokenType": "JWT", "scopeClaim": "scope", "scopeSeparator": " ",
                "allowedClients": sorted(identities), "maximumTokenLifetimeSeconds": token_lifetime,
                "leewayMilliseconds": 30000,
                "jwksSource": {"type": "static", "documentRef": "secret:file/oidc-jwks"},
            },
            "authorityClaims": {"principal": "registry_principal", "purpose": "registry_purpose"},
        },
        "audit": {"hashKeyRef": "secret:file/audit-key", "path": str(work / "audit" / f"{prefix}audit.jsonl")},
        "cursor": {"secretRef": "secret:file/cursor-key"},
        **source,
    }


def verify_source_facts(facts, bindings, indexed_ttl):
    projection_ids = {"person-live", "person-indexed", "holdings-live", "holdings-indexed"}
    expect(isinstance(facts, dict) and set(facts) == {"apiVersion", "kind", "registryId", "revision", "projections"}
           and facts["apiVersion"] == "id.registrystack.org/formats/breg/external-source-facts/v1alpha1"
           and facts["kind"] == "BRegExternalSourceFacts" and facts["registryId"] == "synthetic-licensing"
           and isinstance(facts["revision"], str) and re.fullmatch(r"[A-Za-z0-9:._-]+", facts["revision"]),
           "source facts did not have the expected safe schema envelope")
    projections = facts["projections"]
    expect(isinstance(projections, list) and len(projections) == len(projection_ids)
           and all(isinstance(fact, dict) for fact in projections)
           and {fact.get("id") for fact in projections} == projection_ids,
           "source facts did not cover the four expected projections")
    expected = {binding["id"]: binding for binding in bindings["externalSources"]}
    for fact in projections:
        projection = fact["id"]
        binding = expected[projection]
        indexed = projection.endswith("-indexed")
        person = projection.startswith("person-")
        checked = {
            "id": projection, "mode": "indexed" if indexed else "live",
            "recordType": "person" if person else "holding",
            "authority": "urn:example:population-register" if person else "urn:example:business-register",
            "operation": ("person-batch" if indexed else "person-exact") if person else "holdings-by-business",
            "operationVersion": "1",
            "selectorScheme": "urn:example:person-number" if person else "urn:example:business-number",
            "purpose": "licensing", "scope": "licensing-holders" if person else "licensed-business-holdings",
            "fields": binding["allowedFields"], "connection": "synthetic-licensing",
            "cacheTtlSeconds": indexed_ttl if indexed else None,
        }
        expect(set(fact) == {*checked, "bindingDigest", "grantDigest", "grantValidUntil"}
               and all(fact[key] == value for key, value in checked.items())
               and all(re.fullmatch(r"sha256:[0-9a-f]{64}", fact[key]) for key in ("bindingDigest", "grantDigest"))
               and datetime.fromisoformat(fact["grantValidUntil"]) == datetime.fromisoformat(binding["grantValidUntil"]),
               "source facts did not match the approved fixture operation and fields")


def ready(server, origin):
    deadline = time.monotonic() + 30
    while server.poll() is None and time.monotonic() < deadline:
        try:
            with HTTP.open(origin + "/ready", timeout=1) as response:
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            time.sleep(0.1)
    raise JourneyError("the candidate runtime did not become ready; see the owner-only server log")


@contextmanager
def serving(breg, runtime, work, log_name, origin):
    with (work / log_name).open("xb") as log:
        with subprocess.Popen([breg, "--runtime-config", runtime], cwd=work,
                              stdout=log, stderr=subprocess.STDOUT) as server:
            try:
                ready(server, origin)
                yield
            finally:
                if server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=35)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()


def seed(origin, token):
    def create(route, number, selector, subject, zone):
        status, response = request(
            origin, f"/v1/records/{route}",
            {"Authorization": "Bearer " + token, "Idempotency-Key": f"external-view-fixture-{number}"},
            method="POST", query={"accessProfile": "fixture-editor"},
            body={"data": {"licenceNumber": number, selector: subject, "jurisdiction": zone}},
        )
        expect(status == 201, f"the candidate did not create the fixture {route} record")
        return UUID(response["data"]["recordIdentifier"])

    licences = [
        create("licences", f"L-{i:03}", "holderKey", key, "zone-b" if i == 6 else "zone-a")
        for i, key in enumerate(("person-7", "person-7", "person-8", "person-9", "person-10", "person-11"), 1)
    ]
    businesses = [
        create("licensed-businesses", f"B-{i:03}", "businessKey", f"business-{i}",
               "zone-b" if i == 3 else "zone-a")
        for i in range(1, 4)
    ]
    return licences[0], businesses[0]


def stage_project(source, work):
    paths = ("registry.yaml", "dev-clients.yaml", "tests/journeys.yaml")
    contents = {}
    for name in paths:
        path = source / name
        expect(not path.is_symlink() and not path.parent.is_symlink() and path.is_file(),
               "the saved native fixture must contain registry, dev-client and rehearsal files")
        with path.open("rb") as stream:
            data = stream.read(1_048_577)
        expect(0 < len(data) <= 1_048_576, "a saved native fixture file is empty or too large")
        contents[name] = data
    target = work / "saved-project"
    (target / "tests").mkdir(parents=True, mode=0o700)
    for name, data in contents.items():
        private_write(target / name, data)
    return target


def candidate_binary(path):
    expect(path.is_file() and os.access(path, os.X_OK), "a candidate binary is missing or is not executable")
    return path.resolve(strict=True)


def run(options):
    breg = candidate_binary(options.breg_bin)
    ctl = [candidate_binary(options.bregctl_bin), "--format", "json"]
    expect(shutil.which("openssl") is not None, "OpenSSL is required to generate the synthetic issuer")
    if options.scale:
        import scale_exercise as scale
        expect(shutil.which("psql") is not None, "psql is required to load the scale corpus")
        expect(options.postgres_plan_log is not None and options.postgres_plan_log.is_file(),
               "the scale exercise requires an existing PostgreSQL plan log")
    else:
        scale = None
    work = options.work_dir.resolve()
    work.mkdir(mode=0o700)
    os.umask(0o077)
    project = stage_project(options.project_dir, work) if options.project_dir is not None else PROJECT
    if scale:
        ttl = scale.MANAGED_TTL_SECONDS if options.managed_refresh else scale.FRESHNESS_SECONDS
        project = scale.scale_project(project, work, ttl)
    else:
        ttl = 300
    keys = work / "secrets"
    keys.mkdir()
    (work / "audit").mkdir()
    (work / "empty-package").mkdir()
    with options.postgres_ca_file.open("rb") as stream:
        ca = stream.read(65537)
    expect(0 < len(ca) <= 65536 and b"-----BEGIN CERTIFICATE-----" in ca, "the PostgreSQL CA file is invalid")
    roles = database_urls(options.database_url_dir, keys)
    private_write(keys / "postgres-ca", ca)
    for name in ("audit-key", "cursor-key", "source-key", "control-key"):
        private_write(keys / name, token_hex(32).encode("ascii"))

    identities = {**IDENTITIES, **MANAGED_NOTIFIER} if options.managed_refresh else IDENTITIES
    token_lifetime = 3600 if options.managed_refresh else 1800
    tokens = create_fixture_identity(work, keys, identities, token_lifetime)
    print("Rehearsing the fixture and building its checked package", flush=True)
    rehearsal = work / "rehearsal-runtime.json"
    write_json(rehearsal, runtime_config(work, roles, work / "empty-package", "127.0.0.1:0",
                                        prefix="rehearsal-", token_lifetime=token_lifetime))
    credentials = work / "rehearsal-credentials.json"
    write_json(credentials, {
        "apiVersion": "id.registrystack.org/formats/breg/schema-test-credentials/v1",
        "kind": "BRegSchemaTestCredentials",
        "bindings": [{"journeyId": "fixture-record-custody", "stepId": "create-licence",
                      "credential": {"type": "bearer", "tokenRef": "secret:file/fixture-editor-token"}}],
    })
    receipt = work / "test-receipt.json"
    command(work, "rehearsal", [*ctl, "test", project, "--runtime-config", rehearsal,
                                "--credentials", credentials, "--output", receipt], report=True)
    command(work, "package", [*ctl, "package", project, "--test-receipt", receipt,
                              "--output", work / "build"], report=True)

    source_key = (keys / "source-key").read_text(encoding="ascii")
    control_key = (keys / "control-key").read_text(encoding="ascii")
    if scale:
        fixture = scale.ScaleFixture(scale.SMOKE_CORPUS if options.managed_refresh_smoke else scale.SCALE_CORPUS)
    else:
        fixture = Fixture()
    recovery = None
    with ThreadingHTTPServer(("127.0.0.1", 0), handler(fixture, source_key, control_key)) as source:
        thread = Thread(target=source.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            source_origin = f"http://127.0.0.1:{source.server_port}"
            cutoff = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                address = f"127.0.0.1:{listener.getsockname()[1]}"
            runtime = work / "runtime.json"
            package = work / "build/package"
            bindings = runtime_fragment(source_origin, "source-key", cutoff)
            if options.managed_refresh:
                bindings["externalRefresh"] = scale.managed_runtime()
            write_json(runtime, runtime_config(work, roles, package, address, identities=identities,
                                               token_lifetime=token_lifetime, **bindings))
            facts_path = work / "external-source-facts.json"
            before_facts = fixture.status()
            command(work, "source-facts", [*ctl, "generate", "external-source-facts", project,
                                          "--runtime-config", runtime, "--output", facts_path])
            expect(facts_path.stat().st_mode & 0o077 == 0, "source facts were not owner-only")
            facts = json.loads(facts_path.read_text())
            verify_source_facts(facts, bindings, ttl)
            expect(fixture.status() == before_facts, "source facts generation contacted the source")
            print("Verified all four source bindings before activation", flush=True)
            print("Activating the package with split PostgreSQL roles", flush=True)
            command(work, "activation", [*ctl, "apply", "--runtime-config", runtime,
                                         "--package", package, "--initial"], report=True)
            origin = f"http://{address}"
            with serving(breg, runtime, work, "breg.log", origin):
                if scale:
                    scale.run_scale(work, package, origin, tokens, fixture, options.postgres_plan_log,
                                    {"breg": breg, "bregctl": ctl[0]}, managed=options.managed_refresh)
                    return
                print("Seeding ordinary records and checking the HTTP journey", flush=True)
                licence, business = seed(origin, tokens["fixture-editor"].read_text(encoding="ascii"))
                journey = Journey(argparse.Namespace(
                    breg_origin=origin, source_origin=source_origin,
                    officer_token_file=tokens["officer"], restricted_token_file=tokens["restricted"],
                    refresh_token_file=tokens["licensing-refresh"], control_key_file=keys / "control-key",
                    licence_root=licence, business_root=business,
                ))
                journey.run()
                print("Basic external view HTTP checks passed", flush=True)
                if options.recovery:
                    print("Withdrawing holdings scope during a paged refresh", flush=True)
                    recovery = ScopeRecovery(journey, fixture, work, facts, ctl, runtime, write_json)
                    recovery.withdraw_and_rotate()
            if options.recovery:
                expect(recovery is not None, "scope recovery did not run before the restart")
                print("Restarting and rebuilding the rotated holdings scope", flush=True)
                with serving(breg, runtime, work, "breg-restarted.log", origin):
                    recovery.verify_rebuild()
        finally:
            source.shutdown()
            thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--breg-bin", type=Path, required=True)
    parser.add_argument("--bregctl-bin", type=Path, required=True)
    parser.add_argument("--database-url-dir", type=Path, required=True, help="directory containing four fixture URL files")
    parser.add_argument("--postgres-ca-file", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True, help="new private directory for fixture evidence")
    parser.add_argument("--project-dir", type=Path, help="saved native project for the small fixture")
    parser.add_argument("--recovery", action="store_true", help="exercise small fixture scope withdrawal and restart")
    parser.add_argument("--scale", action="store_true", help="run the million-record acceptance fixture")
    parser.add_argument("--managed-refresh", action="store_true", help="exercise managed refresh with --scale")
    parser.add_argument("--managed-refresh-smoke", action="store_true",
                        help="use a 2,000-root corpus with --scale --managed-refresh")
    parser.add_argument("--postgres-plan-log", type=Path, help="dedicated PostgreSQL auto_explain log for --scale")
    options = parser.parse_args()
    if options.managed_refresh and not options.scale:
        parser.error("--managed-refresh requires --scale")
    if options.managed_refresh_smoke and not options.managed_refresh:
        parser.error("--managed-refresh-smoke requires --managed-refresh")
    if options.project_dir is not None and options.scale:
        parser.error("--project-dir applies to the small fixture")
    if options.recovery and options.scale:
        parser.error("--recovery applies to the small fixture")
    try:
        run(options)
    except (JourneyError, OSError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
        detail = str(error) if isinstance(error, JourneyError) else "fixture setup or response was refused"
        parser.exit(1, f"Candidate journey failed: {detail}\n")
    print("Candidate external view scale journey passed" if options.scale else "Candidate external view journey passed")


if __name__ == "__main__":
    main()
