#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Support module for the Registry Scheduling local acceptance demo.

The demo drives the real `scheduling` and `schedulingctl` binaries against a
disposable PostgreSQL database and proves four acceptance scenarios over the
public HTTP contract (see products/scheduling/demo/README.md):

- AT-01  two callers confirm against the last unit concurrently;
- AT-05  a hold expires and capacity reopens while late confirmation fails;
- AT-06  a lost confirmation response replays under the same idempotency key;
- AT-19  a weekly opening across a daylight-saving fold serves the moved grid.

Authentication is real: the script generates an RSA key pair, publishes the
public key as a static JWKS document the runtime verifies, and signs RFC 9068
access tokens for each demo caller, including the task grants the mutating
routes demand. Nothing here is a credential beyond this throwaway run
directory, and no secret is printed.

Python 3 standard library only, like every Registry Stack support script.
"""

import argparse
import base64
import json
import secrets
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# The fixed demo identities. The issuer and audience never leave the run
# directory; the clients are the three callers the runtime config admits.
DEMO_ISSUER = "https://issuer.scheduling-demo.invalid"
DEMO_AUDIENCE = "scheduling-demo"
DEMO_KEY_ID = "scheduling-demo-1"
BOOKER_A = "demo-booker-a"
BOOKER_B = "demo-booker-b"
READER = "demo-reader"

# The task-grant permissions every booking caller carries: one permission per
# location, naming the offering's service and the actions the demo exercises.
GRANT_PERMISSIONS = [
    {
        "service": "registry-update",
        "location": "bangkok-counter",
        "actions": [
            "hold.create",
            "hold.release",
            "appointment.create",
            "appointment.reschedule",
            "appointment.cancel",
        ],
    },
    {
        "service": "registry-update",
        "location": "new-york-hall",
        "actions": [
            "appointment.create",
            "appointment.reschedule",
            "appointment.cancel",
        ],
    },
]

# The offering and slot facts the scenarios pin. The Bangkok counter opens
# 2026-10-01 (a Thursday) at 09:00 local (02:00Z in Asia/Bangkok); the grid
# steps in 30-minute increments. The fold-day offering serves 2026-11-01,
# where America/New_York falls back and the closure moves the grid anchor.
BANGKOK_OFFERING = "registry-update-30"
BANGKOK_RACE_START = "2026-10-01T02:00:00Z"
# The counter offering carries five-minute buffers before and after each
# booking, so back-to-back grid slots conflict on the one station. The three
# committed Bangkok bookings (race, hold, replay) therefore sit an hour apart.
BANGKOK_HOLD_START = "2026-10-01T04:00:00Z"
BANGKOK_REPLAY_START = "2026-10-01T03:00:00Z"
BANGKOK_REPLAY_CHANGED_START = "2026-10-01T03:30:00Z"
BANGKOK_DAY_START = "2026-10-01T00:00:00Z"
BANGKOK_DAY_END = "2026-10-02T00:00:00Z"

FOLD_OFFERING = "fold-day-update-30"
FOLD_DAY_START = "2026-11-01T00:00:00Z"
FOLD_DAY_END = "2026-11-02T00:00:00Z"
# America/New_York folds on 2026-11-01: the 00:30-02:30 opening spans
# [04:30Z, 07:30Z), and the 00:15-00:45 closure moves the grid anchor to
# 04:45Z. 06:30Z is a wall-clock match off the moved grid and must not serve.
FOLD_FIRST_SLOT = "2026-11-01T04:45:00Z"
FOLD_SERVED_SLOTS = [
    "2026-11-01T04:45:00Z",
    "2026-11-01T05:15:00Z",
    "2026-11-01T05:45:00Z",
]
FOLD_UNSERVED_START = "2026-11-01T06:30:00Z"
FOLD_BOOKED_START = "2026-11-01T05:15:00Z"


def b64url(raw: bytes) -> str:
    """Base64url without padding, the JWT and JWK encoding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------
# Minimal DER reading for one purpose: turn an RSA SubjectPublicKeyInfo into
# the JWK the runtime's JWKS verifier accepts. No third-party library is
# available to support scripts, so the two-byte header walk lives here.
# --------------------------------------------------------------------------

def _der_tlv(data: bytes, offset: int) -> tuple[int, bytes, bytes]:
    """Read one DER tag-length-value at `offset`, returning the tag, the
    value bytes, and the buffer that follows it."""
    tag = data[offset]
    length = data[offset + 1]
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[offset + 2 : offset + 2 + size], "big")
        offset += 2 + size
    else:
        offset += 2
    return tag, data[offset : offset + length], data[offset + length :]


def rsa_public_jwk(public_der: bytes) -> dict:
    """Build the RS256 JWK for an RSA SubjectPublicKeyInfo document."""
    outer_tag, spki, remainder = _der_tlv(public_der, 0)
    if outer_tag != 0x30 or remainder:
        raise ValueError("the public key is not one DER sequence")
    _, _, after_algorithm = _der_tlv(spki, 0)
    bit_tag, bit_string, _ = _der_tlv(after_algorithm, 0)
    if bit_tag != 0x03:
        raise ValueError("the SubjectPublicKeyInfo carries no bit string")
    _, rsa_pair, _ = _der_tlv(bit_string[1:], 0)
    _, modulus_raw, after_modulus = _der_tlv(rsa_pair, 0)
    _, exponent_raw, _ = _der_tlv(after_modulus, 0)
    modulus = modulus_raw.lstrip(b"\x00")
    exponent = exponent_raw.lstrip(b"\x00")
    if not modulus or not exponent:
        raise ValueError("the RSA public key integers are empty")
    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": DEMO_KEY_ID,
        "n": b64url(modulus),
        "e": b64url(exponent),
    }


# --------------------------------------------------------------------------
# Token minting. The header is an RFC 9068 access token (`typ: at+jwt`); the
# signing itself is delegated to openssl so no signing code lives here.
# --------------------------------------------------------------------------

def openssl_sign(signing_input: bytes, key_path: Path) -> bytes:
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key_path)],
        input=signing_input,
        capture_output=True,
        check=True,
    )
    return result.stdout


def mint_token(signer, claims: dict) -> str:
    header = {"alg": "RS256", "typ": "at+jwt", "kid": DEMO_KEY_ID}
    encoded_header = b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signature = b64url(signer(f"{encoded_header}.{encoded_payload}".encode()))
    return f"{encoded_header}.{encoded_payload}.{signature}"


def caller_claims(
    client: str,
    subject: str,
    scopes: list[str] | None = None,
    grant: bool = False,
    now: int | None = None,
) -> dict:
    """One caller's claims: identity, actor kind, scopes, and an optional
    task grant whose scheduling permissions cover the demo's offerings."""
    issued_at = int(time.time()) if now is None else now
    claims = {
        "iss": DEMO_ISSUER,
        "aud": DEMO_AUDIENCE,
        "sub": subject,
        "iat": issued_at,
        "exp": issued_at + 3600,
        "client_id": client,
        "registry_actor_kind": "service",
    }
    if scopes is not None:
        claims["registry_scopes"] = scopes
    if grant:
        claims.update(
            {
                "registry_grant_id": f"grant-{secrets.token_hex(8)}",
                "registry_grant_source_issuer": DEMO_ISSUER,
                "registry_grant_client": client,
                "registry_grant_resource": DEMO_AUDIENCE,
                "registry_grant_exp": issued_at + 3600,
                "registry_grant_bounds": {
                    "type": "scheduling",
                    "permissions": GRANT_PERMISSIONS,
                },
                # A complete grant names its purpose and its approver beside
                # the six registry_grant_* members; an incomplete set is
                # refused as a credentials problem, not honored partially.
                "registry_purpose": "registry-update",
                "registry_approver": "demo-approver",
            }
        )
    return claims


def admission_body(offering: str, start: str, policy_revision: int, subject: str) -> dict:
    """One admission request body. The example policy keys duplicate-active
    bookings by subject, so each caller names itself as the duplicate key the
    same way the offering's policy prescribes."""
    return {
        "offering": offering,
        "start": start,
        "party": {"recipients": 1, "attendees": 1},
        "duplicateKey": subject,
        "policyRevision": policy_revision,
        "capabilities": [],
        "prerequisites": [],
    }


# --------------------------------------------------------------------------
# HTTP over the public contract.
# --------------------------------------------------------------------------

def request(
    method: str,
    base_url: str,
    path: str,
    token: str | None = None,
    idempotency_key: str | None = None,
    body: dict | None = None,
    query: dict | None = None,
) -> tuple[int, dict | None]:
    url = f"{base_url}{path}"
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    payload = None
    headers = {"accept": "application/json"}
    if body is not None:
        payload = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    if idempotency_key is not None:
        headers["idempotency-key"] = idempotency_key
    call = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(call, timeout=15) as response:
            raw = response.read()
            document = json.loads(raw) if raw else None
            return response.status, document
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw else None


def parse_instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def wait_until(deadline: datetime) -> None:
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    if remaining > 0:
        time.sleep(remaining + 0.5)


# --------------------------------------------------------------------------
# The authoring pieces `run.sh` needs written before the runtime starts.
# --------------------------------------------------------------------------

def shorten_hold_ttl(policy_text: str) -> str:
    """Set the hold TTL to one minute so the expiry scenario runs quickly."""
    marker = "ttlMinutes: 5"
    if policy_text.count(marker) != 1:
        raise ValueError("the template policy does not carry exactly one five-minute hold TTL")
    return policy_text.replace(marker, "ttlMinutes: 1")


DEMO_RECORDS = """\
# Live environment records for the scheduling demo: one interchangeable
# station at the Bangkok counter (so the race scenario competes for the last
# unit), one at the New York hall, and the fold-day prep closure that moves
# the 2026-11-01 grid anchor past 04:45Z.
locations:
  - id: bangkok-counter
    timezone: Asia/Bangkok
  - id: new-york-hall
    timezone: America/New_York
pools:
  - id: update-stations
    members:
      - resourceId: station-1
        capabilities: []
        available: true
  - id: hall-stations
    members:
      - resourceId: hall-station-1
        capabilities: []
        available: true
exceptions:
  - id: hall-prep
    location: new-york-hall
    kind: closure
    date: "2026-11-01"
    startTime: "00:15"
    endTime: "00:45"
"""


# The OpenSSL config fragments the throwaway database TLS materials need.
# The runtime's released binary requires TLS to PostgreSQL, so the demo
# generates a two-day certificate authority, a server certificate for
# loopback, and trusts exactly that authority in its runtime configuration.
CA_REQUEST_CONFIG = """\
[req]
distinguished_name = name
x509_extensions = ca
prompt = no
[name]
CN = Scheduling Demo Database CA
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
"""

SERVER_SIGN_CONFIG = """\
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1,DNS:localhost
"""


def generate_database_tls(root: Path) -> None:
    """Generate the demo's throwaway database PKI: a certificate authority
    under the secrets root (the trust the runtime configuration names) and a
    server key pair the demo's PostgreSQL container serves."""
    tls = root / "db-tls"
    tls.mkdir()
    (tls / "ca.cnf").write_text(CA_REQUEST_CONFIG)
    (tls / "server.ext").write_text(SERVER_SIGN_CONFIG)
    run = lambda arguments: subprocess.run(  # noqa: E731
        ["openssl", *arguments], check=True, capture_output=True, cwd=tls
    )
    run([
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-keyout", "ca.key", "-out", "ca.crt", "-config", "ca.cnf",
    ])
    run([
        "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", "server.key", "-out", "server.csr",
        "-subj", "/CN=localhost",
    ])
    run([
        "x509", "-req", "-in", "server.csr",
        "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "server.crt", "-days", "2",
        "-extfile", "server.ext", "-extensions", "server",
    ])
    # Refuse a certificate the extensions never reached: an extension-free
    # server certificate is rejected only at connection time, far from its
    # cause, and the silent form of this failure is exactly that.
    names = subprocess.run(
        ["openssl", "x509", "-in", "server.crt", "-noout", "-ext", "subjectAltName"],
        check=True, capture_output=True, text=True, cwd=tls,
    ).stdout
    if "IP Address:127.0.0.1" not in names and "DNS:localhost" not in names:
        raise SystemExit("the demo server certificate carries no subjectAltName")


def runtime_config(
    project: Path,
    secrets_root: Path,
    audit_path: Path,
    port: int,
    trusted_root_ca: Path | None,
) -> str:
    trust = (
        f"  trustedRootCertificateRef: secret:file/db-root-ca\n"
        if trusted_root_ca is not None
        else ""
    )
    return f"""\
apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1
kind: SchedulingRuntimeConfig
package:
  root: {project}
listener:
  bind: 127.0.0.1:{port}
  tlsTermination: development-loopback
secretProviders:
  file:
    root: {secrets_root}
database:
  runtimeUrlRef: secret:file/db-url
  migrationUrlRef: secret:file/db-url
{trust}authentication:
  oidc:
    issuer: {DEMO_ISSUER}
    audience: {DEMO_AUDIENCE}
    allowedClients: [{BOOKER_A}, {BOOKER_B}, {READER}]
    jwksSource:
      kind: static
      documentRef: secret:file/jwks
audit:
  path: {audit_path}
  hashKeyRef: secret:file/audit-key
retention: {{}}
destinations:
  reminders: null
  hooks: {{}}
"""


def prepare(
    root: Path,
    example: Path,
    database_url: str,
    port: int,
    database_root_ca: Path | None,
) -> None:
    """Lay out the run directory: project copy, key material, records, and
    the runtime configuration, all owner-only."""
    project = root / "project"
    shutil.copytree(example, project)
    policy_path = project / "scheduling.yaml"
    policy_path.write_text(shorten_hold_ttl(policy_path.read_text()))

    signing_key = root / "demo-signing-key.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(signing_key),
        ],
        check=True,
        capture_output=True,
    )
    public_der = subprocess.run(
        ["openssl", "rsa", "-in", str(signing_key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    jwks = {"keys": [rsa_public_jwk(public_der)]}

    secrets_root = root / "secrets"
    secrets_root.mkdir()
    audit_dir = root / "audit"
    audit_dir.mkdir()
    # The audit path is the journal file itself; its advisory lock file is
    # created beside it.
    audit_path = audit_dir / "audit.jsonl"
    # The demo always generates its own database PKI: the demo container
    # serves it, and the runtime trusts exactly its authority. An external
    # --database-url server presents some other chain, so the operator names
    # the authority to trust instead and the demo materials stay unused.
    generate_database_tls(root)
    trust_root: Path | None = None
    if database_root_ca is None:
        (secrets_root / "db-root-ca").write_bytes((root / "db-tls" / "ca.crt").read_bytes())
        trust_root = secrets_root / "db-root-ca"
    elif database_root_ca.is_file():
        (secrets_root / "db-root-ca").write_bytes(database_root_ca.read_bytes())
        trust_root = secrets_root / "db-root-ca"
    else:
        raise SystemExit(f"the database root CA does not exist: {database_root_ca}")
    # Secret files carry no trailing newline: every byte is the secret.
    (secrets_root / "db-url").write_text(database_url)
    (secrets_root / "jwks").write_text(json.dumps(jwks, separators=(",", ":")))
    (secrets_root / "audit-key").write_text(secrets.token_hex(32))
    (root / "records.yaml").write_text(DEMO_RECORDS)
    (root / "runtime.yaml").write_text(
        runtime_config(
            project.resolve(), secrets_root.resolve(), audit_path.resolve(), port, trust_root
        )
    )


# --------------------------------------------------------------------------
# The four acceptance scenarios.
# --------------------------------------------------------------------------

class Verifier:
    def __init__(self, base_url: str, signing_key: Path) -> None:
        self.base_url = base_url
        self.signer = lambda data: openssl_sign(data, signing_key)
        self.failures: list[str] = []
        self.checks = 0
        status, document = request("GET", base_url, "/v1/scheduling", token=self.reader_token())
        self.check("the deployment answers its service document", status == 200,
                   f"status={status} body={document}")
        if document is None or "policyRevision" not in document:
            raise SystemExit("the running deployment did not answer /v1/scheduling")
        self.policy_revision = document["policyRevision"]

    def check(self, claim: str, holds: bool, evidence: str = "") -> None:
        self.checks += 1
        if holds:
            print(f"  pass: {claim}")
        else:
            print(f"  FAIL: {claim}{': ' + evidence if evidence else ''}")
            self.failures.append(claim)

    def reader_token(self) -> str:
        return mint_token(
            self.signer,
            caller_claims(READER, "demo-catalogue-reader", scopes=["scheduling-read"]),
        )

    def booker_token(self, name: str, subject: str) -> str:
        return mint_token(self.signer, caller_claims(name, subject, grant=True))

    def admission(self, offering: str, start: str, subject: str) -> dict:
        return admission_body(offering, start, self.policy_revision, subject)

    def availability(self, token: str, offering: str, start: str, end: str) -> list[dict]:
        _, document = request(
            "GET",
            self.base_url,
            "/v1/availability",
            token=token,
            query={"offering": offering, "start": start, "end": end},
        )
        return document["items"] if document else []

    def race_for_the_last_unit(self) -> None:
        """AT-01: two callers confirm against the last unit concurrently; at
        most one claim succeeds and the loser receives a recoverable
        capacity conflict."""
        print("AT-01: two callers race for the last station")
        reader = self.reader_token()
        slots = self.availability(reader, BANGKOK_OFFERING, BANGKOK_DAY_START, BANGKOK_DAY_END)
        race_slot = next(
            (item for item in slots if item["kind"] == "slot"
             and parse_instant(item["start"]) == parse_instant(BANGKOK_RACE_START)),
            None,
        )
        self.check("the raced slot is published with one free unit",
                   race_slot is not None and race_slot["free"] == 1,
                   json.dumps(race_slot))

        bodies: list[tuple[int, dict | None]] = []
        barrier = threading.Barrier(2)

        def fire(client: str, subject: str, key: str) -> None:
            barrier.wait()
            bodies.append(request(
                "POST",
                self.base_url,
                "/v1/appointments",
                token=self.booker_token(client, subject),
                idempotency_key=key,
                body={"admission": self.admission(BANGKOK_OFFERING, BANGKOK_RACE_START, subject)},
            ))

        threads = [
            threading.Thread(target=fire, args=(BOOKER_A, "demo-race-a", "demo-race-a")),
            threading.Thread(target=fire, args=(BOOKER_B, "demo-race-b", "demo-race-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        statuses = sorted(status for status, _ in bodies)
        codes = [document.get("code") if document else None for _, document in bodies]
        self.check("exactly one confirmation succeeds and one is refused",
                   statuses == [201, 409], f"statuses={statuses} codes={codes}")
        self.check("the loser receives the recoverable capacity conflict",
                   "capacity.exhausted" in codes, f"codes={codes}")

        after = self.availability(reader, BANGKOK_OFFERING, BANGKOK_DAY_START, BANGKOK_DAY_END)
        raced = next(
            (item for item in after if item["kind"] == "slot"
             and parse_instant(item["start"]) == parse_instant(BANGKOK_RACE_START)),
            None,
        )
        # A fully committed slot is not offered at all: the page lists only
        # slots that hold a free unit.
        self.check("the raced slot holds no free unit afterwards",
                   raced is None or raced["free"] == 0,
                   json.dumps(raced))

    def hold_create(self) -> dict | None:
        """AT-05, first half: mint a hold and confirm its slot shows no free
        unit while the hold lives."""
        print("AT-05: a hold is minted, then expires")
        reader = self.reader_token()
        status, hold = request(
            "POST",
            self.base_url,
            "/v1/holds",
            token=self.booker_token(BOOKER_A, "demo-hold"),
            idempotency_key="demo-hold-create",
            body=self.admission(BANGKOK_OFFERING, BANGKOK_HOLD_START, "demo-hold"),
        )
        self.check("the hold is minted", status == 201 and hold is not None,
                   f"status={status} body={hold}")
        if status != 201 or hold is None:
            return None
        held_slot = next(
            (item for item in self.availability(reader, BANGKOK_OFFERING, BANGKOK_DAY_START, BANGKOK_DAY_END)
             if item["kind"] == "slot" and parse_instant(item["start"]) == parse_instant(BANGKOK_HOLD_START)),
            None,
        )
        # Like the raced slot, a held slot leaves the page entirely while no
        # free unit remains.
        self.check("the held slot shows no free unit while the hold lives",
                   held_slot is None or held_slot["free"] == 0,
                   json.dumps(held_slot))
        print(f"  the hold expires at {hold['expiresAt']}; the other scenarios run while its clock does")
        return hold

    def hold_expired(self, hold: dict) -> None:
        """AT-05, second half: after the TTL passes, capacity is bookable
        again and the late confirmation of the expired hold is refused. The
        store counts a hold only while it is unexpired at the observed now,
        so these outcomes do not depend on the cleanup worker having run."""
        reader = self.reader_token()
        booker = self.booker_token(BOOKER_A, "demo-hold")
        wait_until(parse_instant(hold["expiresAt"]))
        expired_slot = next(
            (item for item in self.availability(reader, BANGKOK_OFFERING, BANGKOK_DAY_START, BANGKOK_DAY_END)
             if item["kind"] == "slot" and parse_instant(item["start"]) == parse_instant(BANGKOK_HOLD_START)),
            None,
        )
        self.check("the expired hold's capacity is bookable again",
                   expired_slot is not None and expired_slot["free"] == 1,
                   json.dumps(expired_slot))
        status, problem = request(
            "POST",
            self.base_url,
            "/v1/appointments",
            token=booker,
            idempotency_key="demo-hold-confirm-late",
            body={"hold": hold["holdId"]},
        )
        self.check("late confirmation of the expired hold fails with hold.expired",
                   status == 410 and problem is not None and problem.get("code") == "hold.expired",
                   f"status={status} body={problem}")

    def lost_confirmation_replay(self) -> None:
        """AT-06: a confirmation commits but its response is lost; the
        same-key retry returns the original appointment and a changed
        payload under that key is refused."""
        print("AT-06: a lost confirmation replays under the same key")
        booker = self.booker_token(BOOKER_A, "demo-replay")
        key = "demo-replay-1"
        status, first = request(
            "POST",
            self.base_url,
            "/v1/appointments",
            token=booker,
            idempotency_key=key,
            body={"admission": self.admission(BANGKOK_OFFERING, BANGKOK_REPLAY_START, "demo-replay")},
        )
        self.check("the original confirmation commits", status == 201 and first is not None,
                   f"status={status}")
        if first is None:
            return
        # The response never reached the caller; the retry repeats the exact
        # request under the exact key.
        status, replay = request(
            "POST",
            self.base_url,
            "/v1/appointments",
            token=booker,
            idempotency_key=key,
            body={"admission": self.admission(BANGKOK_OFFERING, BANGKOK_REPLAY_START, "demo-replay")},
        )
        self.check("the same-key retry returns the original appointment",
                   status == 201 and replay is not None
                   and replay.get("appointmentId") == first["appointmentId"],
                   f"status={status}")
        status, problem = request(
            "POST",
            self.base_url,
            "/v1/appointments",
            token=booker,
            idempotency_key=key,
            body={"admission": self.admission(BANGKOK_OFFERING, BANGKOK_REPLAY_CHANGED_START, "demo-replay")},
        )
        self.check("a changed payload under that key is refused",
                   status == 409 and problem is not None
                   and problem.get("code") == "idempotency.key-reused",
                   f"status={status} body={problem}")

    def fold_day_grid(self) -> None:
        """AT-19: the Sunday opening across the 2026-11-01 New York fold
        serves the grid the closure moved (04:45Z anchor), never a
        wall-clock match off it, with no shifted commitment."""
        print("AT-19: the fold-day opening serves the moved grid")
        reader = self.reader_token()
        items = self.availability(reader, FOLD_OFFERING, FOLD_DAY_START, FOLD_DAY_END)
        slots = [item for item in items if item["kind"] == "slot"]
        starts = [parse_instant(item["start"]) for item in slots]
        self.check("the fold-day grid anchors at the moved 04:45Z start",
                   bool(starts) and min(starts) == parse_instant(FOLD_FIRST_SLOT),
                   json.dumps([item["start"] for item in slots]))
        for expected in FOLD_SERVED_SLOTS:
            self.check(f"the moved grid serves {expected}",
                       parse_instant(expected) in starts)
        self.check("the fold does not duplicate the pre-closure 04:30Z start",
                   parse_instant("2026-11-01T04:30:00Z") not in starts)
        self.check("the wall-clock match 06:30Z is not served",
                   parse_instant(FOLD_UNSERVED_START) not in starts)
        status, booked = request(
            "POST",
            self.base_url,
            "/v1/appointments",
            token=self.booker_token(BOOKER_A, "demo-fold-a"),
            idempotency_key="demo-fold-early",
            body={"admission": self.admission(FOLD_OFFERING, FOLD_BOOKED_START, "demo-fold-a")},
        )
        self.check("the moved-grid start books exactly as published",
                   status == 201 and booked is not None
                   and parse_instant(booked["start"]) == parse_instant(FOLD_BOOKED_START),
                   f"status={status}")
        status, problem = request(
            "POST",
            self.base_url,
            "/v1/appointments",
            token=self.booker_token(BOOKER_B, "demo-fold-b"),
            idempotency_key="demo-fold-wall-clock",
            body={"admission": self.admission(FOLD_OFFERING, FOLD_UNSERVED_START, "demo-fold-b")},
        )
        self.check("a wall-clock match off the moved grid is refused",
                   status == 422 and problem is not None
                   and problem.get("code") == "schedule.unpublished",
                   f"status={status} body={problem}")

    def run_all(self) -> int:
        self.race_for_the_last_unit()
        hold = self.hold_create()
        self.lost_confirmation_replay()
        self.fold_day_grid()
        if hold is not None:
            self.hold_expired(hold)
        print(f"{self.checks - len(self.failures)}/{self.checks} checks passed")
        if self.failures:
            for failure in self.failures:
                print(f"failed: {failure}")
            return 1
        return 0


def verify(base_url: str, signing_key: Path) -> int:
    # The four scenarios share no state except the deployment itself: each
    # books under its own subject, its own slot, and its own idempotency key.
    verifier = Verifier(base_url, signing_key)
    return verifier.run_all()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--root", type=Path, required=True)
    prepare_parser.add_argument("--example", type=Path, required=True)
    prepare_parser.add_argument("--database-url", required=True)
    prepare_parser.add_argument("--port", type=int, required=True)
    prepare_parser.add_argument("--database-root-ca", type=Path)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--base-url", required=True)
    verify_parser.add_argument("--signing-key", type=Path, required=True)

    arguments = parser.parse_args()
    if arguments.command == "prepare":
        prepare(
            arguments.root,
            arguments.example,
            arguments.database_url,
            arguments.port,
            arguments.database_root_ca,
        )
        return 0
    return verify(arguments.base_url, arguments.signing_key)


if __name__ == "__main__":
    raise SystemExit(main())
