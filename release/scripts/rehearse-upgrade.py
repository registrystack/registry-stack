#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rehearse the forward state path from the previous release to this source.

The rehearsal downloads the previous release's published Base Registry
Engine, Casework, Evidence, and Messaging binaries, authenticates them the way
release/VERIFY.md describes, and uses them to write real state: an
activated registry package with records and revisions, a Casework review
queue with answered and in-flight work, an Evidence audit stream with a
signed response, and a Messaging package ledger with scheduled and cancelled
messages. It then points the binaries built from this source at that
exact state, runs the documented upgrade steps, and fails unless the state is
still served unchanged and no table lost a row.
A product the previous release did not ship has no state to carry forward,
so its leg is omitted and the report says why.

Only the release download reaches the network. PostgreSQL runs in one
disposable, loopback-bound container, and every credential is synthetic,
generated for the run, and kept in owner-only files.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import release_roster  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "registrystack/registry-stack"
SIGNER_IDENTITY = (
    "https://github.com/registrystack/registry-stack/"
    ".github/workflows/release.yml@refs/heads/main"
)
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"
SEMVER_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256_LINE = re.compile(r"^([0-9a-f]{64})  ([^/\s][^/]*)$")
FIPS_LIBRARY = re.compile(r"^libaws_lc_fips_[A-Za-z0-9_]+\.dylib$")

# Before 1.0, a release reads only the state its immediate predecessor wrote.
# FORWARD_PATH_FLOOR is the earliest release this source reads state from, so a
# rehearsal refuses to start from any earlier release.
# docs/site/src/content/docs/reference/api-stability.mdx states the same.
# check_floor_is_current holds it to the release before the workspace version.
FORWARD_PATH_FLOOR = (0, 38, 0)
STACK_VERSION = re.compile(r"\Astack:\n(?:  .*\n)*?  version: (\S+)\n")
STACK_RELEASED = re.compile(r"\Astack:\n(?:  .*\n)*?  status: released\n")

BINARIES = (
    "breg", "bregctl", "casework", "caseworkctl", "evidence", "evidencectl",
    "messaging", "messagingctl",
)
PLATFORMS = ("linux-amd64", "macos-arm64")
PRODUCTS = ("breg", "casework", "evidence", "messaging")
# A product joins the rehearsal from the first release that published it, and
# is downloaded only for the platforms that release publishes it for.
# release_roster.MESSAGING_FIRST_RELEASE names Messaging's first release; while
# it is None, Messaging has not joined a release and no starting release holds
# Messaging state to upgrade.
PRODUCT_PLATFORMS = {"messaging": ("linux-amd64",)}
POSTGRES_IMAGE = (
    "postgres:17.11@sha256:"
    "67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675"
)
# The server key must be owned by postgres with mode 0600, which a bind mount
# cannot guarantee, so the container copies it before starting the server.
POSTGRES_TLS_ENTRYPOINT = (
    "install -o postgres -m 0600 /tls/server.key.source /tmp/server.key && "
    "exec docker-entrypoint.sh postgres -c ssl=on "
    "-c ssl_cert_file=/tls/server.pem -c ssl_key_file=/tmp/server.key"
)
COMMAND_TIMEOUT_SECONDS = 600
READY_TIMEOUT_SECONDS = 90
HTTP_TIMEOUT_SECONDS = 30


class RehearsalError(RuntimeError):
    """The rehearsal cannot continue, or the upgraded state is not intact."""


# ---------------------------------------------------------------------------
# Release selection and asset authentication. These functions are pure or
# touch only local files, so the unit tests exercise them directly.


def parse_tag(tag: str) -> tuple[int, int, int]:
    match = SEMVER_TAG.fullmatch(tag)
    if match is None:
        raise RehearsalError(f"release tag must be vMAJOR.MINOR.PATCH, got {tag!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def parse_version(version: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(version)
    if match is None:
        raise RehearsalError(
            f"workspace version must be MAJOR.MINOR.PATCH, got {version!r}"
        )
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def workspace_version(repo: Path) -> str:
    with (repo / "Cargo.toml").open("rb") as handle:
        document = tomllib.load(handle)
    version = document.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str):
        raise RehearsalError("Cargo.toml must declare workspace.package.version")
    parse_version(version)
    return version


def select_from_tag(published: list[str], version: str) -> str:
    """Pick the newest published release that this source succeeds.

    That is the newest release at or below the workspace version: before the
    post-release bump the source still carries the version it was released as,
    and after it the source names the next release.
    """

    ceiling = parse_version(version)
    eligible = sorted(
        (parse_tag(tag), tag)
        for tag in published
        if SEMVER_TAG.fullmatch(tag) is not None and parse_tag(tag) <= ceiling
    )
    if not eligible:
        raise RehearsalError(
            f"no published release at or below workspace version {version}"
        )
    return eligible[-1][1]


def check_forward_path(from_tag: str, version: str) -> None:
    """Refuse a starting release the forward state path does not cover."""

    start = parse_tag(from_tag)
    if start > parse_version(version):
        raise RehearsalError(
            f"{from_tag} is newer than workspace version {version}; "
            "a rehearsal only moves state forward"
        )
    if start < FORWARD_PATH_FLOOR:
        floor = "v{}.{}.{}".format(*FORWARD_PATH_FLOOR)
        raise RehearsalError(
            f"refusing {from_tag}: before 1.0 a release reads only the state its "
            f"immediate predecessor wrote, and this source reads state from {floor} "
            "onward; upgrade one release at a time"
        )


def released_versions(repo: Path) -> list[str]:
    """Read the stack version of each release manifest recorded as released.

    A manifest gains `status: released` when its publication is recorded. One
    that never does, because its release was abandoned, is not a release this
    source succeeds.
    """

    versions = []
    for path in sorted((repo / "release/manifests").glob("registry-stack-*.yaml")):
        manifest = path.read_text(encoding="utf-8")
        match = STACK_VERSION.match(manifest)
        if match is None:
            raise RehearsalError(f"release manifest {path.name} names no stack version")
        if STACK_RELEASED.match(manifest) is not None:
            versions.append(match.group(1))
    return versions


def check_floor_is_current(released: list[str], version: str) -> None:
    """Refuse a floor that is not the release before the workspace version.

    That release is the newest released manifest version below the workspace
    version. It changes once main both records a release as published and names
    the next version, and the change that completes the two has to move the
    floor.
    """

    ceiling = parse_version(version)
    earlier = sorted(
        candidate for candidate in map(parse_version, released) if candidate < ceiling
    )
    if not earlier:
        raise RehearsalError(
            f"no released manifest precedes workspace version {version}"
        )
    if FORWARD_PATH_FLOOR != earlier[-1]:
        raise RehearsalError(
            "FORWARD_PATH_FLOOR is v{}.{}.{}, but the release before workspace "
            "version {} is v{}.{}.{}; move the floor as release/OPERATIONS.md "
            "describes".format(*FORWARD_PATH_FLOOR, version, *earlier[-1])
        )


def select_products(requested: list[str] | None, from_tag: str, platform: str,
                    downloading: bool) -> tuple[list[str], dict[str, str]]:
    """The legs to run, and why each default leg the start cannot supply is omitted.

    A product named with --product that the starting release cannot supply
    is refused rather than omitted, so a focused run never passes empty.
    """

    start = parse_tag(from_tag)
    products: list[str] = []
    omitted: dict[str, str] = {}
    for product in requested or PRODUCTS:
        reason = None
        platforms = PRODUCT_PLATFORMS.get(product, PLATFORMS)
        if product == "messaging" and not release_roster.messaging_in_release(start):
            first = release_roster.MESSAGING_FIRST_RELEASE
            if first is None:
                reason = (f"{product} has not joined a release yet "
                          "(release_roster.MESSAGING_FIRST_RELEASE is unset), "
                          f"so {from_tag} holds no {product} state to upgrade")
            else:
                reason = (f"{product} was first shipped in v{first[0]}.{first[1]}.{first[2]}, "
                          f"so {from_tag} holds no {product} state to upgrade")
        elif downloading and platform not in platforms:
            reason = f"{product} publishes no {platform} asset to download"
        if reason is None:
            products.append(product)
        elif requested:
            raise RehearsalError(reason)
        else:
            omitted[product] = reason
    return products, omitted


def product_binaries(products: list[str]) -> tuple[str, ...]:
    """The runtime and tool binaries the named products' legs run."""

    return tuple(binary for binary in BINARIES if binary.removesuffix("ctl") in products)


def asset_names(tag: str, platform: str,
                binaries: tuple[str, ...] = BINARIES) -> dict[str, str]:
    """Map each rehearsed binary to the release asset that carries it."""

    parse_tag(tag)
    if platform not in PLATFORMS:
        raise RehearsalError(f"unsupported platform {platform!r}")
    suffix = ".tar.gz" if platform == "macos-arm64" else ""
    return {binary: f"{binary}-{tag}-{platform}{suffix}" for binary in binaries}


def parse_sha256sums(text: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = SHA256_LINE.fullmatch(line)
        if match is None:
            raise RehearsalError(f"SHA256SUMS line {number} is not '<sha256>  <name>'")
        digest, name = match.groups()
        if name in digests:
            raise RehearsalError(f"SHA256SUMS names {name} more than once")
        digests[name] = digest
    return digests


def verify_assets_by_name(directory: Path, names: list[str], digests: dict[str, str]) -> None:
    """Check every named asset against SHA256SUMS; an absent entry is a failure."""

    for name in names:
        expected = digests.get(name)
        if expected is None:
            raise RehearsalError(f"SHA256SUMS does not cover {name}")
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise RehearsalError(f"release asset {name} was not downloaded")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise RehearsalError(f"{name} does not match its SHA256SUMS entry")


def install_asset(asset: Path, binary: str, destination: Path) -> None:
    """Install one authenticated asset as `destination/binary`.

    A macOS bundle must hold exactly the same-stem executable, its notices, and
    AWS-LC FIPS libraries, as release/VERIFY.md requires; anything else is
    refused before extraction.
    """

    target = destination / binary
    if not asset.name.endswith(".tar.gz"):
        shutil.copyfile(asset, target)
        target.chmod(0o755)
        return
    stem = asset.name[: -len(".tar.gz")]
    with tarfile.open(asset, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise RehearsalError(f"{asset.name} repeats a member")
        executables = [name for name in names if name == stem]
        notices = [name for name in names if name == "THIRD_PARTY_NOTICES"]
        libraries = [name for name in names if FIPS_LIBRARY.fullmatch(name)]
        if (
            len(executables) != 1
            or len(notices) != 1
            or not libraries
            or len(names) != 2 + len(libraries)
            or not all(member.isfile() for member in members)
        ):
            raise RehearsalError(f"{asset.name} is not a closed macOS native bundle")
        for member in members:
            if member.name == "THIRD_PARTY_NOTICES":
                continue
            source = archive.extractfile(member)
            if source is None:
                raise RehearsalError(f"{asset.name} member {member.name} is unreadable")
            output = target if member.name == stem else destination / member.name
            if output.exists() and member.name != stem:
                if output.read_bytes() != source.read():
                    raise RehearsalError(f"{asset.name} ships a conflicting {member.name}")
                continue
            with output.open("wb") as handle:
                shutil.copyfileobj(source, handle)
            output.chmod(0o755)


def row_count_losses(before: dict[str, int], after: dict[str, int]) -> list[str]:
    """Name every table that disappeared or lost rows."""

    losses = []
    for table, count in sorted(before.items()):
        if table not in after:
            losses.append(f"{table} disappeared (held {count} rows)")
        elif after[table] < count:
            losses.append(f"{table} dropped from {count} to {after[table]} rows")
    return losses


def audit_paths(directory: Path, name: str) -> list[Path]:
    return sorted(path for path in directory.iterdir() if path.is_file()
                  and (path.name == name or re.fullmatch(re.escape(name) + r"\.[0-9]+", path.name)))


def archive_audit_files(directory: Path, name: str, archive: Path) -> int:
    private_directory(archive)
    paths = audit_paths(directory, name)
    for path in paths:
        destination = archive / path.name
        if destination.exists():
            raise RehearsalError("audit archive destination already exists")
        path.rename(destination)
    return len(paths)


def audit_record_count(directory: Path, name: str, *, schema: str | None = None) -> int:
    count = 0
    for path in audit_paths(directory, name):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise RehearsalError("audit stream contains an invalid JSON line") from error
            if not isinstance(entry, dict):
                raise RehearsalError("audit stream contains a non-object entry")
            if schema is not None and (
                entry.get("schema") != schema
                or entry.get("phase") not in ("request", "response")
                or not all(isinstance(entry.get(key), str) and entry[key]
                           for key in ("eventId", "time", "correlation"))
                or not isinstance(entry.get("record"), dict)
            ):
                raise RehearsalError("audit stream contains an invalid current envelope")
            count += 1
    return count


def breg_view_differences(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    # An ETag binds the active package revision, which changes on rebuild.
    # Record identifiers, domain data, and stored revisions must still match.
    def state(views: dict[str, Any]) -> dict[str, Any]:
        return {key: {field: value for field, value in view.items() if field != "etag"}
                for key, view in views.items()}

    return view_differences(state(before), state(after))


def view_differences(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Name every captured view that the upgraded binary serves differently."""

    differences = []
    for key in sorted(set(before) | set(after)):
        if key not in after:
            differences.append(f"{key} is no longer served")
        elif key not in before:
            differences.append(f"{key} was not captured before the upgrade")
        elif before[key] != after[key]:
            differences.append(f"{key} changed across the upgrade")
    return differences


# ---------------------------------------------------------------------------
# Process, HTTP, and credential helpers.


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def write_secret(path: Path, value: str | bytes) -> Path:
    data = value.encode() if isinstance(value, str) else value
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)
    path.chmod(0o600)
    return path


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def run(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
    stdin: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-15:]
        raise RehearsalError(
            f"{Path(command[0]).name} {' '.join(command[1:3])} exited "
            f"{result.returncode}:\n" + "\n".join(detail)
        )
    return result


def run_json(command: list[str], **kwargs: Any) -> Any:
    result = run(command, **kwargs)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RehearsalError(f"{Path(command[0]).name} did not print JSON: {exc}") from exc


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: Any = None,
    content_type: str = "application/json",
) -> tuple[int, dict[str, str], Any]:
    data = None
    request_headers = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status, raw, response_headers = response.status, response.read(), response.headers
    except urllib.error.HTTPError as exc:
        status, raw, response_headers = exc.code, exc.read(), exc.headers
    lowered = {key.lower(): value for key, value in response_headers.items()}
    try:
        parsed: Any = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = raw.decode(errors="replace")[:500]
    return status, lowered, parsed


def expect_status(label: str, status: int, body: Any, *expected: int) -> None:
    if status not in expected:
        detail = body if not isinstance(body, dict) else {
            key: body.get(key) for key in ("type", "title", "status", "detail", "code")
        }
        raise RehearsalError(f"{label} returned {status}, expected {expected}: {detail}")


class Keys:
    """Synthetic signing keys generated for one run, never printed."""

    def __init__(self, directory: Path) -> None:
        self.directory = private_directory(directory)
        self.rsa = directory / "issuer-rsa.pem"
        self.ed25519 = directory / "issuer-ed25519.pem"
        run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
             "rsa_keygen_bits:2048", "-out", str(self.rsa)])
        run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.ed25519)])
        for path in (self.rsa, self.ed25519):
            path.chmod(0o600)

    @staticmethod
    def ed25519_x(private_key: Path) -> str:
        der = subprocess.run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"],
            capture_output=True, check=True, timeout=COMMAND_TIMEOUT_SECONDS,
        ).stdout
        return b64url(der[-32:])

    def rsa_jwk(self, kid: str) -> dict[str, str]:
        modulus = run(["openssl", "rsa", "-in", str(self.rsa), "-noout", "-modulus"]).stdout
        n = bytes.fromhex(modulus.strip().split("=", 1)[1])
        return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
                "n": b64url(n), "e": "AQAB"}

    def ed25519_jwk(self, kid: str) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig",
                "x": self.ed25519_x(self.ed25519)}

    @staticmethod
    def sign_ed25519(private_key: Path, message: bytes) -> bytes:
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(message)
            handle.flush()
            return subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
                 "-in", handle.name],
                capture_output=True, check=True, timeout=COMMAND_TIMEOUT_SECONDS,
            ).stdout

    def mint(self, alg: str, kid: str, claims: dict[str, Any], lifetime: int = 240) -> str:
        now = int(time.time())
        body = {"iat": now, "nbf": now, "exp": now + lifetime,
                "jti": "upgrade-rehearsal-" + secrets.token_hex(8), **claims}
        header = {"alg": alg, "typ": "at+jwt", "kid": kid}
        signing_input = (
            b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
            + b64url(json.dumps(body, separators=(",", ":")).encode())
        ).encode()
        if alg == "EdDSA":
            signature = self.sign_ed25519(self.ed25519, signing_input)
        else:
            signature = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(self.rsa)],
                input=signing_input, capture_output=True, check=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            ).stdout
        return signing_input.decode() + "." + b64url(signature)


class Side:
    """One side of the upgrade: the previous release or this source."""

    def __init__(self, label: str, bin_dir: Path, ca_file: Path) -> None:
        self.label = label
        self.bin_dir = bin_dir
        self.ca_file = ca_file

    def path(self, binary: str) -> str:
        return str(self.bin_dir / binary)

    def env(self) -> dict[str, str]:
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("DYLD_", "REGISTRY_", "CASEWORK_", "BREG_",
                                      "MESSAGING_"))}
        env["SSL_CERT_FILE"] = str(self.ca_file)
        # Tools that delegate to a runtime (evidencectl to evidence) must reach
        # this side's binary, never one from the caller's environment.
        env["EVIDENCE_BIN"] = self.path("evidence")
        env["PATH"] = os.pathsep.join([str(self.bin_dir), env.get("PATH", os.defpath)])
        if sys.platform == "darwin":
            env["DYLD_FALLBACK_LIBRARY_PATH"] = str(self.bin_dir)
        return env

    def run(self, binary: str, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return run([self.path(binary), *args], env=self.env(), **kwargs)

    def run_json(self, binary: str, *args: str, **kwargs: Any) -> Any:
        return run_json([self.path(binary), *args], env=self.env(), **kwargs)


class Service:
    """A product server started in the background and stopped gracefully."""

    def __init__(self, side: Side, name: str, args: list[str], log: Path, ready_url: str) -> None:
        self.name = f"{side.label} {name}"
        self.log = log
        self.handle = log.open("ab")
        self.process = subprocess.Popen(
            [side.path(name), *args], env=side.env(), stdout=self.handle,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.handle.close()
                raise RehearsalError(f"{self.name} exited before ready:\n{self.tail()}")
            try:
                with urllib.request.urlopen(ready_url, timeout=2) as response:
                    if response.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                # Not listening yet is the expected state while the service
                # starts; the deadline below reports it with the log tail.
                pass
            time.sleep(0.5)
        self.stop()
        raise RehearsalError(f"{self.name} was not ready in time:\n{self.tail()}")

    def tail(self) -> str:
        lines = self.log.read_text(errors="replace").splitlines()[-12:]
        return "\n".join(lines)

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.handle.close()


class Postgres:
    """One disposable, TLS-only PostgreSQL container bound to loopback."""

    def __init__(self, name: str, tls: Path) -> None:
        self.name = name
        self.ca_file = tls / "ca.pem"
        self._make_certificates(tls)
        run(["docker", "rm", "-f", name], check=False)
        run(["docker", "run", "-d", "--name", name, "-p", "127.0.0.1::5432",
             "-e", "POSTGRES_PASSWORD=" + secrets.token_hex(16),
             "-v", f"{tls / 'server.pem'}:/tls/server.pem:ro",
             "-v", f"{tls / 'server.key'}:/tls/server.key.source:ro",
             "--entrypoint", "bash", POSTGRES_IMAGE, "-c", POSTGRES_TLS_ENTRYPOINT])
        mapped = run(["docker", "port", name, "5432/tcp"]).stdout.strip().splitlines()[0]
        self.port = int(mapped.rsplit(":", 1)[1])
        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            probe = run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1",
                         "-U", "postgres"], check=False)
            if probe.returncode == 0:
                return
            time.sleep(1)
        raise RehearsalError("PostgreSQL did not accept TCP connections in time")

    @staticmethod
    def _make_certificates(tls: Path) -> None:
        private_directory(tls)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=upgrade-rehearsal-ca", "-keyout", str(tls / "ca.key"),
             "-out", str(tls / "ca.pem")])
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", str(tls / "server.key"), "-out", str(tls / "server.csr")])
        (tls / "san.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        run(["openssl", "x509", "-req", "-in", str(tls / "server.csr"), "-CA",
             str(tls / "ca.pem"), "-CAkey", str(tls / "ca.key"), "-CAcreateserial",
             "-days", "2", "-extfile", str(tls / "san.ext"), "-out", str(tls / "server.pem")])
        (tls / "ca.pem").chmod(0o644)
        (tls / "server.pem").chmod(0o644)

    def sql(self, database: str, statements: str) -> str:
        return run(["docker", "exec", "-i", self.name, "psql", "-v", "ON_ERROR_STOP=1",
                    "-q", "-AtX", "-U", "postgres", "-d", database],
                   stdin=statements).stdout

    def url(self, role: str, password: str, database: str) -> str:
        return f"postgresql://{role}:{password}@localhost:{self.port}/{database}"

    def row_counts(self, database: str) -> dict[str, int]:
        output = self.sql(database, """
            SELECT format('%I.%I', table_schema, table_name) || ' ' ||
              (xpath('/row/c/text()', query_to_xml(
                format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name),
                false, true, '')))[1]::text
            FROM information_schema.tables
            WHERE table_type = 'BASE TABLE'
              AND table_schema NOT IN ('pg_catalog', 'information_schema')
            ORDER BY 1;
        """)
        counts = {}
        for line in output.splitlines():
            table, count = line.rsplit(" ", 1)
            counts[table] = int(count)
        if not counts:
            raise RehearsalError(f"database {database} holds no tables to compare")
        return counts

    def remove(self) -> None:
        run(["docker", "rm", "-f", self.name], check=False)


class JwksServer:
    """Serve one static key set over loopback HTTP, or HTTPS with the
    rehearsal's server certificate, for the Evidence issuer."""

    def __init__(self, document: dict[str, Any], tls: Path | None = None) -> None:
        body = json.dumps(document).encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/oauth2/jwks":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(tls / "server.pem", tls / "server.key")
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def ecdsa_der_to_raw(der: bytes) -> bytes:
    """Turn an ASN.1 P-256 ECDSA signature into the fixed-width r||s JWS form."""

    def integer(offset: int) -> tuple[bytes, int]:
        if der[offset] != 0x02 or der[offset + 1] & 0x80:
            raise RehearsalError("ECDSA signature is not a short DER INTEGER")
        length = der[offset + 1]
        value = der[offset + 2:offset + 2 + length].lstrip(b"\0")
        if len(value) > 32:
            raise RehearsalError("ECDSA signature component is wider than P-256")
        return value.rjust(32, b"\0"), offset + 2 + length

    if len(der) < 8 or der[0] != 0x30 or der[1] & 0x80 or der[1] != len(der) - 2:
        raise RehearsalError("ECDSA signature is not a short DER SEQUENCE")
    r, offset = integer(2)
    s, offset = integer(offset)
    if offset != len(der):
        raise RehearsalError("ECDSA signature has trailing bytes")
    return r + s


def ec_public_jwk(private_key: Path) -> dict[str, str]:
    """Describe a P-256 key as the ES256 public JWK Evidence publishes."""

    der = subprocess.run(["openssl", "ec", "-in", str(private_key), "-pubout", "-outform",
                          "DER"], check=True, capture_output=True).stdout
    point = der[-65:]
    if point[0] != 0x04:
        raise RehearsalError("P-256 public key is not an uncompressed point")
    members = {"crv": "P-256", "kty": "EC", "x": b64url(point[1:33]), "y": b64url(point[33:])}
    thumbprint = hashlib.sha256(json.dumps(members, separators=(",", ":"),
                                           sort_keys=True).encode()).digest()
    return {"alg": "ES256", **members, "kid": b64url(thumbprint)}


class TransitServer:
    """Answer the two Transit calls an Evidence `transit` signer makes, over a
    Unix socket, with one P-256 key held in a local file."""

    KEY_NAME = "evidence-signing"

    def __init__(self, private_key: Path) -> None:
        public_pem = subprocess.run(["openssl", "ec", "-in", str(private_key), "-pubout"],
                                    check=True, capture_output=True, text=True).stdout
        metadata = json.dumps({"data": {
            "type": "ecdsa-p256", "derived": False, "exportable": False,
            "allow_plaintext_backup": False, "supports_signing": True, "latest_version": 1,
            "min_encryption_version": 1, "keys": {"1": {"public_key": public_pem}}}}).encode()
        key_path = f"/v1/transit/keys/{self.KEY_NAME}"
        sign_path = f"/v1/transit/sign/{self.KEY_NAME}/sha2-256"

        class Handler(BaseHTTPRequestHandler):
            def reply(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def refuse(self, message: str) -> None:
                self.reply(400, json.dumps({"errors": [message]}).encode())

            def do_GET(self) -> None:  # noqa: N802
                if self.path != key_path:
                    self.refuse("unknown path")
                    return
                self.reply(200, metadata)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    request = json.loads(self.rfile.read(length))
                    digest = base64.b64decode(request["input"], validate=True)
                except (ValueError, KeyError, TypeError):
                    self.refuse("malformed sign request")
                    return
                if (self.path != sign_path or request.get("key_version") != 1
                        or request.get("prehashed") is not True
                        or request.get("marshaling_algorithm") != "jws" or len(digest) != 32):
                    self.refuse("sign request does not match the rehearsal key")
                    return
                der = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey",
                                      str(private_key)], input=digest, check=True,
                                     capture_output=True).stdout
                signature = "vault:v1:" + b64url(ecdsa_der_to_raw(der))
                self.reply(200, json.dumps({"data": {"signature": signature}}).encode())

            def address_string(self) -> str:
                return "transit"

            def log_message(self, *_args: Any) -> None:
                return

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        # A Unix socket path is limited to about 104 bytes on macOS.
        self.directory = Path(tempfile.mkdtemp(prefix="rehearsal-transit-", dir="/tmp"))
        self.socket_path = self.directory / "transit.sock"
        self.server = Server(str(self.socket_path), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.directory)


def load_yaml(path: Path) -> Any:
    import yaml  # PyYAML; CI runs this script through `uv run --with PyYAML`.

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def dump_yaml(path: Path, document: Any) -> None:
    import yaml

    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# Base Registry Engine: package, activate, write records, upgrade, compare.


BREG_ISSUER = "https://issuer.upgrade-rehearsal.invalid"
BREG_AUDIENCE = "breg"
BREG_CLIENT = "upgrade-rehearsal"
BREG_KID = "upgrade-rehearsal-issuer"
BREG_DATABASE_ID = "upgrade-rehearsal-db"
BREG_ENVIRONMENT = "staging"
BREG_INSTANCE_ID = "upgrade-rehearsal-instance"


def instance_claim(side: Side, runtime: Path) -> dict[str, Any] | None:
    return side.run_json("bregctl", "--format", "json", "instance-claim", "status",
                         "--runtime-config", str(runtime))["status"]["claim"]


def claim_differences(before: dict[str, Any] | None,
                      after: dict[str, Any] | None) -> list[str]:
    """The upgrade carries a recorded instance claim over, or records one."""

    if after is None:
        return ["the upgraded database records no instance claim"]
    if before is not None and before != after:
        return ["the upgrade changed the instance claim the database recorded"]
    return []


def expect_plan(plan: dict[str, Any], activation: str, digest: str) -> None:
    if (plan.get("pending") is not True or plan.get("activation") != activation
            or plan.get("packageDigest") != digest):
        raise RehearsalError(f"bregctl plan did not report a pending {activation} "
                             "activation of the package")


def expect_ledger(status: dict[str, Any], active: str) -> list[str]:
    """Check the active package is the last applied, chained ledger entry.

    Returns the ledger as planKind:outcome pairs in apply order.
    """

    entries = sorted(status["ledger"], key=lambda entry: entry["applyOrder"])
    if status["activePackageDigest"] != active or status["maintenanceStatus"] != "ready":
        raise RehearsalError("bregctl status did not report the applied package as "
                             "active and ready")
    applied = [entry for entry in entries if entry["outcome"] == "applied"]
    if (not applied or applied[-1]["packageDigest"] != active
            or applied[-1]["activationId"] != status["activationId"]):
        raise RehearsalError("the active package is not the last applied ledger entry")
    for previous, current in zip(applied, applied[1:]):
        if current["predecessorPackageDigest"] != previous["packageDigest"]:
            raise RehearsalError("an applied successor does not chain from the package "
                                 "it replaced in the ledger")
    return [f"{entry['planKind']}:{entry['outcome']}" for entry in entries]


class Breg:
    def __init__(self, work: Path, keys: Keys, postgres: Postgres) -> None:
        self.work = private_directory(work)
        self.keys = keys
        self.postgres = postgres
        self.secrets = private_directory(work / "secrets")
        self.project = work / "project"
        self.runtime = work / "runtime.yaml"
        self.port = free_port()
        self.operator: dict[str, Any] = {}

    def provision(self) -> None:
        passwords = {role: secrets.token_hex(16)
                     for role in ("registry_migration", "registry_runtime")}
        self.postgres.sql("postgres", "".join(
            f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT "
            f"NOBYPASSRLS PASSWORD '{password}';\n"
            for role, password in passwords.items()
        ))
        for database in ("registry", "schematest"):
            self.create_database(database)
            for role, password in passwords.items():
                kind = "migration" if role == "registry_migration" else "runtime"
                write_secret(self.secrets / f"{kind}-url-{database}",
                             self.postgres.url(role, password, database))
        write_secret(self.secrets / "audit-key", secrets.token_hex(32))
        write_secret(self.secrets / "cursor-key", secrets.token_hex(32))
        write_secret(self.secrets / "jwks.json",
                     json.dumps({"keys": [self.keys.ed25519_jwk(BREG_KID)]}))

    def create_database(self, database: str) -> None:
        """Create one empty database the way the operator guide provisions it."""

        self.postgres.sql("postgres", f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE);')
        self.postgres.sql("postgres", f'CREATE DATABASE "{database}";')
        self.postgres.sql(database, f"""
                CREATE EXTENSION btree_gist;
                REVOKE ALL ON DATABASE "{database}" FROM PUBLIC;
                GRANT CONNECT ON DATABASE "{database}" TO registry_migration, registry_runtime;
                CREATE SCHEMA registry_internal AUTHORIZATION registry_migration;
                CREATE SCHEMA registry_data AUTHORIZATION registry_migration;
                CREATE SCHEMA registry_source AUTHORIZATION registry_migration;
                CREATE SCHEMA registry_derived AUTHORIZATION registry_migration;
                CREATE SCHEMA registry_context AUTHORIZATION registry_migration;
                REVOKE ALL ON SCHEMA registry_internal, registry_data, registry_source,
                  registry_derived, registry_context FROM PUBLIC;
            """)

    def author(self, side: Side) -> None:
        side.run("bregctl", "init", str(self.project))
        journeys = load_yaml(self.project / "tests" / "journeys.yaml")
        for journey in journeys["journeys"]:
            for step in journey["steps"]:
                if step.get("accessProfile") == "operator" and step.get("claims"):
                    self.operator = step["claims"]
                    break
            if self.operator:
                break
        if not self.operator:
            raise RehearsalError("the BReg starter journeys name no operator step")
        self.clients = sorted({BREG_CLIENT} | {
            step["claims"]["requesterClient"]
            for journey in journeys["journeys"] for step in journey["steps"]
            if "requesterClient" in (step.get("claims") or {})})

    @staticmethod
    def claims(claims: dict[str, Any]) -> dict[str, Any]:
        """Turn a journey step's claims into the access token that carries them."""

        token = {"iss": BREG_ISSUER, "aud": BREG_AUDIENCE, "sub": claims["principal"],
                 "registry_principal": claims["principal"],
                 "scope": " ".join(claims.get("scopes", [])),
                 "registry_actor_kind": claims.get("actorKind", "human"),
                 "client_id": claims.get("requesterClient", BREG_CLIENT)}
        if "purpose" in claims:
            token["registry_purpose"] = claims["purpose"]
        token.update(claims.get("claims", {}))
        token.update(claims.get("directClaims", {}))
        return token

    def write_runtime(self, path: Path, database: str, package_root: Path, port: int) -> None:
        dump_yaml(path, {
            "apiVersion": "registry.registrystack.org/breg-runtime/v1alpha1",
            "kind": "BRegRuntimeConfig",
            "listener": {"bind": f"127.0.0.1:{port}",
                         "publicOrigin": f"http://127.0.0.1:{port}"},
            "identity": {"environment": BREG_ENVIRONMENT,
                         "instanceId": BREG_INSTANCE_ID,
                         "databaseId": BREG_DATABASE_ID,
                         "databaseInitializationEnvironment": BREG_ENVIRONMENT},
            "secretProviders": {"file": {"root": str(self.secrets)}},
            "database": {"runtimeUrlRef": f"secret:file/runtime-url-{database}",
                         "migrationUrlRef": f"secret:file/migration-url-{database}",
                         "pool": {"maxSize": 8},
                         "roles": {"migration": "registry_migration",
                                   "runtime": "registry_runtime"}},
            "package": {"root": str(package_root)},
            "authentication": {
                "oidc": {"issuer": BREG_ISSUER, "audience": BREG_AUDIENCE,
                         "allowedAlgorithm": "EdDSA", "accessTokenType": "at+jwt",
                         "scopeClaim": "scope", "scopeSeparator": " ",
                         "allowedClients": self.clients, "deniedKids": [],
                         "maxTokenLifetimeSeconds": 300, "leewayMilliseconds": 30000,
                         "jwksSource": {"kind": "static",
                                        "documentRef": "secret:file/jwks.json"}},
                "authorityClaims": {"principal": "registry_principal",
                                    "purpose": "registry_purpose"}},
            "audit": {"hashKeyRef": "secret:file/audit-key",
                      "path": str(private_directory(path.parent / "audit") / "breg.jsonl")},
            "cursor": {"secretRef": "secret:file/cursor-key"},
        })

    def credentials(self, path: Path) -> None:
        journeys = load_yaml(self.project / "tests" / "journeys.yaml")
        bindings = []
        for journey in journeys["journeys"]:
            for step in journey["steps"]:
                claims = step.get("claims")
                if claims is None:
                    credential: dict[str, Any] = {"type": "anonymous"}
                else:
                    name = f"journey-token-{journey['id']}-{step['id']}"
                    write_secret(self.secrets / name, self.keys.mint(
                        "EdDSA", BREG_KID, self.claims(claims), lifetime=280))
                    credential = {"type": "bearer", "tokenRef": f"secret:file/{name}"}
                bindings.append({"journeyId": journey["id"], "stepId": step["id"],
                                 "credential": credential})
        path.write_text(json.dumps({
            "apiVersion": "registry.registrystack.org/breg-schema-test-credentials/v1",
            "kind": "SchemaTestCredentials", "bindings": bindings}, indent=1))

    def test_runtime(self, build: Path) -> tuple[Path, Path]:
        """Prepare an empty schema-test database; return its runtime and credentials."""

        private_directory(build)
        self.create_database("schematest")
        empty = private_directory(build / "empty-package-root")
        test_runtime = build / "runtime-test.yaml"
        self.write_runtime(test_runtime, "schematest", empty, free_port())
        credentials = build / "credentials.json"
        self.credentials(credentials)
        return test_runtime, credentials

    def package(self, side: Side, build: Path, baseline: Path | None = None) -> tuple[Path, str]:
        """Test and package the project; return the package and its digest.

        `baseline` is the active package this one succeeds.
        """

        test_runtime, credentials = self.test_runtime(build)
        baseline_args = ["--baseline-package", str(baseline)] if baseline else []
        side.run_json("bregctl", "--format", "json", "test", str(self.project),
                      "--runtime-config", str(test_runtime), "--credentials",
                      str(credentials), *baseline_args, "--output",
                      str(build / "receipt.json"))
        output = build / "out"
        report = side.run_json("bregctl", "--format", "json", "package", str(self.project),
                               *baseline_args, "--test-receipt", str(build / "receipt.json"),
                               "--output", str(output))
        digest = report.get("packageDigest")
        if not isinstance(digest, str):
            raise RehearsalError("bregctl package reported no packageDigest")
        return output / "package", digest

    def token(self) -> str:
        return self.keys.mint("EdDSA", BREG_KID, self.claims(self.operator))

    def call(self, method: str, path: str, body: Any = None,
             headers: dict[str, str] | None = None,
             content_type: str = "application/json") -> tuple[int, dict[str, str], Any]:
        request_headers = {"Authorization": "Bearer " + self.token(),
                           "Accept": "application/json", **(headers or {})}
        if body is not None:
            request_headers.setdefault("Idempotency-Key", str(uuid.uuid4()))
        return http(method, f"http://127.0.0.1:{self.port}{path}", headers=request_headers,
                    body=body, content_type=content_type)

    def create(self, route: str, data: dict[str, Any]) -> str:
        status, _headers, body = self.call("POST", f"/v1/records/{route}", {"data": data})
        expect_status(f"create {route}", status, body, 200, 201)
        return body["data"]["recordIdentifier"]

    def patch_status(self, record: str, value: str) -> None:
        status, headers, body = self.call("GET", f"/v1/records/records/{record}")
        expect_status("read record", status, body, 200)
        status, _headers, body = self.call(
            "PATCH", f"/v1/records/records/{record}",
            [{"op": "replace", "path": "/data/status", "value": value}],
            headers={"If-Match": headers["etag"]},
            content_type="application/json-patch+json")
        expect_status("patch record", status, body, 200)

    def seed(self, tag: str) -> dict[str, list[str]]:
        groups = [self.create("record-groups", {"code": f"{tag}-group-{index}",
                                                "label": f"Group {index}"})
                  for index in range(2)]
        records = []
        for index in range(4):
            record = self.create("records", {"code": f"{tag}-record-{index}",
                                             "label": f"Record {index}",
                                             "group": groups[index % 2], "status": "draft"})
            for value in ("active", "retired")[: index % 3]:
                self.patch_status(record, value)
            records.append(record)
        return {"record-groups": groups, "records": records}

    def views(self, seeded: dict[str, list[str]]) -> dict[str, Any]:
        views: dict[str, Any] = {}
        for route, identifiers in seeded.items():
            for identifier in identifiers:
                status, headers, body = self.call("GET", f"/v1/records/{route}/{identifier}")
                expect_status(f"read {route}", status, body, 200)
                data = body.get("data", {})
                views[f"{route}/{identifier}"] = {
                    "etag": headers.get("etag"),
                    "domainData": data.get("domainData"),
                    "revision": data.get("revisionIdentifier"),
                }
        return views


def rehearse_breg(work: Path, keys: Keys, postgres: Postgres, old: Side, new: Side,
                  report: dict[str, Any]) -> None:
    breg = Breg(work, keys, postgres)
    breg.provision()
    breg.author(old)
    package, _digest = breg.package(old, work / "build-1")
    breg.write_runtime(breg.runtime, "registry", package, breg.port)
    old.run_json("bregctl", "--format", "json", "apply", "--runtime-config",
                 str(breg.runtime), "--package", str(package), "--initial")
    ready = f"http://127.0.0.1:{breg.port}/ready"
    service = Service(old, "breg", breg_arguments(breg.runtime), work / "breg-old.log", ready)
    try:
        seeded = breg.seed("before")
        before_views = breg.views(seeded)
    finally:
        service.stop()
    before_counts = postgres.row_counts("registry")
    claim_before = instance_claim(old, breg.runtime)

    def apply(target: Path, digest: str) -> None:
        plan = new.run_json("bregctl", "--format", "json", "plan", "--runtime-config",
                            str(breg.runtime), "--package", str(target))
        expect_plan(plan, "successor", digest)
        new.run_json("bregctl", "--format", "json", "apply", "--runtime-config",
                     str(breg.runtime), "--package", str(target))
        breg.write_runtime(breg.runtime, "registry", target, breg.port)

    def serve(log: str) -> dict[str, Any]:
        new.run_json("bregctl", "--format", "json", "verify", "--runtime-config",
                     str(breg.runtime))
        service = Service(new, "breg", breg_arguments(breg.runtime), work / log, ready)
        try:
            return breg.views(seeded)
        finally:
            service.stop()

    claim_after = instance_claim(new, breg.runtime)
    upgraded_views = serve("breg-upgraded.log")

    # An additive successor proves the upgraded ledger moves forward.
    registry = load_yaml(breg.project / "registry.yaml")
    group = next(entity for entity in registry["entities"] if entity["id"] == "record-group")
    group["fields"].append({"id": "rehearsal-note", "type": "string", "maxLength": 200,
                            "classification": "public"})
    dump_yaml(breg.project / "registry.yaml", registry)
    successor, successor_digest = breg.package(new, work / "build-successor", baseline=package)
    apply(successor, successor_digest)
    ledger = expect_ledger(
        new.run_json("bregctl", "--format", "json", "status", "--runtime-config",
                     str(breg.runtime)), successor_digest)
    expected = ["initial:applied", "successor:applied"]
    if ledger[-2:] != expected:
        raise RehearsalError(f"the activation ledger recorded {ledger}, expected it to end "
                             f"with {expected}")
    successor_views = serve("breg-successor.log")
    service = Service(new, "breg", breg_arguments(breg.runtime), work / "breg-written.log",
                      ready)
    try:
        written = breg.seed("after")
        breg.views(written)
    finally:
        service.stop()
    new.run_json("bregctl", "--format", "json", "doctor", "--runtime-config", str(breg.runtime))
    losses = row_count_losses(before_counts, postgres.row_counts("registry"))
    differences = (breg_view_differences(before_views, upgraded_views)
                   + breg_view_differences(before_views, successor_views)
                   + claim_differences(claim_before, claim_after))

    report["breg"] = {
        "records": sum(len(value) for value in seeded.values()),
        "tables": len(before_counts),
        "ledger": ledger,
        "instanceClaimRecordedBeforeUpgrade": claim_before is not None,
        "viewDifferences": differences,
        "rowLosses": losses,
    }
    if differences or losses:
        raise RehearsalError("Base Registry Engine state did not survive the upgrade: "
                             + "; ".join(differences + losses))


# ---------------------------------------------------------------------------
# Casework: activate, bootstrap, write review work, upgrade and apply,
# compare.


CASEWORK_ISSUER = "https://issuer.upgrade-rehearsal.invalid"
CASEWORK_AUDIENCE = "urn:upgrade-rehearsal:casework"
CASEWORK_KID = "upgrade-rehearsal-rsa"
CASEWORK_DATABASE_ID = "upgrade-rehearsal-casework"
CASEWORK_OPERATOR_REFERENCE = "upgrade-rehearsal"
CASEWORK_ALREADY_ACTIVE = "casework.activation.already-active"
CASEWORK_ACTORS = {
    "administrator": ("upgrade-rehearsal-admin", "casework:admin", True),
    "staff": ("upgrade-rehearsal-staff", "casework:staff", True),
    "supervisor": ("upgrade-rehearsal-supervisor", "casework:supervisor", True),
    "requester": ("upgrade-rehearsal-requester", "casework:request", False),
}


class Casework:
    def __init__(self, work: Path, keys: Keys, postgres: Postgres) -> None:
        self.work = private_directory(work)
        self.keys = keys
        self.postgres = postgres
        self.secrets = private_directory(work / "secrets")
        self.audit = private_directory(work / "audit")
        self.project = work / "project"
        self.package = work / "package"
        self.runtime = work / "runtime.yaml"
        self.port = free_port()

    def provision(self) -> None:
        migration, runtime = secrets.token_hex(16), secrets.token_hex(16)
        self.postgres.sql("postgres", f"""
            CREATE ROLE casework_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              NOINHERIT NOBYPASSRLS PASSWORD '{migration}';
            CREATE ROLE casework_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              NOINHERIT NOBYPASSRLS PASSWORD '{runtime}';
        """)
        self.postgres.sql("postgres", "CREATE DATABASE casework;")
        self.postgres.sql("casework", """
            REVOKE ALL ON DATABASE casework FROM PUBLIC;
            GRANT CONNECT ON DATABASE casework TO casework_migration, casework_runtime;
            ALTER SCHEMA public OWNER TO casework_migration;
            REVOKE ALL ON SCHEMA public FROM PUBLIC;
            GRANT USAGE ON SCHEMA public TO casework_runtime;
            ALTER DEFAULT PRIVILEGES FOR ROLE casework_migration IN SCHEMA public
              GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO casework_runtime;
            ALTER DEFAULT PRIVILEGES FOR ROLE casework_migration IN SCHEMA public
              GRANT USAGE, SELECT ON SEQUENCES TO casework_runtime;
        """)
        write_secret(self.secrets / "runtime-url",
                     self.postgres.url("casework_runtime", runtime, "casework"))
        write_secret(self.secrets / "migration-url",
                     self.postgres.url("casework_migration", migration, "casework"))
        write_secret(self.secrets / "database-root.pem", self.postgres.ca_file.read_bytes())
        write_secret(self.secrets / "audit-key", secrets.token_hex(32))
        write_secret(self.secrets / "jwks.json",
                     json.dumps({"keys": [self.keys.rsa_jwk(CASEWORK_KID)]}))

    def author(self, side: Side) -> None:
        side.run("caseworkctl", "init", "--template", "standalone-decision", str(self.project))
        project = load_yaml(self.project / "casework.yaml")
        producers = project.get("reviewProducers") or []
        if len(producers) != 1:
            raise RehearsalError("the Casework starter must declare exactly one producer")
        producers[0]["issuer"] = CASEWORK_ISSUER
        producers[0]["subject"] = CASEWORK_ACTORS["requester"][0]
        dump_yaml(self.project / "casework.yaml", project)
        side.run("caseworkctl", "package", str(self.project), "--output", str(self.package))
        dump_yaml(self.runtime, {
            "apiVersion": "registry.registrystack.org/casework-runtime/v1alpha1",
            "kind": "CaseworkRuntimeConfig",
            "package": {"root": str(self.package)},
            "listener": {"bind": f"127.0.0.1:{self.port}",
                         "tlsTermination": "development-loopback",
                         "networkExposure": "private-address"},
            "secretProviders": {"file": {"root": str(self.secrets)}},
            "database": {"runtimeUrlRef": "secret:file/runtime-url",
                         "migrationUrlRef": "secret:file/migration-url",
                         "trustedRootCertificateRef": "secret:file/database-root.pem"},
            "authentication": {"oidc": {
                "issuer": CASEWORK_ISSUER, "audience": CASEWORK_AUDIENCE,
                "scopeClaim": "scope",
                "humanIdentity": {"claim": "registry_actor_kind", "value": "human"},
                "jwksSource": {"kind": "static", "documentRef": "secret:file/jwks.json"}}},
            "audit": {"path": str(self.audit / "casework.ndjson"),
                      "hashKeyRef": "secret:file/audit-key"},
        })

    def activate(self, side: Side, active: str | None = None) -> dict[str, Any]:
        """Name the database in runtime.yaml, then plan and apply with the
        migration credential, the upgrade step the Casework changelog names.
        The first apply on an empty database migrates it and records the
        first activation.

        `active` is the activation the previous release already recorded. When
        plan reports that activation as already active with nothing pending,
        apply would refuse, so nothing is applied. Returns the apply report,
        or the active activation when nothing was applied."""
        runtime = load_yaml(self.runtime)
        runtime.setdefault("identity", {})["databaseId"] = CASEWORK_DATABASE_ID
        dump_yaml(self.runtime, runtime)
        config = ["--runtime-config", str(self.runtime)]
        planned = side.run_json("caseworkctl", "--format", "json", "plan", *config)
        if planned.get("changesPending") is True:
            return side.run_json("caseworkctl", "--format", "json", "apply", *config,
                                 "--operator-reference", CASEWORK_OPERATOR_REFERENCE)
        if active is None:
            raise RehearsalError("caseworkctl plan reported nothing pending before the "
                                 "first activation")
        current = planned.get("active") or {}
        refusals = [refusal.get("code") for refusal in planned.get("refusals") or []]
        if current.get("activationId") != active or refusals != [CASEWORK_ALREADY_ACTIVE]:
            raise RehearsalError("caseworkctl plan reported nothing pending without naming "
                                 "the previous release's activation as already active")
        return current

    def call(self, actor: str, method: str, path: str, body: Any = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], Any]:
        subject, scope, human = CASEWORK_ACTORS[actor]
        claims: dict[str, Any] = {"iss": CASEWORK_ISSUER, "aud": CASEWORK_AUDIENCE,
                                  "sub": subject, "scope": scope, "client_id": subject}
        if human:
            claims["registry_actor_kind"] = "human"
        request_headers = {
            "Authorization": "Bearer " + self.keys.mint("RS256", CASEWORK_KID, claims),
            "Accept": "application/json", "Registry-Casework-Profile": actor,
            **(headers or {})}
        if method == "POST":
            request_headers.setdefault("Idempotency-Key", str(uuid.uuid4()))
        return http(method, f"http://127.0.0.1:{self.port}{path}",
                    headers=request_headers, body=body)

    def bootstrap(self) -> None:
        status, _headers, body = self.call("administrator", "POST", "/v1/directory/bootstrap", {
            "teamId": "decisions-team", "queueId": "decisions",
            "staff": [{"issuer": CASEWORK_ISSUER, "subject": CASEWORK_ACTORS["staff"][0]}],
            "supervisors": [{"issuer": CASEWORK_ISSUER,
                             "subject": CASEWORK_ACTORS["supervisor"][0]}],
        }, {"If-Match": '"0"'})
        expect_status("directory bootstrap", status, body, 200, 201)

    def request_review(self, reference: str) -> str:
        digest = hashlib.sha256(reference.encode()).hexdigest()
        status, _headers, body = self.call("requester", "POST", "/v1/review-requests", {
            "kind": "decision",
            "subject": {"source": "standalone", "type": "batch", "id": reference,
                        "version": "1", "digest": f"sha256:{digest}"},
            "requesterReference": reference,
            "context": {"strategy": "submitted",
                        "snapshot": {"summary": f"Upgrade rehearsal {reference}",
                                     "reference": reference}},
        })
        expect_status("review request", status, body, 201)
        return body["requestId"]

    def tasks(self) -> list[dict[str, Any]]:
        status, _headers, body = self.call("staff", "GET", "/v1/review-tasks?limit=25")
        expect_status("review tasks", status, body, 200)
        return body["items"]

    def task_for(self, request_id: str) -> dict[str, Any]:
        for task in self.tasks():
            if task.get("requestId") == request_id:
                return task
        raise RehearsalError(f"no review task is open for request {request_id}")

    def claim(self, request_id: str) -> dict[str, Any]:
        task = self.task_for(request_id)
        status, _headers, body = self.call(
            "staff", "POST", f"/v1/review-tasks/{task['taskId']}/claim",
            headers={"If-Match": f'"{task["revision"]}"'})
        expect_status("claim review task", status, body, 200)
        return body

    def decide(self, request_id: str) -> None:
        task = self.task_for(request_id)
        status, _headers, body = self.call(
            "staff", "POST", f"/v1/review-tasks/{task['taskId']}/decisions",
            {"decision": {"type": "answer", "outcome": "confirmed"}},
            {"If-Match": f'"{task["revision"]}"'})
        expect_status("decide review task", status, body, 204)

    def views(self, requests: list[str]) -> dict[str, Any]:
        views: dict[str, Any] = {"tasks": sorted(
            (task.get("taskId"), task.get("requestId"), task.get("state"),
             task.get("revision")) for task in self.tasks())}
        for request_id in requests:
            status, _headers, body = self.call("requester", "GET",
                                               f"/v1/review-requests/{request_id}")
            expect_status("read review request", status, body, 200)
            views[f"request/{request_id}"] = body
            status, _headers, body = self.call("requester", "GET",
                                               f"/v1/review-requests/{request_id}/result")
            views[f"result/{request_id}"] = {"status": status, "body": body}
        return views


def rehearse_casework(work: Path, keys: Keys, postgres: Postgres, old: Side, new: Side,
                      report: dict[str, Any]) -> None:
    casework = Casework(work, keys, postgres)
    casework.provision()
    casework.author(old)
    runtime = ["--runtime-config", str(casework.runtime)]
    seeded = casework.activate(old)["activationId"]
    ready = f"http://127.0.0.1:{casework.port}/ready"
    service = Service(old, "casework", [*runtime, "serve"], work / "casework-old.log", ready)
    try:
        casework.bootstrap()
        requests = [casework.request_review(f"before-{index}") for index in range(3)]
        casework.claim(requests[0])
        casework.decide(requests[0])
        casework.claim(requests[1])
        before_views = casework.views(requests)
        if (before_views[f"result/{requests[0]}"]["status"] != 200
                or len(before_views["tasks"]) < 2):
            raise RehearsalError("the previous release did not record the answered "
                                 "and in-flight review work the rehearsal compares")
    finally:
        service.stop()
    before_counts = postgres.row_counts("casework")

    archived_files = archive_audit_files(casework.audit, "casework.ndjson", work / "audit-archive")
    activation = casework.activate(new, seeded)
    losses = row_count_losses(before_counts, postgres.row_counts("casework"))
    service = Service(new, "casework", [*runtime, "serve"], work / "casework-new.log", ready)
    try:
        after_views = casework.views(requests)
        differences = view_differences(before_views, after_views)
        casework.decide(requests[1])
        casework.request_review("after-0")
    finally:
        service.stop()
    losses += row_count_losses(before_counts, postgres.row_counts("casework"))
    new.run_json("caseworkctl", "--format", "json", "check", str(casework.project))

    report["casework"] = {
        "reviewRequests": len(requests),
        "tables": len(before_counts),
        "auditFilesArchived": archived_files,
        "activationId": activation["activationId"],
        "activatedOnUpgrade": activation["activationId"] != seeded,
        "viewDifferences": differences,
        "rowLosses": losses,
    }
    if differences or losses:
        raise RehearsalError("Casework state did not survive the upgrade: "
                             + "; ".join(differences + losses))


# ---------------------------------------------------------------------------
# Messaging: activate the starter, schedule and cancel messages, upgrade,
# compare.


MESSAGING_ISSUER = "https://issuer.upgrade-rehearsal.invalid"
MESSAGING_AUDIENCE = "urn:upgrade-rehearsal:messaging"
MESSAGING_KID = "upgrade-rehearsal-messaging-rsa"
MESSAGING_SENDER = {"sub": "upgrade-rehearsal-sender", "azp": "case-system",
                    "registry_scopes": "messaging:send",
                    "registry_actor_kind": "service"}
MESSAGING_TEMPLATES = {"email": "appointment-reminder", "sms": "appointment-reminder-sms"}
MESSAGING_RECIPIENTS = {"email": {"email": "upgrade-rehearsal@example.invalid"},
                        "sms": {"phone": "+15555550100"}}
MESSAGING_SENDER_PROFILES = {"email": "transactional", "sms": "reminders-sms"}


class Messaging:
    def __init__(self, work: Path, keys: Keys, postgres: Postgres) -> None:
        self.work = private_directory(work)
        self.keys = keys
        self.postgres = postgres
        self.secrets = private_directory(work / "secrets")
        self.audit = private_directory(work / "audit")
        self.project = work / "project"
        self.package = work / "package"
        self.runtime = work / "runtime.yaml"
        self.port = free_port()
        # Every message is scheduled a day out, so no dispatch attempt can
        # change what the previous release served before the upgrade.
        now = time.time()
        self.not_before = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 86400))
        self.expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 2 * 86400))

    def provision(self) -> None:
        migration, runtime = secrets.token_hex(16), secrets.token_hex(16)
        self.postgres.sql("postgres", f"""
            CREATE ROLE messaging_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              NOINHERIT NOBYPASSRLS PASSWORD '{migration}';
            CREATE ROLE messaging_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
              NOINHERIT NOBYPASSRLS PASSWORD '{runtime}';
        """)
        self.postgres.sql("postgres", "CREATE DATABASE messaging;")
        self.postgres.sql("messaging", """
            REVOKE ALL ON DATABASE messaging FROM PUBLIC;
            GRANT CONNECT ON DATABASE messaging TO messaging_migration, messaging_runtime;
            ALTER SCHEMA public OWNER TO messaging_migration;
            REVOKE ALL ON SCHEMA public FROM PUBLIC;
            GRANT USAGE ON SCHEMA public TO messaging_runtime;
        """)
        write_secret(self.secrets / "runtime-database-url",
                     self.postgres.url("messaging_runtime", runtime, "messaging"))
        write_secret(self.secrets / "migration-database-url",
                     self.postgres.url("messaging_migration", migration, "messaging"))
        write_secret(self.secrets / "postgres-ca.pem", self.postgres.ca_file.read_bytes())
        write_secret(self.secrets / "messaging-audit-key", secrets.token_hex(32))
        write_secret(self.secrets / "jwks.json",
                     json.dumps({"keys": [self.keys.rsa_jwk(MESSAGING_KID)]}))

    def author(self, side: Side) -> None:
        side.run("messagingctl", "init", str(self.project))
        side.run("messagingctl", "check", "--project", str(self.project))
        side.run("messagingctl", "package", str(self.project), "--output", str(self.package))
        side.run("messagingctl", "check", "--package", str(self.package))
        dump_yaml(self.runtime, {
            "apiVersion": "registry.registrystack.org/messaging-runtime/v1alpha1",
            "kind": "MessagingRuntimeConfig",
            "identity": {"databaseId": "messaging-upgrade-rehearsal"},
            "package": {"root": str(self.package)},
            "listener": {"bind": f"127.0.0.1:{self.port}",
                         "tlsTermination": "development-loopback",
                         "networkExposure": "private-address"},
            "secretProviders": {"file": {"root": str(self.secrets)}},
            "database": {"runtimeUrlRef": "secret:file/runtime-database-url",
                         "migrationUrlRef": "secret:file/migration-database-url",
                         "trustedRootCertificateRef": "secret:file/postgres-ca.pem"},
            "authentication": {"oidc": {
                "issuer": MESSAGING_ISSUER, "audience": MESSAGING_AUDIENCE,
                "allowedClients": ["case-system", "operations-console"],
                "jwksSource": {"kind": "static", "documentRef": "secret:file/jwks.json"}}},
            "audit": {"path": str(self.audit / "messaging.ndjson"),
                      "hashKeyRef": "secret:file/messaging-audit-key"},
        })

    def call(self, method: str, path: str, body: Any = None,
             headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], Any]:
        claims = {"iss": MESSAGING_ISSUER, "aud": MESSAGING_AUDIENCE, **MESSAGING_SENDER}
        request_headers = {
            "Authorization": "Bearer " + self.keys.mint("RS256", MESSAGING_KID, claims),
            "Accept": "application/json", **(headers or {})}
        return http(method, f"http://127.0.0.1:{self.port}{path}",
                    headers=request_headers, body=body)

    def submission(self, channel: str, reference: str) -> dict[str, Any]:
        template = MESSAGING_TEMPLATES[channel]
        sample = self.project / "templates" / template / "1" / "sample.json"
        return {"senderProfile": MESSAGING_SENDER_PROFILES[channel],
                "to": MESSAGING_RECIPIENTS[channel],
                "template": {"id": template, "version": "1"}, "locale": "en",
                "data": json.loads(sample.read_text(encoding="utf-8")),
                "correlationId": reference,
                "notBefore": self.not_before, "expiresAt": self.expires_at}

    def submit(self, key: str, body: dict[str, Any]) -> dict[str, Any]:
        status, _headers, receipt = self.call("POST", "/v1/messages", body,
                                              {"Idempotency-Key": key})
        expect_status("message submission", status, receipt, 202)
        return receipt

    def cancel(self, message_id: str) -> None:
        status, _headers, body = self.call("POST", f"/v1/messages/{message_id}/cancel")
        expect_status("message cancellation", status, body, 200)

    def views(self, message_ids: list[str]) -> dict[str, Any]:
        views: dict[str, Any] = {}
        for message_id in message_ids:
            status, _headers, body = self.call("GET", f"/v1/messages/{message_id}")
            expect_status("read message", status, body, 200)
            views[f"message/{message_id}"] = body
        return views


def rehearse_messaging(work: Path, keys: Keys, postgres: Postgres, old: Side, new: Side,
                       report: dict[str, Any]) -> None:
    messaging = Messaging(work, keys, postgres)
    messaging.provision()
    messaging.author(old)
    runtime = ["--runtime-config", str(messaging.runtime)]
    old.run("messagingctl", "plan", "--runtime-config", str(messaging.runtime))
    old.run("messagingctl", "apply", "--runtime-config", str(messaging.runtime))
    old.run("messagingctl", "status", "--runtime-config", str(messaging.runtime))
    ready = f"http://127.0.0.1:{messaging.port}/ready"
    service = Service(old, "messaging", [*runtime, "serve"], work / "messaging-old.log", ready)
    try:
        submitted = []
        for index, channel in enumerate(("email", "sms", "email")):
            key = str(uuid.uuid4())
            body = messaging.submission(channel, f"upgrade-rehearsal-{index}")
            submitted.append((key, body, messaging.submit(key, body)))
        message_ids = [receipt["id"] for _key, _body, receipt in submitted]
        messaging.cancel(message_ids[0])
        before_views = messaging.views(message_ids)
    finally:
        service.stop()
    before_counts = postgres.row_counts("messaging")

    new.run("messagingctl", "check", "--runtime-config", str(messaging.runtime))
    # The ledger must still name the package on disk: a dry run that reports
    # a change means the upgrade lost the activation.
    ledger = new.run_json("messagingctl", "--format", "json", "plan", "--runtime-config",
                          str(messaging.runtime))
    differences = []
    if ledger.get("change") != "none" or ledger.get("activeDigest") != ledger.get(
            "packageDigest"):
        differences.append("the package ledger no longer names the applied package")
    losses = row_count_losses(before_counts, postgres.row_counts("messaging"))
    service = Service(new, "messaging", [*runtime, "serve"], work / "messaging-new.log", ready)
    try:
        after_views = messaging.views(message_ids)
        differences += view_differences(before_views, after_views)
        key, body, receipt = submitted[1]
        if messaging.submit(key, body) != receipt:
            differences.append("an idempotent resubmission no longer answers its "
                               "stored receipt")
        messaging.cancel(message_ids[1])
        messaging.submit(str(uuid.uuid4()), messaging.submission("sms", "after-upgrade"))
    finally:
        service.stop()
    losses += row_count_losses(before_counts, postgres.row_counts("messaging"))

    report["messaging"] = {
        "messages": len(message_ids),
        "tables": len(before_counts),
        "viewDifferences": differences,
        "rowLosses": losses,
    }
    if differences or losses:
        raise RehearsalError("Messaging state did not survive the upgrade: "
                             + "; ".join(differences + losses))


# ---------------------------------------------------------------------------
# Evidence: sign a response, archive the old stream, upgrade, inspect new entries.


EVIDENCE_KID = "upgrade-rehearsal-evidence-issuer"
EVIDENCE_REQUIREMENT = "urn:example:requirement:record-status:v1"
EVIDENCE_PURPOSE = "record-status-check"
EVIDENCE_LOCAL_IDENTIFIERS = "urn:registrystack:evidence:local:"
EVIDENCE_REHEARSAL_IDENTIFIERS = "urn:example:upgrade-rehearsal:"
EVIDENCE_PUBLIC_ORIGIN = "https://evidence.example.test"


def evidence_production_governance(document: dict[str, Any], issuer: str,
                                   public_jwk_file: str) -> dict[str, Any]:
    """Turn the governance `target new --local` writes into a production one:
    `evidencectl package` refuses a local target, and a production profile
    refuses the local starter's disposable identifiers, plain-HTTP origins,
    and empty response formats."""

    text = json.dumps(document).replace(EVIDENCE_LOCAL_IDENTIFIERS,
                                        EVIDENCE_REHEARSAL_IDENTIFIERS)
    governance = json.loads(text)
    governance["assuranceProfile"] = "production"
    governance["service"]["publicOrigin"] = EVIDENCE_PUBLIC_ORIGIN
    governance["publication"]["endpointUrl"] = EVIDENCE_PUBLIC_ORIGIN
    governance["responseFormats"] = ["signed-jws"]
    governance["signing"]["activePublicJwkFile"] = public_jwk_file
    # A local target grants every starter request implicitly; production
    # names the one path the rehearsal's request takes.
    for profile in governance["authorityProfiles"].values():
        if not profile["grants"]:
            profile["grants"] = [{
                "requirement": EVIDENCE_REQUIREMENT, "purpose": EVIDENCE_PURPOSE,
                "audienceFrom": "authenticated-requester", "responseFormats": ["signed-jws"],
                "subjects": [{"role": "subject", "selectorProfile": "record-reference-v1",
                              "valueOrigin": "request"}]}]
    oidc = governance["authentication"]["oidc"]
    oidc["issuer"] = issuer
    oidc["jwksSource"] = {"kind": "uri", "uri": f"{issuer}/oauth2/jwks"}
    return governance


def breg_arguments(runtime: Path) -> list[str]:
    return ["--runtime-config", str(runtime)]


def evidence_arguments(runtime: Path, subcommand: str) -> list[str]:
    return [subcommand, "--runtime-config", str(runtime)]


class Evidence:
    def __init__(self, work: Path, keys: Keys, tls: Path) -> None:
        self.work = private_directory(work)
        self.keys = keys
        self.project = work / "project"
        self.target = work / "target"
        self.candidate = work / "candidate"
        self.installed = work / "installed"
        self.runtime = work / "runtime.yaml"
        self.audit = private_directory(work / "audit")
        self.port = free_port()
        self.jwks = JwksServer({"keys": [keys.rsa_jwk(EVIDENCE_KID)]}, tls)
        self.issuer = f"https://127.0.0.1:{self.jwks.port}"
        signing_key = work / "transit-signing.pem"
        run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out",
             str(signing_key)])
        signing_key.chmod(0o600)
        self.signing_jwk = ec_public_jwk(signing_key)
        self.transit = TransitServer(signing_key)
        self.governance: dict[str, Any] = {}

    def stop(self) -> None:
        self.jwks.stop()
        self.transit.stop()

    def target_runtime(self, runtime: dict[str, Any]) -> dict[str, Any]:
        """Point a target runtime at this rehearsal's listener, audit file,
        extract, Transit signer, and installed package."""

        runtime["signer"] = {"kind": "transit", "unixSocketPath": str(self.transit.socket_path),
                             "mount": "transit", "keyName": TransitServer.KEY_NAME,
                             "keyVersion": 1, "timeoutMilliseconds": 2000}
        # The package is installed at a stable path outside the candidate.
        runtime["package"]["root"] = str(self.installed)
        runtime["listener"]["bind"] = f"127.0.0.1:{self.port}"
        runtime["audit"]["path"] = str(self.audit / "evidence.jsonl")
        extract = self.work / "record-status.sqlite"
        if not extract.exists():
            self.extract()
        runtime["sourceExtracts"] = {"record-status-extract": {"path": str(extract)}}
        return runtime

    def package(self, side: Side, candidate: Path) -> None:
        """Package the target, install the package, and write the operative
        runtime beside it."""

        target_runtime = self.target / "runtime.yaml"
        side.run("evidencectl", "package", "--target", str(self.target), "--output",
                 str(candidate), str(self.project))
        runtime = load_yaml(target_runtime)
        if self.installed.exists():
            # evidencectl seals every package directory read-only.
            for directory, _, _ in os.walk(self.installed):
                os.chmod(directory, 0o700)
            shutil.rmtree(self.installed)
        candidate.rename(self.installed)
        if self.runtime.exists():
            self.runtime.chmod(0o600)
        dump_yaml(self.runtime, runtime)
        # Evidence refuses a deployment input it could rewrite.
        self.runtime.chmod(0o444)

    def author(self, side: Side) -> None:
        side.run("evidencectl", "new", "--transport", "sqlite-extract", "--profile", "local",
                 str(self.project))
        side.run("evidencectl", "target", "new", "--local", "--project", str(self.project),
                 str(self.target))
        # `evidencectl package` refuses a local target, so the rehearsal
        # deploys a production one signing through Transit.
        public_keys = self.target / "public-keys"
        for stale in public_keys.iterdir():
            stale.unlink()
        public_jwk_file = f"public-keys/{self.signing_jwk['kid']}.jwk.json"
        (self.target / public_jwk_file).write_text(json.dumps(self.signing_jwk) + "\n")
        governance_path = self.target / "governance.yaml"
        self.governance = evidence_production_governance(load_yaml(governance_path),
                                                         self.issuer, public_jwk_file)
        dump_yaml(governance_path, self.governance)
        target_runtime = self.target / "runtime.yaml"
        dump_yaml(target_runtime, self.target_runtime(load_yaml(target_runtime)))
        self.package(side, self.candidate)

    def upgrade(self, side: Side) -> None:
        """Package the unchanged target with this side's evidencectl, install
        the package, and point the operative runtime at it, the documented
        upgrade step. The audit stream, secrets, and keys stay where they are.
        """

        self.package(side, self.work / "candidate-upgraded")

    def extract(self) -> Path:
        """Publish the starter's synthetic extract as a fresh read-only SQLite file."""

        fixture = load_yaml(self.project / "fixtures" / "record-status.yaml")
        statements = fixture["common"]["extract"]
        published = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        statements = re.sub(r"'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'", f"'{published}'",
                            statements)
        path = self.work / "record-status.sqlite"
        connection = sqlite3.connect(path)
        try:
            connection.executescript(statements)
            connection.commit()
        finally:
            connection.close()
        path.chmod(0o444)
        return path

    def request(self) -> tuple[int, Any]:
        authentication = self.governance["authentication"]["oidc"]
        profile = next(iter(self.governance["authorityProfiles"].values()))
        claims = {"iss": self.issuer, "aud": authentication["audience"],
                  "sub": "upgrade-rehearsal-caller", "client_id": "upgrade-rehearsal-caller",
                  "scope": " ".join(authentication["requiredScopes"]),
                  "registry_actor_kind": "service",
                  authentication["requesterTagsClaim"]: profile["requesterTags"],
                  authentication["evidenceAudienceClaim"]:
                      EVIDENCE_REHEARSAL_IDENTIFIERS + "caller"}
        token = self.keys.mint("RS256", EVIDENCE_KID, claims)
        status, _headers, body = http(
            "POST", f"http://127.0.0.1:{self.port}/v1/evidence",
            headers={"Authorization": "Bearer " + token, "Accept": "application/jose+json"},
            body={"requestNonce": b64url(secrets.token_bytes(32)),
                  "requirement": EVIDENCE_REQUIREMENT, "purpose": EVIDENCE_PURPOSE,
                  "subjects": [{"role": "subject", "selector": {
                      "profile": "record-reference-v1",
                      "values": {"record_reference": "REC-0001"}}}]})
        return status, body


def rehearse_evidence(work: Path, keys: Keys, tls: Path, old: Side, new: Side,
                      report: dict[str, Any]) -> None:
    evidence = Evidence(work, keys, tls)
    try:
        evidence.author(old)
        check = evidence_arguments(evidence.runtime, "check")
        serve = evidence_arguments(evidence.runtime, "serve")
        old.run("evidence", *check)
        ready = f"http://127.0.0.1:{evidence.port}/ready"
        service = Service(old, "evidence", serve, work / "evidence-old.log", ready)
        try:
            status, before = evidence.request()
            expect_status("previous release evidence request", status, before, 200)
            _status, _headers, jwks = http(
                "GET", f"http://127.0.0.1:{evidence.port}/.well-known/evidence/jwks.json")
        finally:
            service.stop()
        records_before = audit_record_count(evidence.audit, "evidence.jsonl")
        archive = work / "audit-archive"
        archive_audit_files(evidence.audit, "evidence.jsonl", archive)

        evidence.upgrade(new)
        new.run("evidence", *check)
        service = Service(new, "evidence", serve, work / "evidence-new.log", ready)
        try:
            status, after = evidence.request()
            expect_status("upgraded evidence request", status, after, 200)
            _status, _headers, jwks_after = http(
                "GET", f"http://127.0.0.1:{evidence.port}/.well-known/evidence/jwks.json")
        finally:
            service.stop()
        fresh_records = audit_record_count(evidence.audit, "evidence.jsonl", schema="registry.evidence.audit/v2")
        archived_records = audit_record_count(archive, "evidence.jsonl")
        records_after = archived_records + fresh_records
    finally:
        evidence.stop()

    losses = []
    if records_before == 0 or archived_records != records_before or fresh_records < 2:
        losses.append("the archived audit stream was not preserved or the upgraded request wrote fewer than two entries")
    differences = view_differences({"jwks": jwks}, {"jwks": jwks_after})
    report["evidence"] = {
        "auditRecordsBefore": records_before,
        "auditRecordsAfter": records_after,
        "freshAuditRecords": fresh_records,
        "archivedAuditRecords": archived_records,
        "viewDifferences": differences,
        "rowLosses": losses,
    }
    if differences or losses:
        raise RehearsalError("Evidence state did not survive the upgrade: "
                             + "; ".join(differences + losses))


# ---------------------------------------------------------------------------
# Release download and orchestration.


def published_tags() -> list[str]:
    output = run(["gh", "release", "list", "--repo", REPOSITORY, "--limit", "100",
                  "--exclude-drafts", "--exclude-pre-releases", "--json", "tagName"]).stdout
    return [entry["tagName"] for entry in json.loads(output)]


def fetch_release(tag: str, platform: str, download: Path, bin_dir: Path,
                  binaries: tuple[str, ...]) -> None:
    """Download, authenticate, and install the previous release's binaries."""

    view = json.loads(run(["gh", "release", "view", tag, "--repo", REPOSITORY, "--json",
                           "isDraft,isPrerelease,tagName"]).stdout)
    if view != {"isDraft": False, "isPrerelease": False, "tagName": tag}:
        raise RehearsalError(f"{tag} is not a public, non-prerelease release")
    assets = asset_names(tag, platform, binaries)
    bundle = f"registry-stack-{tag}-SHA256SUMS.sigstore.json"
    private_directory(download)
    patterns = ["SHA256SUMS", bundle, *assets.values()]
    run(["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", str(download),
         *[argument for pattern in patterns for argument in ("--pattern", pattern)]])
    run(["cosign", "verify-blob", str(download / "SHA256SUMS"), "--bundle",
         str(download / bundle), "--certificate-identity", SIGNER_IDENTITY,
         "--certificate-oidc-issuer", SIGNER_ISSUER])
    digests = parse_sha256sums((download / "SHA256SUMS").read_text(encoding="utf-8"))
    verify_assets_by_name(download, list(assets.values()), digests)
    private_directory(bin_dir)
    for binary, asset in assets.items():
        install_asset(download / asset, binary, bin_dir)


def check_binaries(side: Side, expected_version: str | None,
                   binaries: tuple[str, ...]) -> dict[str, str]:
    versions = {}
    for binary in binaries:
        if not (side.bin_dir / binary).is_file():
            raise RehearsalError(f"{side.label} binaries lack {binary} in {side.bin_dir}")
        output = side.run(binary, "--version").stdout.strip()
        if expected_version is not None and not output.endswith(" " + expected_version):
            raise RehearsalError(f"{side.label} {binary} reports {output!r}, "
                                 f"expected version {expected_version}")
        versions[binary] = output
    return versions


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--to-bin-dir", type=Path,
                        help="directory holding breg, bregctl, casework, caseworkctl, "
                             "evidence, evidencectl, messaging, and messagingctl built "
                             "from this source")
    parser.add_argument("--fetch-only", action="store_true",
                        help="download and authenticate the previous release's binaries "
                             "into WORK_DIR/from-bin, check their versions, and stop")
    parser.add_argument("--from-tag",
                        help="published release to upgrade from; defaults to the newest "
                             "release at or below the workspace version")
    parser.add_argument("--platform", choices=PLATFORMS, required=True,
                        help="release asset platform matching this host")
    parser.add_argument("--work-dir", type=Path, required=True,
                        help="new directory for the rehearsal's state and logs")
    parser.add_argument("--container-name", default="registry-upgrade-rehearsal-postgres",
                        help="name of the disposable PostgreSQL container")
    parser.add_argument("--product", action="append", choices=PRODUCTS,
                        help="rehearse only the named products; repeatable")
    parser.add_argument("--from-bin-dir", type=Path,
                        help="use these previous-release binaries instead of downloading "
                             "them; their provenance is NOT verified")
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    args = parser.parse_args(argv)
    if args.fetch_only and args.from_bin_dir is not None:
        parser.error("--fetch-only downloads the release, so it refuses --from-bin-dir")
    if not args.fetch_only and args.to_bin_dir is None:
        parser.error("--to-bin-dir is required unless --fetch-only is given")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        version = workspace_version(ROOT)
        check_floor_is_current(released_versions(ROOT), version)
        from_tag = args.from_tag or select_from_tag(published_tags(), version)
        check_forward_path(from_tag, version)
        products, omitted = select_products(args.product, from_tag, args.platform,
                                            args.from_bin_dir is None)
        if args.work_dir.exists():
            raise RehearsalError(f"{args.work_dir} already exists")
        work = private_directory(args.work_dir.resolve())
        tls = work / "tls"
        report: dict[str, Any] = {"from": from_tag, "toWorkspaceVersion": version,
                                  "platform": args.platform, "omitted": omitted}
        for product, reason in omitted.items():
            print(f"omitting {product}: {reason}", flush=True)
        binaries = product_binaries(products)
        if args.from_bin_dir is None:
            from_bin = work / "from-bin"
            fetch_release(from_tag, args.platform, work / "download", from_bin, binaries)
            report["fromProvenance"] = "cosign and SHA256SUMS verified"
        else:
            from_bin = args.from_bin_dir.resolve()
            report["fromProvenance"] = "UNVERIFIED local override"
            print(f"warning: {from_bin} is not authenticated as {from_tag}", file=sys.stderr)
        old = Side("from", from_bin, tls / "ca.pem")
        report["fromVersions"] = check_binaries(old, from_tag[1:], binaries)
        if args.fetch_only:
            report["fromBinDir"] = str(from_bin)
            if args.report:
                args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        new = Side("to", args.to_bin_dir.resolve(), tls / "ca.pem")
        report["toVersions"] = check_binaries(new, None, binaries)
        keys = Keys(work / "keys")
        postgres = None
        try:
            if {"breg", "casework", "messaging"} & set(products):
                postgres = Postgres(args.container_name, tls)
            else:
                Postgres._make_certificates(tls)
            for product in products:
                print(f"rehearsing {product}: {from_tag} -> workspace {version}", flush=True)
                leg_work = work / product
                if product == "breg":
                    rehearse_breg(leg_work, keys, postgres, old, new, report)
                elif product == "casework":
                    rehearse_casework(leg_work, keys, postgres, old, new, report)
                elif product == "messaging":
                    rehearse_messaging(leg_work, keys, postgres, old, new, report)
                else:
                    rehearse_evidence(leg_work, keys, tls, old, new, report)
                print(f"{product}: state served and no rows dropped", flush=True)
        finally:
            if postgres is not None:
                postgres.remove()
            if args.report:
                args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    except (RehearsalError, subprocess.SubprocessError, OSError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
