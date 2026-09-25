#!/usr/bin/env python3
"""Bounded helpers for the Evidence load-test development session.

The stock ``evidencectl dev`` lifecycle owns the issuer container, the signing
bundle, and the Evidence process. ``evidencectl source mock serve`` owns the
synthetic source. This module prepares only the authored load-test project and
its synthetic subject pool, and validates the non-secret references that the
load harness consumes.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


MARKER = "registry-stack-evidence-loadtest-v1"
BUILD_PROFILES = ("debug", "release")
QUESTION_ID = "adult-status"
REQUIREMENT = f"urn:registrystack:evidence:local:requirement:{QUESTION_ID}"
SELECTOR_PROFILE = f"local-subject-{QUESTION_ID}-v1"
PURPOSE = "age-check"
ACCESS_POLICY = "loadtest"
CLIENT_PREFIX = "loadtest-"
DEFAULT_CLIENTS = 128
# Every fetched token must outlive the fetch plus the 4-minute run window that
# run.sh enforces, so the whole client set has to be fetched well inside the
# issuer's token lifetime.
MAXIMUM_CLIENTS = 256
MINIMUM_TOKEN_SECONDS = 245
TOKEN_FETCH_PARALLELISM = 16
SUBJECTS = 200
ABSENT_SUBJECTS = 50
MINOR_EVERY = 5
OPENAPI_PLACEHOLDER = "http://127.0.0.1:MOCK_PORT"
RATE_LIMIT_KEYS = (
    "requestsPerPrincipalPerMinute",
    "burstPerPrincipal",
    "failedSelectorAttemptsPerPrincipalAuthorityPerMinute",
)


class LoadtestError(RuntimeError):
    pass


def _write_new(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def _replace_file(path: Path, content: str) -> None:
    """Replace an owner-only file atomically so a reader never sees a partial list."""
    staging = path.with_name(f".{path.name}.{os.getpid()}")
    _write_new(staging, content)
    os.replace(staging, path)


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LoadtestError(f"{path.name} must contain one JSON object")
    return value


def _owner_only_regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise LoadtestError(f"{label} must be an owner-only regular file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise LoadtestError(f"{label} must be an owner-only regular file")
    return path.resolve()


def _require_root(root: Path) -> Path:
    if root.is_symlink():
        raise LoadtestError("load-test run directory must not be a symbolic link")
    resolved = root.resolve()
    if not resolved.is_dir():
        raise LoadtestError("load-test run directory must be an existing ordinary directory")
    marker = resolved / ".launcher-owned"
    if marker.read_text(encoding="ascii").strip() != MARKER:
        raise LoadtestError("load-test run directory has no matching ownership marker")
    return resolved


def reserve_ports() -> tuple[int, int, int]:
    """Return free loopback ports for the source mock, Evidence, and the issuer."""
    listeners: list[socket.socket] = []
    try:
        for _ in range(3):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return tuple(listener.getsockname()[1] for listener in listeners)  # type: ignore[return-value]
    finally:
        for listener in listeners:
            listener.close()


def client_ids(count: int) -> list[str]:
    if not 1 <= count <= MAXIMUM_CLIENTS:
        raise LoadtestError(f"load client count must be between 1 and {MAXIMUM_CLIENTS}")
    return [f"{CLIENT_PREFIX}{index:03d}" for index in range(1, count + 1)]


def subject_id(index: int) -> str:
    return f"lt-subject-{index:04d}"


def absent_id(index: int) -> str:
    return f"lt-absent-{index:04d}"


def date_of_birth(index: int) -> str:
    """Deterministic synthetic birth date; every fifth subject is a minor."""
    month = index % 12 + 1
    day = index % 28 + 1
    year = 2012 + index % 7 if index % MINOR_EVERY == 0 else 1950 + index % 50
    return f"{year:04d}-{month:02d}-{day:02d}"


def render_openapi(template: Path, port: int, output: Path) -> None:
    if not 1 <= port <= 65535:
        raise LoadtestError("source mock port must be a TCP port")
    source = template.read_text(encoding="utf-8")
    if source.count(OPENAPI_PLACEHOLDER) != 1:
        raise LoadtestError("load-test OpenAPI template must name the mock origin exactly once")
    _write_new(output, source.replace(OPENAPI_PLACEHOLDER, f"http://127.0.0.1:{port}", 1))


def _mock_plan(count: int) -> str:
    lines = [
        "version: 1",
        "openapi: ../source.openapi.yaml",
        "operations:",
        "  - method: GET",
        "    path: /people/{person_id}",
        "    operationId: getPerson",
        "    response:",
        "      status: 200",
        "      mediaType: application/json",
        "    cases:",
    ]
    for index in range(1, count + 1):
        identifier = subject_id(index)
        lines.extend(
            [
                f"      - name: {identifier}",
                "        request:",
                f"          pathParameters: {{person_id: {identifier}}}",
                f"        body: cases/{identifier}.json",
            ]
        )
    return "\n".join(lines) + "\n"


def local_project(tracked: Path, project: Path, pool: Path) -> None:
    """Add the tracked question and a synthetic source mock to an initialised project."""
    if tracked.is_symlink() or not tracked.is_dir():
        raise LoadtestError("tracked load-test project must be an ordinary directory")
    if any(path.is_symlink() for path in tracked.rglob("*")):
        raise LoadtestError("tracked load-test project must not contain symbolic links")
    if project.is_symlink() or not (project / "evidence-project.yaml").is_file():
        raise LoadtestError("load-test project must be initialised by evidencectl init first")
    if pool.exists() or pool.is_symlink():
        raise LoadtestError("load-test subject pool must not already exist")
    for relative in (f"questions/{QUESTION_ID}.yaml", f"derivations/{QUESTION_ID}.rhai"):
        destination = project / relative
        if destination.exists():
            raise LoadtestError(f"initialised project already has {relative}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tracked / relative, destination)
    mocks = project / "mocks"
    if (mocks / "source.yaml").exists():
        raise LoadtestError("initialised project already has a source mock plan")
    (mocks / "cases").mkdir(parents=True, exist_ok=True)
    (mocks / "source.yaml").write_text(_mock_plan(SUBJECTS), encoding="utf-8")
    minors = 0
    for index in range(1, SUBJECTS + 1):
        identifier = subject_id(index)
        born = date_of_birth(index)
        minors += int(index % MINOR_EVERY == 0)
        body = {"person_id": identifier, "name": f"Load Subject {index:04d}", "date_of_birth": born}
        _write_new(mocks / "cases" / f"{identifier}.json", json.dumps(body, sort_keys=True) + "\n", 0o644)
    pool.mkdir(mode=0o700)
    _write_new(pool / "subjects.txt", "".join(f"{subject_id(i)}\n" for i in range(1, SUBJECTS + 1)))
    _write_new(pool / "absent.txt", "".join(f"{absent_id(i)}\n" for i in range(1, ABSENT_SUBJECTS + 1)))
    facts = {
        "subjects": SUBJECTS,
        "adultSubjects": SUBJECTS - minors,
        "minorSubjects": minors,
        "absentSubjects": ABSENT_SUBJECTS,
    }
    _write_new(pool / "pool-facts.json", json.dumps(facts, indent=2, sort_keys=True) + "\n")


def bundle_rate_limits(bundle_text: str) -> dict[str, int]:
    """Read the per-principal limits the development bundle actually enforces."""
    limits = {}
    for key in RATE_LIMIT_KEYS:
        matches = re.findall(rf'"?{key}"?\s*:\s*([0-9]+)', bundle_text)
        if len(matches) != 1:
            raise LoadtestError(f"development bundle does not state exactly one {key}")
        limits[key] = int(matches[0])
    return limits


def _process_command(pid: int) -> str:
    result = subprocess.run(
        ["ps", "-ww", "-p", str(pid), "-o", "command="],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _process_cwd(pid: int) -> str:
    result = subprocess.run(
        ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return ""
    names = [line[1:] for line in result.stdout.splitlines() if line.startswith("n")]
    return names[0] if len(names) == 1 else ""


# `source mock serve --config` resolves its project-relative plan against the
# working directory, so the launcher starts the mock inside the project and
# ownership is the exact command line plus that working directory.
MOCK_CONFIG = "mocks/source.yaml"


def mock_command(evidencectl: Path, port: int) -> str:
    return f"{evidencectl} source mock serve --config {MOCK_CONFIG} --http-addr 127.0.0.1:{port}"


def _is_owned_mock(pid: int, evidencectl: Path, project: Path, port: int) -> bool:
    return _process_command(pid) == mock_command(evidencectl, port) and _process_cwd(pid) == str(project.resolve())


def write_environment(
    root: Path,
    dev_report: Path,
    evidencectl: Path,
    build_profile: str,
    runtime_library_path: str,
    mock_pid: int,
    mock_port: int,
    clients: int,
) -> None:
    root = _require_root(root)
    report = _read_json_object(dev_report)
    project = (root / "project").resolve()
    if Path(report.get("project", "")).resolve() != project or report.get("status") != "ready":
        raise LoadtestError("evidencectl dev did not report the expected ready project")
    origin = urlparse(str(report.get("evidenceOrigin", "")))
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None:
        raise LoadtestError("evidencectl dev reported a non-loopback Evidence origin")
    executable = evidencectl.resolve()
    if not executable.is_file():
        raise LoadtestError("evidencectl path must be a regular file")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("build profile must be debug or release")
    if ":" in runtime_library_path or (runtime_library_path and not Path(runtime_library_path).is_dir()):
        raise LoadtestError("runtime library path must be one existing directory")
    client_ids(clients)
    if not _is_owned_mock(mock_pid, executable, project, mock_port):
        raise LoadtestError("the recorded source mock process is not the one this launcher started")
    bundle = project / ".evidence/dev/bundle/evidence.yaml"
    bundle_text = bundle.read_text(encoding="utf-8")
    for expected in (REQUIREMENT, SELECTOR_PROFILE):
        if expected not in bundle_text:
            raise LoadtestError("development bundle does not publish the load-test requirement")
    limits = bundle_rate_limits(bundle_text)
    environment = {
        "evidence_url": f"http://127.0.0.1:{origin.port}",
        "evidencectl": str(executable),
        "build_profile": build_profile,
        "runtime_library_path": runtime_library_path,
        "project": str(project),
        "clients": clients,
        "requirement": REQUIREMENT,
        "selector_profile": SELECTOR_PROFILE,
        "purpose": PURPOSE,
        "rate_limits": limits,
        "mock": {"pid": mock_pid, "port": mock_port},
    }
    _write_new(root / "env.json", json.dumps(environment, indent=2, sort_keys=True) + "\n")
    facts = _read_json_object(root / "pool/pool-facts.json")
    summary = {**facts, "loadClients": clients, **limits}
    _write_new(root / "pool/pool-summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")


def describe(root: Path, repository: Path) -> tuple[str, str, str, str, str]:
    """Validate an owned environment and return its non-secret shell fields."""
    root = _require_root(root)
    environment = _read_json_object(root / "env.json")
    build_profile = environment.get("build_profile", "debug")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("environment records an unknown build profile")
    evidencectl = Path(str(environment.get("evidencectl", "")))
    if evidencectl != repository.resolve() / "target" / build_profile / "evidencectl" or not evidencectl.is_file():
        raise LoadtestError(
            "the evidencectl recorded by this environment is unavailable; preserve state and restore the matching build"
        )
    project = Path(str(environment.get("project", "")))
    if project != root / "project":
        raise LoadtestError("load-test environment references paths outside its owned checkout state")
    clients = environment.get("clients")
    if not isinstance(clients, int) or isinstance(clients, bool):
        raise LoadtestError("load-test environment does not record its client count")
    client_ids(clients)
    library_path = str(environment.get("runtime_library_path", ""))
    if ":" in library_path or any(character.isspace() for character in library_path):
        raise LoadtestError("runtime library path must be one directory without separators")
    for value in (str(evidencectl), str(project)):
        if any(character.isspace() for character in value) or ":" in value:
            raise LoadtestError("load-test paths must not contain whitespace or colons")
    origin = urlparse(str(environment.get("evidence_url", "")))
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None:
        raise LoadtestError("load-test environment records a non-loopback Evidence origin")
    return str(environment["evidence_url"]), str(evidencectl), str(project), str(clients), library_path


def owned_mock_pid(root: Path) -> int | None:
    """Return the recorded mock PID only while it still runs the command this launcher started."""
    root = _require_root(root)
    environment = _read_json_object(root / "env.json")
    mock = environment.get("mock")
    if not isinstance(mock, dict):
        raise LoadtestError("load-test environment does not record its source mock")
    pid, port = mock.get("pid"), mock.get("port")
    if not all(isinstance(value, int) and not isinstance(value, bool) and value > 0 for value in (pid, port)):
        raise LoadtestError("load-test environment records an invalid source mock")
    owned = _is_owned_mock(pid, Path(str(environment["evidencectl"])), Path(str(environment["project"])), port)
    return pid if owned else None


def _token_seconds_remaining(header: str) -> float:
    """Return the remaining token lifetime without exposing the token itself."""
    token = header[len("Authorization: Bearer ") :].strip()
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    expiry = claims.get("exp") if isinstance(claims, dict) else None
    if not isinstance(expiry, (int, float)) or isinstance(expiry, bool):
        raise LoadtestError("evidencectl dev token returned a token without an expiry")
    return float(expiry) - time.time()


def fresh_header(evidencectl: Path, project: Path, client: str) -> Path:
    result = subprocess.run(
        [str(evidencectl), "--format", "json", "dev", "token", client, str(project)],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    report = json.loads(result.stdout)
    expected = project.resolve() / f".evidence/dev/generated/keys/{client}.header"
    reported = Path(report.get("headerFile", "")).resolve()
    if report.get("status") != "ready" or reported != expected:
        raise LoadtestError("evidencectl dev token reported a header outside the owned session")
    _owner_only_regular(reported, "authorization header")
    value = reported.read_text(encoding="ascii")
    if not value.startswith("Authorization: Bearer ") or value.count(".") != 2 or not value.endswith("\n"):
        raise LoadtestError("evidencectl dev token returned a malformed authorization header")
    return reported


def fresh_headers(root: Path, repository: Path) -> Path:
    """Fetch one fresh header per load client and write the list of their paths."""
    _, evidencectl, project, clients, _ = describe(root, repository)
    identifiers = client_ids(int(clients))
    with ThreadPoolExecutor(max_workers=TOKEN_FETCH_PARALLELISM) as pool:
        paths = list(pool.map(lambda client: fresh_header(Path(evidencectl), Path(project), client), identifiers))
    # The earliest fetched token expires first; check every one after the batch.
    shortest = min(_token_seconds_remaining(path.read_text(encoding="ascii")) for path in paths)
    if shortest < MINIMUM_TOKEN_SECONDS:
        raise LoadtestError(
            f"fresh tokens expire within {int(shortest)} seconds, too soon for a 4-minute run window"
        )
    listing = root.resolve() / "header-files.txt"
    _replace_file(listing, "".join(f"{path}\n" for path in paths))
    return listing


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("ports")
    clients = commands.add_parser("clients")
    clients.add_argument("--count", type=int, required=True)
    openapi = commands.add_parser("openapi")
    openapi.add_argument("--template", type=Path, required=True)
    openapi.add_argument("--port", type=int, required=True)
    openapi.add_argument("--out", type=Path, required=True)
    local = commands.add_parser("local-project")
    local.add_argument("--tracked", type=Path, required=True)
    local.add_argument("--project", type=Path, required=True)
    local.add_argument("--pool", type=Path, required=True)
    environment = commands.add_parser("environment")
    environment.add_argument("--root", type=Path, required=True)
    environment.add_argument("--dev-report", type=Path, required=True)
    environment.add_argument("--evidencectl", type=Path, required=True)
    environment.add_argument("--build-profile", choices=BUILD_PROFILES, required=True)
    environment.add_argument("--runtime-library-path", default="")
    environment.add_argument("--mock-pid", type=int, required=True)
    environment.add_argument("--mock-port", type=int, required=True)
    environment.add_argument("--clients", type=int, required=True)
    for name in ("describe", "mock-pid", "headers"):
        command = commands.add_parser(name)
        command.add_argument("--root", type=Path, required=True)
        if name != "mock-pid":
            command.add_argument("--repository", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "ports":
            print(" ".join(str(port) for port in reserve_ports()))
        elif arguments.command == "clients":
            print("\n".join(client_ids(arguments.count)))
        elif arguments.command == "openapi":
            render_openapi(arguments.template, arguments.port, arguments.out)
        elif arguments.command == "local-project":
            local_project(arguments.tracked, arguments.project, arguments.pool)
        elif arguments.command == "environment":
            write_environment(
                arguments.root,
                arguments.dev_report,
                arguments.evidencectl,
                arguments.build_profile,
                arguments.runtime_library_path,
                arguments.mock_pid,
                arguments.mock_port,
                arguments.clients,
            )
        elif arguments.command == "describe":
            print(" ".join(describe(arguments.root, arguments.repository)))
        elif arguments.command == "mock-pid":
            pid = owned_mock_pid(arguments.root)
            if pid is None:
                print("the recorded source mock is not running", file=sys.stderr)
                return 3
            print(pid)
        elif arguments.command == "headers":
            print(fresh_headers(arguments.root, arguments.repository))
    except (
        LoadtestError,
        OSError,
        UnicodeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"load-test environment error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
