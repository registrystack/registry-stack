#!/usr/bin/env python3
"""Bounded helpers for the Registry Casework load-test development session.

The stock ``caseworkctl dev`` lifecycle owns PostgreSQL, the local token
issuer, credentials, the directory seed, and the Casework process. This module
prepares only the authored load-test project and validates the non-secret
references that the load harness consumes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


MARKER = "registry-stack-casework-loadtest-v1"
PRODUCER_CLIENT = "loadtest-producer"
STAFF_CLIENT = "loadtest-staff"
HEADER_CLIENTS = (PRODUCER_CLIENT, STAFF_CLIENT)
DATABASE_NAME = "casework_dev"
# The runtime pool is fixed in crates/registry-casework/src/store.rs; the
# development lifecycle cannot change it, so the evidence records the constant.
RUNTIME_POOL_MAX = 32
BUILD_PROFILES = ("debug", "release")
EXAMPLE_ISSUER_LINE = "    issuer: http://127.0.0.1:8091\n"
EXAMPLE_SUBJECT_LINE = "    subject: requester\n"
SUBJECT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
# Synthetic local callers. One client binds each access profile the example
# declares, which is what caseworkctl dev requires, so the load harness drives
# every Staff request through one principal and every producer request through
# another. Nothing here is a credential.
DEV_CLIENTS = """version: 1
clients:
  - id: loadtest-admin
    accessProfile: administrator
    scopes: [casework:admin]
    claims:
      registry_actor_kind: human
  - id: loadtest-supervisor
    accessProfile: supervisor
    scopes: [casework:supervisor]
    claims:
      registry_actor_kind: human
  - id: loadtest-staff
    accessProfile: staff
    scopes: [casework:staff]
    claims:
      registry_actor_kind: human
  - id: loadtest-producer
    accessProfile: requester
    scopes: [casework:request]
directory:
  - team: loadtest-decisions
    queue: decisions
    staff: [loadtest-staff]
    supervisors: [loadtest-supervisor]
"""


class LoadtestError(RuntimeError):
    pass


def _write_new(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


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
    if not marker.is_file() or marker.read_text(encoding="ascii").strip() != MARKER:
        raise LoadtestError("load-test run directory has no matching ownership marker")
    return resolved


def reserve_ports() -> tuple[int, int, int]:
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


def _replace_once(source: str, expected: str, replacement: str) -> str:
    if source.count(expected) != 1:
        raise LoadtestError(f"example no longer has the expected line: {expected.strip()}")
    return source.replace(expected, replacement, 1)


def producer_subject(caseworkctl: Path) -> str:
    """The stable local subject caseworkctl dev issues to the producer client."""
    result = subprocess.run(
        [str(caseworkctl), "--format", "json", "dev", "identity", PRODUCER_CLIENT],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    if not isinstance(report, dict):
        raise LoadtestError("caseworkctl dev identity did not report one JSON object")
    subject = report.get("subject")
    if report.get("clientId") != PRODUCER_CLIENT or not isinstance(subject, str):
        raise LoadtestError("caseworkctl dev identity did not report the producer subject")
    if not SUBJECT_PATTERN.fullmatch(subject):
        raise LoadtestError("caseworkctl dev identity reported an unbounded subject")
    return subject


def local_project(example: Path, project: Path, issuer_port: int, subject: str) -> None:
    if example.is_symlink() or not example.is_dir():
        raise LoadtestError("standalone-decision example must be an ordinary directory")
    if any(path.is_symlink() for path in example.rglob("*")):
        raise LoadtestError("standalone-decision example must not contain symbolic links")
    if project.exists() or project.is_symlink():
        raise LoadtestError("load-test project output must not already exist")
    if not 1 <= issuer_port <= 65535:
        raise LoadtestError("issuer port must be a TCP port")
    if not SUBJECT_PATTERN.fullmatch(subject):
        raise LoadtestError("producer subject must be one bounded identifier")
    shutil.copytree(example, project, symlinks=False)
    policy = project / "casework.yaml"
    source = policy.read_text(encoding="utf-8")
    source = _replace_once(source, EXAMPLE_ISSUER_LINE, f"    issuer: http://127.0.0.1:{issuer_port}\n")
    source = _replace_once(source, EXAMPLE_SUBJECT_LINE, f"    subject: {subject}\n")
    policy.write_text(source, encoding="utf-8")
    (project / "dev-clients.yaml").write_text(DEV_CLIENTS, encoding="utf-8")


def write_environment(
    root: Path,
    dev_report: Path,
    caseworkctl: Path,
    build_profile: str,
    runtime_library_path: str,
) -> None:
    root = _require_root(root)
    report = _read_json_object(dev_report)
    project = (root / "project").resolve()
    if Path(str(report.get("project", ""))).resolve() != project or report.get("status") != "ready":
        raise LoadtestError("caseworkctl dev did not report the expected ready project")
    expected_state = project / ".casework/dev/state.json"
    if Path(str(report.get("stateFile", ""))).resolve() != expected_state.resolve():
        raise LoadtestError("caseworkctl dev reported state outside the load-test project")
    state = _read_json_object(_owner_only_regular(expected_state, "development state"))
    container = state.get("containerId")
    if (
        not isinstance(container, str)
        or len(container) != 64
        or not all(c in "0123456789abcdefABCDEF" for c in container)
    ):
        raise LoadtestError("development state has no bounded database container identity")
    origin = urlparse(str(report.get("caseworkUrl", "")))
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None or origin.path not in ("", "/"):
        raise LoadtestError("caseworkctl dev reported a non-loopback Casework origin")
    reported_clients = {
        client.get("id") for client in report.get("clients", []) if isinstance(client, dict)
    }
    if not set(HEADER_CLIENTS) <= reported_clients:
        raise LoadtestError("caseworkctl dev did not register the load-test clients")
    executable = caseworkctl.resolve()
    if not executable.is_file():
        raise LoadtestError("caseworkctl path must be a regular file")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("build profile must be debug or release")
    if ":" in runtime_library_path or (runtime_library_path and not Path(runtime_library_path).is_dir()):
        raise LoadtestError("runtime library path must be one existing directory")
    environment = {
        "casework_url": f"http://127.0.0.1:{origin.port}",
        "caseworkctl": str(executable),
        "build_profile": build_profile,
        "runtime_library_path": runtime_library_path,
        "project": str(project),
        "pool_max": RUNTIME_POOL_MAX,
        "database": {"container": container, "database": DATABASE_NAME},
    }
    _write_new(root / "env.json", json.dumps(environment, indent=2, sort_keys=True) + "\n")


def describe(root: Path, repository: Path) -> tuple[str, str, str, str]:
    """Validate an owned environment and return its non-secret shell fields."""
    root = _require_root(root)
    environment = _read_json_object(root / "env.json")
    build_profile = environment.get("build_profile")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("environment records an unknown build profile")
    caseworkctl = Path(str(environment.get("caseworkctl", "")))
    if caseworkctl != repository.resolve() / "target" / build_profile / "caseworkctl" or not caseworkctl.is_file():
        raise LoadtestError(
            "the caseworkctl recorded by this environment is unavailable; preserve state and restore the matching build"
        )
    project = Path(str(environment.get("project", "")))
    if project != root / "project":
        raise LoadtestError("load-test environment references paths outside its owned checkout state")
    origin = urlparse(str(environment.get("casework_url", "")))
    if (
        origin.scheme != "http"
        or origin.hostname != "127.0.0.1"
        or origin.port is None
        or origin.path
        or origin.query
        or origin.fragment
    ):
        raise LoadtestError("environment records a non-loopback Casework origin")
    library_path = str(environment.get("runtime_library_path", ""))
    if ":" in library_path or any(character.isspace() for character in library_path):
        raise LoadtestError("runtime library path must be one directory without separators")
    for value in (str(caseworkctl), str(project)):
        if any(character.isspace() for character in value):
            raise LoadtestError("load-test paths must not contain whitespace")
    return str(environment["casework_url"]), str(caseworkctl), str(project), library_path


def fresh_header(caseworkctl: Path, project: Path, client: str) -> Path:
    if client not in HEADER_CLIENTS:
        raise LoadtestError("the load-test client is not registered")
    result = subprocess.run(
        [str(caseworkctl), "--format", "json", "dev", "token", client, str(project)],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    report = json.loads(result.stdout)
    expected = project.resolve() / f".casework/dev/secrets/{client}.header"
    reported = Path(str(report.get("headerFile", ""))).resolve()
    if reported != expected:
        raise LoadtestError("caseworkctl dev token reported a header outside the owned session")
    _owner_only_regular(reported, "authorization header")
    value = reported.read_text(encoding="ascii")
    if not value.startswith("Authorization: Bearer ") or value.count(".") != 2 or not value.endswith("\n"):
        raise LoadtestError("caseworkctl dev token returned a malformed authorization header")
    return reported


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("ports")
    subject = commands.add_parser("producer-subject")
    subject.add_argument("--caseworkctl", type=Path, required=True)
    local = commands.add_parser("local-project")
    local.add_argument("--example", type=Path, required=True)
    local.add_argument("--project", type=Path, required=True)
    local.add_argument("--issuer-port", type=int, required=True)
    local.add_argument("--producer-subject", required=True)
    environment = commands.add_parser("environment")
    environment.add_argument("--root", type=Path, required=True)
    environment.add_argument("--dev-report", type=Path, required=True)
    environment.add_argument("--caseworkctl", type=Path, required=True)
    environment.add_argument("--build-profile", choices=BUILD_PROFILES, required=True)
    environment.add_argument("--runtime-library-path", default="")
    describe_command = commands.add_parser("describe")
    describe_command.add_argument("--root", type=Path, required=True)
    describe_command.add_argument("--repository", type=Path, required=True)
    header = commands.add_parser("header")
    header.add_argument("--caseworkctl", type=Path, required=True)
    header.add_argument("--project", type=Path, required=True)
    header.add_argument("--client", choices=HEADER_CLIENTS, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "ports":
            print(" ".join(str(port) for port in reserve_ports()))
        elif arguments.command == "producer-subject":
            print(producer_subject(arguments.caseworkctl))
        elif arguments.command == "local-project":
            local_project(arguments.example, arguments.project, arguments.issuer_port, arguments.producer_subject)
        elif arguments.command == "environment":
            write_environment(
                arguments.root,
                arguments.dev_report,
                arguments.caseworkctl,
                arguments.build_profile,
                arguments.runtime_library_path,
            )
        elif arguments.command == "describe":
            print(" ".join(describe(arguments.root, arguments.repository)))
        elif arguments.command == "header":
            print(fresh_header(arguments.caseworkctl, arguments.project, arguments.client))
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
