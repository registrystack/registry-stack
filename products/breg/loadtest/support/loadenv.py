#!/usr/bin/env python3
"""Bounded helpers for the BReg load-test development session.

The stock ``bregctl dev`` lifecycle owns PostgreSQL, ThunderID, package
activation, credentials, and the BReg process. This module prepares only the
authored load-test project and validates the non-secret references that the
load harness consumes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CLIENT_ID = "loadtest-driver"
DATABASE_NAME = "breg_dev"
DEV_POOL_MAX = 4
PROJECT_REPLACEMENTS = {
    "  environment: acceptance": "  environment: local",
    "  instanceId: business-establishments-acceptance": "  instanceId: business-establishments-loadtest",
    "  sourceRevision: business-establishments-acceptance-0.1.0": "  sourceRevision: business-establishments-loadtest-0.1.0",
}
DEV_CLIENTS = """version: 1
clients:
  - id: loadtest-driver
    accessProfiles: [business-operator]
    scopes: [registry:business:operate]
    claims:
      registry_principal: synthetic-business-operator
      registry_purpose: business-administration
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
    if marker.read_text(encoding="ascii").strip() != "registry-stack-breg-loadtest-v2":
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
        raise LoadtestError(f"fixture no longer has the expected line: {expected.strip()}")
    return source.replace(expected, replacement, 1)


def _without_nonrepresentative_journey(source: str) -> str:
    """Drop the alternate-claims case that cannot share a dev profile client."""
    kept: list[str] = []
    skipping = False
    found = False
    for line in source.splitlines(keepends=True):
        if line.startswith("      - id:"):
            skipping = "operator-without-purpose-is-concealed" in line
            found = found or skipping
        if not skipping:
            kept.append(line)
    if not found:
        raise LoadtestError("fixture no longer has the expected no-purpose journey")
    return "".join(kept)


def local_project(fixture: Path, project: Path) -> None:
    if fixture.is_symlink() or not fixture.is_dir():
        raise LoadtestError("business-establishments fixture must be an ordinary directory")
    if any(path.is_symlink() for path in fixture.rglob("*")):
        raise LoadtestError("business-establishments fixture must not contain symbolic links")
    if project.exists() or project.is_symlink():
        raise LoadtestError("load-test project output must not already exist")
    shutil.copytree(fixture, project, symlinks=False)
    registry = project / "registry.yaml"
    source = registry.read_text(encoding="utf-8")
    for expected, replacement in PROJECT_REPLACEMENTS.items():
        source = _replace_once(source, expected, replacement)
    registry.write_text(source, encoding="utf-8")
    journeys = project / "tests/journeys.yaml"
    journeys.write_text(
        _without_nonrepresentative_journey(journeys.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    (project / "dev-clients.yaml").write_text(DEV_CLIENTS, encoding="utf-8")


def write_environment(root: Path, dev_report: Path, bregctl: Path) -> None:
    root = _require_root(root)
    report = _read_json_object(dev_report)
    project = (root / "project").resolve()
    if Path(report.get("project", "")).resolve() != project or report.get("status") != "ready":
        raise LoadtestError("bregctl dev did not report the expected ready project")
    expected_state = project / ".breg/dev/state.json"
    if Path(report.get("stateFile", "")).resolve() != expected_state.resolve():
        raise LoadtestError("bregctl dev reported state outside the load-test project")
    state = _read_json_object(_owner_only_regular(expected_state, "development state"))
    container = state.get("containerId")
    if not isinstance(container, str) or len(container) != 64 or not all(c in "0123456789abcdefABCDEF" for c in container):
        raise LoadtestError("development state has no bounded database container identity")
    origin = urlparse(str(report.get("bregUrl", "")))
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None:
        raise LoadtestError("bregctl dev reported a non-loopback BReg origin")
    executable = bregctl.resolve()
    if not executable.is_file():
        raise LoadtestError("bregctl path must be a regular file")
    environment = {
        "breg_url": report["bregUrl"],
        "bregctl": str(executable),
        "project": str(project),
        "pool_max": DEV_POOL_MAX,
        "database": {"container": container, "database": DATABASE_NAME},
    }
    _write_new(root / "env.json", json.dumps(environment, indent=2, sort_keys=True) + "\n")


def fresh_header(bregctl: Path, project: Path, client: str) -> Path:
    if client != CLIENT_ID:
        raise LoadtestError("the load-test client is not registered")
    result = subprocess.run(
        [str(bregctl), "--format", "json", "dev", "token", client, str(project)],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    report = json.loads(result.stdout)
    expected = project.resolve() / f".breg/dev/secrets/{client}.header"
    reported = Path(report.get("headerFile", "")).resolve()
    if reported != expected:
        raise LoadtestError("bregctl dev token reported a header outside the owned session")
    _owner_only_regular(reported, "authorization header")
    value = reported.read_text(encoding="ascii")
    if not value.startswith("Authorization: Bearer ") or value.count(".") != 2 or not value.endswith("\n"):
        raise LoadtestError("bregctl dev token returned a malformed authorization header")
    return reported


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("ports")
    local = commands.add_parser("local-project")
    local.add_argument("--fixture", type=Path, required=True)
    local.add_argument("--project", type=Path, required=True)
    environment = commands.add_parser("environment")
    environment.add_argument("--root", type=Path, required=True)
    environment.add_argument("--dev-report", type=Path, required=True)
    environment.add_argument("--bregctl", type=Path, required=True)
    header = commands.add_parser("header")
    header.add_argument("--bregctl", type=Path, required=True)
    header.add_argument("--project", type=Path, required=True)
    header.add_argument("--client", default=CLIENT_ID)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "ports":
            print(" ".join(str(port) for port in reserve_ports()))
        elif arguments.command == "local-project":
            local_project(arguments.fixture, arguments.project)
        elif arguments.command == "environment":
            write_environment(arguments.root, arguments.dev_report, arguments.bregctl)
        elif arguments.command == "header":
            print(fresh_header(arguments.bregctl, arguments.project, arguments.client))
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
