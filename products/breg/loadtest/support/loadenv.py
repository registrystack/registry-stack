#!/usr/bin/env python3
"""Bounded helpers for the BReg load-test development run.

``rstack dev`` owns PostgreSQL, the local issuer, package activation,
credentials, and the BReg process. This module prepares only the authored
load-test project and validates the non-secret references that the load
harness consumes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CLIENT_ID = "loadtest-driver"
RUN_ID = re.compile(r"[0-9a-f]{32}")
STATE_DIRECTORY = "state"
DEV_POOL_MAX = 4
BUILD_PROFILES = ("debug", "release")
SOURCE_REVISION = "business-establishments-loadtest-0.1.0"
DEV_PLAN = """apiVersion: id.registrystack.org/formats/rstack/dev/v1alpha1
kind: RStackDev
issuer: https://identity.loadtest.example.test
products:
  - {product: breg, project: ., audience: "urn:example:business-establishments"}
people:
  loadtest-driver:
    subject: synthetic-business-operator
    client: loadtest-driver
    grants:
      breg:
        profile: business-operator
        scopes: ["registry:business:operate"]
        claims:
          registry_actor_kind: human
          registry_purpose: business-administration
scenarioFile: dev/scenarios.yaml
"""

# The authored journeys carry the fixture's checks. This one read proves the
# served registry answers the load client before the harness seeds it.
DEV_SCENARIOS = """apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1
kind: RStackScenarios
scenarios:
  - id: operator-lists-establishments
    steps:
      - id: list-establishments
        product: breg
        as: loadtest-driver
        method: GET
        path: /v1/records/establishments?$top=1
        expect: {status: 200}
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


def _without_nonrepresentative_journey(source: str) -> str:
    """Drop the alternate-claims case that cannot share the one dev person."""
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
    model = _read_json_object(registry)
    package = model.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("sourceRevision"), str):
        raise LoadtestError("business-establishments fixture must declare package.sourceRevision")
    package["sourceRevision"] = SOURCE_REVISION
    registry.write_text(json.dumps(model, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    journeys = project / "tests/journeys.yaml"
    journeys.write_text(
        _without_nonrepresentative_journey(journeys.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    (project / "dev.yaml").write_text(DEV_PLAN, encoding="utf-8")
    (project / "dev").mkdir()
    (project / "dev/scenarios.yaml").write_text(DEV_SCENARIOS, encoding="utf-8")


def _hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdefABCDEF" for c in value)


def database_container(run_id: str, docker: str = "docker") -> str:
    """The full ID of the one container a run's managed database occupies."""
    if not RUN_ID.fullmatch(run_id):
        raise LoadtestError("run id must be 32 lowercase hexadecimal characters")
    result = subprocess.run(
        [docker, "ps", "--all", "--no-trunc", "--quiet", "--filter", f"label=org.registrystack.rstack.dev-run={run_id}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    containers = result.stdout.split()
    if len(containers) != 1:
        raise LoadtestError("the run must own exactly one managed database container")
    return containers[0]


def write_environment(
    root: Path,
    dev_report: Path,
    rstack: Path,
    build_profile: str,
    runtime_library_path: str,
    container: str,
) -> None:
    root = _require_root(root)
    report = _read_json_object(dev_report)
    run_id = report.get("run_id")
    products = report.get("products")
    scenarios = report.get("scenarios")
    if (
        report.get("schema_version") != "registry.rstack.dev.v1"
        or not isinstance(run_id, str)
        or not RUN_ID.fullmatch(run_id)
        or not isinstance(products, dict)
        or not isinstance(scenarios, list)
        or any(not isinstance(item, dict) or item.get("result") != "passed" for item in scenarios)
    ):
        raise LoadtestError("rstack dev did not report a ready run")
    if not _hex(container, 64):
        raise LoadtestError("the run has no bounded database container identity")
    origin = urlparse(str(products.get("breg", "")))
    if origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None:
        raise LoadtestError("rstack dev reported a non-loopback BReg origin")
    executable = rstack.resolve()
    if not executable.is_file():
        raise LoadtestError("rstack path must be a regular file")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("build profile must be debug or release")
    if ":" in runtime_library_path or (runtime_library_path and not Path(runtime_library_path).is_dir()):
        raise LoadtestError("runtime library path must be one existing directory")
    environment = {
        "breg_url": products["breg"],
        "rstack": str(executable),
        "run_id": run_id,
        "build_profile": build_profile,
        "runtime_library_path": runtime_library_path,
        "project": str((root / "project").resolve()),
        "pool_max": DEV_POOL_MAX,
        "database": {"container": container, "database": f"rstack_{run_id}_breg"},
    }
    _write_new(root / "env.json", json.dumps(environment, indent=2, sort_keys=True) + "\n")


def describe(root: Path, repository: Path) -> tuple[str, str, str, str, str]:
    """Validate an owned environment and return its non-secret shell fields."""
    root = _require_root(root)
    environment = _read_json_object(root / "env.json")
    build_profile = environment.get("build_profile", "debug")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("environment records an unknown build profile")
    rstack = Path(str(environment.get("rstack", "")))
    if rstack != repository.resolve() / "target" / build_profile / "rstack" or not rstack.is_file():
        raise LoadtestError(
            "the rstack recorded by this environment is unavailable; preserve state and restore the matching build"
        )
    run_id = str(environment.get("run_id", ""))
    if not RUN_ID.fullmatch(run_id):
        raise LoadtestError("environment records no valid run id")
    project = Path(str(environment.get("project", "")))
    if project != root / "project":
        raise LoadtestError("load-test environment references paths outside its owned checkout state")
    library_path = str(environment.get("runtime_library_path", ""))
    if ":" in library_path or any(character.isspace() for character in library_path):
        raise LoadtestError("runtime library path must be one directory without separators")
    state_dir = root / STATE_DIRECTORY
    for value in (str(rstack), str(state_dir)):
        if any(character.isspace() for character in value):
            raise LoadtestError("load-test paths must not contain whitespace")
    return str(environment["breg_url"]), str(rstack), run_id, str(state_dir), library_path


def fresh_header(rstack: Path, run_id: str, state_dir: Path, client: str) -> Path:
    if client != CLIENT_ID:
        raise LoadtestError("the load-test client is not registered")
    if not RUN_ID.fullmatch(run_id):
        raise LoadtestError("run id must be 32 lowercase hexadecimal characters")
    # `--install-root` names the directory that holds the sibling built tools.
    result = subprocess.run(
        [
            str(rstack),
            "--install-root",
            str(rstack.resolve().parent),
            "--format",
            "json",
            "dev",
            "token",
            run_id,
            "--as",
            client,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
        env={**os.environ, "RSTACK_DEV_STATE_DIR": str(state_dir)},
    )
    credentials = json.loads(result.stdout).get("credentials")
    if not isinstance(credentials, list) or len(credentials) != 1:
        raise LoadtestError("rstack dev token must report exactly one credential")
    reported = _owner_only_regular(Path(str(credentials[0].get("header_file", ""))), "authorization header")
    value = reported.read_text(encoding="ascii")
    if not value.startswith("Authorization: Bearer ") or value.count(".") != 2 or not value.endswith("\n"):
        raise LoadtestError("rstack dev token returned a malformed authorization header")
    return reported


def _run_id_of(dev_report: Path) -> str:
    return str(_read_json_object(dev_report).get("run_id", ""))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    local = commands.add_parser("local-project")
    local.add_argument("--fixture", type=Path, required=True)
    local.add_argument("--project", type=Path, required=True)
    environment = commands.add_parser("environment")
    environment.add_argument("--root", type=Path, required=True)
    environment.add_argument("--dev-report", type=Path, required=True)
    environment.add_argument("--rstack", type=Path, required=True)
    environment.add_argument("--build-profile", choices=BUILD_PROFILES, required=True)
    environment.add_argument("--runtime-library-path", default="")
    describe_command = commands.add_parser("describe")
    describe_command.add_argument("--root", type=Path, required=True)
    describe_command.add_argument("--repository", type=Path, required=True)
    header = commands.add_parser("header")
    header.add_argument("--rstack", type=Path, required=True)
    header.add_argument("--run-id", required=True)
    header.add_argument("--state-dir", type=Path, required=True)
    header.add_argument("--client", default=CLIENT_ID)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "local-project":
            local_project(arguments.fixture, arguments.project)
        elif arguments.command == "environment":
            write_environment(
                arguments.root,
                arguments.dev_report,
                arguments.rstack,
                arguments.build_profile,
                arguments.runtime_library_path,
                database_container(_run_id_of(arguments.dev_report)),
            )
        elif arguments.command == "describe":
            print(" ".join(describe(arguments.root, arguments.repository)))
        elif arguments.command == "header":
            print(fresh_header(arguments.rstack, arguments.run_id, arguments.state_dir, arguments.client))
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
