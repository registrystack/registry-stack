"""Bounded helpers for the Registry Casework load-test development run.

``rstack dev`` owns PostgreSQL, the local token signing key, credentials, the
directory seed, and the Casework process. This module prepares only the
authored load-test project and validates the non-secret references that the
load harness consumes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


MARKER = "registry-stack-casework-loadtest-v2"
# The people the standalone-decision example's dev.yaml declares: the load
# harness drives every Staff request through one principal and every producer
# request through another.
PRODUCER_PERSON = "requester"
STAFF_PERSON = "staff"
HEADER_PEOPLE = (PRODUCER_PERSON, STAFF_PERSON)
RUN_ID = re.compile(r"[0-9a-f]{32}")
# The runtime pool is fixed in crates/registry-casework/src/store.rs; the
# development run cannot change it, so the evidence records the constant.
RUNTIME_POOL_MAX = 32
BUILD_PROFILES = ("debug", "release")
# The scenario only staffs the decisions queue. The example's own scenario
# also decides a request, which the load-test seed counts must not include.
SCENARIOS = """# yaml-language-server: $schema=https://id.registrystack.org/schemas/rstack/scenarios/scenarios.v1alpha1.schema.json
apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1
kind: RStackScenarios
scenarios:
  - id: staff-the-queue
    steps:
      - id: staff-the-queue
        product: casework
        as: administrator
        method: POST
        path: /v1/directory/bootstrap
        headers: {If-Match: '"0"', Idempotency-Key: staff-the-queue}
        body:
          teamId: decisions-team
          staff: [{issuer: https://identity.standalone.example.test, subject: staff}]
          supervisors: []
          queueId: decisions
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
    if not marker.is_file() or marker.read_text(encoding="ascii").strip() != MARKER:
        raise LoadtestError("load-test run directory has no matching ownership marker")
    return resolved


def local_project(example: Path, project: Path) -> None:
    if example.is_symlink() or not example.is_dir():
        raise LoadtestError("standalone-decision example must be an ordinary directory")
    if any(path.is_symlink() for path in example.rglob("*")):
        raise LoadtestError("standalone-decision example must not contain symbolic links")
    if project.exists() or project.is_symlink():
        raise LoadtestError("load-test project output must not already exist")
    shutil.copytree(example, project, symlinks=False, ignore=shutil.ignore_patterns("tests", "dev-clients.yaml"))
    (project / "tests").mkdir()
    (project / "tests/scenarios.yaml").write_text(SCENARIOS, encoding="utf-8")


def _run_id(value: object) -> str:
    if not isinstance(value, str) or not RUN_ID.fullmatch(value):
        raise LoadtestError("rstack dev reported a malformed run identifier")
    return value


def _loopback_origin(value: object, label: str) -> str:
    origin = urlparse(str(value))
    if (
        origin.scheme != "http"
        or origin.hostname != "127.0.0.1"
        or origin.port is None
        or origin.path not in ("", "/")
        or origin.query
        or origin.fragment
    ):
        raise LoadtestError(f"{label} must be a loopback Casework origin")
    return f"http://127.0.0.1:{origin.port}"


def write_environment(
    root: Path,
    start_report: Path,
    rstack: Path,
    build_profile: str,
    runtime_library_path: str,
) -> None:
    root = _require_root(root)
    report = _read_json_object(start_report)
    run_id = _run_id(report.get("run_id"))
    products = report.get("products")
    if not isinstance(products, dict) or "casework" not in products:
        raise LoadtestError("rstack dev did not report a Casework origin")
    casework_url = _loopback_origin(products["casework"], "rstack dev reported origin")
    executable = rstack.resolve()
    if not executable.is_file():
        raise LoadtestError("rstack path must be a regular file")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("build profile must be debug or release")
    if ":" in runtime_library_path or (runtime_library_path and not Path(runtime_library_path).is_dir()):
        raise LoadtestError("runtime library path must be one existing directory")
    environment = {
        "casework_url": casework_url,
        "rstack": str(executable),
        "build_profile": build_profile,
        "runtime_library_path": runtime_library_path,
        "run_id": run_id,
        "state_dir": str(root / "state"),
        "pool_max": RUNTIME_POOL_MAX,
        # rstack dev names the managed database after the run.
        "database": {"database": f"rstack_{run_id}_casework"},
    }
    _write_new(root / "env.json", json.dumps(environment, indent=2, sort_keys=True) + "\n")


def describe(root: Path, repository: Path) -> tuple[str, str, str, str]:
    """Validate an owned environment and return its non-secret shell fields."""
    root = _require_root(root)
    environment = _read_json_object(root / "env.json")
    build_profile = environment.get("build_profile")
    if build_profile not in BUILD_PROFILES:
        raise LoadtestError("environment records an unknown build profile")
    rstack = Path(str(environment.get("rstack", "")))
    if rstack != repository.resolve() / "target" / build_profile / "rstack" or not rstack.is_file():
        raise LoadtestError(
            "the rstack recorded by this environment is unavailable; preserve state and restore the matching build"
        )
    if Path(str(environment.get("state_dir", ""))) != root / "state":
        raise LoadtestError("load-test environment references paths outside its owned checkout state")
    run_id = _run_id(environment.get("run_id"))
    casework_url = _loopback_origin(environment.get("casework_url", ""), "environment origin")
    if casework_url != environment["casework_url"]:
        raise LoadtestError("environment records a non-canonical Casework origin")
    library_path = str(environment.get("runtime_library_path", ""))
    if ":" in library_path or any(character.isspace() for character in library_path):
        raise LoadtestError("runtime library path must be one directory without separators")
    if any(character.isspace() for character in str(rstack)):
        raise LoadtestError("load-test paths must not contain whitespace")
    return casework_url, str(rstack), run_id, library_path


def fresh_header(rstack: Path, run_id: str, state_dir: Path, person: str) -> Path:
    if person not in HEADER_PEOPLE:
        raise LoadtestError("the load-test person is not registered")
    _run_id(run_id)
    result = subprocess.run(
        [str(rstack), "--format", "json", "dev", "token", run_id, "--as", person],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
        env={**os.environ, "RSTACK_DEV_STATE_DIR": str(state_dir)},
    )
    report = json.loads(result.stdout)
    credentials = report.get("credentials") if isinstance(report, dict) else None
    if not isinstance(credentials, list) or len(credentials) != 1 or not isinstance(credentials[0], dict):
        raise LoadtestError("rstack dev token did not report one credential")
    reported = Path(str(credentials[0].get("header_file", ""))).resolve()
    if reported.parent != (state_dir / run_id).resolve():
        raise LoadtestError("rstack dev token reported a header outside the owned run")
    _owner_only_regular(reported, "authorization header")
    value = reported.read_text(encoding="ascii")
    lines = value.split("\n")
    # The file carries the bearer line, the Casework profile, and then the
    # review profile.
    if (
        not value.endswith("\n")
        or len(lines) != 4
        or not lines[0].startswith("Authorization: Bearer ")
        or lines[0].count(".") != 2
        or not lines[1].startswith("Registry-Casework-Profile: ")
        or not lines[2].startswith("Registry-Review-Profile: ")
    ):
        raise LoadtestError("rstack dev token returned a malformed authorization header")
    return reported


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    local = commands.add_parser("local-project")
    local.add_argument("--example", type=Path, required=True)
    local.add_argument("--project", type=Path, required=True)
    environment = commands.add_parser("environment")
    environment.add_argument("--root", type=Path, required=True)
    environment.add_argument("--start-report", type=Path, required=True)
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
    header.add_argument("--person", choices=HEADER_PEOPLE, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "local-project":
            local_project(arguments.example, arguments.project)
        elif arguments.command == "environment":
            write_environment(
                arguments.root,
                arguments.start_report,
                arguments.rstack,
                arguments.build_profile,
                arguments.runtime_library_path,
            )
        elif arguments.command == "describe":
            print(" ".join(describe(arguments.root, arguments.repository)))
        elif arguments.command == "header":
            print(fresh_header(arguments.rstack, arguments.run_id, arguments.state_dir, arguments.person))
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
