#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in generated TypeScript/Python client proof over disposable PostgreSQL.

Run from the checkout with COORDINATOR_TEST_DATABASE_URL naming an owned
loopback PostgreSQL 17+ database. Its identity must create/drop fixture schemas
and roles. Requires Cargo's native build toolchain, Node/npm and Pyright.
Missing pinned Node development dependencies are installed locally with npm ci;
native bindings and their runtime library paths are prepared from this checkout.
No global tools are installed and missing prerequisites are never skipped.
"""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[3]
NODE = REPO / "crates/registry-coordinator-client-node"
PYTHON = REPO / "crates/registry-coordinator-client-py"


class PrerequisiteError(ValueError):
    """An explicit proof prerequisite is unavailable."""


def proof_environment(source: dict[str, str]) -> dict[str, str]:
    environment = dict(source)
    environment.update(
        RUSTC_WRAPPER="", CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
        CARGO_PROFILE_TEST_DEBUG="0", PYO3_PYTHON=sys.executable,
    )
    environment.setdefault("CARGO_BUILD_JOBS", "2")
    # npm builds from the binding directory; keep every Cargo invocation on
    # the same target even when the caller supplied a repository-relative path.
    for name in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR"):
        if environment.get(name):
            target = Path(environment[name]).expanduser()
            environment[name] = str((REPO / target).resolve() if not target.is_absolute() else target)
    # The current npm build, not an ambient override, supplies the Node addon.
    environment.pop("NAPI_RS_NATIVE_LIBRARY_PATH", None)
    return environment


def require_database(environment: dict[str, str]) -> None:
    message = "COORDINATOR_TEST_DATABASE_URL must name an owned disposable loopback PostgreSQL 17+ database"
    try:
        database = urlsplit(environment.get("COORDINATOR_TEST_DATABASE_URL", ""))
        local = database.hostname == "localhost" or ipaddress.ip_address(database.hostname or "").is_loopback
        valid = database.scheme in {"postgres", "postgresql"} and local and bool(database.path.strip("/"))
    except ValueError:
        valid = False
    if not valid:
        raise PrerequisiteError(message)


def executable(name: str, override: str | None = None) -> Path:
    selected = override or name
    candidate = shutil.which(selected)
    if candidate is None:
        expanded = Path(selected).expanduser()
        if expanded.is_file() and os.access(expanded, os.X_OK):
            candidate = str(expanded)
    if candidate is None:
        if name == "pyright":
            raise PrerequisiteError(
                "Pyright is required: install it in a local virtual environment and pass "
                "--pyright /path/to/venv/bin/pyright, or put it on PATH"
            )
        raise PrerequisiteError(f"{name} is required; provide its executable on PATH or the named override")
    return Path(candidate).absolute()


def run_command(command: list[str], environment: dict[str, str], *, cwd: Path = REPO,
                capture: bool = False) -> str:
    result = subprocess.run(command, cwd=cwd, env=environment, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout or ""


def prepare_node(environment: dict[str, str], npm: Path, compiler: str | None) -> Path:
    required = [NODE / "node_modules/.bin/tsc", NODE / "node_modules/.bin/napi",
                NODE / "node_modules/@types/node/package.json"]
    if not all(path.is_file() for path in required):
        print("Installing pinned Node development dependencies locally.", flush=True)
        run_command([str(npm), "ci"], environment, cwd=NODE)
    tsc = executable("tsc", compiler or str(required[0]))
    return tsc


def prepare_runtime(environment: dict[str, str], directory: Path) -> None:
    if sys.platform != "darwin":
        return
    # Use the maintained resolver over this exact build, never glob an ambient
    # target directory containing multiple feature/profile outputs.
    spec = importlib.util.spec_from_file_location(
        "cargo_runtime_library_path", REPO / "scripts/cargo_runtime_library_path.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    messages = directory / "binding-build.jsonl"
    command = ["cargo", "build", "--locked", "-p", "registry-coordinator-client-node",
               "-p", "registry-coordinator-client-py", "--lib", "--features",
               "registry-coordinator-client-py/extension-module", "--message-format=json-render-diagnostics"]
    with messages.open("w") as output:
        result = subprocess.run(command, cwd=REPO, env=environment, stdout=output)
    lines = messages.read_text().splitlines()
    if result.returncode:
        sys.stderr.write(helper.rendered_diagnostics(lines))
        raise PrerequisiteError("current-source native binding build failed")
    try:
        runtime = str(helper.resolve_aws_lc_fips_artifacts(lines))
    except helper.ResolutionError as error:
        raise PrerequisiteError(f"could not prepare the native FIPS runtime library: {error}") from None
    environment["REGISTRY_CARGO_RUNTIME_LIBRARY_PATH"] = runtime
    prior = environment.get("DYLD_FALLBACK_LIBRARY_PATH")
    environment["DYLD_FALLBACK_LIBRARY_PATH"] = runtime + (os.pathsep + prior if prior else "")


def tool_wrapper(directory: Path, name: str, target: Path) -> None:
    wrapper = directory / name
    wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(str(target)) + ' "$@"\n')
    wrapper.chmod(0o700)


def proof_commands() -> list[list[str]]:
    common = ["cargo", "test", "--locked", "-p", "registry-coordinator",
              "--features", "schema,postgres-test"]
    return [
        common + ["--test", "sdk_generation", "--", "--ignored", "--test-threads=1"],
        common + ["--test", "deployment_postgres", "generated_", "--", "--ignored", "--test-threads=1"],
    ]


def run(compiler: str | None = None, checker: str | None = None) -> None:
    if sys.platform not in {"darwin", "linux"}:
        raise PrerequisiteError("the generated-client native proofs support macOS and Linux")
    environment = proof_environment(dict(os.environ))
    require_database(environment)
    for name in ("cargo", "node"):
        executable(name)
    npm = executable("npm")
    pyright = executable("pyright", checker or environment.get("COORDINATOR_SDK_PYRIGHT"))
    tsc = prepare_node(environment, npm, compiler or environment.get("COORDINATOR_SDK_TSC"))
    environment["COORDINATOR_SDK_TSC"] = str(tsc)
    with tempfile.TemporaryDirectory(prefix="coordinator-generated-clients-") as temporary:
        directory = Path(temporary)
        tools = directory / "bin"
        tools.mkdir()
        tool_wrapper(tools, "pyright", pyright)
        tool_wrapper(tools, "python3", Path(sys.executable))
        environment["PATH"] = str(tools) + os.pathsep + environment.get("PATH", os.defpath)
        prepare_runtime(environment, directory)
        print("Building current Coordinator Node and Python bindings.", flush=True)
        run_command([str(npm), "run", "build:debug"], environment, cwd=NODE)
        # Reuse the owning Python import/bootstrap layout and its locked build.
        bootstrap = PYTHON / "tests/python"
        script = (
            "import sys; from pathlib import Path; "
            f"sys.path.insert(0, {str(bootstrap)!r}); "
            "from bootstrap import ensure_built; ensure_built(); "
            "import registry_coordinator_client as client; "
            "print(Path(client.__file__).resolve().parent.parent)"
        )
        module_root = run_command([sys.executable, "-c", script], environment, capture=True).strip()
        if not (Path(module_root) / "registry_coordinator_client/__init__.py").is_file():
            raise PrerequisiteError("the owning Python bootstrap did not produce its module import root")
        environment["COORDINATOR_SDK_PYTHON_ROOT"] = module_root
        run_command([str(tsc), "--version"], environment)
        run_command([str(pyright), "--version"], environment)
        for command in proof_commands():
            run_command(command, environment)
    print("Generated-client proofs passed: strict types, four workflows, and successful terminal output.", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tsc", help="TypeScript executable (default: pinned local Node development dependency)")
    parser.add_argument("--pyright", help="Pyright executable (default: COORDINATOR_SDK_PYRIGHT or PATH)")
    arguments = parser.parse_args()
    try:
        run(arguments.tsc, arguments.pyright)
    except (PrerequisiteError, subprocess.CalledProcessError, OSError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            print("Generated-client proof failed; see the preceding tool diagnostics.", file=sys.stderr)
            return error.returncode or 1
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
