#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit native Adapter connector and job-destination acceptance.

Run: python3 products/adapter/scripts/test-connector-native.py --env FILE
Run the job destinations with: --suite job-destinations

The environment or env file supplies CARGO_TARGET_DIR and
ADAPTER_TEST_DATABASE_URL. The target is explicit, and the database must be an
owned disposable local PostgreSQL database. The runner builds every product
binary required by the selected suite in one Cargo invocation, takes the exact
executables from Cargo's JSON messages, and passes only those paths to the
ignored native tests. The fixtures use unique databases, roles and schemas and
clean up their product services, but the job suites may retain unique Adapter
schemas inside a caller-supplied database. That database must therefore be
disposable and its caller owns final removal. The default
products/adapter/scripts/test-job-postgres.sh wrapper instead owns and removes
the whole PostgreSQL container around the job suite.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[3]

ENV_FILE_KEYS = {
    "ADAPTER_TEST_DATABASE_URL",
    "AWS_LC_FIPS_SYS_CMAKE_BUILDER",
    "CARGO_TARGET_DIR",
}

SUITES = {
    "connector": {
        "binaries": {
            "ADAPTER_BREG_BIN": "breg",
            "ADAPTER_BREGCTL_BIN": "bregctl",
        },
        "build": [
            "cargo", "build", "--locked",
            "-p", "registry-breg", "-p", "registry-bregctl",
            "--features", "registry-breg/runtime,registry-breg/postgres-test",
            "--bin", "breg", "--bin", "bregctl",
            "--message-format", "json-render-diagnostics",
        ],
        "test": [
            "cargo", "test", "--locked",
            "-p", "registry-adapter-connectors",
            "--features", "breg", "--test", "breg_native",
            "--", "--ignored", "--nocapture",
        ],
    },
    "job-destinations": {
        "binaries": {
            "ADAPTER_BREG_BIN": "breg",
            "ADAPTER_BREGCTL_BIN": "bregctl",
            "ADAPTER_COORDINATOR_BIN": "coordinator",
            "ADAPTER_COORDINATORCTL_BIN": "coordinatorctl",
            "ADAPTER_CASEWORK_BIN": "casework",
            "ADAPTER_CASEWORKCTL_BIN": "caseworkctl",
        },
        "build": [
            "cargo", "build", "--locked",
            "-p", "registry-breg", "-p", "registry-bregctl",
            "-p", "registry-coordinator",
            "-p", "registry-casework", "-p", "registry-caseworkctl",
            "--features", "registry-breg/runtime,registry-breg/postgres-test",
            "--bin", "breg", "--bin", "bregctl",
            "--bin", "coordinator", "--bin", "coordinatorctl",
            "--bin", "casework", "--bin", "caseworkctl",
            "--message-format", "json-render-diagnostics",
        ],
        "test": [
            "cargo", "test", "--locked", "--no-fail-fast",
            "-p", "registry-adapter-job",
            "--features",
            "job-postgres,native-test-support,postgres-test,signed-coordinator-event",
            "--test", "direct_breg_native",
            "--test", "signed_coordinator_event_native",
            "--", "--ignored", "--nocapture", "--test-threads=1",
        ],
    },
}


def native_fixture():
    # Reuse the coordinator runner's shared build helpers (a private build
    # directory, rendered diagnostics, and the exact FIPS library path on
    # macOS) without provisioning its unrelated composition. Its module
    # imports its own sibling fixtures, so their directory joins sys.path.
    sys.path.insert(0, str(REPO / "products/coordinator/scripts"))
    spec = importlib.util.spec_from_file_location(
        "coordinator_native_services", REPO / "products/coordinator/scripts/test-real-services.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def selected_environment(env_file):
    environment = dict(os.environ)
    if env_file:
        # Read only named prerequisites, never execute the file or dump it.
        for line in env_file.read_text().splitlines():
            fields = shlex.split(line, comments=True)
            if fields and fields[0] == "export":
                fields = fields[1:]
            for field in fields:
                key, separator, value = field.partition("=")
                if separator and key in ENV_FILE_KEYS:
                    environment[key] = value
    return environment


def prerequisites(environment):
    configured_target = environment.get("CARGO_TARGET_DIR")
    if not configured_target:
        raise SystemExit("CARGO_TARGET_DIR must name the configured Cargo target directory")
    target = Path(configured_target)
    if not target.is_absolute():
        raise SystemExit("CARGO_TARGET_DIR must be an absolute path")
    if not environment.get("ADAPTER_TEST_DATABASE_URL"):
        raise SystemExit("ADAPTER_TEST_DATABASE_URL must name an owned disposable local PostgreSQL database")
    database = urlsplit(environment["ADAPTER_TEST_DATABASE_URL"])
    if database.scheme not in {"postgres", "postgresql"} or database.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("native acceptance requires a loopback PostgreSQL URL")
    return target.resolve()


def built_executables(messages, required, target):
    artifacts = {}
    for message in messages:
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        target_message = message.get("target", {})
        name = target_message.get("name")
        if name not in required or "bin" not in target_message.get("kind", []):
            continue
        path = Path(message["executable"]).resolve()
        previous = artifacts.get(name)
        if previous is not None and previous != path:
            raise SystemExit(f"Cargo reported more than one executable for {name}")
        artifacts[name] = path
    for name in required:
        if name not in artifacts:
            raise SystemExit(f"Cargo did not report the required executable: {name}")
        path = artifacts[name]
        if not path.is_relative_to(target):
            raise SystemExit(f"Cargo reported {name} outside the configured Cargo target")
        if not path.is_file() or not os.access(path, os.X_OK):
            raise SystemExit(f"Cargo reported no executable file for {name}")
    return artifacts


def run(env_file, suite_name="connector"):
    environment = selected_environment(env_file)
    target = prerequisites(environment)
    environment.update(CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    suite = SUITES[suite_name]
    module = native_fixture()
    metadata_target = Path(module.cargo_metadata(environment)["target_directory"]).resolve()
    if metadata_target != target:
        raise SystemExit("configured CARGO_TARGET_DIR does not match Cargo target metadata")
    with tempfile.TemporaryDirectory(prefix="adapter-breg-connector-build-") as root:
        log_path = Path(root) / "build.jsonl"
        messages = module.cargo_build(suite["build"], log_path, environment)
        artifacts = built_executables(messages, suite["binaries"].values(), target)
        if sys.platform == "darwin":
            environment["DYLD_FALLBACK_LIBRARY_PATH"] = str(module.exact_fips_library(messages).parent)
        for variable, name in suite["binaries"].items():
            # Always replace inherited paths. Every product process in the
            # proof must be the exact artifact from this joint source build.
            environment[variable] = str(artifacts[name])
        result = subprocess.run(suite["test"], cwd=REPO, env=environment)
        return result.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path)
    parser.add_argument("--suite", choices=tuple(SUITES), default="connector")
    arguments = parser.parse_args()
    raise SystemExit(run(arguments.env, arguments.suite))
