#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit native BReg connector journey acceptance.

Run: python3 products/adapter/scripts/test-connector-native.py --env FILE
The env file supplies ADAPTER_TEST_DATABASE_URL, an owned disposable local
PostgreSQL database. This runner builds the BReg product binaries, sets the
connector test's environment, and runs crates/registry-adapter-connectors'
ignored native tests. It creates and removes only unique fixture databases,
roles and schemas.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[3]


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


def run(env_file):
    environment = dict(os.environ)
    if env_file:
        # Read only named prerequisites, never execute the file or dump it.
        for line in env_file.read_text().splitlines():
            fields = shlex.split(line, comments=True)
            if fields and fields[0] == "export":
                fields = fields[1:]
            for field in fields:
                key, separator, value = field.partition("=")
                if separator and key in {"ADAPTER_TEST_DATABASE_URL", "AWS_LC_FIPS_SYS_CMAKE_BUILDER"}:
                    environment[key] = value
    if not environment.get("ADAPTER_TEST_DATABASE_URL"):
        raise SystemExit("ADAPTER_TEST_DATABASE_URL must name an owned disposable local PostgreSQL database")
    database = urlsplit(environment["ADAPTER_TEST_DATABASE_URL"])
    if database.scheme not in {"postgres", "postgresql"} or database.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("native acceptance requires a loopback PostgreSQL URL")
    environment.update(CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    target = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=REPO, env=environment))["target_directory"]
    with tempfile.TemporaryDirectory(prefix="adapter-breg-connector-build-") as root:
        log_path = Path(root) / "build.jsonl"
        module = native_fixture()
        command = ["cargo", "build", "--locked", "-p", "registry-breg", "-p", "registry-bregctl",
            "--features", "registry-breg/runtime,registry-breg/postgres-test",
            "--bin", "breg", "--bin", "bregctl",
            "--message-format", "json-render-diagnostics"]
        messages = module.cargo_build(command, log_path, environment)
        if sys.platform == "darwin":
            environment["DYLD_FALLBACK_LIBRARY_PATH"] = str(module.exact_fips_library(messages).parent)
        environment["ADAPTER_BREG_BIN"] = str(Path(target) / "debug/breg")
        environment["ADAPTER_BREGCTL_BIN"] = str(Path(target) / "debug/bregctl")
        result = subprocess.run(["cargo", "test", "--locked", "-p", "registry-adapter-connectors",
            "--features", "breg", "--test", "breg_native",
            "--", "--ignored", "--nocapture"], cwd=REPO, env=environment)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path)
    arguments = parser.parse_args()
    run(arguments.env)
