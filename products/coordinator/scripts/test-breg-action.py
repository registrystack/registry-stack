#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit native BReg action acceptance. Only use a disposable local database.

Run: python3 products/coordinator/scripts/test-breg-action.py --env FILE
The env file supplies COORDINATOR_TEST_DATABASE_URL. This runner creates and
removes only unique fixture databases/roles; it never resets that database.
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


def proxy(origin):
    # Reuse the existing lost-response behavior without provisioning its
    # unrelated Casework/Messaging/Scheduling composition.
    spec = importlib.util.spec_from_file_location(
        "coordinator_native_services", Path(__file__).with_name("test-real-services.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    instance = module.LostResponseProxy(origin, "/v1/actions/update-item?accessProfile=writer")
    requests = []
    handler = instance.server.RequestHandlerClass
    forward = handler.forward

    def observed(self):
        requests.append({"method": self.command, "path": self.path})
        return forward(self)

    handler.forward = observed
    print(instance.url, flush=True)
    try:
        for command in sys.stdin:
            if command.strip() == "observations":
                print(json.dumps({"commands": instance.commands, "requests": requests}), flush=True)
            elif command.strip() == "close":
                break
            else:
                raise ValueError("unknown fixture proxy command")
    finally:
        instance.close()


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
                if separator and key in {"COORDINATOR_TEST_DATABASE_URL", "AWS_LC_FIPS_SYS_CMAKE_BUILDER"}:
                    environment[key] = value
    if not environment.get("COORDINATOR_TEST_DATABASE_URL"):
        raise SystemExit("COORDINATOR_TEST_DATABASE_URL must name an owned disposable local PostgreSQL database")
    database = urlsplit(environment["COORDINATOR_TEST_DATABASE_URL"])
    if database.scheme not in {"postgres", "postgresql"} or database.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("native action acceptance requires a loopback PostgreSQL URL")
    environment.update(CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    target = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=REPO, env=environment))["target_directory"]
    with tempfile.TemporaryDirectory(prefix="coordinator-breg-build-") as root:
        log_path = Path(root) / "build.jsonl"
        with log_path.open("w") as log:
            build = subprocess.run(["cargo", "build", "--locked", "-p", "registry-breg", "-p", "registry-bregctl",
                "--features", "registry-breg/runtime,registry-breg/postgres-test", "--bin", "breg", "--bin", "bregctl",
                "--message-format", "json"], cwd=REPO, env=environment, stdout=log)
        if build.returncode:
            raise SystemExit("current-source BReg build failed")
        libraries = []
        for line in log_path.read_text().splitlines():
            item = json.loads(line)
            if item.get("reason") == "build-script-executed" and "aws-lc-fips-sys" in item.get("package_id", ""):
                libraries.append(str(Path(item["out_dir"]) / "build/artifacts"))
        if sys.platform == "darwin":
            if not libraries:
                raise SystemExit("current Cargo build did not identify its FIPS shared libraries")
            environment["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(libraries)
        environment["COORDINATOR_BREG_BIN"] = str(Path(target) / "debug/breg")
        environment["COORDINATOR_BREGCTL_BIN"] = str(Path(target) / "debug/bregctl")
        result = subprocess.run(["cargo", "test", "--locked", "-p", "registry-coordinator", "--features", "postgres-test",
            "--test", "breg_action_native", "--", "--ignored", "--nocapture"], cwd=REPO, env=environment)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path)
    parser.add_argument("--proxy-origin", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.proxy_origin:
        proxy(arguments.proxy_origin)
    else:
        run(arguments.env)
