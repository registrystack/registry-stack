#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit native BReg action and Worker/Store journey acceptance.

Run: python3 products/coordinator/scripts/test-breg-action.py --env FILE
The env file supplies distinct COORDINATOR_TEST_DATABASE_URL and
COORDINATOR_MESSAGING_TEST_DATABASE_URL disposable local databases. This runner
creates and removes only unique fixture databases, roles and schemas.
"""
import argparse
import importlib.util
import hashlib
import io
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
    spec = importlib.util.spec_from_file_location(
        "coordinator_native_services", Path(__file__).with_name("test-real-services.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def proxy(origin, mutation_path, observe_only):
    # Reuse the existing lost-response behavior without provisioning its
    # unrelated Casework/Messaging/Scheduling composition.
    module = native_fixture()
    instance = module.LostResponseProxy(origin, mutation_path)
    instance.lost = observe_only
    requests = []
    handler = instance.server.RequestHandlerClass
    forward = handler.forward

    def observed(self):
        length = int(self.headers.get("Content-Length", "0"))
        assert 0 <= length <= 131_072
        body = self.rfile.read(length)
        requests.append({"method": self.command, "path": self.path,
                         "bodyHash": hashlib.sha256(body).hexdigest(),
                         "key": self.headers.get("Idempotency-Key")})
        source = self.rfile
        self.rfile = io.BytesIO(body)
        try:
            return forward(self)
        finally:
            self.rfile = source

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


def run(env_file, citizen=False):
    environment = dict(os.environ)
    if env_file:
        # Read only named prerequisites, never execute the file or dump it.
        for line in env_file.read_text().splitlines():
            fields = shlex.split(line, comments=True)
            if fields and fields[0] == "export":
                fields = fields[1:]
            for field in fields:
                key, separator, value = field.partition("=")
                if separator and key in {"COORDINATOR_TEST_DATABASE_URL", "COORDINATOR_MESSAGING_TEST_DATABASE_URL", "AWS_LC_FIPS_SYS_CMAKE_BUILDER"}:
                    environment[key] = value
    for key in ("COORDINATOR_TEST_DATABASE_URL", "COORDINATOR_MESSAGING_TEST_DATABASE_URL"):
        if not environment.get(key):
            raise SystemExit(f"{key} must name an owned disposable local PostgreSQL database")
        database = urlsplit(environment[key])
        if database.scheme not in {"postgres", "postgresql"} or database.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise SystemExit("native acceptance requires loopback PostgreSQL URLs")
    if environment["COORDINATOR_TEST_DATABASE_URL"] == environment["COORDINATOR_MESSAGING_TEST_DATABASE_URL"]:
        raise SystemExit("Coordinator and Messaging require distinct disposable databases")
    environment.update(CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
    target = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=REPO, env=environment))["target_directory"]
    with tempfile.TemporaryDirectory(prefix="coordinator-breg-build-") as root:
        log_path = Path(root) / "build.jsonl"
        module = native_fixture()
        command = ["cargo", "build", "--locked", "-p", "registry-breg", "-p", "registry-bregctl",
            "-p", "registry-messaging", "-p", "registry-messagingctl",
            "--features", "registry-breg/runtime,registry-breg/postgres-test,registry-messaging/postgres-test",
            "--bin", "breg", "--bin", "bregctl", "--bin", "messaging", "--bin", "messagingctl",
            "--message-format", "json-render-diagnostics"]
        if citizen:
            command.extend(["-p", "registry-breg-mcp", "-p", "registry-breg-review",
                            "--bin", "breg-mcp", "--bin", "breg-review"])
        messages = module.cargo_build(command, log_path, environment)
        if sys.platform == "darwin":
            environment["DYLD_FALLBACK_LIBRARY_PATH"] = str(module.exact_fips_library(messages).parent)
        environment["COORDINATOR_BREG_BIN"] = str(Path(target) / "debug/breg")
        environment["COORDINATOR_BREGCTL_BIN"] = str(Path(target) / "debug/bregctl")
        environment["COORDINATOR_MESSAGING_BIN"] = str(Path(target) / "debug/messaging")
        environment["COORDINATOR_MESSAGINGCTL_BIN"] = str(Path(target) / "debug/messagingctl")
        result = subprocess.run(["cargo", "test", "--locked", "-p", "registry-coordinator", "--features", "postgres-test",
            "--test", "breg_action_native", "--test", "breg_event_native",
            "--", "--ignored", "--nocapture"], cwd=REPO, env=environment)
        if result.returncode or not citizen:
            raise SystemExit(result.returncode)
        environment["BREG_REVIEW_NATIVE_BIN"] = str(Path(target) / "debug/breg-review")
        result = subprocess.run(["cargo", "test", "--locked", "-p", "registry-breg-mcp",
            "--test", "native_citizen", "--", "--ignored", "--nocapture"], cwd=REPO, env=environment)
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path)
    parser.add_argument("--citizen", action="store_true",
                        help="also compose the built citizen MCP gateway and review page with native BReg")
    parser.add_argument("--proxy-origin", help=argparse.SUPPRESS)
    parser.add_argument("--mutation-path", default="/v1/actions/update-item?accessProfile=writer", help=argparse.SUPPRESS)
    parser.add_argument("--observe-only", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.proxy_origin:
        proxy(arguments.proxy_origin, arguments.mutation_path, arguments.observe_only)
    else:
        run(arguments.env, arguments.citizen)
