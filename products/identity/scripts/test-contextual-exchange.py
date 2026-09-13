#!/usr/bin/env python3
"""Run the real pinned-container institutional exchange proof.

The Rust driver uses a new private state directory and a uniquely owned container.
It retains files and stops only that container. Never provide an existing state
path. It prints bounded case outcomes, never keys, assertions or access tokens.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import os
import subprocess
import tempfile
import uuid


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, help="already-built contextual-exchange example")
    parser.add_argument("--state", type=Path, help="fresh absolute state directory")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    state = args.state or Path(tempfile.gettempdir()) / f"registry-contextual-gate0-{uuid.uuid4().hex}"
    if not state.is_absolute() or state.exists():
        parser.error("--state must be an absent absolute directory")
    driver = args.driver
    if driver is None:
        env = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0")
        built = subprocess.run(["cargo", "build", "--locked", "-p", "registry-thunderid-tooling", "--example", "contextual-exchange"], cwd=root, env=env, check=False)
        if built.returncode:
            return built.returncode
        target = Path(env.get("CARGO_TARGET_DIR", root / "target"))
        if not target.is_absolute():
            target = root / target
        driver = target / "debug/examples/contextual-exchange"
    print(f"Gate0 retained state: {state}", flush=True)
    command = [str(driver.resolve()), "--state", str(state)]
    return subprocess.run(command, cwd=root, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
