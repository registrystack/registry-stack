#!/usr/bin/env python3
"""Run a Cargo CI command for a JSON package list without shell interpolation."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess


PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def package_args(raw_packages: str) -> list[str]:
    packages = json.loads(raw_packages)
    if not isinstance(packages, list) or not packages:
        raise ValueError("CI_RUST_PACKAGES must be a non-empty JSON array")
    if not all(
        isinstance(package, str) and PACKAGE_NAME.fullmatch(package)
        for package in packages
    ):
        raise ValueError("CI_RUST_PACKAGES contains an invalid Cargo package name")
    return [argument for package in packages for argument in ("-p", package)]


def command_args(command: str, packages: list[str], all_features: bool) -> list[str]:
    args = ["cargo", command, "--locked", "--profile", "ci"]
    if command == "clippy":
        args.append("--all-targets")
    args.extend(packages)
    if all_features:
        args.append("--all-features")
    if command == "clippy":
        args.extend(("--", "-D", "warnings"))
    return args


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("clippy", "test"))
    args = parser.parse_args()

    packages = package_args(os.environ.get("CI_RUST_PACKAGES", ""))
    raw_all_features = os.environ.get("CI_RUST_ALL_FEATURES", "false")
    if raw_all_features not in {"true", "false"}:
        raise ValueError("CI_RUST_ALL_FEATURES must be true or false")
    all_features = raw_all_features == "true"
    subprocess.run(
        command_args(args.command, packages, all_features),
        check=True,
    )


if __name__ == "__main__":
    main()
