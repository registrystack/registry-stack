#!/usr/bin/env python3
"""Keep the `rstack` bootstrap launcher free of signing, OIDC and HTTP-server code.

`rstack` installs and selects releases before any product is trusted, and the
release builds it as a plain binary without the FIPS cryptographic module. Its
normal dependency tree must therefore not contain the platform crypto, OIDC or
HTTP utility crates, a FIPS or AWS-LC library, a JWT or elliptic-curve
signing library, or an async HTTP stack. The usual way to break this is
enabling the `session` feature of `registry-thunderid-tooling` for the
launcher.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

PACKAGE = "registry-rstack"
BANNED_NAMES = frozenset(
    {
        "registry-platform-authcommon",
        "registry-platform-crypto",
        "registry-platform-httputil",
        "registry-platform-oidc",
        "jsonwebtoken",
        "ed25519-dalek",
        "p256",
        "p384",
        "p521",
        "openssl",
        "openssl-sys",
        "reqwest",
        "hyper",
        "tokio",
    }
)
BANNED_PATTERNS = (re.compile(r"^aws-lc(-.+)?$"),)


def banned(names: list[str]) -> list[str]:
    """The banned package names among `names`, sorted and without repeats."""
    return sorted(
        {
            name
            for name in names
            if name in BANNED_NAMES or any(pattern.match(name) for pattern in BANNED_PATTERNS)
        }
    )


def package_names(tree: str) -> list[str]:
    """Package names from `cargo tree --prefix none --format '{p}'` output."""
    return [line.split()[0] for line in tree.splitlines() if line.strip()]


def normal_tree() -> str:
    result = subprocess.run(
        [
            "cargo",
            "tree",
            "--locked",
            "-p",
            PACKAGE,
            "-e",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"cargo tree failed for {PACKAGE} (exit {result.returncode})")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tree-file",
        help="read `cargo tree --prefix none --format '{p}'` output from a file instead of running cargo",
    )
    arguments = parser.parse_args()
    if arguments.tree_file:
        with open(arguments.tree_file, encoding="utf-8") as handle:
            tree = handle.read()
    else:
        tree = normal_tree()
    names = package_names(tree)
    if not names:
        raise SystemExit("the dependency tree is empty; refusing to pass")
    found = banned(names)
    if found:
        print(
            f"{PACKAGE} must stay a plain bootstrap launcher; its normal dependency tree contains: "
            + ", ".join(found)
            + ". Do not enable the registry-thunderid-tooling `session` feature or add these crates to it.",
            file=sys.stderr,
        )
        return 1
    print(f"{PACKAGE}: no banned dependency among {len(set(names))} normal packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
