#!/usr/bin/env python3
"""Build nightly coverage shards from the validated CI package inventory."""

from __future__ import annotations

import json
import os
import subprocess

from ci_changes import SHARDS, Workspace


def coverage_matrix() -> dict[str, list[dict[str, str]]]:
    # Keep the existing Codecov manifest flag; other flags follow shard names.
    # BREG database/TLS features need the services owned by its dedicated CI
    # gates. This is ordinary package coverage, not those integration journeys.
    return {
        "include": [
            {
                "name": name,
                "packages": " ".join(packages),
                "all_features": str(name in {"platform", "relay-v2"}).lower(),
                "features": "",
                "flag": "manifest-unit" if name == "manifest" else name,
            }
            for name, packages in SHARDS.items()
        ]
    }


def main() -> None:
    metadata = json.loads(
        subprocess.run(
            ("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    Workspace(metadata)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"matrix={json.dumps(coverage_matrix())}\n")


if __name__ == "__main__":
    main()
