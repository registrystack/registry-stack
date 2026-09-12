#!/usr/bin/env python3
"""Real-container ThunderID acceptance launcher for Registry Stack.

Selects the fixed acceptance cases by ``--case`` (repeatable) or ``--all``,
lists them with ``--list``, and exits non-zero when any required subcase
fails or cannot run: a missing prerequisite is a failing skip, never a
passing one. It creates and cleans up only its own synthetic resources, on
its own retained session state, and never stops or adopts a container it
does not own.

The launcher calls built public CLIs or test binaries; it implements no
OAuth client of its own.

Cross-repository subcases (``--app-kit``, ``--starter``, ``--solmara``) run
only when the corresponding path is supplied; ``--all`` cannot silently omit
a repository. Record the exact source/version of every input alongside the
recorded result.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

# Fixed case IDs. Subcases owned by this launcher per the test-ownership
# table; first required at the package noted in parentheses.
CASES: dict[str, list[str]] = {
    "A01": ["auth-valid", "auth-negative", "concurrent-replay"],  # P3/P5
    "A02": ["scopes-and-cache"],  # P3
    "A03": ["rust", "node", "python", "progressive", "source-oauth"],  # P3/P5
    "A04": ["resource-retargeting"],  # P5
    "A05": ["claims-and-admin"],  # P5
    "A06": ["breg-authority", "issuer-portability"],  # P4
    "A07": ["request-origin"],  # P5
    "A08": ["offer-auth", "relay-route", "offer-to-evidence"],  # P6
    "A09": ["schema-and-restart"],  # P3
    "A10": ["client-key-rotation", "client-and-role-revocation"],  # P3
    "A11": [
        "breg-fresh",
        "breg-retained",
        "breg-export",
        "evidence-fresh",
        "evidence-retained",
        "source-add-and-row-denial",
        "app-kit",
        "starter",
        "solmara",
    ],  # P4/P5/P6
    "A12": ["restore", "issuer-key-rotation"],  # P7
    "A13": ["issuer-outage", "resource-audit-outage", "redaction"],  # P7
    "A14": ["secret-methods", "qgis-token-renewal"],  # P7
    "A15": ["restart-replay"],  # P3
    "A16": ["archive-verification"],  # P7
}

# The package each subcase first becomes runnable in. A case selected before
# its package is implemented fails loudly with this reason rather than
# skipping green. Packages P4 and later are not yet wired in this branch;
# see the implementation checklist in registry-internal for their status.
FIRST_REQUIRED_AT: dict[str, str] = {
    "A01": "P3/P5",
    "A02": "P3",
    "A03": "P3/P5",
    "A04": "P5",
    "A05": "P5",
    "A06": "P4",
    "A07": "P5",
    "A08": "P6",
    "A09": "P3",
    "A10": "P3",
    "A11": "P4/P5/P6",
    "A12": "P7",
    "A13": "P7",
    "A14": "P7",
    "A15": "P3",
    "A16": "P7",
}

IMPLEMENTED_PACKAGES = {"P3"}


def list_cases() -> None:
    for case, subcases in CASES.items():
        for subcase in subcases:
            print(f"{case}.{subcase}  (first required at {FIRST_REQUIRED_AT[case]})")


def require_docker() -> None:
    try:
        subprocess.run(
            ["docker", "info"], capture_output=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(
            "a running container engine is a prerequisite: the real-container "
            "cases cannot run without one (this is a failing skip, not a pass)"
        ) from error


def run_subcase(case: str, subcase: str, args: argparse.Namespace) -> bool:
    package = FIRST_REQUIRED_AT[case].split("/")[0]
    if package not in IMPLEMENTED_PACKAGES:
        print(
            f"FAIL {case}.{subcase}: first required at {FIRST_REQUIRED_AT[case]}, "
            "whose owning package is not implemented on this branch; see the "
            "implementation checklist in registry-internal",
            file=sys.stderr,
        )
        return False
    # P3 subcases drive the tooling crate's session lifecycle through a test
    # binary built from the owning worktree. The concrete drivers are wired
    # package by package; a driver that is not built is a failing skip.
    driver = args.artifacts / "registry-thunderid-integration" if args.artifacts else None
    if driver is None or not driver.exists():
        print(
            f"FAIL {case}.{subcase}: --artifacts DIR must name the built "
            "integration test binary; without it the subcase cannot run",
            file=sys.stderr,
        )
        return False
    result = subprocess.run(
        [str(driver), "--case", f"{case}.{subcase}", "--state", str(args.state)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"FAIL {case}.{subcase}: {result.stderr.strip()}", file=sys.stderr)
        return False
    print(f"PASS {case}.{subcase}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", default=[], help="case id, e.g. A09")
    parser.add_argument("--all", action="store_true", help="run every case")
    parser.add_argument("--list", action="store_true", help="list case ids and subcases")
    parser.add_argument(
        "--artifacts", type=__import__("pathlib").Path, help="candidate binaries directory"
    )
    parser.add_argument("--app-kit", type=__import__("pathlib").Path)
    parser.add_argument("--starter", type=__import__("pathlib").Path)
    parser.add_argument("--solmara", type=__import__("pathlib").Path)
    parser.add_argument(
        "--state", type=__import__("pathlib").Path,
        default=__import__("pathlib").Path("/tmp/registry-thunderid-integration"),
    )
    args = parser.parse_args()

    if args.list:
        list_cases()
        return 0

    selected = args.case
    if args.all:
        selected = list(CASES)
        for name, value in (("app-kit", args.app_kit), ("starter", args.starter), ("solmara", args.solmara)):
            if value is None:
                print(
                    f"--all requires --{name} for the cross-repository subcases; "
                    "a repository cannot be silently omitted",
                    file=sys.stderr,
                )
                return 2
    if not selected:
        print("select --case or --all, or --list", file=sys.stderr)
        return 2
    for case in selected:
        if case not in CASES:
            print(f"unknown case {case}; use --list", file=sys.stderr)
            return 2

    require_docker()
    failures = [
        (case, subcase)
        for case in selected
        for subcase in CASES[case]
        if not run_subcase(case, subcase, args)
    ]
    if failures:
        print(f"{len(failures)} subcase(s) failed or could not run", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
