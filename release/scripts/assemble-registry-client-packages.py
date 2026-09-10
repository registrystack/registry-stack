#!/usr/bin/env python3
"""Assemble the published Registry Stack client artifacts from a checkout.

The release workflows build these on a runner, from steps spread across
`release-candidate.yml` and `release-rehearsal.yml`. This script performs the
same steps on a development machine, so a packaging change can be proven
against a real tarball and a real wheel, in a throwaway consumer project,
before it reaches a release candidate.

It produces, into `--output-dir`:

  registrystack-client-<version>.tgz                    the public root package
  registrystack-client-<platform>-<version>.tgz         its native platform package
  registry_stack_client-<version>-<wheel tag>.whl       the public Python wheel

Prerequisites this script does not perform:

  * the Node bindings selected for this version, built for this platform from
    `crates/registry-{discovery,evidence,relay,breg,casework}-client-node`:
    `npm ci && npm run build:debug` (or `npm run build` for a release build)
  * a maturin for the Python half, passed with `--maturin`; the release
    workflows install the pinned one from
    `release/requirements/maturin-1.9.6.txt` into a virtual environment

`--dry-run` prints the exact commands instead of running them, which is the
readable form of the recipe.

Python wheels use the release profile by default. `--python-profile ci` opts
into the workspace's cheaper CI profile for installed-package tutorial checks;
it still assembles all five bindings with the same platform and package layout.

The checked-in `crates/registry-stack-client-node/package.json` is never
modified: the optional platform dependencies bind in a staging copy, because
the version they name only exists at pack time.

Casework joins the automatic public client roster at 0.30.0. The explicit
`--include-casework` option permits integration checks against a local 0.29
candidate; it does not change the roster used to validate published 0.29 bytes.
"""

from __future__ import annotations

import argparse
import json
import platform
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import client_registry


ROOT = Path(__file__).resolve().parents[2]
PRODUCTS = ("discovery", "evidence", "relay", "breg", "casework")
NODE_PRODUCTS = PRODUCTS
# BReg and Casework publish no standalone wheel, so their internal wheels use
# explicit native stems. The other product wheels retain their historical stems.
WHEEL_STEMS = {
    "discovery": "registry_discovery_client",
    "evidence": "registry_evidence_client",
    "relay": "registry_relay_client",
    "breg": "registry_breg_client_native",
    "casework": "registry_casework_client_native",
}
# The platform, wheel tag, and maturin flags each release matrix entry uses.
PLATFORMS = {
    "darwin-arm64": {
        "wheel_tag": "cp310-abi3-macosx_11_0_arm64",
        "maturin_flags": (),
    },
    "linux-x64-gnu": {
        "wheel_tag": "cp310-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64",
        "maturin_flags": ("--compatibility", "manylinux_2_17", "--zig"),
    },
    "linux-arm64-gnu": {
        "wheel_tag": "cp310-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64",
        "maturin_flags": ("--compatibility", "manylinux_2_17", "--zig"),
    },
}
HOST_PLATFORMS = {
    ("Darwin", "arm64"): "darwin-arm64",
    ("Linux", "x86_64"): "linux-x64-gnu",
    ("Linux", "aarch64"): "linux-arm64-gnu",
}


@dataclass(frozen=True)
class Step:
    """One command, run from one directory."""

    description: str
    argv: tuple[str, ...]
    cwd: Path

    def render(self) -> str:
        return f"(cd {shlex.quote(str(self.cwd))} && {shlex.join(self.argv)})"


def host_platform() -> str:
    key = (platform.system(), platform.machine())
    if key not in HOST_PLATFORMS:
        raise SystemExit(
            f"no Registry Stack client platform package is built for {key[0]} {key[1]}"
        )
    return HOST_PLATFORMS[key]


def facade_version(root: Path) -> str:
    manifest = json.loads(
        (root / "crates" / "registry-stack-client-node" / "package.json").read_text(
            encoding="utf-8"
        )
    )
    return str(manifest["version"])


def node_steps(
    root: Path, version: str, napi_platform: str, work_dir: Path, output_dir: Path
) -> list[Step]:
    facade = root / "crates" / "registry-stack-client-node"
    staging = work_dir / "node-root"
    steps = [
        Step(
            "discard the previous staged copy so removed files do not linger",
            ("rm", "-rf", str(staging)),
            root,
        ),
        Step(
            "make the staging and output directories",
            ("mkdir", "-p", str(staging), str(output_dir)),
            root,
        ),
        Step(
            "stage the facade so the checked-in manifest stays untouched",
            ("cp", "-R", f"{facade}/.", str(staging)),
            root,
        ),
        Step(
            "drop development dependencies from the staged copy",
            ("rm", "-rf", str(staging / "node_modules")),
            root,
        ),
        Step(
            "bind the platform packages this version depends on",
            (
                "python3",
                str(root / "release" / "scripts" / "client_registry.py"),
                "bind-optional-deps",
                "--package-json",
                str(staging / "package.json"),
                "--version",
                version,
                "--client",
                "stack",
            ),
            root,
        ),
    ]
    for product in NODE_PRODUCTS:
        binding = root / "crates" / f"registry-{product}-client-node"
        steps.append(
            Step(
                f"add the built {product} addon to the platform package",
                (
                    "cp",
                    str(binding / f"{product}-client.{napi_platform}.node"),
                    str(staging / "npm" / napi_platform) + "/",
                ),
                root,
            )
        )
    steps.append(
        Step(
            "pack the public root package",
            ("npm", "pack", "--ignore-scripts", "--pack-destination", str(output_dir)),
            staging,
        )
    )
    steps.append(
        Step(
            "pack its native platform package",
            (
                "npm",
                "pack",
                f"./npm/{napi_platform}",
                "--ignore-scripts",
                "--pack-destination",
                str(output_dir),
            ),
            staging,
        )
    )
    return steps


def python_steps(
    root: Path,
    version: str,
    napi_platform: str,
    maturin: str,
    work_dir: Path,
    output_dir: Path,
    python_profile: str = "release",
    include_casework: bool = False,
) -> list[Step]:
    if python_profile not in ("release", "ci"):
        raise ValueError(f"unsupported Python build profile: {python_profile}")
    profile_flags = ("--release",) if python_profile == "release" else ("--profile", "ci")
    built = work_dir / "product-wheels"
    wheel_tag = PLATFORMS[napi_platform]["wheel_tag"]
    flags = PLATFORMS[napi_platform]["maturin_flags"]
    steps = [
        Step(
            "discard the previous product wheels so a stale one is never packed",
            ("rm", "-rf", str(built)),
            root,
        ),
        Step(
            "make the staging and output directories",
            ("mkdir", "-p", str(built), str(output_dir)),
            root,
        ),
    ]
    for product in PRODUCTS:
        steps.append(
            Step(
                f"build the {product} product wheel",
                (maturin, "build", *profile_flags, "--locked", *flags, "--out", str(built)),
                root / "crates" / f"registry-{product}-client-py",
            )
        )
    assemble = [
        "python3",
        str(root / "release" / "scripts" / "assemble-registry-client-wheel.py"),
        "--version",
        version,
        "--output-dir",
        str(output_dir),
    ]
    if include_casework:
        assemble.append("--include-casework")
    for product in PRODUCTS:
        assemble += [
            f"--{product}-wheel",
            str(built / f"{WHEEL_STEMS[product]}-{version}-{wheel_tag}.whl"),
        ]
    steps.append(
        Step("assemble the one public wheel", tuple(assemble), root),
    )
    return steps


def plan(
    root: Path,
    version: str,
    napi_platform: str,
    artifacts: str,
    maturin: str,
    work_dir: Path,
    output_dir: Path,
    python_profile: str = "release",
    include_casework: bool = False,
) -> list[Step]:
    if not client_registry.includes_casework(
        version, include_casework=include_casework
    ):
        raise ValueError(
            "this checkout contains the Casework client; versions before 0.30.0 "
            "require the explicit --include-casework local-candidate option"
        )
    steps: list[Step] = []
    if artifacts in ("all", "node"):
        steps += node_steps(root, version, napi_platform, work_dir, output_dir)
    if artifacts in ("all", "python"):
        steps += python_steps(
            root,
            version,
            napi_platform,
            maturin,
            work_dir,
            output_dir,
            python_profile,
            include_casework,
        )
    return steps


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="staging directory, defaults to <output-dir>/staging",
    )
    parser.add_argument("--version", help="defaults to the facade package version")
    parser.add_argument(
        "--napi-platform",
        choices=sorted(PLATFORMS),
        help="defaults to this machine's platform package",
    )
    parser.add_argument(
        "--artifacts", choices=("all", "node", "python"), default="all"
    )
    parser.add_argument("--maturin", default="maturin")
    parser.add_argument(
        "--python-profile",
        choices=("release", "ci"),
        default="release",
        help="Python binding build profile; ci is for installed-package CI checks",
    )
    parser.add_argument(
        "--include-casework",
        action="store_true",
        help="include Casework in an explicit local candidate before version 0.30.0",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    napi_platform = args.napi_platform or host_platform()
    version = args.version or facade_version(ROOT)
    output_dir = args.output_dir.resolve()
    work_dir = (args.work_dir or (args.output_dir / "staging")).resolve()

    try:
        steps = plan(
            ROOT,
            version,
            napi_platform,
            args.artifacts,
            args.maturin,
            work_dir,
            output_dir,
            args.python_profile,
            args.include_casework,
        )
    except (ValueError, client_registry.ClientRegistryError) as exc:
        parser.error(str(exc))
    for step in steps:
        print(f"# {step.description}")
        print(step.render())
        if args.dry_run:
            continue
        result = subprocess.run(step.argv, cwd=step.cwd, check=False)
        if result.returncode != 0:
            print(f"failed: {step.description}", file=sys.stderr)
            return result.returncode
    if args.dry_run:
        return 0

    expected = []
    if args.artifacts in ("all", "node"):
        expected += [
            output_dir / f"registrystack-client-{version}.tgz",
            output_dir / f"registrystack-client-{napi_platform}-{version}.tgz",
        ]
    if args.artifacts in ("all", "python"):
        tag = PLATFORMS[napi_platform]["wheel_tag"]
        expected.append(output_dir / f"registry_stack_client-{version}-{tag}.whl")
    missing = [str(path) for path in expected if not path.is_file()]
    if missing:
        print("expected artifacts are missing: " + ", ".join(missing), file=sys.stderr)
        return 1
    for path in expected:
        print(str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
