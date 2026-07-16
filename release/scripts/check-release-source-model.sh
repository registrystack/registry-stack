#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_dir="$(cd "${script_dir}/.." && pwd)"
mode="${1:-${REGISTRY_RELEASE_SOURCE_MODE:-monorepo}}"

resolve_dir() {
	local raw="$1"
	local candidate
	if [[ "${raw}" = /* ]]; then
		candidate="${raw}"
	else
		candidate="${release_dir}/${raw}"
	fi
	python3 - "${candidate}" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
}

repo_head() {
	git -C "$1" rev-parse HEAD
}

dirty_count() {
	git -C "$1" status --short | wc -l | tr -d ' '
}

require_cargo_repo() {
	local name="$1"
	local path="$2"
	if [[ ! -f "${path}/Cargo.toml" ]]; then
		echo "release source model failed: ${name} checkout not found at ${path}" >&2
		exit 2
	fi
}

require_path() {
	local name="$1"
	local path="$2"
	if [[ ! -e "${path}" ]]; then
		echo "release source model failed: ${name} not found at ${path}" >&2
		exit 2
	fi
}

if [[ "${mode}" != "monorepo" ]]; then
	echo "usage: REGISTRY_RELEASE_SOURCE_MODE=monorepo release/scripts/check-release-source-model.sh [monorepo]" >&2
	exit 2
fi

stack_root="$(resolve_dir "${REGISTRY_STACK_SOURCE_DIR:-..}")"
stack_git_root="$(git -C "${stack_root}" rev-parse --show-toplevel)"
stack_head="$(repo_head "${stack_root}")"
stack_dirty="$(dirty_count "${stack_root}")"
require_cargo_repo "registry-stack" "${stack_root}"
require_path "registry-platform crates" "${stack_root}/crates/registry-platform-authcommon"
require_path "registry-manifest crates" "${stack_root}/crates/registry-manifest-core"
require_path "registry-notary crates" "${stack_root}/crates/registry-notary-server"
require_path "registry-relay crate" "${stack_root}/crates/registry-relay"
require_path "registryctl crate" "${stack_root}/crates/registryctl"
if [[ "${stack_git_root}" != "${stack_root}" ]]; then
	echo "release source model failed: registry-stack source dir must be the monorepo root, got ${stack_root} inside ${stack_git_root}" >&2
	exit 2
fi
printf 'release-source registry-stack %s %s dirty=%s\n' "${stack_root}" "${stack_head}" "${stack_dirty}"

python3 - "${stack_root}" "${release_dir}"/manifests/registry-stack-*.yaml <<'PY'
import re
import sys
import tomllib
from pathlib import Path

import yaml

HEX40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(?:[-+].*)?$")
CROSSWALK_REPO = "PublicSchema/crosswalk"
CROSSWALK_SOURCE_PREFIX = "git+https://github.com/PublicSchema/crosswalk?"
HISTORICAL_LAB_EXTERNALS = (
    "registry-atlas",
    "esignet-relay-authenticator",
)

stack_root = Path(sys.argv[1])
manifest_paths = [Path(arg) for arg in sys.argv[2:]]


def fail(message: str) -> None:
    global failed
    print(f"release source model failed: {message}", file=sys.stderr)
    failed = True


def parse_semver(value: object, *, manifest: Path) -> tuple[int, int, int] | None:
    match = SEMVER.fullmatch(str(value or ""))
    if not match:
        fail(f"{manifest.name} stack.version must be SemVer")
        return None
    return tuple(int(part) for part in match.groups())


def live_crosswalk_ref() -> str | None:
    cargo_toml = tomllib.loads((stack_root / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_dependencies = cargo_toml.get("workspace", {}).get("dependencies", {})
    crosswalk_dependencies = {
        name: entry
        for name, entry in workspace_dependencies.items()
        if name.startswith("crosswalk-")
    }
    if not crosswalk_dependencies or not all(
        isinstance(entry, dict) for entry in crosswalk_dependencies.values()
    ):
        fail("Cargo.toml Crosswalk workspace dependencies must use pinned dependency tables")
        return None
    refs = {
        entry.get("rev")
        for entry in crosswalk_dependencies.values()
    }
    repos = {
        entry.get("git")
        for entry in crosswalk_dependencies.values()
    }
    if len(refs) != 1 or None in refs or not HEX40.fullmatch(next(iter(refs), "")):
        fail("Cargo.toml Crosswalk workspace dependencies must share one 40-hex rev")
        return None
    if repos != {"https://github.com/PublicSchema/crosswalk"}:
        fail("Cargo.toml Crosswalk workspace dependencies must use the canonical repository")
        return None

    ref = next(iter(refs))
    cargo_lock = tomllib.loads((stack_root / "Cargo.lock").read_text(encoding="utf-8"))
    lock_packages = [
        package
        for package in cargo_lock.get("package", [])
        if isinstance(package, dict)
        and str(package.get("name", "")).startswith("crosswalk-")
    ]
    if not lock_packages:
        fail("Cargo.lock must contain Crosswalk packages")
        return None
    lock_sources = [package.get("source") for package in lock_packages]
    if not all(
        isinstance(source, str)
        and source.startswith(CROSSWALK_SOURCE_PREFIX)
        and "#" in source
        for source in lock_sources
    ):
        fail("Cargo.lock Crosswalk packages must resolve from the canonical repository")
        return None
    lock_refs = {source.rsplit("#", 1)[-1] for source in lock_sources}
    if lock_refs != {ref}:
        fail("Cargo.lock Crosswalk packages must resolve the Cargo.toml Crosswalk rev")
        return None
    return ref

failed = False
crosswalk_ref = live_crosswalk_ref()
loaded_manifests: list[tuple[Path, dict, tuple[int, int, int]]] = []
for path in manifest_paths:
    if not path.is_file():
        fail(f"no release manifest at {path}")
        continue
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        fail(f"{path.name} must contain a mapping")
        continue
    stack = manifest.get("stack")
    version = parse_semver(
        stack.get("version") if isinstance(stack, dict) else None,
        manifest=path,
    )
    if version is not None:
        loaded_manifests.append((path, manifest, version))
    external = manifest.get("external") if isinstance(manifest, dict) else None
    if not isinstance(external, dict) or not external:
        fail(f"{path.name} has no external section")
        continue
    required_externals = ["crosswalk"]
    artifacts = manifest.get("artifacts")
    if isinstance(artifacts, dict) and "registry-lab" in artifacts:
        required_externals.extend(HISTORICAL_LAB_EXTERNALS)
    for name in required_externals:
        if name not in external:
            fail(f"{path.name} is missing required external.{name}")
    for name in sorted(external):
        entry = external[name]
        repo = entry.get("repo") if isinstance(entry, dict) else None
        ref = str(entry.get("ref", "")) if isinstance(entry, dict) else ""
        if not repo or not HEX40.fullmatch(ref):
            fail(f"{path.name} external.{name} must record a repo and a 40-hex ref")
            continue
        print(f"release-source-external {path.name} {name} {repo} {ref}")

if loaded_manifests and crosswalk_ref is not None:
    latest_path, latest_manifest, _ = max(loaded_manifests, key=lambda item: item[2])
    latest_external = latest_manifest.get("external")
    latest_crosswalk = (
        latest_external.get("crosswalk", {}) if isinstance(latest_external, dict) else {}
    )
    if not isinstance(latest_crosswalk, dict):
        latest_crosswalk = {}
    if latest_crosswalk.get("repo") != CROSSWALK_REPO:
        fail(f"{latest_path.name} external.crosswalk.repo must be {CROSSWALK_REPO}")
    if latest_crosswalk.get("ref") != crosswalk_ref:
        fail(
            f"{latest_path.name} external.crosswalk.ref must match the live Cargo pin {crosswalk_ref}"
        )

if failed:
    sys.exit(1)
PY
