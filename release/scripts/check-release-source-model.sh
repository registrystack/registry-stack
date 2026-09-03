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
require_path "registry-discovery profile crate" "${stack_root}/crates/registry-discovery-profile"
require_path "registry-discovery runtime crate" "${stack_root}/crates/registry-discovery"
require_path "registry-discovery authoring crate" "${stack_root}/crates/registry-discoveryctl"
require_path "registry-discovery client crate" "${stack_root}/crates/registry-discovery-client"
require_path "registry-discovery Node client binding" "${stack_root}/crates/registry-discovery-client-node"
require_path "registry-discovery Python client binding" "${stack_root}/crates/registry-discovery-client-py"
require_path "registry-relay-v2 crate" "${stack_root}/crates/registry-relay-v2"
require_path "registry-relayctl crate" "${stack_root}/crates/registry-relayctl"
require_path "registry-relay HTTP contract crate" "${stack_root}/crates/registry-relay-http-contract"
require_path "registry-relay client crate" "${stack_root}/crates/registry-relay-client"
require_path "registry-relay Node client binding" "${stack_root}/crates/registry-relay-client-node"
require_path "registry-relay Python client binding" "${stack_root}/crates/registry-relay-client-py"
require_path "registry-evidence crate" "${stack_root}/crates/registry-evidence"
require_path "registry-evidencectl crate" "${stack_root}/crates/registry-evidencectl"
require_path "registry-mint crate" "${stack_root}/crates/registry-mint"
require_path "registry-evidence-oid4vci crate" "${stack_root}/crates/registry-evidence-oid4vci"
require_path "registry-server crate" "${stack_root}/crates/registry-server"
require_path "registry-serverctl crate" "${stack_root}/crates/registry-serverctl"
if [[ "${stack_git_root}" != "${stack_root}" ]]; then
	echo "release source model failed: registry-stack source dir must be the monorepo root, got ${stack_root} inside ${stack_git_root}" >&2
	exit 2
fi
printf 'release-source registry-stack %s %s dirty=%s\n' "${stack_root}" "${stack_head}" "${stack_dirty}"

python3 - "${stack_root}" "${release_dir}"/manifests/registry-stack-*.yaml <<'PY'
import re
import sys
from pathlib import Path

import yaml

HEX40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(?:[-+].*)?$")
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


failed = False
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
    external = manifest.get("external") if isinstance(manifest, dict) else None
    if not isinstance(external, dict):
        fail(f"{path.name} external must be a mapping")
        continue
    required_externals = []
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

if failed:
    sys.exit(1)
PY
