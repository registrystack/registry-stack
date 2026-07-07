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

external_gitlinks="$(git -C "${stack_root}" ls-files -s -- lab/vendor | awk '$1 == "160000" {n = split($NF, parts, "/"); print parts[n] "=" $2}')"
RELEASE_EXTERNAL_GITLINKS="${external_gitlinks}" python3 - "${release_dir}"/manifests/registry-stack-*.yaml <<'PY'
import os
import re
import sys
from pathlib import Path

import yaml

HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_EXTERNALS = (
    "crosswalk",
    "esignet-relay-authenticator",
    "registry-atlas",
)

gitlinks = {}
for gitlink_line in os.environ.get("RELEASE_EXTERNAL_GITLINKS", "").splitlines():
    gitlink_name, _, gitlink_sha = gitlink_line.partition("=")
    if gitlink_name and gitlink_sha:
        gitlinks[gitlink_name] = gitlink_sha


def version_key(manifest):
    stack = manifest.get("stack", {}) if isinstance(manifest, dict) else {}
    parts = str(stack.get("version", "")).split(".")
    if parts != [""] and all(part.isdigit() for part in parts):
        return tuple(int(part) for part in parts)
    return ()


manifests = []
failed = False
for arg in sys.argv[1:]:
    path = Path(arg)
    if not path.is_file():
        print(f"release source model failed: no release manifest at {arg}", file=sys.stderr)
        failed = True
        continue
    manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    external = manifest.get("external") if isinstance(manifest, dict) else None
    if not isinstance(external, dict) or not external:
        print(f"release source model failed: {path.name} has no external section", file=sys.stderr)
        failed = True
        continue
    manifests.append((version_key(manifest), path, external))
    for name in REQUIRED_EXTERNALS:
        if name not in external:
            print(
                f"release source model failed: {path.name} is missing required external.{name}",
                file=sys.stderr,
            )
            failed = True
    for name in sorted(external):
        entry = external[name]
        repo = entry.get("repo") if isinstance(entry, dict) else None
        ref = str(entry.get("ref", "")) if isinstance(entry, dict) else ""
        if not repo or not HEX40.fullmatch(ref):
            print(
                f"release source model failed: {path.name} external.{name} must record a repo and a 40-hex ref",
                file=sys.stderr,
            )
            failed = True
            continue
        print(f"release-source-external {path.name} {name} {repo} {ref}")

if gitlinks and manifests:
    _, current_path, current_external = max(manifests, key=lambda item: item[0])
    for name in sorted(gitlinks):
        entry = current_external.get(name)
        if not isinstance(entry, dict):
            continue
        ref = str(entry.get("ref", ""))
        if ref != gitlinks[name]:
            print(
                f"release source model failed: {current_path.name} external.{name} ref {ref} "
                f"does not match committed lab/vendor/{name} gitlink {gitlinks[name]}",
                file=sys.stderr,
            )
            failed = True
        else:
            print(f"release-source-external-pin {current_path.name} {name} gitlink={ref}")
if failed:
    sys.exit(1)
PY
