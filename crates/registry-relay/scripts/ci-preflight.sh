#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_root=""

cleanup() {
  if [[ -n "${tmp_root}" && "${CI_PREFLIGHT_KEEP_WORKSPACE:-0}" != "1" ]]; then
    rm -rf "${tmp_root}"
  elif [[ -n "${tmp_root}" ]]; then
    echo "==> registry-relay: kept preflight workspace at ${tmp_root}"
  fi
}
trap cleanup EXIT

fail() {
  echo "registry-relay CI preflight failed: $*" >&2
  exit 2
}

run() {
  echo "==> registry-relay: $*"
  "$@"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

require_tool cargo
require_tool git
require_tool python3
require_tool rsync

read_workflow_ref_config() {
  python3 - "$repo_root" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
workflow_dir = root / ".github" / "workflows"
keys = (
    "REGISTRY_PLATFORM_REPOSITORY",
    "REGISTRY_PLATFORM_REF",
    "REGISTRY_MANIFEST_REPOSITORY",
    "REGISTRY_MANIFEST_REF",
    "CROSSWALK_REPOSITORY",
    "CROSSWALK_REF",
)
values = {key: set() for key in keys}

for path in sorted(workflow_dir.glob("*.yml")):
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        for key in keys:
            match = re.match(rf"^{key}\s*:\s*(.+)$", stripped)
            if match:
                values[key].add(match.group(1).strip().strip("'\""))

for key, seen in values.items():
    if not seen:
        raise SystemExit(f"missing {key} in .github/workflows/*.yml")
    if len(seen) != 1:
        rendered = ", ".join(sorted(seen))
        raise SystemExit(f"inconsistent {key} values in workflows: {rendered}")
    value = next(iter(seen))
    if key.endswith("_REF") and not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SystemExit(f"{key} must be a full commit SHA, got {value!r}")
    print(f"{key}={value}")
PY
}

registry_platform_repository=""
registry_platform_ref=""
registry_manifest_repository=""
registry_manifest_ref=""
crosswalk_repository=""
crosswalk_ref=""

while IFS='=' read -r key value; do
  case "$key" in
    REGISTRY_PLATFORM_REPOSITORY) registry_platform_repository="$value" ;;
    REGISTRY_PLATFORM_REF) registry_platform_ref="$value" ;;
    REGISTRY_MANIFEST_REPOSITORY) registry_manifest_repository="$value" ;;
    REGISTRY_MANIFEST_REF) registry_manifest_ref="$value" ;;
    CROSSWALK_REPOSITORY) crosswalk_repository="$value" ;;
    CROSSWALK_REF) crosswalk_ref="$value" ;;
  esac
done < <(read_workflow_ref_config)

checkout_ref() {
  local label="$1"
  local env_name="$2"
  local default_source="$3"
  local repository="$4"
  local ref="$5"
  local destination="$6"
  local source="${!env_name:-$default_source}"
  local clone_source=""

  if [[ "${CI_PREFLIGHT_USE_WORKTREE:-0}" == "1" && -d "${source}/.git" ]]; then
    echo "==> registry-relay: using ${label} working tree from ${source}"
    echo "==> registry-relay: clean CI still checks out ${label} ${ref} from ${repository}"
    run rsync -a \
      --exclude '/.git' \
      --exclude '/target' \
      "${source}/" \
      "${destination}/"
    [[ -f "${destination}/Cargo.toml" ]] || fail "${label} working tree is missing Cargo.toml"
    return
  fi

  if [[ -d "${source}/.git" ]] && git -C "$source" cat-file -e "${ref}^{commit}" 2>/dev/null; then
    clone_source="$source"
  else
    clone_source="https://github.com/${repository}.git"
  fi

  echo "==> registry-relay: checking out ${label} ${ref} from ${clone_source}"
  if ! git clone --quiet --no-checkout "$clone_source" "$destination"; then
    fail "could not clone ${label} from ${clone_source}; set ${env_name} to a checkout containing ${ref}"
  fi
  if ! git -C "$destination" checkout --quiet --detach "$ref"; then
    fail "could not checkout ${label} ref ${ref}; set ${env_name} to a checkout containing that commit"
  fi
  [[ -f "${destination}/Cargo.toml" ]] || fail "${label} checkout is missing Cargo.toml"
}

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-relay-ci-preflight.XXXXXX")"
work_root="${tmp_root}/registry-relay"
mkdir -p "$work_root"

run rsync -a \
  --exclude '/.git' \
  --exclude '/target' \
  "${repo_root}/" \
  "${work_root}/"

checkout_ref \
  "registry-platform" \
  "REGISTRY_PLATFORM_SOURCE_DIR" \
  "${repo_root}/../registry-platform" \
  "$registry_platform_repository" \
  "$registry_platform_ref" \
  "${tmp_root}/registry-platform"

checkout_ref \
  "registry-manifest" \
  "REGISTRY_MANIFEST_SOURCE_DIR" \
  "${repo_root}/../registry-manifest" \
  "$registry_manifest_repository" \
  "$registry_manifest_ref" \
  "${tmp_root}/registry-manifest"

if [[ -n "${CROSSWALK_SOURCE_DIR:-}" ]]; then
  crosswalk_source_env="CROSSWALK_SOURCE_DIR"
elif [[ -n "${CEL_MAPPING_SOURCE_DIR:-}" ]]; then
  echo "warning: CEL_MAPPING_SOURCE_DIR is deprecated, please use CROSSWALK_SOURCE_DIR instead" >&2
  crosswalk_source_env="CEL_MAPPING_SOURCE_DIR"
else
  crosswalk_source_env="CROSSWALK_SOURCE_DIR"
fi

checkout_ref \
  "crosswalk" \
  "$crosswalk_source_env" \
  "${repo_root}/../crosswalk" \
  "$crosswalk_repository" \
  "$crosswalk_ref" \
  "${tmp_root}/crosswalk"

cd "$work_root"
run cargo metadata --locked --all-features --format-version 1 >/dev/null
run cargo check --locked --workspace --all-features
