#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: products/platform/scripts/audit-configs.sh [--base DIR] [--format markdown|tsv|paths] [--check]

Enumerates Registry Relay configuration surfaces governed alongside the
shared platform crates in the Registry Stack monorepo.

Defaults:
  --base REPO_ROOT       detected from this script's location
  --format markdown      human-readable inventory table

Flags:
  --check                exit non-zero when an expected config root is missing
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
base="$(cd "${script_dir}/../../.." && pwd)"
format="markdown"
check=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      base="${2:?missing value for --base}"
      shift 2
      ;;
    --format)
      format="${2:?missing value for --format}"
      shift 2
      ;;
    --check)
      check=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$format" in
  markdown|tsv|paths) ;;
  *)
    echo "unsupported format: $format" >&2
    exit 2
    ;;
esac

base="${base%/}"

declare -a roots=(
  "relay|operator examples|crates/registry-relay/config"
  "relay|demo config|crates/registry-relay/demo/config"
  "relay|performance config|crates/registry-relay/perf/config"
  "relay|integration profiles|crates/registry-relay/profiles"
  "relay|config test fixtures|crates/registry-relay/tests/fixtures/config"
)

found_root=false
missing_roots=()
rows=()

notes_for_file() {
  local file="$1"
  local notes=()

  if grep -Eq 'token_env|bearer_tokens|api_keys' "$file"; then
    notes+=("static-auth")
  fi
  if grep -q 'token_env' "$file"; then
    notes+=("token_env->hash_env")
  fi
  if grep -Eq 'hash_env|sha256:' "$file"; then
    notes+=("fingerprint")
  fi
  if grep -Eiq 'oidc|issuer|jwks|allowed_clients|client_id|azp' "$file"; then
    notes+=("oidc")
  fi
  if grep -Eiq 'audit|hash_secret|syslog|jsonl' "$file"; then
    notes+=("audit")
  fi
  if grep -Eiq 'sd.?jwt|credential|holder|cnf|vct' "$file"; then
    notes+=("sd-jwt")
  fi

  if [[ ${#notes[@]} -eq 0 ]]; then
    printf '%s' "review"
  else
    local IFS=','
    printf '%s' "${notes[*]}"
  fi
}

for root_spec in "${roots[@]}"; do
  IFS='|' read -r app category rel_root <<<"$root_spec"
  abs_root="$base/$rel_root"

  if [[ ! -d "$abs_root" ]]; then
    missing_roots+=("$rel_root")
    continue
  fi

  found_root=true
  while IFS= read -r file; do
    rel_file="${file#"$base"/}"
    notes="$(notes_for_file "$file")"
    rows+=("$app|$category|$rel_file|$notes")
  done < <(
    find "$abs_root" -type f \
      \( -name '*.yaml' -o -name '*.yml' -o -name '*.toml' -o -name '*.json' \) \
      ! -path '*/target/*' \
      ! -path '*/.git/*' \
      ! -path '*/.claude/worktrees/*' \
      | sort
  )
done

if [[ "$check" == true ]]; then
  if [[ "$found_root" == false ]]; then
    echo "no Registry Relay config roots found under $base" >&2
    exit 1
  fi
  if [[ ${#missing_roots[@]} -gt 0 ]]; then
    echo "expected monorepo config roots are missing under $base:" >&2
    printf '  %s\n' "${missing_roots[@]}" >&2
    exit 1
  fi
fi

case "$format" in
  paths)
    for row in "${rows[@]}"; do
      IFS='|' read -r _app _category rel_file _notes <<<"$row"
      printf '%s\n' "$rel_file"
    done
    ;;
  tsv)
    printf 'app\tcategory\tfile\tnotes\n'
    for row in "${rows[@]}"; do
      IFS='|' read -r app category rel_file notes <<<"$row"
      printf '%s\t%s\t%s\t%s\n' "$app" "$category" "$rel_file" "$notes"
    done
    ;;
  markdown)
    cat <<'HEADER'
# Generated Config Drift Inventory

| App | Category | File | Notes |
| --- | --- | --- | --- |
HEADER
    for row in "${rows[@]}"; do
      IFS='|' read -r app category rel_file notes <<<"$row"
      printf '| %s | %s | `%s` | %s |\n' "$app" "$category" "$rel_file" "$notes"
    done
    ;;
esac
