#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/audit-configs.sh [--base DIR] [--format markdown|tsv|paths] [--check]

Enumerates Registry Witness and Registry Relay config files that are likely to
drift during the registry-platform v0.1.0 migration.

Defaults:
  --base ..              parent directory containing registry-witness/relay
  --format markdown      human-readable inventory table

Flags:
  --check                exit non-zero when no expected consumer roots exist
USAGE
}

base=".."
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
  "witness|demo config|registry-witness/demo/config"
  "witness|perf config|registry-witness/perf/config"
  "witness|server test fixtures|registry-witness/crates/registry-witness-server/tests"
  "relay|operator examples|registry-relay/config"
  "relay|demo config|registry-relay/demo/config"
  "relay|config test fixtures|registry-relay/tests/fixtures/config"
)

found_root=false
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

if [[ "$check" == true && "$found_root" == false ]]; then
  echo "no registry-witness or registry-relay config roots found under $base" >&2
  exit 1
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
