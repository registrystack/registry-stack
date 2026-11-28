#!/usr/bin/env bash
set -euo pipefail

# No product answers a cross-origin request, with one exception. Each product
# is called by a server, never by script running in a browser page, so no
# crate under `crates/` may add a CORS layer, define a CORS policy, or emit
# `Access-Control-Allow-Origin`, and no `Cargo.toml` may enable the `cors`
# feature of tower-http. The exception is the Evidence public check route,
# which any origin may read. Allowed sites are matched by file and function
# name, never by line:
#
#   * `public_check_cors` in the Evidence server, and the `use` that imports
#     its layer: the one CORS layer.
#   * `public_check_response_headers` in the Evidence contracts, which documents
#     that route's response header.
#   * `apply_conditional_corp` in registry-platform-httpsec, which only reads
#     the header to mark a response cross-origin.
#   * the `cors` feature in the Evidence manifest.
#
# The check route's allowed request headers are pinned to exactly
# `Content-Type` and `Registry-Client`: `public_check_cors` must call
# `allow_headers` once with that list, so a third header fails the check.
#
# The builder calls `allow_headers(`, `allow_origin(`, `allow_methods(`,
# `expose_headers(` and `allow_private_network(` count as CORS tokens, so they
# are allowed only inside `public_check_cors`, never at its call site. The
# Evidence server must define exactly one `fn public_check_cors`.
#
# `Access-Control-Allow-Credentials`, in any letter case or as a header
# constant or `allow_credentials` call, is refused everywhere, the allowed
# sites included. So are `permissive(` and `very_permissive(`, which turn
# credentials or wildcard headers on without naming them.
#
# Test code is exempt: a file under a `tests` directory or named `tests.rs`
# or `*_tests.rs`, and the remainder of a file after its first
# `#[cfg(test)] mod`. Usage: check-no-cross-origin.sh [REPOSITORY_ROOT]

CDPATH=''
default_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
root=${1:-$default_root}

if [[ ! -d "$root/crates" ]]; then
  printf 'check-no-cross-origin: no crates directory under %s\n' "$root" >&2
  exit 2
fi

findings=0

# Source references. The awk program takes the entries space-separated. Each is `path-suffix|function`. The function is the
# innermost top-level `fn` the line sits in, or `use` for an import line.
allowed_sites=(
  'crates/registry-evidence/src/server.rs|public_check_cors'
  'crates/registry-evidence/src/server.rs|use'
  'crates/registry-evidence/src/contracts.rs|public_check_response_headers'
  'crates/registry-platform-httpsec/src/server.rs|apply_conditional_corp'
)
sites_argument="${allowed_sites[*]}"

# shellcheck disable=SC2016 # awk program, nothing to expand
source_scan='
  function allowed(scope,    count, parts, index_, path) {
    count = split(sites, entries, " ")
    for (index_ = 1; index_ <= count; index_++) {
      split(entries[index_], parts, "|")
      path = parts[1]
      if (parts[2] == scope &&
          substr(FILENAME, length(FILENAME) - length(path) + 1) == path) {
        return 1
      }
    }
    return 0
  }
  # Scanning stops at the first `#[cfg(test)] mod`, which by convention closes
  # the file with its unit tests.
  /^[[:space:]]*#\[cfg\(test\)\]/ { pending = 1; next }
  pending && /^[[:space:]]*#\[/ { next }
  pending && /^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?mod[[:space:]]/ { exit }
  { pending = 0 }
  FNR == 1 { current = "" }
  /^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?(async[[:space:]]+)?(unsafe[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+/ {
    name = $0
    sub(/^.*fn[[:space:]]+/, "", name)
    sub(/[^A-Za-z0-9_].*$/, "", name)
    current = name
  }
  {
    scope = current
    if ($0 ~ /^(pub(\([a-z]+\))?[[:space:]]+)?use[[:space:]]/) { scope = "use" }
    lower = tolower($0)
    if (lower ~ /access-control-allow-credentials|access_control_allow_credentials|allow_credentials|permissive[[:space:]]*\(/) {
      print FILENAME ":" FNR ": " $0
    } else if (lower ~ /corslayer|corspolicy|tower_http::cors|access-control-allow-origin|access_control_allow_origin|allow_headers[[:space:]]*\(|allow_origin[[:space:]]*\(|allow_methods[[:space:]]*\(|expose_headers[[:space:]]*\(|allow_private_network[[:space:]]*\(/ && !allowed(scope)) {
      print FILENAME ":" FNR ": " $0
    }
  }
  /^}/ { current = "" }
'
while IFS= read -r -d '' file; do
  matches=$(awk -v sites="$sites_argument" "$source_scan" "$file")
  if [[ -n "$matches" ]]; then
    printf '%s\n' "$matches"
    findings=$((findings + 1))
  fi
done < <(
  find "$root/crates" -type f -name '*.rs' \
    -not -path '*/tests/*' -not -name 'tests.rs' -not -name '*_tests.rs' \
    -not -path '*/target/*' -print0 | sort -z
)

# Manifests: the `cors` feature on a tower-http dependency, whether written
# inline, across lines, or as a `[...tower-http]` table.
# shellcheck disable=SC2016 # awk program, nothing to expand
manifest_scan='
  /^[[:space:]]*\[/ { table = ($0 ~ /tower-http/); inline = 0 }
  /^[[:space:]]*tower-http[[:space:]]*[.=]/ {
    inline = ($0 ~ /\{/ && $0 !~ /\}/)
    if ($0 ~ /"cors"/) { print FILENAME ":" FNR ": " $0; next }
    next
  }
  (table || inline) && /"cors"/ { print FILENAME ":" FNR ": " $0 }
  inline && /\}/ { inline = 0 }
'
while IFS= read -r -d '' manifest; do
  if [[ "$manifest" == */crates/registry-evidence/Cargo.toml ]]; then
    continue
  fi
  matches=$(awk "$manifest_scan" "$manifest")
  if [[ -n "$matches" ]]; then
    printf '%s\n' "$matches"
    findings=$((findings + 1))
  fi
done < <(
  {
    find "$root/crates" -type f -name Cargo.toml -not -path '*/target/*' -print0
    [[ -f "$root/Cargo.toml" ]] && printf '%s\0' "$root/Cargo.toml"
  } | sort -z
)

# The exact allowed request headers of the public check route.
evidence_server="$root/crates/registry-evidence/src/server.rs"
expected_headers='CONTENT_TYPE,HeaderName::from_static("registry-client")'
if [[ -f "$evidence_server" ]]; then
  cors_body=$(awk '
    /^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?fn[[:space:]]+public_check_cors[^A-Za-z0-9_]/ { inside = 1 }
    inside { print }
    inside && /^}/ { exit }
  ' "$evidence_server" | tr -d '[:space:]')
  allowed_headers=$(
    printf '%s' "$cors_body" |
      sed -n 's/.*\.allow_headers(\[\([^]]*\)\]).*/\1/p' |
      sed 's/,$//'
  )
  header_calls=$(printf '%s' "${cors_body//allow_headers(/$'\n'}" | wc -l)
  function_count=$(
    grep -Ec '^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?(async[[:space:]]+)?(unsafe[[:space:]]+)?fn[[:space:]]+public_check_cors[^A-Za-z0-9_]' "$evidence_server" || true
  )
  if [[ "${function_count:-0}" != "1" ]]; then
    printf '%s: must define exactly one fn public_check_cors\n' "$evidence_server"
    findings=$((findings + 1))
  fi
  if [[ "${header_calls//[[:space:]]/}" != "1" ||
    "$allowed_headers" != "$expected_headers" ]]; then
    printf '%s: public_check_cors must allow exactly Content-Type and Registry-Client\n' "$evidence_server"
    findings=$((findings + 1))
  fi
fi

if [[ "$findings" -gt 0 ]]; then
  printf 'check-no-cross-origin: %d file(s) could answer a cross-origin request\n' "$findings" >&2
  exit 1
fi
printf 'check-no-cross-origin: ok\n'
