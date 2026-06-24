#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if [[ -z "${REGISTRY_NOTARY_ROTATED_ISSUER_JWK:-}" || -z "${REGISTRY_NOTARY_ISSUER_PUBLIC_JWK:-}" ]]; then
  echo "missing Lab 2 issuer rotation material; run just generate first" >&2
  exit 1
fi

resolve_dir() {
  local raw="$1"
  if [[ "${raw}" = /* ]]; then
    python3 - "${raw}" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
  else
    python3 - "${repo_root}/${raw}" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
  fi
}

platform_source_dir="$(resolve_dir "${REGISTRY_PLATFORM_SOURCE_DIR:-vendor/registry-platform}")"
vendor_platform_dir="$(resolve_dir "vendor/registry-platform")"
manifest_path="tools/lab2-governed-config/Cargo.toml"

if [[ "${platform_source_dir}" == "${vendor_platform_dir}" ]]; then
  cargo run --quiet --manifest-path "${manifest_path}"
else
  test -f "${platform_source_dir}/Cargo.toml" || {
    echo "REGISTRY_PLATFORM_SOURCE_DIR does not point to a Registry Platform checkout: ${platform_source_dir}" >&2
    exit 2
  }
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/registry-lab2-governed-config.XXXXXX")"
  cleanup() {
    rm -rf "${tmp_dir}"
  }
  trap cleanup EXIT
  cp -R tools/lab2-governed-config/. "${tmp_dir}/"
  python3 - "${tmp_dir}/Cargo.toml" "${platform_source_dir}" <<'PY'
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
platform = Path(sys.argv[2])
body = manifest.read_text(encoding="utf-8")
body = body.replace(
    'registry-platform-config = { path = "../../vendor/registry-platform/crates/registry-platform-config" }',
    f'registry-platform-config = {{ path = "{platform / "crates/registry-platform-config"}" }}',
)
body = body.replace(
    'registry-platform-ops = { path = "../../vendor/registry-platform/crates/registry-platform-ops" }',
    f'registry-platform-ops = {{ path = "{platform / "crates/registry-platform-ops"}" }}',
)
manifest.write_text(body, encoding="utf-8")
PY
  cargo run --quiet --manifest-path "${tmp_dir}/Cargo.toml"
fi
