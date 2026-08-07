#!/usr/bin/env bash
set -euo pipefail

if [[ ${EVIDENCE_WALLET_COMPAT:-0} != 1 ]]; then
  printf 'SKIP: set EVIDENCE_WALLET_COMPAT=1 to run the opt-in compatibility harness.\n'
  exit 0
fi

if (( $# != 7 )); then
  printf 'internal usage: wallet-verifier-harness <name> <repo> <tag> <commit> <adapter-env> <credential> <jwks>\n' >&2
  exit 2
fi

name=$1
repository=$2
tag=$3
pinned_commit=$4
adapter_environment=$5
credential=$6
jwks=$7

for tool in git python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf '%s compatibility needs %s on PATH.\n' "$name" "$tool" >&2
    exit 1
  }
done
[[ -f $credential && -f $jwks ]] || {
  printf '%s compatibility needs readable credential and JWKS files.\n' "$name" >&2
  exit 1
}

adapter=${!adapter_environment:-}
[[ -n $adapter && -x $adapter ]] || {
  printf '%s must name an executable adapter in %s.\n' "$name" "$adapter_environment" >&2
  exit 1
}

resolved=$(git ls-remote --tags --refs "$repository" "refs/tags/$tag" | awk 'NR == 1 {print $1}')
[[ $resolved == "$pinned_commit" ]] || {
  printf '%s upstream tag did not resolve to the reviewed commit.\n' "$name" >&2
  exit 1
}

expected_version="$name $tag $pinned_commit"
actual_version=$($adapter --registry-stack-version)
[[ $actual_version == "$expected_version" ]] || {
  printf 'Adapter version mismatch. Expected exactly: %s\n' "$expected_version" >&2
  exit 1
}

"$adapter" verify --credential "$credential" --jwks "$jwks"

compatibility_directory=$(mktemp -d)
tampered="$compatibility_directory/tampered.sd-jwt-vc"
trap 'rm -rf -- "$compatibility_directory"' EXIT HUP INT TERM
python3 - "$credential" "$tampered" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").strip()
parts = source.split("~")
jwt = parts[0].split(".")
if len(jwt) != 3 or not jwt[2]:
    raise SystemExit("credential does not contain an issuer signature")
replacement = "A" if jwt[2][0] != "A" else "B"
jwt[2] = replacement + jwt[2][1:]
parts[0] = ".".join(jwt)
pathlib.Path(sys.argv[2]).write_text("~".join(parts), encoding="utf-8")
PY

if "$adapter" verify --credential "$tampered" --jwks "$jwks" >/dev/null 2>&1; then
  printf '%s accepted a mutated issuer signature. No compatibility claim is permitted.\n' "$name" >&2
  exit 1
fi

printf 'PASS: %s performed full third-party verification and rejected a mutated issuer signature.\n' "$name"
