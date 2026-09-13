#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

group=""
include_casework_override=0
purpose=""
source_sha=""
version=""
output=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --group) group="${2:-}"; shift 2 ;;
    --include-casework) include_casework_override=1; shift ;;
    --purpose) purpose="${2:-}"; shift 2 ;;
    --source-sha) source_sha="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

usage() {
  printf 'usage: %s [--include-casework] --group core|breg|bregctl|casework|all --purpose candidate_input|review_only --source-sha SHA --version VERSION --output DIRECTORY\n' "$0" >&2
  exit 2
}

if [[ "${group}" != core && "${group}" != breg &&
      "${group}" != bregctl && "${group}" != casework && "${group}" != all ]]; then
  usage
fi
if [[ "${purpose}" != candidate_input && "${purpose}" != review_only ]]; then
  usage
fi
if [[ ! "${source_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  usage
fi
if [[ ! "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  usage
fi
if [[ "$(git -C "${repo_root}" rev-parse HEAD)" != "${source_sha}" ]]; then
  printf 'source SHA does not match the checked-out commit\n' >&2
  exit 2
fi
if [[ -z "${output}" || -e "${output}" || -L "${output}" ]]; then
  printf 'output must name a new directory: %s\n' "${output}" >&2
  exit 2
fi

target=aarch64-apple-darwin
asset=macos-arm64
rust_toolchain=1.95.0
tag="v${version}"
export REGISTRY_RELEASE_TAG="${tag}"
IFS=. read -r version_major version_minor _version_patch <<<"${version}"
include_breg=0
if ((version_major > 0 || version_minor >= 26)); then
  include_breg=1
fi
include_casework=0
if ((version_major > 0 || version_minor >= 30)) ||
   [[ "${include_casework_override}" -eq 1 ]]; then
  include_casework=1
fi

output_parent="$(dirname -- "${output}")"
output_name="$(basename -- "${output}")"
mkdir -p -- "${output_parent}"
output_parent="$(cd -- "${output_parent}" && pwd)"
output="${output_parent}/${output_name}"
temporary="$(mktemp -d "${output_parent}/.${output_name}.XXXXXX")"
cleanup() {
  rm -rf -- "${temporary}"
}
trap cleanup EXIT
mkdir "${temporary}/platform"

cargo_bin="${CARGO:-cargo}"
target_root="${CARGO_TARGET_DIR:-${repo_root}/target}"
if [[ "${target_root}" != /* ]]; then
  target_root="${repo_root}/${target_root}"
fi

stage() {
  local binary="$1"
  local destination="$2"
  cp -- "${target_root}/${target}/release/${binary}" \
    "${temporary}/platform/${destination}"
  chmod 0755 "${temporary}/platform/${destination}"
}

build_core() {
  "${cargo_bin}" build --release --locked \
    -p registry-relayctl -p registry-evidence -p registry-evidencectl \
    -p registry-evidence-oid4vci \
    --target "${target}"

  stage relayctl "relayctl-${tag}-${asset}"
  test "$("${temporary}/platform/relayctl-${tag}-${asset}" --version)" = \
    "relayctl ${version}"
  local binary
  for binary in evidence evidencectl evidence-oid4vci; do
    stage "${binary}" "${binary}-${tag}-${asset}"
  done
}

build_breg() {
  if [[ "${include_breg}" -ne 1 ]]; then
    return
  fi
  "${cargo_bin}" build --release --locked \
    -p registry-breg --bin breg --features runtime \
    --target "${target}"

  stage breg "breg-${tag}-${asset}"
  test "$("${temporary}/platform/breg-${tag}-${asset}" --version)" = \
    "breg ${version}"
}

build_bregctl() {
  if [[ "${include_breg}" -ne 1 ]]; then
    return
  fi
  "${cargo_bin}" build --release --locked \
    -p registry-bregctl \
    --target "${target}"

  stage bregctl "bregctl-${tag}-${asset}"
  test "$("${temporary}/platform/bregctl-${tag}-${asset}" --version)" = \
    "bregctl ${version}"
}

build_casework() {
  if [[ "${include_casework}" -ne 1 ]]; then
    return
  fi
  "${cargo_bin}" build --release --locked \
    -p registry-casework --bin casework \
    --target "${target}"
  "${cargo_bin}" build --release --locked \
    -p registry-caseworkctl --bin caseworkctl \
    --target "${target}"

  local binary
  for binary in casework caseworkctl; do
    stage "${binary}" "${binary}-${tag}-${asset}"
    test "$("${temporary}/platform/${binary}-${tag}-${asset}" --version)" = \
      "${binary} ${version}"
  done
}

cd -- "${repo_root}"
if [[ "${group}" == core || "${group}" == all ]]; then
  build_core
fi
if [[ "${group}" == breg || "${group}" == all ]]; then
  build_breg
fi
if [[ "${group}" == bregctl || "${group}" == all ]]; then
  build_bregctl
fi
if [[ "${group}" == casework || "${group}" == all ]]; then
  build_casework
fi

assets=()
if [[ "${group}" == core || "${group}" == all ]]; then
  assets+=(
    "relayctl-${tag}-${asset}"
    "evidence-${tag}-${asset}"
    "evidencectl-${tag}-${asset}"
    "evidence-oid4vci-${tag}-${asset}"
  )
fi
if [[ ("${group}" == breg || "${group}" == all) && "${include_breg}" -eq 1 ]]; then
  assets+=("breg-${tag}-${asset}")
fi
if [[ ("${group}" == bregctl || "${group}" == all) && "${include_breg}" -eq 1 ]]; then
  assets+=("bregctl-${tag}-${asset}")
fi
if [[ ("${group}" == casework || "${group}" == all) && "${include_casework}" -eq 1 ]]; then
  assets+=("casework-${tag}-${asset}" "caseworkctl-${tag}-${asset}")
fi

(
  cd -- "${temporary}/platform"
  : >../SHA256SUMS
  for item in "${assets[@]}"; do
    digest="$(shasum -a 256 -- "${item}" | awk '{print $1}')"
    printf '%s  %s\n' "${digest}" "${item}" >>../SHA256SUMS
  done
)
printf '%s\npurpose=%s\nsource_sha=%s\nversion=%s\ntarget=%s\nasset=%s\ngroup=%s\nrust_toolchain=%s\n' \
  registry-stack.release-native-platform-shard.v1 \
  "${purpose}" "${source_sha}" "${version}" "${target}" "${asset}" \
  "${group}" "${rust_toolchain}" \
  >"${temporary}/RELEASE_NATIVE_PLATFORM_SHARD"

mv -- "${temporary}" "${output}"
trap - EXIT
