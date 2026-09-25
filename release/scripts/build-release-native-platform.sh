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
bundle_fips=0
if ((version_major > 0 || version_minor >= 33)); then
  bundle_fips=1
  # AWS-LC FIPS supports a shared module on macOS. It refuses static macOS
  # builds, so package that module with every executable from v0.33 onward.
  # CMake otherwise inherits the host SDK minimum for the shared dylib, which
  # can be newer than the macOS 11 release contract carried by the binaries.
  export AWS_LC_FIPS_SYS_STATIC=0
  export MACOSX_DEPLOYMENT_TARGET=11.0
else
  # Historical shards retain their original standalone executable contract.
  export AWS_LC_FIPS_SYS_STATIC=1
fi
include_breg=0
if ((version_major > 0 || version_minor >= 26)); then
  include_breg=1
fi
# The citizen MCP gateway and its review page ship in the BReg release set.
# They depend on the engine only through its client, so they build in the
# bregctl group rather than beside the runtime.
include_breg_services=0
if ((version_major > 0 || version_minor >= 35)); then
  include_breg_services=1
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
fips_library_root="${target_root}/${target}/release/build"
packager="${repo_root}/release/scripts/macos_fips_packaging.py"
staged_executable=""

stage() {
  local binary="$1"
  local destination="$2"
  local dependencies
  local source="${target_root}/${target}/release/${binary}"
  if [[ "${bundle_fips}" -eq 1 ]]; then
    local archive="${temporary}/platform/${destination}.tar.gz"
    local extracted="${temporary}/smoke/${destination}"
    python3 "${packager}" archive \
      --binary "${source}" \
      --asset-name "${destination}" \
      --library-root "${fips_library_root}" \
      --notice "${repo_root}/THIRD_PARTY_NOTICES" \
      --output "${archive}"
    python3 "${packager}" extract \
      --archive "${archive}" \
      --destination "${extracted}" \
      --expected-executable "${destination}"
    staged_executable="${extracted}/${destination}"
    return
  fi

  cp -- "${source}" "${temporary}/platform/${destination}"
  chmod 0755 "${temporary}/platform/${destination}"
  if ! dependencies="$(otool -L "${temporary}/platform/${destination}")"; then
    printf 'cannot inspect macOS release binary dependencies: %s\n' \
      "${destination}" >&2
    return 1
  fi
  if grep -Eq 'libaws_lc_fips_[^/[:space:]]*_crypto\.dylib' \
      <<<"${dependencies}"; then
    printf 'macOS release binary retains an unpackaged AWS-LC-FIPS dylib: %s\n' \
      "${destination}" >&2
    return 1
  fi
  staged_executable="${temporary}/platform/${destination}"
}

build_core() {
  "${cargo_bin}" build --release --locked \
    -p registry-relayctl -p registry-evidence -p registry-evidencectl \
    -p registry-evidence-oid4vci \
    --target "${target}"

  stage relayctl "relayctl-${tag}-${asset}"
  test "$("${staged_executable}" --version)" = \
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
  test "$("${staged_executable}" --version)" = \
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
  test "$("${staged_executable}" --version)" = \
    "bregctl ${version}"

  if [[ "${include_breg_services}" -ne 1 ]]; then
    return
  fi
  "${cargo_bin}" build --release --locked \
    -p registry-breg-mcp --bin breg-mcp \
    --target "${target}"
  "${cargo_bin}" build --release --locked \
    -p registry-breg-review --bin breg-review \
    --target "${target}"

  local binary
  for binary in breg-mcp breg-review; do
    stage "${binary}" "${binary}-${tag}-${asset}"
    test "$("${staged_executable}" --version)" = \
      "${binary} ${version}"
  done
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
    test "$("${staged_executable}" --version)" = \
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
rm -rf -- "${temporary}/smoke"

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
  if [[ "${include_breg_services}" -eq 1 ]]; then
    assets+=("breg-mcp-${tag}-${asset}" "breg-review-${tag}-${asset}")
  fi
fi
if [[ ("${group}" == casework || "${group}" == all) && "${include_casework}" -eq 1 ]]; then
  assets+=("casework-${tag}-${asset}" "caseworkctl-${tag}-${asset}")
fi
if [[ "${bundle_fips}" -eq 1 ]]; then
  for index in "${!assets[@]}"; do
    assets[${index}]="${assets[${index}]}.tar.gz"
  done
fi

(
  cd -- "${temporary}/platform"
  : >../SHA256SUMS
  for item in "${assets[@]}"; do
    digest="$(shasum -a 256 -- "${item}" | awk '{print $1}')"
    printf '%s  %s\n' "${digest}" "${item}" >>../SHA256SUMS
  done
)
shard_format=registry-stack.release-native-platform-shard.v1
if [[ "${bundle_fips}" -eq 1 ]]; then
  shard_format=registry-stack.release-native-platform-shard.v2
fi
printf '%s\npurpose=%s\nsource_sha=%s\nversion=%s\ntarget=%s\nasset=%s\ngroup=%s\nrust_toolchain=%s\n' \
  "${shard_format}" \
  "${purpose}" "${source_sha}" "${version}" "${target}" "${asset}" \
  "${group}" "${rust_toolchain}" \
  >"${temporary}/RELEASE_NATIVE_PLATFORM_SHARD"

mv -- "${temporary}" "${output}"
trap - EXIT
