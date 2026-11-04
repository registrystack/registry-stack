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
nightly_tag=""
exclude_discovery=0
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --group) group="${2:-}"; shift 2 ;;
    --include-casework) include_casework_override=1; shift ;;
    --purpose) purpose="${2:-}"; shift 2 ;;
    --source-sha) source_sha="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --nightly-tag) nightly_tag="${2:-}"; shift 2 ;;
    --exclude-unit)
      if [[ "${2:-}" != discovery ]]; then
        printf 'only --exclude-unit discovery is supported\n' >&2
        exit 2
      fi
      exclude_discovery=1
      shift 2
      ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

usage() {
  printf 'usage: %s [--include-casework] [--nightly-tag TAG] [--exclude-unit discovery] --group core|breg|bregctl|casework|scheduling|all --purpose candidate_input|review_only --source-sha SHA --version VERSION --output DIRECTORY\n' "$0" >&2
  exit 2
}

if [[ "${group}" != core && "${group}" != breg &&
      "${group}" != bregctl && "${group}" != casework &&
      "${group}" != scheduling && "${group}" != all ]]; then
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
display_version="${version}"
if [[ -n "${nightly_tag}" ]]; then
  if [[ ! "${nightly_tag}" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-nightly\.([0-9]{8})\.([0-9a-f]{40})$ ||
        "${BASH_REMATCH[1]:-}" != "${version}" ]]; then
    printf 'nightly tag must match v%s-nightly.<YYYYMMDD>.<40-character lowercase source SHA>\n' "${version}" >&2
    exit 2
  fi
  nightly_date="${BASH_REMATCH[2]}"
  nightly_source_sha="${BASH_REMATCH[3]}"
  if ! python3 -c 'import datetime, sys; datetime.datetime.strptime(sys.argv[1], "%Y%m%d")' "${nightly_date}" 2>/dev/null; then
    printf 'nightly tag contains an invalid YYYYMMDD date\n' >&2
    exit 2
  fi
  if [[ "${nightly_source_sha}" != "${source_sha}" ]]; then
    printf 'nightly tag source SHA does not match --source-sha\n' >&2
    exit 2
  fi
  if [[ "${purpose}" != review_only ]]; then
    printf 'nightly native shards must use purpose review_only\n' >&2
    exit 2
  fi
  tag="${nightly_tag}"
  display_version="${nightly_tag#v}"
  export REGISTRY_NIGHTLY_TAG="${nightly_tag}"
  unset REGISTRY_RELEASE_TAG
else
  export REGISTRY_RELEASE_TAG="${tag}"
  unset REGISTRY_NIGHTLY_TAG
fi
IFS=. read -r version_major version_minor _version_patch <<<"${version}"
bundle_fips=0
if ((version_major > 0 || version_minor >= 33)); then
  bundle_fips=1
  # AWS-LC FIPS supports a shared module on macOS. It refuses static macOS
  # builds, so package that module with crypto-using executables from v0.33 onward.
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
# release_roster.py names the first release that ships the citizen MCP
# gateway and its review page in the BReg set; until it does, no version
# builds them. They depend on the engine only through its client, so they
# build in the bregctl group rather than beside the runtime.
include_breg_services=0
breg_services_in_release="$(python3 "${script_dir}/release_roster.py" \
  breg-services-in-release "${version}")"
if [[ "${breg_services_in_release}" == true ]]; then
  include_breg_services=1
fi
include_casework=0
if ((version_major > 0 || version_minor >= 30)) ||
   [[ "${include_casework_override}" -eq 1 ]]; then
  include_casework=1
fi
# Scheduling's operator tool is native from 0.36.0; its runtime joins at 0.44.0.
include_schedulingctl=0
if ((version_major > 0 || version_minor >= 36)); then
  include_schedulingctl=1
fi
include_rstack=0
if [[ "$(python3 "${script_dir}/release_roster.py" \
  rstack-in-release "${version}")" == true ]]; then
  include_rstack=1
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
  if [[ "${bundle_fips}" -eq 1 && "${binary}" != registry-manifest ]]; then
    local archive="${temporary}/platform/${destination}.tar.gz"
    local extracted="${temporary}/smoke/${destination}"
    # These programs do not link the release's AWS-LC FIPS dylib. Keep the list
    # explicit so a missing FIPS load on any required consumer still fails in
    # the strict FIPS packager instead of silently becoming plain.
    if [[ "${binary}" == rstack || "${binary}" == discovery ]]; then
      python3 "${packager}" archive-plain \
        --binary "${source}" \
        --asset-name "${destination}" \
        --notice "${repo_root}/THIRD_PARTY_NOTICES" \
        --output "${archive}"
      python3 "${packager}" extract-plain \
        --archive "${archive}" \
        --destination "${extracted}" \
        --expected-executable "${destination}"
    else
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
    fi
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

# Compare the staged executable's version line with the release identity and
# name both when they differ, so a failed check says which binary and why.
check_version() {
  local expected="$1"
  local observed
  observed="$("${staged_executable}" --version)"
  if [[ "${observed}" != "${expected}" ]]; then
    printf '%s reports "%s"; the release identity expects "%s"\n' \
      "$(basename -- "${staged_executable}")" "${observed}" "${expected}" >&2
    return 1
  fi
}

build_core() {
  if [[ "${include_rstack}" -eq 1 ]]; then
    "${cargo_bin}" build --release --locked \
      -p registry-rstack --bin rstack --target "${target}"
    stage rstack "rstack-${tag}-${asset}"
    check_version "rstack ${display_version}"
  fi
  "${cargo_bin}" build --release --locked \
    -p registry-evidence -p registry-evidencectl \
    -p registry-evidence-oid4vci \
    --target "${target}"

  local binary
  for binary in evidence evidencectl evidence-oid4vci; do
    stage "${binary}" "${binary}-${tag}-${asset}"
    check_version "${binary} ${display_version}"
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
  check_version "breg ${display_version}"
}

build_bregctl() {
  if [[ "${include_breg}" -ne 1 ]]; then
    return
  fi
  "${cargo_bin}" build --release --locked \
    -p registry-bregctl \
    --target "${target}"

  stage bregctl "bregctl-${tag}-${asset}"
  check_version "bregctl ${display_version}"

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
    check_version "${binary} ${display_version}"
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
    check_version "${binary} ${display_version}"
  done
}

build_scheduling() {
  if [[ "${include_schedulingctl}" -ne 1 ]]; then
    return
  fi
  if [[ "${additional_platform_builds}" == *"registry-scheduling scheduling"* ]]; then
    "${cargo_bin}" build --release --locked \
      -p registry-scheduling --bin scheduling --target "${target}"
    stage scheduling "scheduling-${tag}-${asset}"
    check_version "scheduling ${display_version}"
  fi
  "${cargo_bin}" build --release --locked \
    -p registry-schedulingctl --bin schedulingctl \
    --target "${target}"

  stage schedulingctl "schedulingctl-${tag}-${asset}"
  check_version "schedulingctl ${display_version}"
}

additional_platform_builds="$(python3 "${repo_root}/release/scripts/release_roster.py" additional-platform-builds "${version}")"
if [[ "${exclude_discovery}" -eq 1 ]]; then
  filtered_platform_builds=""
  while read -r package binary; do
    if [[ "${package}" == registry-discovery* ]]; then
      continue
    fi
    filtered_platform_builds+="${package} ${binary}"$'\n'
  done <<<"${additional_platform_builds}"
  additional_platform_builds="${filtered_platform_builds%$'\n'}"
fi
build_additional_platforms() {
  local package binary expected typst_pin
  [[ -n "${additional_platform_builds}" ]] || return 0
  while read -r package binary; do
    [[ "${binary}" != scheduling ]] || continue
    "${cargo_bin}" build --release --locked -p "${package}" --bin "${binary}" --target "${target}"
    stage "${binary}" "${binary}-${tag}-${asset}"
    expected="${binary} ${display_version}"
    if [[ "${binary}" == registry-render ]]; then
      typst_pin="$(sed -n 's/^pub const TYPST_PIN: &str = "\([^"]*\)";$/\1/p' "${repo_root}/crates/registry-render/src/lib.rs")"
      test -n "${typst_pin}"
      expected+=" (typst ${typst_pin})"
    fi
    check_version "${expected}"
  done <<<"${additional_platform_builds}"
}

cd -- "${repo_root}"
if [[ "${group}" == core || "${group}" == all ]]; then
  build_core
  build_additional_platforms
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
if [[ "${group}" == scheduling || "${group}" == all ]]; then
  build_scheduling
fi
rm -rf -- "${temporary}/smoke"

assets=()
if [[ ("${group}" == core || "${group}" == all) && -n "${additional_platform_builds}" ]]; then
  while read -r package binary; do
    [[ "${binary}" != scheduling ]] || continue
    assets+=("${binary}-${tag}-${asset}")
  done <<<"${additional_platform_builds}"
fi
if [[ "${group}" == core || "${group}" == all ]]; then
  if [[ "${include_rstack}" -eq 1 ]]; then
    assets+=("rstack-${tag}-${asset}")
  fi
  assets+=(
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
if [[ ("${group}" == scheduling || "${group}" == all) && "${include_schedulingctl}" -eq 1 ]]; then
  if [[ "${additional_platform_builds}" == *"registry-scheduling scheduling"* ]]; then
    assets+=("scheduling-${tag}-${asset}")
  fi
  assets+=("schedulingctl-${tag}-${asset}")
fi
if [[ "${bundle_fips}" -eq 1 ]]; then
  for index in "${!assets[@]}"; do
    if [[ "${assets[${index}]}" != registry-manifest-* ]]; then
      assets[index]="${assets[${index}]}.tar.gz"
    fi
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
if [[ -n "${nightly_tag}" ]]; then
  shard_format=registry-stack.release-native-platform-shard.v3
elif [[ "${bundle_fips}" -eq 1 ]]; then
  shard_format=registry-stack.release-native-platform-shard.v2
fi
if [[ -n "${nightly_tag}" ]]; then
  printf '%s\npurpose=%s\nsource_sha=%s\nversion=%s\nnightly_tag=%s\ntarget=%s\nasset=%s\ngroup=%s\nrust_toolchain=%s\n' \
    "${shard_format}" \
    "${purpose}" "${source_sha}" "${version}" "${nightly_tag}" \
    "${target}" "${asset}" "${group}" "${rust_toolchain}" \
    >"${temporary}/RELEASE_NATIVE_PLATFORM_SHARD"
else
  printf '%s\npurpose=%s\nsource_sha=%s\nversion=%s\ntarget=%s\nasset=%s\ngroup=%s\nrust_toolchain=%s\n' \
    "${shard_format}" \
    "${purpose}" "${source_sha}" "${version}" "${target}" "${asset}" \
    "${group}" "${rust_toolchain}" \
    >"${temporary}/RELEASE_NATIVE_PLATFORM_SHARD"
fi

mv -- "${temporary}" "${output}"
trap - EXIT
