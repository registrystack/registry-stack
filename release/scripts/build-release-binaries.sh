#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

group=all
include_casework_override=0
while [[ "$#" -gt 1 ]]; do
  case "$1" in
    --group) group="${2:-}"; shift 2 ;;
    --include-casework) include_casework_override=1; shift ;;
    *) break ;;
  esac
done
if [[ "$#" -eq 1 ]]; then
  version="$1"
else
  printf 'usage: %s [--include-casework] [--group core|breg|casework] <release-version>\n' "$0" >&2
  exit 2
fi
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ||
      ("${group}" != all && "${group}" != core && "${group}" != breg &&
       "${group}" != casework) ]]; then
  printf 'usage: %s [--include-casework] [--group core|breg|casework] <release-version>\n' "$0" >&2
  exit 2
fi
tag="v${version}"
# The Discovery binary joins the release payload at 0.24.0. A candidate rebuilt
# for an earlier version must stage exactly the assets its recorded inventory
# names, so seal-candidate keeps accepting it.
IFS=. read -r version_major version_minor _version_patch <<<"${version}"
include_discovery=0
if ((version_major > 0 || version_minor >= 24)); then
  include_discovery=1
fi
include_breg=0
if ((version_major > 0 || version_minor >= 26)); then
  include_breg=1
fi
include_casework=0
if ((version_major > 0 || version_minor >= 30)) ||
   [[ "${include_casework_override}" -eq 1 ]]; then
  include_casework=1
fi

# Compile and link every product binary through Zig against the glibc stubs of
# the release floor. The builder carries a much newer glibc, and without this
# the highest symbol version it happens to export becomes the floor by
# accident: the binaries start here and refuse to start on a supported
# distribution, with a dynamic linker error at the adopter's first run.
release_zig_wrapper_root=""
cleanup_zig_toolchain() {
  if [[ -n "${release_zig_wrapper_root}" ]]; then
    rm -rf -- "${release_zig_wrapper_root}"
  fi
}

prepare_zig_toolchain() {
  # shellcheck source-path=SCRIPTDIR
  # shellcheck source=../glibc-floor.env
  . "${repo_root}/release/glibc-floor.env"
  local floor="${REGISTRY_GLIBC_FLOOR:?REGISTRY_GLIBC_FLOOR is required}"

  local machine zig_arch
  machine="$(uname -m)"
  case "${machine}" in
    x86_64) zig_arch=x86_64 ;;
    aarch64 | arm64) zig_arch=aarch64 ;;
    *)
      printf 'no approved zig glibc target for %s\n' "${machine}" >&2
      exit 2
      ;;
  esac

  # Cargo fingerprints the compiler/linker paths. An identical pinned recipe
  # must expose the same paths in each fresh container, including after a lock
  # update. Changed compiler inputs get different paths and invalidate native
  # build outputs even when a build script does not track those files itself.
  local wrapper_key wrapper_root
  wrapper_key="$(
    {
      printf '%s\0' "${zig_arch}" /usr/bin/python3
      (
        cd -- "${repo_root}"
        sha256sum \
          rust-toolchain.toml \
          release/scripts/build-release-binaries.sh \
          release/docker/Dockerfile.builder \
          release/requirements/ziglang-0.12.1.txt \
          release/glibc-floor.env \
          release/scripts/zig-glibc-compiler
      )
    } | sha256sum | cut -d ' ' -f 1
  )"
  wrapper_root="/tmp/registry-release-zig-${wrapper_key}"
  # /tmp belongs to this disposable container. Claim the exact directory
  # exclusively; never follow, reuse, or remove an unexpected existing path.
  if ! mkdir -m 0700 -- "${wrapper_root}"; then
    printf 'cannot create canonical compiler directory: %s\n' "${wrapper_root}" >&2
    exit 2
  fi
  release_zig_wrapper_root="${wrapper_root}"
  trap cleanup_zig_toolchain EXIT
  ln -s "${script_dir}/zig-glibc-compiler" "${release_zig_wrapper_root}/zig-cc"
  ln -s "${script_dir}/zig-glibc-compiler" "${release_zig_wrapper_root}/zig-cxx"

  local rust_target="${zig_arch}-unknown-linux-gnu"
  local target_env="${rust_target//-/_}"
  local cargo_target_env
  cargo_target_env="$(printf '%s' "${target_env}" | tr '[:lower:]' '[:upper:]')"

  # Zig picks its cache from HOME, which the builder points at the mounted
  # checkout, so an unset cache directory fills the working tree with build
  # artefacts. Both live under the wrapper root the exit trap removes.
  export ZIG_GLOBAL_CACHE_DIR="${release_zig_wrapper_root}/cache-global"
  export ZIG_LOCAL_CACHE_DIR="${release_zig_wrapper_root}/cache-local"
  export REGISTRY_ZIG_PYTHON=/usr/bin/python3
  export REGISTRY_ZIG_TARGET="${zig_arch}-linux-gnu.${floor}"
  export HOST_CC="${release_zig_wrapper_root}/zig-cc"
  export HOST_CXX="${release_zig_wrapper_root}/zig-cxx"
  export TARGET_CC="${release_zig_wrapper_root}/zig-cc"
  export TARGET_CXX="${release_zig_wrapper_root}/zig-cxx"
  export "CC_${target_env}=${release_zig_wrapper_root}/zig-cc"
  export "CXX_${target_env}=${release_zig_wrapper_root}/zig-cxx"
  export "CARGO_TARGET_${cargo_target_env}_LINKER=${release_zig_wrapper_root}/zig-cc"
}

build_payload() {
  export RUSTFLAGS="${RELEASE_RUSTFLAGS:?RELEASE_RUSTFLAGS is required}"
  prepare_zig_toolchain

  if [[ "${group}" == all || "${group}" == core ]]; then
    cargo build --release --locked \
      -p registry-manifest-cli
    cp target/release/registry-manifest "dist/bin/registry-manifest-${RELEASE_TAG}-linux-amd64"

    # Build and stage the production Relay before relayctl enables the separate
    # authoring-only tooling feature on the Relay library dependency.
    cargo build --release --locked \
      -p registry-relay-v2 \
      --bin relay \
      --no-default-features
    cp target/release/relay "dist/bin/relay-${RELEASE_TAG}-linux-amd64"
    cp target/release/relay dist/image-bin/relay

    cargo build --release --locked \
      -p registry-relayctl
    cp target/release/relayctl "dist/bin/relayctl-${RELEASE_TAG}-linux-amd64"

    cargo build --release --locked \
      -p registry-evidence \
      -p registry-evidencectl \
      -p registry-mint \
      -p registry-evidence-oid4vci
    cp target/release/evidence "dist/bin/evidence-${RELEASE_TAG}-linux-amd64"
    cp target/release/evidencectl "dist/bin/evidencectl-${RELEASE_TAG}-linux-amd64"
    cp target/release/mint "dist/bin/mint-${RELEASE_TAG}-linux-amd64"
    cp target/release/evidence-oid4vci "dist/bin/evidence-oid4vci-${RELEASE_TAG}-linux-amd64"
    cp target/release/evidence dist/image-bin/evidence
    cp target/release/mint dist/image-bin/mint

    if [[ "${include_discovery}" -eq 1 ]]; then
      cargo build --release --locked \
        -p registry-discovery \
        --bin discovery
      cp target/release/discovery "dist/bin/discovery-${RELEASE_TAG}-linux-amd64"
      cp target/release/discovery dist/image-bin/discovery
    fi
  fi

  if [[ ("${group}" == all || "${group}" == breg) && "${include_breg}" -eq 1 ]]; then
    cargo build --release --locked \
      -p registry-breg \
      --bin breg \
      --features runtime
    cargo build --release --locked \
      -p registry-bregctl
    cp target/release/breg "dist/bin/breg-${RELEASE_TAG}-linux-amd64"
    cp target/release/bregctl "dist/bin/bregctl-${RELEASE_TAG}-linux-amd64"
    cp target/release/breg dist/image-bin/breg
  fi

  if [[ ("${group}" == all || "${group}" == casework) && "${include_casework}" -eq 1 ]]; then
    cargo build --release --locked \
      -p registry-casework --bin casework
    cargo build --release --locked \
      -p registry-caseworkctl --bin caseworkctl
    cp target/release/casework "dist/bin/casework-${RELEASE_TAG}-linux-amd64"
    cp target/release/caseworkctl "dist/bin/caseworkctl-${RELEASE_TAG}-linux-amd64"
    cp target/release/casework dist/image-bin/casework
  fi

  # Nothing but the staged payload is in these directories yet: the checksum
  # files and the builder image record are written by the outer invocation
  # after this container exits. Every staged binary is checked, so a build that
  # slipped past the Zig toolchain fails here instead of at an adopter's first
  # run.
  shopt -s nullglob
  local staged_binaries=(dist/bin/* dist/image-bin/*)
  shopt -u nullglob
  if [[ "${#staged_binaries[@]}" -gt 0 ]]; then
    "${script_dir}/check-glibc-floor.sh" "${staged_binaries[@]}"
  fi
}

# The outer invocation prepares the pinned container. The inner invocation is
# re-executed inside it as the host uid/gid so mounted release outputs are never
# owned by root on either GitHub-hosted runners or an operator workstation.
if [[ "${RELEASE_BUILDER_READY:-0}" -eq 1 ]]; then
  if [[ "${repo_root}" != "/workspace" ||
        "${CARGO_HOME:-}" != "/workspace/.cargo-home" ||
        "${CARGO_TARGET_DIR:-}" != "/workspace/target" ||
        "${RELEASE_TAG:-}" != "${tag}" ||
        "${REGISTRY_RELEASE_TAG:-}" != "${tag}" ]]; then
    printf 'RELEASE_BUILDER_READY is internal to the canonical builder container\n' >&2
    exit 2
  fi
  build_payload
  exit 0
fi

default_builder_image="rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3"
if [[ -n "${RELEASE_BUILDER_IMAGE:-}" && "${RELEASE_BUILDER_IMAGE}" != "${default_builder_image}" ]]; then
  printf 'RELEASE_BUILDER_IMAGE must remain pinned to %s\n' "${default_builder_image}" >&2
  exit 2
fi
release_builder_recipe="${repo_root}/release/docker/Dockerfile.builder"
# The recipe is the Dockerfile plus every file it installs from, so a change to
# either names a different builder image.
release_builder_recipe_sha="$(
  cat \
    "${release_builder_recipe}" \
    "${repo_root}/release/requirements/ziglang-0.12.1.txt" \
    | sha256sum \
    | cut -d ' ' -f 1
)"
release_builder_image="registry-stack-release-builder:${release_builder_recipe_sha}"
release_cargo_home="${RELEASE_CARGO_HOME:-${repo_root}/.cargo-home}"
release_target_dir="${RELEASE_TARGET_DIR:-${repo_root}/target}"

if [[ "${release_cargo_home}" != /* ]]; then
  release_cargo_home="${repo_root}/${release_cargo_home}"
fi
if [[ "${release_target_dir}" != /* ]]; then
  release_target_dir="${repo_root}/${release_target_dir}"
fi

mkdir -p "${release_cargo_home}" "${release_target_dir}"
rm -rf -- \
  "${repo_root}/dist/bin" \
  "${repo_root}/dist/image-bin" \
  "${repo_root}/dist/RELEASE_BINARY_SHARD" \
  "${repo_root}/dist/RELEASE_BUILDER_IMAGE"
mkdir -p "${repo_root}/dist/bin" "${repo_root}/dist/image-bin"

# Rust retains dependency source paths in panic and diagnostic strings even
# when release binaries are stripped. Mount host state at canonical container
# paths and remap those paths so independent hosts produce identical bytes.
release_rustflags="--remap-path-prefix=/workspace/.cargo-home=/cargo-home --remap-path-prefix=/workspace=/source"
casework_args=()
if [[ "${include_casework_override}" -eq 1 ]]; then
  casework_args+=(--include-casework)
fi

docker build \
  --platform linux/amd64 \
  --file "${release_builder_recipe}" \
  --tag "${release_builder_image}" \
  "${repo_root}"

docker run --rm \
  --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  --volume "${repo_root}:/workspace" \
  --volume "${release_cargo_home}:/workspace/.cargo-home" \
  --volume "${release_target_dir}:/workspace/target" \
  --workdir /workspace \
  --env CARGO_HOME=/workspace/.cargo-home \
  --env CARGO_TARGET_DIR=/workspace/target \
  --env CARGO_INCREMENTAL=0 \
  --env CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}" \
  --env HOME=/workspace \
  --env RELEASE_INCLUDE_DISCOVERY="${include_discovery}" \
  --env RELEASE_INCLUDE_BREG="${include_breg}" \
  --env RELEASE_INCLUDE_CASEWORK="${include_casework}" \
  --env RELEASE_TAG="${tag}" \
  --env REGISTRY_RELEASE_TAG="${tag}" \
  --env RELEASE_RUSTFLAGS="${release_rustflags}" \
  --env RELEASE_BUILDER_READY=1 \
  "${release_builder_image}" \
  /workspace/release/scripts/build-release-binaries.sh \
    "${casework_args[@]}" \
    --group "${group}" "${version}"

if [[ "${group}" == all ]]; then
  printf '%s\n' "${default_builder_image}" >"${repo_root}/dist/image-bin/RELEASE_BUILDER_IMAGE"
else
  if [[ ! "${RELEASE_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'RELEASE_SOURCE_SHA must be the exact source commit for a binary shard\n' >&2
    exit 2
  fi
  printf '%s\n' "${default_builder_image}" >"${repo_root}/dist/RELEASE_BUILDER_IMAGE"
  printf '%s\nsource_sha=%s\nversion=%s\ngroup=%s\n' \
    registry-stack.release-binary-shard.v1 \
    "${RELEASE_SOURCE_SHA}" "${version}" "${group}" \
    >"${repo_root}/dist/RELEASE_BINARY_SHARD"
fi
# The staged asset lists follow the same gate as the build above, so a version
# that predates an asset neither checksums nor chmods a file it never built.
bin_assets=()
image_bin_binaries=()
if [[ ("${group}" == all || "${group}" == core) && "${include_discovery}" -eq 1 ]]; then
  bin_assets+=("discovery-${tag}-linux-amd64")
  image_bin_binaries+=(discovery)
fi
if [[ ("${group}" == all || "${group}" == breg) && "${include_breg}" -eq 1 ]]; then
  bin_assets+=(
    "breg-${tag}-linux-amd64"
    "bregctl-${tag}-linux-amd64"
  )
  image_bin_binaries+=(breg)
fi
if [[ ("${group}" == all || "${group}" == casework) && "${include_casework}" -eq 1 ]]; then
  bin_assets+=(
    "casework-${tag}-linux-amd64"
    "caseworkctl-${tag}-linux-amd64"
  )
  image_bin_binaries+=(casework)
fi
if [[ "${group}" == all || "${group}" == core ]]; then
  bin_assets+=(
    "evidence-${tag}-linux-amd64"
    "evidencectl-${tag}-linux-amd64"
    "mint-${tag}-linux-amd64"
    "evidence-oid4vci-${tag}-linux-amd64"
    "registry-manifest-${tag}-linux-amd64"
    "relay-${tag}-linux-amd64"
    "relayctl-${tag}-linux-amd64"
  )
  image_bin_binaries+=(evidence mint relay)
fi

for asset in "${bin_assets[@]}"; do
  chmod 0755 "${repo_root}/dist/bin/${asset}"
done
for asset in "${image_bin_binaries[@]}"; do
  chmod 0755 "${repo_root}/dist/image-bin/${asset}"
done

(
  cd -- "${repo_root}/dist/bin"
  if [[ "${#bin_assets[@]}" -eq 0 ]]; then
    : >SHA256SUMS
  else
    sha256sum -- "${bin_assets[@]}" >SHA256SUMS
  fi
)
if [[ "${group}" == all ]]; then
  (
    cd -- "${repo_root}/dist/image-bin"
    sha256sum -- RELEASE_BUILDER_IMAGE "${image_bin_binaries[@]}" >SHA256SUMS
  )
fi

printf 'built %s release binaries for %s with canonical container paths\n' \
  "${group}" "${tag}"
