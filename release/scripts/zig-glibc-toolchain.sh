#!/usr/bin/env bash
# The Zig toolchain behind every Linux product binary, for a build recipe to
# source. The canonical recipe selects it inside the builder image and the
# native arm64 recipes install it on their runner, so both architectures
# compile and link against the glibc stubs of the floor in
# release/glibc-floor.env through one wrapper, one pinned Zig, and one set of
# variables. The glibc of the machine doing the build never reaches a binary.
set -euo pipefail

zig_glibc_release="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# Print the Zig architecture of this machine. A product binary is built on the
# architecture it runs on; only its glibc differs from the machine's own.
zig_glibc_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
    x86_64) printf 'x86_64\n' ;;
    aarch64 | arm64) printf 'aarch64\n' ;;
    *)
      printf 'no approved zig glibc target for %s\n' "${machine}" >&2
      return 2
      ;;
  esac
}

# select_zig_glibc_toolchain <zig-python> <wrapper-root>
#
# Send every C and C++ compile and every link of the build that follows
# through the Zig wrapper at the release floor. <zig-python> is the interpreter
# carrying the hash-pinned ziglang wheel. <wrapper-root> is an existing
# directory the caller owns; its path reaches Cargo's fingerprints, so the
# caller decides when it is stable and when it changes.
select_zig_glibc_toolchain() {
  local zig_python="$1"
  local wrapper_root="$2"
  # shellcheck source-path=SCRIPTDIR
  # shellcheck source=../glibc-floor.env
  . "${zig_glibc_release}/glibc-floor.env"
  local floor="${REGISTRY_GLIBC_FLOOR:?REGISTRY_GLIBC_FLOOR is required}"
  local zig_arch
  zig_arch="$(zig_glibc_arch)" || exit 2

  ln -s "${zig_glibc_release}/scripts/zig-glibc-compiler" "${wrapper_root}/zig-cc"
  ln -s "${zig_glibc_release}/scripts/zig-glibc-compiler" "${wrapper_root}/zig-cxx"

  local rust_target="${zig_arch}-unknown-linux-gnu"
  local target_env="${rust_target//-/_}"
  local cargo_target_env
  cargo_target_env="$(printf '%s' "${target_env}" | tr '[:lower:]' '[:upper:]')"

  # Zig picks its cache from HOME, which the builder points at the mounted
  # checkout, so an unset cache directory fills the working tree with build
  # artefacts. Both live under the wrapper root instead.
  export ZIG_GLOBAL_CACHE_DIR="${wrapper_root}/cache-global"
  export ZIG_LOCAL_CACHE_DIR="${wrapper_root}/cache-local"
  export REGISTRY_ZIG_PYTHON="${zig_python}"
  export REGISTRY_ZIG_TARGET="${zig_arch}-linux-gnu.${floor}"
  export HOST_CC="${wrapper_root}/zig-cc"
  export HOST_CXX="${wrapper_root}/zig-cxx"
  export TARGET_CC="${wrapper_root}/zig-cc"
  export TARGET_CXX="${wrapper_root}/zig-cxx"
  export "CC_${target_env}=${wrapper_root}/zig-cc"
  export "CXX_${target_env}=${wrapper_root}/zig-cxx"
  export "CARGO_TARGET_${cargo_target_env}_LINKER=${wrapper_root}/zig-cc"
}

# install_zig_glibc_toolchain <root>
#
# For a build outside the builder image, which already carries the pinned Zig.
# Install the same hash-pinned wheel into a private environment under <root>,
# then select it. <root> must not exist: an environment this call did not
# create is never trusted with the compiler.
install_zig_glibc_toolchain() {
  local root="$1"
  # Refuse an unsupported machine before anything is created.
  zig_glibc_arch >/dev/null || exit 2
  if ! mkdir -m 0700 -- "${root}"; then
    printf 'cannot create zig toolchain directory: %s\n' "${root}" >&2
    exit 2
  fi
  python3 -m venv "${root}/python"
  "${root}/python/bin/pip" install --quiet \
    --require-hashes --only-binary=:all: \
    --requirement "${zig_glibc_release}/requirements/ziglang-0.12.1.txt"
  # The requirement carries a platform marker. Where it does not match, pip
  # installs nothing and still succeeds, so run the module to prove the wheel
  # is there.
  if ! "${root}/python/bin/python" -m ziglang version >/dev/null; then
    printf 'the pinned zig is not installed in %s\n' "${root}/python" >&2
    exit 2
  fi
  mkdir -- "${root}/compiler"
  select_zig_glibc_toolchain "${root}/python/bin/python" "${root}/compiler"
}
