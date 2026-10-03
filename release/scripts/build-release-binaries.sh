#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

group=all
include_casework_override=0
nightly_tag=""
while [[ "$#" -gt 1 ]]; do
  case "$1" in
    --group) group="${2:-}"; shift 2 ;;
    --include-casework) include_casework_override=1; shift ;;
    --nightly-tag) nightly_tag="${2:-}"; shift 2 ;;
    *) break ;;
  esac
done
if [[ "$#" -eq 1 ]]; then
  version="$1"
else
  printf 'usage: %s [--include-casework] [--nightly-tag TAG] [--group core|breg|casework|scheduling|messaging] <release-version>\n' "$0" >&2
  exit 2
fi
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ||
      ("${group}" != all && "${group}" != core && "${group}" != breg &&
       "${group}" != casework && "${group}" != scheduling &&
       "${group}" != messaging) ]]; then
  printf 'usage: %s [--include-casework] [--nightly-tag TAG] [--group core|breg|casework|scheduling|messaging] <release-version>\n' "$0" >&2
  exit 2
fi
tag="v${version}"
nightly_source_sha=""
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
  if [[ -n "${RELEASE_SOURCE_SHA:-}" &&
        "${RELEASE_SOURCE_SHA}" != "${nightly_source_sha}" ]]; then
    printf 'nightly tag source SHA does not match RELEASE_SOURCE_SHA\n' >&2
    exit 2
  fi
  tag="${nightly_tag}"
fi
# The Discovery binary joins the release payload at 0.24.0. A candidate rebuilt
# for an earlier version must stage exactly the assets its recorded inventory
# names, so seal-candidate keeps accepting it.
IFS=. read -r version_major version_minor _version_patch <<<"${version}"
include_discovery=0
if ((version_major > 0 || version_minor >= 24)); then
  include_discovery=1
fi
include_discoveryctl=0
discoveryctl_in_release="$(python3 "${script_dir}/release_roster.py" \
  discoveryctl-in-release "${version}")"
if [[ "${discoveryctl_in_release}" == true ]]; then
  include_discoveryctl=1
fi
include_breg=0
if ((version_major > 0 || version_minor >= 26)); then
  include_breg=1
fi
# release_roster.py names the first release that ships the citizen MCP
# gateway and its review page in the BReg set; until it does, no version
# builds or stages them.
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
include_scheduling=0
if ((version_major > 0 || version_minor >= 33)); then
  include_scheduling=1
fi
include_scheduling_binary=0
scheduling_binary_in_release="$(python3 "${script_dir}/release_roster.py" \
  scheduling-binary-in-release "${version}")"
if [[ "${scheduling_binary_in_release}" == true ]]; then
  include_scheduling_binary=1
fi
# From 0.36.0 schedulingctl is a release binary and each stateful product
# image carries its operator tool beside the runtime binary.
include_operator_tools=0
if ((version_major > 0 || version_minor >= 36)); then
  include_operator_tools=1
fi
# release_roster.py names the first release that ships Messaging; until it
# does, no version builds or stages the Messaging binaries.
include_messaging=0
messaging_in_release="$(python3 "${script_dir}/release_roster.py" \
  messaging-in-release "${version}")"
if [[ "${messaging_in_release}" == true ]]; then
  include_messaging=1
fi
# Registry Render first ships as both a release binary and image in the release
# named by release_roster.py.
include_render=0
render_in_release="$(python3 "${script_dir}/release_roster.py" \
  render-in-release "${version}")"
if [[ "${render_in_release}" == true ]]; then
  include_render=1
fi
# The Evidence OID4VCI binary predates its image. Keep publishing the binary for
# historical versions and stage it as image input only from its first image
# release.
include_evidence_oid4vci_image=0
evidence_oid4vci_image_in_release="$(python3 "${script_dir}/release_roster.py" \
  evidence-oid4vci-image-in-release "${version}")"
if [[ "${evidence_oid4vci_image_in_release}" == true ]]; then
  include_evidence_oid4vci_image=1
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

# A release binary must be a function of the source tree, not of the checkout
# it was built in. Several vendored build scripts run `git rev-parse HEAD` and
# bake the answer into the crate they build, and CARGO_HOME sits inside the
# mounted repository, so without the discovery ceiling the outer invocation
# sets they resolve this repository's own HEAD. Every commit then produces
# different release bytes, and an image advisory fingerprint recorded in one
# commit can never match the candidate built from the next one.
#
# The ceiling is the control; this reads the staged payload back and refuses a
# build where a commit reached the output anyway, through a path the ceiling
# does not cover. It looks for the exact commit, so a build script that embeds
# only an abbreviation of it passes here and is caught by the ceiling instead.
check_source_commit_absent() {
  local commit="${RELEASE_SOURCE_COMMIT:-}"
  if [[ -n "${nightly_tag}" &&
        "${REGISTRY_NIGHTLY_TAG:-}" == "${nightly_tag}" &&
        -z "${REGISTRY_RELEASE_TAG:-}" &&
        "${nightly_source_sha}" == "${commit}" ]]; then
    printf 'nightly tag %s intentionally embeds source commit %s; source commit absence check skipped\n' \
      "${nightly_tag}" "${commit}"
    return 0
  fi
  if [[ ! "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
    # A checkout with no commit has none to embed, so there is nothing to find.
    printf 'source commit unknown, so staged binaries were not checked for it\n' >&2
    return 0
  fi
  local failures=0
  local binary
  for binary in "$@"; do
    if grep -qaF -- "${commit}" "${binary}"; then
      printf '%s embeds the source commit %s; the build read the checkout git state\n' \
        "${binary}" "${commit}" >&2
      failures=$((failures + 1))
    fi
  done
  if [[ "${failures}" -ne 0 ]]; then
    printf 'source commit check failed for %d of %d binaries\n' "${failures}" "$#" >&2
    return 1
  fi
  printf 'no staged binary embeds the source commit %s\n' "${commit}"
}

build_payload() {
  export RUSTFLAGS="${RELEASE_RUSTFLAGS:?RELEASE_RUSTFLAGS is required}"
  prepare_zig_toolchain

  if [[ "${group}" == all || "${group}" == core ]]; then
    cargo build --release --locked \
      -p registry-manifest-cli
    cp target/release/registry-manifest "dist/bin/registry-manifest-${RELEASE_TAG}-linux-amd64"
    test "$("dist/bin/registry-manifest-${RELEASE_TAG}-linux-amd64" --version)" = \
      "registry-manifest ${RELEASE_TAG#v}"

    cargo build --release --locked \
      -p registry-evidence \
      -p registry-evidencectl \
      -p registry-evidence-oid4vci
    cp target/release/evidence "dist/bin/evidence-${RELEASE_TAG}-linux-amd64"
    cp target/release/evidencectl "dist/bin/evidencectl-${RELEASE_TAG}-linux-amd64"
    cp target/release/evidence-oid4vci "dist/bin/evidence-oid4vci-${RELEASE_TAG}-linux-amd64"
    cp target/release/evidence dist/image-bin/evidence
    if [[ "${include_evidence_oid4vci_image}" -eq 1 ]]; then
      cp target/release/evidence-oid4vci dist/image-bin/evidence-oid4vci
    fi

    if [[ "${include_render}" -eq 1 ]]; then
      cargo build --release --locked \
        -p registry-render --bin registry-render
      cp target/release/registry-render \
        "dist/bin/registry-render-${RELEASE_TAG}-linux-amd64"
      cp target/release/registry-render dist/image-bin/registry-render
    fi

    if [[ "${include_discovery}" -eq 1 ]]; then
      cargo build --release --locked \
        -p registry-discovery \
        --bin discovery
      cp target/release/discovery "dist/bin/discovery-${RELEASE_TAG}-linux-amd64"
      cp target/release/discovery dist/image-bin/discovery
    fi
    if [[ "${include_discoveryctl}" -eq 1 ]]; then
      cargo build --release --locked \
        -p registry-discoveryctl --bin discoveryctl
      cp target/release/discoveryctl \
        "dist/bin/discoveryctl-${RELEASE_TAG}-linux-amd64"
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
    if [[ "${include_operator_tools}" -eq 1 ]]; then
      cp target/release/bregctl dist/image-bin/bregctl
    fi
    if [[ "${include_breg_services}" -eq 1 ]]; then
      cargo build --release --locked \
        -p registry-breg-mcp --bin breg-mcp
      cargo build --release --locked \
        -p registry-breg-review --bin breg-review
      cp target/release/breg-mcp "dist/bin/breg-mcp-${RELEASE_TAG}-linux-amd64"
      cp target/release/breg-review "dist/bin/breg-review-${RELEASE_TAG}-linux-amd64"
      cp target/release/breg-mcp dist/image-bin/breg-mcp
      cp target/release/breg-review dist/image-bin/breg-review
    fi
  fi

  if [[ ("${group}" == all || "${group}" == casework) && "${include_casework}" -eq 1 ]]; then
    cargo build --release --locked \
      -p registry-casework --bin casework
    cargo build --release --locked \
      -p registry-caseworkctl --bin caseworkctl
    cp target/release/casework "dist/bin/casework-${RELEASE_TAG}-linux-amd64"
    cp target/release/caseworkctl "dist/bin/caseworkctl-${RELEASE_TAG}-linux-amd64"
    cp target/release/casework dist/image-bin/casework
    if [[ "${include_operator_tools}" -eq 1 ]]; then
      cp target/release/caseworkctl dist/image-bin/caseworkctl
    fi
  fi

  if [[ ("${group}" == all || "${group}" == scheduling) && "${include_scheduling}" -eq 1 ]]; then
    cargo build --release --locked \
      -p registry-scheduling --bin scheduling
    cp target/release/scheduling dist/image-bin/scheduling
    if [[ "${group}" == scheduling || "${include_scheduling_binary}" -eq 1 ]]; then
      cp target/release/scheduling \
        "dist/bin/scheduling-${RELEASE_TAG}-linux-amd64"
    fi
    if [[ "${include_operator_tools}" -eq 1 ]]; then
      cargo build --release --locked \
        -p registry-schedulingctl --bin schedulingctl
      cp target/release/schedulingctl \
        "dist/bin/schedulingctl-${RELEASE_TAG}-linux-amd64"
      cp target/release/schedulingctl dist/image-bin/schedulingctl
    fi
  fi

  if [[ ("${group}" == all || "${group}" == messaging) && "${include_messaging}" -eq 1 ]]; then
    cargo build --release --locked \
      -p registry-messaging --bin messaging
    cargo build --release --locked \
      -p registry-messagingctl --bin messagingctl
    cp target/release/messaging "dist/bin/messaging-${RELEASE_TAG}-linux-amd64"
    cp target/release/messagingctl "dist/bin/messagingctl-${RELEASE_TAG}-linux-amd64"
    cp target/release/messaging dist/image-bin/messaging
    if [[ "${include_operator_tools}" -eq 1 ]]; then
      cp target/release/messagingctl dist/image-bin/messagingctl
    fi
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
    check_source_commit_absent "${staged_binaries[@]}"
  fi
}

# The outer invocation prepares the pinned container. The inner invocation is
# re-executed inside it as the host uid/gid so mounted release outputs are never
# owned by root on either GitHub-hosted runners or an operator workstation.
if [[ "${RELEASE_BUILDER_READY:-0}" -eq 1 ]]; then
  identity_matches=0
  if [[ -n "${nightly_tag}" &&
        "${REGISTRY_NIGHTLY_TAG:-}" == "${tag}" &&
        -z "${REGISTRY_RELEASE_TAG:-}" ]]; then
    identity_matches=1
  elif [[ -z "${nightly_tag}" &&
          "${REGISTRY_RELEASE_TAG:-}" == "${tag}" &&
          -z "${REGISTRY_NIGHTLY_TAG:-}" ]]; then
    identity_matches=1
  fi
  if [[ "${repo_root}" != "/workspace" ||
        "${CARGO_HOME:-}" != "/workspace/.cargo-home" ||
        "${CARGO_TARGET_DIR:-}" != "/workspace/target" ||
        "${GIT_CEILING_DIRECTORIES:-}" != "/workspace" ||
        "${RELEASE_TAG:-}" != "${tag}" ||
        "${identity_matches}" -ne 1 ]]; then
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
# Build scripts must not read this checkout's git state: see
# check_source_commit_absent above. GIT_CEILING_DIRECTORIES below stops
# repository discovery at the mount point, which reaches every build script
# because Cargo runs them below the repository root, and RELEASE_SOURCE_COMMIT
# is the commit the staged payload is then checked against. A release build is
# told its exact source commit; a local build reads the checkout it is in.
release_source_commit="${RELEASE_SOURCE_SHA:-}"
if [[ ! "${release_source_commit}" =~ ^[0-9a-f]{40}$ ]]; then
  release_source_commit="$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || true)"
fi
if [[ -n "${nightly_tag}" && "${release_source_commit}" != "${nightly_source_sha}" ]]; then
  printf 'nightly tag source SHA does not match the checked-out source commit\n' >&2
  exit 2
fi
casework_args=()
if [[ "${include_casework_override}" -eq 1 ]]; then
  casework_args+=(--include-casework)
fi
nightly_args=()
identity_env_args=()
if [[ -n "${nightly_tag}" ]]; then
  nightly_args+=(--nightly-tag "${nightly_tag}")
  identity_env_args+=(--env REGISTRY_NIGHTLY_TAG="${nightly_tag}")
else
  identity_env_args+=(--env REGISTRY_RELEASE_TAG="${tag}")
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
  --env GIT_CEILING_DIRECTORIES=/workspace \
  --env RELEASE_SOURCE_COMMIT="${release_source_commit}" \
  --env CARGO_INCREMENTAL=0 \
  --env CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}" \
  --env HOME=/workspace \
  --env RELEASE_INCLUDE_DISCOVERY="${include_discovery}" \
  --env RELEASE_INCLUDE_DISCOVERYCTL="${include_discoveryctl}" \
  --env RELEASE_INCLUDE_BREG="${include_breg}" \
  --env RELEASE_INCLUDE_BREG_SERVICES="${include_breg_services}" \
  --env RELEASE_INCLUDE_CASEWORK="${include_casework}" \
  --env RELEASE_INCLUDE_SCHEDULING="${include_scheduling}" \
  --env RELEASE_INCLUDE_SCHEDULING_BINARY="${include_scheduling_binary}" \
  --env RELEASE_INCLUDE_OPERATOR_TOOLS="${include_operator_tools}" \
  --env RELEASE_INCLUDE_MESSAGING="${include_messaging}" \
  --env RELEASE_INCLUDE_RENDER="${include_render}" \
  --env RELEASE_INCLUDE_EVIDENCE_OID4VCI_IMAGE="${include_evidence_oid4vci_image}" \
  --env RELEASE_TAG="${tag}" \
  "${identity_env_args[@]}" \
  --env RELEASE_RUSTFLAGS="${release_rustflags}" \
  --env RELEASE_BUILDER_READY=1 \
  "${release_builder_image}" \
  /workspace/release/scripts/build-release-binaries.sh \
    "${casework_args[@]}" \
    "${nightly_args[@]}" \
    --group "${group}" "${version}"

if [[ "${group}" == all ]]; then
  printf '%s\n' "${default_builder_image}" >"${repo_root}/dist/image-bin/RELEASE_BUILDER_IMAGE"
else
  if [[ ! "${RELEASE_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'RELEASE_SOURCE_SHA must be the exact source commit for a binary shard\n' >&2
    exit 2
  fi
  printf '%s\n' "${default_builder_image}" >"${repo_root}/dist/RELEASE_BUILDER_IMAGE"
  if [[ -n "${nightly_tag}" ]]; then
    printf '%s\nsource_sha=%s\nversion=%s\nnightly_tag=%s\ngroup=%s\n' \
      registry-stack.release-binary-shard.v2 \
      "${RELEASE_SOURCE_SHA}" "${version}" "${nightly_tag}" "${group}" \
      >"${repo_root}/dist/RELEASE_BINARY_SHARD"
  else
    printf '%s\nsource_sha=%s\nversion=%s\ngroup=%s\n' \
      registry-stack.release-binary-shard.v1 \
      "${RELEASE_SOURCE_SHA}" "${version}" "${group}" \
      >"${repo_root}/dist/RELEASE_BINARY_SHARD"
  fi
fi
# The staged asset lists follow the same gate as the build above, so a version
# that predates an asset neither checksums nor chmods a file it never built.
bin_assets=()
image_bin_binaries=()
if [[ ("${group}" == all || "${group}" == core) && "${include_discovery}" -eq 1 ]]; then
  bin_assets+=("discovery-${tag}-linux-amd64")
  image_bin_binaries+=(discovery)
fi
if [[ ("${group}" == all || "${group}" == core) && "${include_discoveryctl}" -eq 1 ]]; then
  bin_assets+=("discoveryctl-${tag}-linux-amd64")
fi
if [[ ("${group}" == all || "${group}" == breg) && "${include_breg}" -eq 1 ]]; then
  bin_assets+=(
    "breg-${tag}-linux-amd64"
    "bregctl-${tag}-linux-amd64"
  )
  image_bin_binaries+=(breg)
  if [[ "${include_operator_tools}" -eq 1 ]]; then
    image_bin_binaries+=(bregctl)
  fi
  if [[ "${include_breg_services}" -eq 1 ]]; then
    bin_assets+=(
      "breg-mcp-${tag}-linux-amd64"
      "breg-review-${tag}-linux-amd64"
    )
    image_bin_binaries+=(breg-mcp breg-review)
  fi
fi
if [[ ("${group}" == all || "${group}" == casework) && "${include_casework}" -eq 1 ]]; then
  bin_assets+=(
    "casework-${tag}-linux-amd64"
    "caseworkctl-${tag}-linux-amd64"
  )
  image_bin_binaries+=(casework)
  if [[ "${include_operator_tools}" -eq 1 ]]; then
    image_bin_binaries+=(caseworkctl)
  fi
fi
if [[ ("${group}" == scheduling || ("${group}" == all && "${include_scheduling_binary}" -eq 1)) && "${include_scheduling}" -eq 1 ]]; then
  bin_assets+=("scheduling-${tag}-linux-amd64")
fi
if [[ ("${group}" == all || "${group}" == scheduling) && "${include_operator_tools}" -eq 1 ]]; then
  bin_assets+=("schedulingctl-${tag}-linux-amd64")
fi
if [[ "${group}" == all && "${include_scheduling}" -eq 1 ]]; then
  image_bin_binaries+=(scheduling)
  if [[ "${include_operator_tools}" -eq 1 ]]; then
    image_bin_binaries+=(schedulingctl)
  fi
fi
if [[ ("${group}" == all || "${group}" == messaging) && "${include_messaging}" -eq 1 ]]; then
  bin_assets+=(
    "messaging-${tag}-linux-amd64"
    "messagingctl-${tag}-linux-amd64"
  )
  image_bin_binaries+=(messaging)
  if [[ "${include_operator_tools}" -eq 1 ]]; then
    image_bin_binaries+=(messagingctl)
  fi
fi
if [[ "${group}" == all || "${group}" == core ]]; then
  bin_assets+=(
    "evidence-${tag}-linux-amd64"
    "evidencectl-${tag}-linux-amd64"
    "evidence-oid4vci-${tag}-linux-amd64"
    "registry-manifest-${tag}-linux-amd64"
  )
  image_bin_binaries+=(evidence)
  if [[ "${include_evidence_oid4vci_image}" -eq 1 ]]; then
    image_bin_binaries+=(evidence-oid4vci)
  fi
  if [[ "${include_render}" -eq 1 ]]; then
    bin_assets+=("registry-render-${tag}-linux-amd64")
    image_bin_binaries+=(registry-render)
  fi
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
