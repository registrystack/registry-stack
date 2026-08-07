#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'usage: %s <release-version>\n' "$0" >&2
  exit 2
fi

version="$1"
tag="v${version}"
default_builder_image="rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3"
if [[ -n "${RELEASE_BUILDER_IMAGE:-}" && "${RELEASE_BUILDER_IMAGE}" != "${default_builder_image}" ]]; then
  printf 'RELEASE_BUILDER_IMAGE must remain pinned to %s\n' "${default_builder_image}" >&2
  exit 2
fi
release_builder_image="${default_builder_image}"
release_cargo_home="${RELEASE_CARGO_HOME:-${repo_root}/.cargo-home}"
release_target_dir="${RELEASE_TARGET_DIR:-${repo_root}/target}"
relay_feature_profile="${repo_root}/crates/registry-relay/canonical-release-features.txt"
relay_release_features="$(<"${relay_feature_profile}")"
sh "${repo_root}/crates/registry-relay/scripts/validate-feature-profile.sh" \
  "${relay_release_features}"

if [[ "${release_cargo_home}" != /* ]]; then
  release_cargo_home="${repo_root}/${release_cargo_home}"
fi
if [[ "${release_target_dir}" != /* ]]; then
  release_target_dir="${repo_root}/${release_target_dir}"
fi

mkdir -p "${release_cargo_home}" "${release_target_dir}"
rm -rf -- "${repo_root}/dist/bin" "${repo_root}/dist/image-bin"
mkdir -p "${repo_root}/dist/bin" "${repo_root}/dist/image-bin"

# Rust retains dependency source paths in panic and diagnostic strings even
# when release binaries are stripped. Mount host state at canonical container
# paths and remap those paths so independent hosts produce identical bytes.
release_rustflags="--remap-path-prefix=/workspace/.cargo-home=/cargo-home --remap-path-prefix=/workspace=/source"

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
  --env RELEASE_TAG="${tag}" \
  --env REGISTRY_RELEASE_TAG="${tag}" \
  --env RELEASE_RELAY_FEATURES="${relay_release_features}" \
  --env RELEASE_RUSTFLAGS="${release_rustflags}" \
  "${release_builder_image}" \
  bash -c 'set -euo pipefail
    export RUSTFLAGS="${RELEASE_RUSTFLAGS}"

    # Registryctl enables experimental Relay libraries for project authoring.
    # Build it separately so Cargo cannot unify those features into the
    # production Relay executable.
    cargo build --release --locked \
      -p registryctl \
      -p registry-manifest-cli
    cp target/release/registryctl "dist/bin/registryctl-${RELEASE_TAG}-linux-amd64"
    cp target/release/registry-manifest "dist/bin/registry-manifest-${RELEASE_TAG}-linux-amd64"

    REGISTRY_RELAY_FEATURES="${RELEASE_RELAY_FEATURES}" \
      cargo build --release --locked \
      -p registry-relay \
      --no-default-features \
      --features "${RELEASE_RELAY_FEATURES}"
    python3 release/scripts/check-release-relay-features.py target/release/registry-relay
    cp target/release/registry-relay "dist/bin/registry-relay-${RELEASE_TAG}-linux-amd64"
    cp target/release/registry-relay-rhai-worker "dist/bin/registry-relay-rhai-worker-${RELEASE_TAG}-linux-amd64"
    cp target/release/registry-relay dist/image-bin/registry-relay
    cp target/release/registry-relay-rhai-worker dist/image-bin/registry-relay-rhai-worker

    cargo build --release --locked \
      -p registry-evidence \
      -p registry-evidencectl \
      -p registry-mint
    cp target/release/evidence "dist/bin/evidence-${RELEASE_TAG}-linux-amd64"
    cp target/release/evidencectl "dist/bin/evidencectl-${RELEASE_TAG}-linux-amd64"
    cp target/release/mint "dist/bin/mint-${RELEASE_TAG}-linux-amd64"
  '

printf '%s\n' "${release_builder_image}" > "${repo_root}/dist/image-bin/RELEASE_BUILDER_IMAGE"
chmod 0755 \
  "${repo_root}/dist/bin/registryctl-${tag}-linux-amd64" \
  "${repo_root}/dist/bin/registry-manifest-${tag}-linux-amd64" \
  "${repo_root}/dist/bin/registry-relay-${tag}-linux-amd64" \
  "${repo_root}/dist/bin/registry-relay-rhai-worker-${tag}-linux-amd64" \
  "${repo_root}/dist/bin/evidence-${tag}-linux-amd64" \
  "${repo_root}/dist/bin/evidencectl-${tag}-linux-amd64" \
  "${repo_root}/dist/bin/mint-${tag}-linux-amd64" \
  "${repo_root}/dist/image-bin/registry-relay" \
  "${repo_root}/dist/image-bin/registry-relay-rhai-worker"

(
  cd -- "${repo_root}/dist/bin"
  sha256sum -- \
    "evidence-${tag}-linux-amd64" \
    "evidencectl-${tag}-linux-amd64" \
    "mint-${tag}-linux-amd64" \
    "registry-manifest-${tag}-linux-amd64" \
    "registry-relay-${tag}-linux-amd64" \
    "registry-relay-rhai-worker-${tag}-linux-amd64" \
    "registryctl-${tag}-linux-amd64" \
    > SHA256SUMS
)
(
  cd -- "${repo_root}/dist/image-bin"
  sha256sum -- \
    RELEASE_BUILDER_IMAGE \
    registry-relay \
    registry-relay-rhai-worker \
    > SHA256SUMS
)

printf 'built release binaries for %s with canonical container paths\n' "${tag}"
