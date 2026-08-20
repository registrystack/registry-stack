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
# The Discovery binary joins the release payload at 0.24.0. A candidate rebuilt
# for an earlier version must stage exactly the assets its recorded inventory
# names, so seal-candidate keeps accepting it.
IFS=. read -r version_major version_minor _version_patch <<<"${version}"
include_discovery=0
if ((version_major > 0 || version_minor >= 24)); then
  include_discovery=1
fi
default_builder_image="rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3"
if [[ -n "${RELEASE_BUILDER_IMAGE:-}" && "${RELEASE_BUILDER_IMAGE}" != "${default_builder_image}" ]]; then
  printf 'RELEASE_BUILDER_IMAGE must remain pinned to %s\n' "${default_builder_image}" >&2
  exit 2
fi
release_builder_image="${default_builder_image}"
release_cargo_home="${RELEASE_CARGO_HOME:-${repo_root}/.cargo-home}"
release_target_dir="${RELEASE_TARGET_DIR:-${repo_root}/target}"

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
  --env RELEASE_INCLUDE_DISCOVERY="${include_discovery}" \
  --env RELEASE_TAG="${tag}" \
  --env REGISTRY_RELEASE_TAG="${tag}" \
  --env RELEASE_RUSTFLAGS="${release_rustflags}" \
  "${release_builder_image}" \
  bash -c 'set -euo pipefail
    export RUSTFLAGS="${RELEASE_RUSTFLAGS}"

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

    if [[ "${RELEASE_INCLUDE_DISCOVERY}" -eq 1 ]]; then
      cargo build --release --locked \
        -p registry-discovery \
        --bin discovery
      cp target/release/discovery "dist/bin/discovery-${RELEASE_TAG}-linux-amd64"
      cp target/release/discovery dist/image-bin/discovery
    fi
  '

printf '%s\n' "${release_builder_image}" > "${repo_root}/dist/image-bin/RELEASE_BUILDER_IMAGE"
# The staged asset lists follow the same gate as the build above, so a version
# that predates an asset neither checksums nor chmods a file it never built.
bin_assets=()
image_bin_binaries=()
if [[ "${include_discovery}" -eq 1 ]]; then
  bin_assets+=("discovery-${tag}-linux-amd64")
  image_bin_binaries+=(discovery)
fi
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

for asset in "${bin_assets[@]}"; do
  chmod 0755 "${repo_root}/dist/bin/${asset}"
done
for asset in "${image_bin_binaries[@]}"; do
  chmod 0755 "${repo_root}/dist/image-bin/${asset}"
done

(
  cd -- "${repo_root}/dist/bin"
  sha256sum -- "${bin_assets[@]}" > SHA256SUMS
)
(
  cd -- "${repo_root}/dist/image-bin"
  sha256sum -- RELEASE_BUILDER_IMAGE "${image_bin_binaries[@]}" > SHA256SUMS
)

printf 'built release binaries for %s with canonical container paths\n' "${tag}"
