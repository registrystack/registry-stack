#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 <release-version>" >&2
  exit 2
fi

version="$1"
tag="v${version}"
default_builder_image="rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3"
if [[ -n "${RELEASE_BUILDER_IMAGE:-}" && "${RELEASE_BUILDER_IMAGE}" != "${default_builder_image}" ]]; then
  echo "RELEASE_BUILDER_IMAGE must remain pinned to ${default_builder_image}" >&2
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

docker run --rm \
  --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  --volume "${repo_root}:/workspace" \
  --volume "${release_cargo_home}:/workspace/.cargo-home" \
  --volume "${release_target_dir}:/workspace/target" \
  --workdir /workspace \
  --env CARGO_HOME=/workspace/.cargo-home \
  --env CARGO_TARGET_DIR=/workspace/target \
  --env CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}" \
  --env HOME=/workspace \
  "${release_builder_image}" \
  bash -c 'set -euo pipefail
    cargo build --release --locked \
      -p registryctl \
      -p registry-manifest-cli \
      -p registry-relay \
      -p registry-notary \
      --features registry-notary/registry-notary-cel
    cp target/release/registry-notary dist/image-bin/registry-notary
    cargo build --release --locked \
      -p registry-notary \
      --features registry-notary/registry-notary-cel,registry-notary/pkcs11
    cp target/release/registry-notary dist/image-bin/registry-notary-pkcs11
    cargo build --release --locked \
      -p registry-notary-server \
      --bin registry-notary-cel-worker \
      --features registry-notary-server/registry-notary-cel
    cp target/release/registry-notary-cel-worker dist/image-bin/registry-notary-cel-worker'

cd -- "${repo_root}"
cp "${release_target_dir}/release/registryctl" "dist/bin/registryctl-${tag}-linux-amd64"
cp "${release_target_dir}/release/registry-manifest" "dist/bin/registry-manifest-${tag}-linux-amd64"
cp "${release_target_dir}/release/registry-relay" "dist/bin/registry-relay-${tag}-linux-amd64"
cp "${release_target_dir}/release/registry-relay-rhai-worker" "dist/bin/registry-relay-rhai-worker-${tag}-linux-amd64"
cp dist/image-bin/registry-notary "dist/bin/registry-notary-${tag}-linux-amd64"
cp dist/image-bin/registry-notary-cel-worker "dist/bin/registry-notary-cel-worker-${tag}-linux-amd64"
mv dist/image-bin/registry-notary-pkcs11 dist/image-bin/registry-notary
cp "${release_target_dir}/release/registry-relay" dist/image-bin/registry-relay
cp "${release_target_dir}/release/registry-relay-rhai-worker" dist/image-bin/registry-relay-rhai-worker
printf '%s\n' "${release_builder_image}" > dist/image-bin/RELEASE_BUILDER_IMAGE
chmod 0755 dist/bin/* \
  dist/image-bin/registry-notary \
  dist/image-bin/registry-notary-cel-worker \
  dist/image-bin/registry-relay \
  dist/image-bin/registry-relay-rhai-worker
(cd dist/bin && sha256sum -- * > SHA256SUMS)
(cd dist/image-bin && sha256sum -- * > SHA256SUMS)
