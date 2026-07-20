#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
checker="${script_dir}/check-release-image-oci-labels.py"
image_builder="${script_dir}/build-release-image.sh"
layout_comparator="${script_dir}/compare-release-image-layouts.py"
images=(registry-notary registry-relay)
relay_dockerfile="${repo_root}/release/docker/Dockerfile.registry-relay"

source_label="https://github.com/registrystack/registry-stack"
revision_label="0123456789abcdef0123456789abcdef01234567"
wrong_revision_label="89abcdef0123456789abcdef0123456789abcdef"
version_label="v0.0.0-oci-label-smoke"
source_date_epoch=0

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-stack-oci-labels.XXXXXX")"
smoke_builder="registry-stack-release-smoke-$$-${RANDOM}"
buildkit_image="moby/buildkit:v0.31.2@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
trap 'docker buildx rm --force "${smoke_builder}" >/dev/null 2>&1 || true; rm -rf -- "${tmp_root}"' EXIT

context_dir="${tmp_root}/context"
mkdir -p "${context_dir}/dist/image-bin"
true_binary=/bin/true
if [[ ! -x "${true_binary}" ]]; then
  true_binary="$(type -P true)"
fi
cp "${true_binary}" "${context_dir}/dist/image-bin/registry-relay"
cp "${true_binary}" "${context_dir}/dist/image-bin/registry-relay-rhai-worker"
cp "${true_binary}" "${context_dir}/dist/image-bin/registry-notary"
cp "${true_binary}" "${context_dir}/dist/image-bin/registry-notary-cel-worker"
cp "${repo_root}/LICENSE" "${context_dir}/LICENSE"

docker buildx create \
  --name "${smoke_builder}" \
  --driver docker-container \
  --driver-opt "image=${buildkit_image}" \
  --bootstrap >/dev/null

build_layout() {
  local name="$1"
  local layout="$2"
  local revision="$3"
  local version="$4"
  local metadata="${layout}.metadata.json"

  RELEASE_IMAGE_CONTEXT="${context_dir}" \
    RELEASE_IMAGE_NO_CACHE=true \
    RELEASE_IMAGE_OCI_LAYOUT="${layout}" \
    RELEASE_BUILDX_BUILDER="${smoke_builder}" \
    "${image_builder}" \
      "${name}" \
      "example.invalid/${name}:oci-label-smoke" \
      "${source_label}" \
      "${revision}" \
      "${version}" \
      "${metadata}" >&2
}

build_negative_layout() {
  local dockerfile="$1"
  local layout="$2"
  local revision="$3"
  local version="${4-}"
  local -a label_args=(
    --label "org.opencontainers.image.source=${source_label}"
    --label "org.opencontainers.image.revision=${revision}"
  )
  if [[ -n "${version}" ]]; then
    label_args+=(--label "org.opencontainers.image.version=${version}")
  fi

  docker buildx build \
    --builder "${smoke_builder}" \
    --platform linux/amd64 \
    --file "${dockerfile}" \
    --provenance=false \
    --no-cache \
    --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
    "${label_args[@]}" \
    --output "type=oci,dest=${layout},tar=false,rewrite-timestamp=true,compatibility-version=20" \
    "${context_dir}"
}

expect_failure() {
  local description="$1"
  shift
  if "$@"; then
    printf 'error: %s unexpectedly passed\n' "${description}" >&2
    return 1
  fi
}

for image in "${images[@]}"; do
  first_layout="${tmp_root}/correct-${image}-first"
  second_layout="${tmp_root}/correct-${image}-second"
  touch -t 200001010101 \
    "${context_dir}/dist/image-bin/registry-relay" \
    "${context_dir}/dist/image-bin/registry-relay-rhai-worker" \
    "${context_dir}/dist/image-bin/registry-notary" \
    "${context_dir}/dist/image-bin/registry-notary-cel-worker" \
    "${context_dir}/LICENSE"
  build_layout "${image}" "${first_layout}" "${revision_label}" "${version_label}"
  python3 "${checker}" "oci-layout://${first_layout}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}"

  # Source mtimes and uncached RUN timestamps must not affect release-owned
  # layers. The exporter also normalizes inherited layers to the fixed epoch.
  touch -t 203001010101 \
    "${context_dir}/dist/image-bin/registry-relay" \
    "${context_dir}/dist/image-bin/registry-relay-rhai-worker" \
    "${context_dir}/dist/image-bin/registry-notary" \
    "${context_dir}/dist/image-bin/registry-notary-cel-worker" \
    "${context_dir}/LICENSE"
  build_layout "${image}" "${second_layout}" "${revision_label}" "${version_label}"
  python3 "${layout_comparator}" "${first_layout}" "${second_layout}"
done

correct_layout="${tmp_root}/correct-registry-relay-first"
missing_version_layout="${tmp_root}/missing-version"
wrong_revision_layout="${tmp_root}/wrong-revision"

expect_failure "lower-case image config template" \
  python3 "${checker}" "oci-layout://${correct_layout}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}" \
    --format-template '{{json .Image.config}}'

build_negative_layout "${relay_dockerfile}" "${missing_version_layout}" "${revision_label}"
expect_failure "image missing the version label" \
  python3 "${checker}" "oci-layout://${missing_version_layout}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}"

build_negative_layout "${relay_dockerfile}" "${wrong_revision_layout}" \
  "${wrong_revision_label}" "${version_label}"
expect_failure "image with the wrong revision label" \
  python3 "${checker}" "oci-layout://${wrong_revision_layout}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}"
python3 "${layout_comparator}" "${correct_layout}" "${wrong_revision_layout}" \
  --rootfs-only

printf 'release image OCI label smoke checks passed\n'
