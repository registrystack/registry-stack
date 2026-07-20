#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
checker="${script_dir}/check-release-image-oci-labels.py"
dockerfile="${repo_root}/release/docker/Dockerfile.registry-relay"

source_label="https://github.com/registrystack/registry-stack"
revision_label="0123456789abcdef0123456789abcdef01234567"
wrong_revision_label="89abcdef0123456789abcdef0123456789abcdef"
version_label="v0.0.0-oci-label-smoke"

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-stack-oci-labels.XXXXXX")"
trap 'rm -rf -- "${tmp_root}"' EXIT

context_dir="${tmp_root}/context"
mkdir -p "${context_dir}/dist/image-bin"
true_binary=/bin/true
if [[ ! -x "${true_binary}" ]]; then
  true_binary="$(type -P true)"
fi
cp "${true_binary}" "${context_dir}/dist/image-bin/registry-relay"
cp "${true_binary}" "${context_dir}/dist/image-bin/registry-relay-rhai-worker"
cp "${repo_root}/LICENSE" "${context_dir}/LICENSE"

build_layout() {
  local layout="$1"
  local revision="$2"
  local version="${3-}"
  local -a label_args=(
    --label "org.opencontainers.image.source=${source_label}"
    --label "org.opencontainers.image.revision=${revision}"
  )
  if [[ -n "${version}" ]]; then
    label_args+=(--label "org.opencontainers.image.version=${version}")
  fi

  docker buildx build \
    --platform linux/amd64 \
    --file "${dockerfile}" \
    --provenance=false \
    "${label_args[@]}" \
    --output "type=oci,dest=${layout},tar=false" \
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

correct_layout="${tmp_root}/correct"
missing_version_layout="${tmp_root}/missing-version"
wrong_revision_layout="${tmp_root}/wrong-revision"

build_layout "${correct_layout}" "${revision_label}" "${version_label}"
python3 "${checker}" "oci-layout://${correct_layout}" \
  --source "${source_label}" \
  --revision "${revision_label}" \
  --version "${version_label}"

expect_failure "lower-case image config template" \
  python3 "${checker}" "oci-layout://${correct_layout}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}" \
    --format-template '{{json .Image.config}}'

build_layout "${missing_version_layout}" "${revision_label}"
expect_failure "image missing the version label" \
  python3 "${checker}" "oci-layout://${missing_version_layout}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}"

build_layout "${wrong_revision_layout}" "${wrong_revision_label}" "${version_label}"
expect_failure "image with the wrong revision label" \
  python3 "${checker}" "oci-layout://${wrong_revision_layout}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}"

printf 'release image OCI label smoke checks passed\n'
