#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

if [[ $# -ne 6 ]]; then
  echo "usage: $0 <image-name> <image-ref> <source-label> <revision-label> <version-label> <metadata-file>" >&2
  exit 2
fi

name="$1"
image="$2"
source_label="$3"
revision_label="$4"
version_label="$5"
metadata_file="$6"
source_date_epoch=0
default_buildkit_image="moby/buildkit:v0.31.2@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
default_buildkit_repo_digest="moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
release_buildkit_image="${default_buildkit_image}"
release_buildx_builder="${RELEASE_BUILDX_BUILDER:-}"
release_image_context="${RELEASE_IMAGE_CONTEXT:-${repo_root}}"
created_builder=false

case "${name}" in
  registry-notary|registry-relay)
    dockerfile="${repo_root}/release/docker/Dockerfile.${name}"
    ;;
  *)
    echo "unsupported release image: ${name}" >&2
    exit 2
    ;;
esac

cache_args=()
if [[ -n "${RELEASE_IMAGE_CACHE_FROM:-}" ]]; then
  cache_args+=(--cache-from "${RELEASE_IMAGE_CACHE_FROM}")
fi

no_cache_args=()
if [[ "${RELEASE_IMAGE_NO_CACHE:-}" == "true" ]]; then
  no_cache_args+=(--no-cache)
elif [[ -n "${RELEASE_IMAGE_NO_CACHE:-}" ]]; then
  echo "RELEASE_IMAGE_NO_CACHE must be true when set" >&2
  exit 2
fi

provenance_args=()
if [[ -n "${RELEASE_IMAGE_OCI_LAYOUT:-}" ]]; then
  if [[ "${RELEASE_IMAGE_OCI_LAYOUT}" != /* || "${RELEASE_IMAGE_OCI_LAYOUT}" == *','* ]]; then
    echo "RELEASE_IMAGE_OCI_LAYOUT must be an absolute path without commas" >&2
    exit 2
  fi
  if [[ -n "${RELEASE_IMAGE_REGISTRY_INSECURE:-}" ]]; then
    echo "RELEASE_IMAGE_REGISTRY_INSECURE is incompatible with RELEASE_IMAGE_OCI_LAYOUT" >&2
    exit 2
  fi
  output="type=oci,dest=${RELEASE_IMAGE_OCI_LAYOUT},tar=false,rewrite-timestamp=true,compatibility-version=20"
  # Timestamped BuildKit attestations make retained comparison layouts vary.
  # Registry-pushed release images keep BuildKit provenance; only the local
  # exact-reproduction layout suppresses it.
  provenance_args+=(--provenance=false)
else
  output="type=registry,push=true,rewrite-timestamp=true,compatibility-version=20"
  if [[ "${RELEASE_IMAGE_REGISTRY_INSECURE:-}" == "true" ]]; then
    output+=",registry.insecure=true"
  elif [[ -n "${RELEASE_IMAGE_REGISTRY_INSECURE:-}" ]]; then
    echo "RELEASE_IMAGE_REGISTRY_INSECURE must be true when set" >&2
    exit 2
  fi
fi

if [[ ! -d "${release_image_context}" ]]; then
  echo "RELEASE_IMAGE_CONTEXT must name an existing directory" >&2
  exit 2
fi

buildx_version="$(docker buildx version)"
if ! grep -Eq ' v0\.33\.0([[:space:]]|$)' <<<"${buildx_version}"; then
  echo "release build requires docker buildx v0.33.0, got: ${buildx_version}" >&2
  exit 1
fi

if [[ -z "${release_buildx_builder}" ]]; then
  release_buildx_builder="registry-stack-release-$$-${RANDOM}"
  builder_args=(
    --name "${release_buildx_builder}"
    --driver docker-container
    --driver-opt "image=${release_buildkit_image}"
  )
  if [[ -n "${RELEASE_BUILDKIT_NETWORK:-}" ]]; then
    builder_args+=(--driver-opt "network=${RELEASE_BUILDKIT_NETWORK}")
  fi
  docker buildx create \
    "${builder_args[@]}" \
    --bootstrap >/dev/null
  created_builder=true
fi

cleanup_builder() {
  if [[ "${created_builder}" == true ]]; then
    docker buildx rm --force "${release_buildx_builder}" >/dev/null 2>&1 || true
  fi
}
trap cleanup_builder EXIT

buildkit_details="$(docker buildx inspect "${release_buildx_builder}" --bootstrap)"
if ! grep -Eq '^[[:space:]]*Driver:[[:space:]]+docker-container[[:space:]]*$' <<<"${buildkit_details}"; then
  echo "release builder ${release_buildx_builder} must use the docker-container driver" >&2
  exit 1
fi
if ! grep -Eq 'BuildKit( version:)?[[:space:]]+v0\.31\.2([[:space:]]|$)' <<<"${buildkit_details}"; then
  echo "release builder ${release_buildx_builder} is not BuildKit v0.31.2" >&2
  exit 1
fi

expected_builder_container="buildx_buildkit_${release_buildx_builder}0"
builder_container_prefix="buildx_buildkit_${release_buildx_builder}"
builder_containers=()
while IFS= read -r container; do
  if [[ "${container}" == "${builder_container_prefix}"* ]]; then
    builder_containers+=("${container}")
  fi
done < <(docker ps --all --format '{{.Names}}')
if [[ "${#builder_containers[@]}" -ne 1 || "${builder_containers[0]}" != "${expected_builder_container}" ]]; then
  echo "release builder ${release_buildx_builder} must have exactly one standard BuildKit container named ${expected_builder_container}" >&2
  exit 1
fi

if ! builder_container_image="$(docker inspect --format '{{.Config.Image}}' "${expected_builder_container}")"; then
  echo "could not inspect release builder container ${expected_builder_container}" >&2
  exit 1
fi
if [[ "${builder_container_image}" != "${release_buildkit_image}" ]]; then
  echo "release builder ${release_buildx_builder} must use ${release_buildkit_image}" >&2
  exit 1
fi
if ! buildkit_repo_digests="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${release_buildkit_image}")"; then
  echo "could not inspect the pinned BuildKit image ${release_buildkit_image}" >&2
  exit 1
fi
if ! grep -Fxq "${default_buildkit_repo_digest}" <<<"${buildkit_repo_digests}"; then
  echo "release builder ${release_buildx_builder} must resolve ${default_buildkit_repo_digest}" >&2
  exit 1
fi

if [[ -n "${RELEASE_IMAGE_CACHE_TO:-}" ]]; then
  cache_args+=(--cache-to "${RELEASE_IMAGE_CACHE_TO}")
fi

mkdir -p "$(dirname -- "${metadata_file}")"
cd -- "${release_image_context}"
docker buildx build \
  --builder "${release_buildx_builder}" \
  --platform linux/amd64 \
  --file "${dockerfile}" \
  --tag "${image}" \
  "${provenance_args[@]}" \
  --label "org.opencontainers.image.source=${source_label}" \
  --label "org.opencontainers.image.revision=${revision_label}" \
  --label "org.opencontainers.image.version=${version_label}" \
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
  --metadata-file "${metadata_file}" \
  "${no_cache_args[@]}" \
  "${cache_args[@]}" \
  --output "${output}" \
  .
