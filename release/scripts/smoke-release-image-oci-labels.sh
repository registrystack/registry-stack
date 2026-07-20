#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
checker="${script_dir}/check-release-image-oci-labels.py"
image_builder="${script_dir}/build-release-image.sh"
images=(registry-notary registry-relay)
relay_dockerfile="${repo_root}/release/docker/Dockerfile.registry-relay"

source_label="https://github.com/registrystack/registry-stack"
revision_label="0123456789abcdef0123456789abcdef01234567"
wrong_revision_label="89abcdef0123456789abcdef0123456789abcdef"
version_label="v0.0.0-oci-label-smoke"
source_date_epoch=0

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-stack-oci-labels.XXXXXX")"
network="registry-stack-release-smoke-$$"
registry_name="${network}-registry"
smoke_builder="${network}-builder"
buildkit_image="moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f"
trap 'docker buildx rm --force "${smoke_builder}" >/dev/null 2>&1 || true; docker rm --force "${registry_name}" >/dev/null 2>&1 || true; docker network rm "${network}" >/dev/null 2>&1 || true; rm -rf -- "${tmp_root}"' EXIT

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

docker network create "${network}" >/dev/null
docker run --detach --rm \
  --name "${registry_name}" \
  --network "${network}" \
  --network-alias registry \
  --publish 127.0.0.1::5000 \
  registry:3@sha256:1be55279f18a2fe1a74edf2664cac61c1bea305b7b4642dab412e7affdcb3e33 >/dev/null
registry_port="$(docker port "${registry_name}" 5000/tcp | awk -F: 'NR == 1 { print $NF }')"
registry_host="127.0.0.1:${registry_port}"
docker buildx create \
  --name "${smoke_builder}" \
  --driver docker-container \
  --driver-opt "image=${buildkit_image}" \
  --driver-opt "network=${network}" \
  --bootstrap >/dev/null

build_published_image() {
  local name="$1"
  local tag="$2"
  local revision="$3"
  local version="$4"
  local metadata="${tmp_root}/${name}-${tag}.metadata.json"
  local internal_ref="registry:5000/${name}:${tag}"

  RELEASE_IMAGE_CONTEXT="${context_dir}" \
    RELEASE_IMAGE_NO_CACHE=true \
    RELEASE_IMAGE_REGISTRY_INSECURE=true \
    RELEASE_BUILDX_BUILDER="${smoke_builder}" \
    "${image_builder}" \
      "${name}" \
      "${internal_ref}" \
      "${source_label}" \
      "${revision}" \
      "${version}" \
      "${metadata}" >&2
  printf '%s/%s:%s\n' "${registry_host}" "${name}" "${tag}"
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
    --platform linux/amd64 \
    --file "${dockerfile}" \
    --no-cache \
    --provenance=false \
    "${label_args[@]}" \
    --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
    --output "type=oci,dest=${layout},rewrite-timestamp=true,tar=false" \
    "${context_dir}"
}

compare_application_images() {
  local name="$1"
  local first_tag="$2"
  local second_tag="$3"
  python3 - "${registry_host}" "${name}" "${first_tag}" "${second_tag}" <<'PY'
import json
import sys
import urllib.request


def fetch(host: str, repository: str, reference: str) -> tuple[str, dict]:
    request = urllib.request.Request(
        f"http://{host}/v2/{repository}/manifests/{reference}",
        headers={
            "Accept": ", ".join(
                (
                    "application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
            )
        },
    )
    with urllib.request.urlopen(request) as response:
        return response.headers["Docker-Content-Digest"], json.load(response)


def application_image(host: str, repository: str, tag: str) -> tuple[str, list[str]]:
    digest, document = fetch(host, repository, tag)
    if "manifests" in document:
        descriptors = document["manifests"]
        platform = next(
            (
                descriptor
                for descriptor in descriptors
                if descriptor.get("platform", {}).get("os") == "linux"
                and descriptor.get("platform", {}).get("architecture") == "amd64"
            ),
            None,
        )
        if platform is None:
            raise SystemExit(f"{repository}:{tag}: missing linux/amd64 application manifest")
        digest, document = fetch(host, repository, platform["digest"])
    return digest, [layer["digest"] for layer in document["layers"]]


host, repository, first_tag, second_tag = sys.argv[1:]
first_manifest, first_layers = application_image(host, repository, first_tag)
second_manifest, second_layers = application_image(host, repository, second_tag)
if first_manifest != second_manifest:
    raise SystemExit(
        "application image manifests differed after timestamp-rewritten no-cache builds: "
        f"{first_manifest} != {second_manifest}"
    )
if first_layers != second_layers:
    raise SystemExit(
        "application image layer sequences differed after timestamp-rewritten no-cache builds: "
        f"{first_layers} != {second_layers}"
    )
PY
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
  correct_ref="$(build_published_image "${image}" correct "${revision_label}" "${version_label}")"
  python3 "${checker}" "${correct_ref}" \
    --source "${source_label}" \
    --revision "${revision_label}" \
    --version "${version_label}"

  touch "${context_dir}/dist/image-bin/${image}"
  if [[ "${image}" == "registry-notary" ]]; then
    touch "${context_dir}/dist/image-bin/registry-notary-cel-worker"
  else
    touch "${context_dir}/dist/image-bin/registry-relay-rhai-worker" "${context_dir}/LICENSE"
  fi
  build_published_image "${image}" reproducible "${revision_label}" "${version_label}" >/dev/null
  compare_application_images "${image}" correct reproducible
done

correct_ref="${registry_host}/registry-relay:correct"
missing_version_layout="${tmp_root}/missing-version"
wrong_revision_layout="${tmp_root}/wrong-revision"

expect_failure "lower-case image config template" \
  python3 "${checker}" "${correct_ref}" \
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

printf 'release image OCI label smoke checks passed\n'
