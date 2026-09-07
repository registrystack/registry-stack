#!/usr/bin/env bash
# Copies the PublicSchema reference model files this crate embeds from a local
# checkout of https://github.com/PublicSchema/publicschema.org and records the
# commit they came from in PIN.yaml. Run it from anywhere:
#
#   crates/registry-linkml/publicschema/sync-snapshot.sh /path/to/publicschema.org
#
# The file list is closed on purpose: the picker reads the domain concepts, the
# shared slots, and the code lists, and leaves out the bibliography, the metric
# catalog, the external system schemas, and the value crosswalks.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s CHECKOUT\n' "$0" >&2
  exit 2
fi

checkout="$1"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
files=(
  publicschema.yaml
  assessment.yaml
  biometric.yaml
  categories.yaml
  civil_status.yaml
  common.yaml
  consent.yaml
  core.yaml
  credentials.yaml
  document.yaml
  identity.yaml
  misc.yaml
  payment.yaml
  program.yaml
  vocabularies.yaml
)

if [[ ! -f "${checkout}/schema/publicschema.yaml" ]]; then
  printf 'not a publicschema.org checkout: %s\n' "${checkout}" >&2
  exit 1
fi

commit="$(git -C "${checkout}" rev-parse HEAD)"
commit_date="$(git -C "${checkout}" show -s --format=%cs HEAD)"
version="$(sed -n 's/^version: *//p' "${checkout}/schema/publicschema.yaml" | head -n 1)"
if [[ -z "${version}" ]]; then
  printf 'schema/publicschema.yaml declares no version\n' >&2
  exit 1
fi

for file in "${files[@]}"; do
  cp "${checkout}/schema/${file}" "${here}/schema/${file}"
done
cp "${checkout}/LICENSE-VOCABULARY" "${here}/LICENSE-VOCABULARY"

{
  printf '# Written by sync-snapshot.sh; do not edit by hand.\n'
  printf 'repository: https://github.com/PublicSchema/publicschema.org\n'
  printf 'commit: %s\n' "${commit}"
  printf 'commitDate: %s\n' "${commit_date}"
  printf 'version: "%s"\n' "${version}"
  printf 'license: CC-BY-4.0\n'
  printf 'files:\n'
  for file in "${files[@]}"; do
    printf '  - schema/%s\n' "${file}"
  done
} >"${here}/PIN.yaml"

printf 'snapshot at %s (%s, version %s)\n' "${commit}" "${commit_date}" "${version}"
