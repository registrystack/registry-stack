#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CITIZEN_OID4VCI_ENABLED="${CITIZEN_OID4VCI_ENABLED:-1}"
export CITIZEN_OID4VCI_PROBE="${CITIZEN_OID4VCI_PROBE:-1}"

exec "${script_dir}/smoke-citizen-self-attestation.sh"
