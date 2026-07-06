#!/usr/bin/env bash
set -euo pipefail

# The release source proof lives in release/scripts/ now (registry-stack#224);
# this wrapper stays only so existing lab/ callers keep working during the
# transition to the standalone lab repo.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${script_dir}/../../release/scripts/check-release-source-model.sh" "$@"
