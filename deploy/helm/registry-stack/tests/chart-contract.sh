#!/usr/bin/env bash
set -euo pipefail

# Single CI entry point. Renders the chart with Helm, converts the manifests
# with mikefarah yq v4 and runs the structured assertions in
# test_chart_contract.py. Both tools are required.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helm_bin="${HELM_BIN:-helm}"
yq_bin="${YQ_BIN:-yq}"

for tool in "$helm_bin" "$yq_bin" python3; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf 'chart-contract: required tool not found: %s\n' "$tool" >&2
		exit 1
	fi
done

export HELM_BIN="$helm_bin" YQ_BIN="$yq_bin"
exec python3 -I "$here/test_chart_contract.py" "$@"
