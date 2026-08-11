#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRODUCT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

forbidden='social[-_ ]?assistance|business[-_ ]?registry|civil[-_ ]?event|labour[-_ ]?statistics|crvs|birth|death|household|benefit|company'

production_sources=(
  "$PRODUCT_DIR/../../crates/registry-relay-v2/src"
  "$PRODUCT_DIR/../../crates/registry-relayctl/src"
  "$PRODUCT_DIR/../../crates/registry-relay-http-contract/src"
  "$PRODUCT_DIR/../../crates/registry-relay-http-contract/Cargo.toml"
  "$PRODUCT_DIR/../../crates/registry-relay-client/src"
  "$PRODUCT_DIR/../../crates/registry-relay-client/Cargo.toml"
  "$PRODUCT_DIR/../../crates/registry-relay-client-node/src"
  "$PRODUCT_DIR/../../crates/registry-relay-client-node/Cargo.toml"
  "$PRODUCT_DIR/../../crates/registry-relay-client-node/client.js"
  "$PRODUCT_DIR/../../crates/registry-relay-client-node/client.d.ts"
  "$PRODUCT_DIR/../../crates/registry-relay-client-node/index.js"
  "$PRODUCT_DIR/../../crates/registry-relay-client-node/index.d.ts"
  "$PRODUCT_DIR/../../crates/registry-relay-client-node/package.json"
  "$PRODUCT_DIR/../../crates/registry-relay-client-py/src"
  "$PRODUCT_DIR/../../crates/registry-relay-client-py/Cargo.toml"
  "$PRODUCT_DIR/../../crates/registry-relay-client-py/python"
  "$PRODUCT_DIR/../../crates/registry-relay-client-py/pyproject.toml"
  "$PRODUCT_DIR/../../crates/registry-platform-sqlite/src"
)

for path in "${production_sources[@]}"; do
  if [[ ! -e "$path" ]]; then
    echo "relay-v2 source-neutrality: required production source is missing: $path" >&2
    exit 1
  fi
done

set +e
rg -i -l "$forbidden" "${production_sources[@]}" >/dev/null
rg_status=$?
set -e
if [[ "$rg_status" -eq 0 ]]; then
  echo "relay-v2 source-neutrality: acceptance-domain term in Relay V2 production source" >&2
  exit 1
fi
if [[ "$rg_status" -ne 1 ]]; then
  echo "relay-v2 source-neutrality: production source scan failed" >&2
  exit "$rg_status"
fi

while IFS= read -r path; do
  relative="${path#"$PRODUCT_DIR/"}"
  case "$relative" in
    acceptance/*|CONCEPT.md|DEFINITION-OF-DONE.md|CONFIGURATION-EXAMPLES.md|IMPLEMENTATION.md|README.md|STANDARDS-ALIGNMENT.md|scripts/check-source-neutrality.sh|scripts/check-generated.sh|scripts/test_adopter_workflow.py|scripts/validate_product.py|scripts/test_validate_product.py|contracts/generated-baselines.yaml|contracts/package-layout.yaml|contracts/acceptance-scenario-matrix.yaml|contracts/security-invariant-matrix.yaml)
      continue
      ;;
  esac
  echo "relay-v2 source-neutrality: domain term outside acceptance/docs: $relative" >&2
  exit 1
done < <(rg -i -l "$forbidden" "$PRODUCT_DIR" || true)

if rg -i -n 'legacy/generated-crud|api/legacy|test/openAPI' "$PRODUCT_DIR/acceptance" "$PRODUCT_DIR/contracts" >/dev/null; then
  echo "relay-v2 source-neutrality: legacy Digital Registries OpenAPI input referenced" >&2
  exit 1
fi

echo "relay-v2 source-neutrality passed"
