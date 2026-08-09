#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRODUCT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

forbidden='social[-_ ]?assistance|business[-_ ]?registry|civil[-_ ]?event|crvs|birth|death|household|benefit|company'

if rg -i -l "$forbidden" \
  "$PRODUCT_DIR/../../crates/registry-relay-v2/src" \
  "$PRODUCT_DIR/../../crates/registry-relayctl/src" >/dev/null; then
  echo "relay-v2 source-neutrality: acceptance-domain term in Relay V2 production source" >&2
  exit 1
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
