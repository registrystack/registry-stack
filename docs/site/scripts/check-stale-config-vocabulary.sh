#!/usr/bin/env bash
set -euo pipefail

# CONFIG_VOCABULARY_ROOT points the check at another docs-site tree; its tests
# use it to run against fixture trees. The default is this site.
ROOT="${CONFIG_VOCABULARY_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PATTERN='registry\.validation\.report\.v1|schema:\s*registry\.validation|checks\[\]\.(product_report|findings)|YAML parsed successfully|auth\.oidc\.(jwks_uri|allowed_typ|leeway_seconds)|(extendE|e)ntities\[\]\.events\[\]|webhook\.destinationId'
PATHS=(
  "$ROOT/README.md"
  "$ROOT/src/content/docs"
  "$ROOT/src/data"
  "$ROOT/scripts"
)

status=0
if command -v rg >/dev/null 2>&1; then
  rg -n --no-ignore --glob '!**/check-stale-config-vocabulary.*' "$PATTERN" "${PATHS[@]}" || status=$?
else
  grep -RInE --exclude='check-stale-config-vocabulary.*' "$PATTERN" "${PATHS[@]}" || status=$?
fi

if [[ "$status" -eq 0 ]]; then
  echo "stale config vocabulary found" >&2
  exit 1
elif [[ "$status" -ne 1 ]]; then
  echo "stale config vocabulary search failed with exit code $status" >&2
  exit "$status"
fi

# Retired Base Registry Engine vocabulary.
#
# CROSS_PRODUCT_RETIRED is refused on every page: each spelling names a
# retired BReg contract and carries no other product's meaning. BREG_RETIRED
# is refused only on BReg pages (see is_breg_page), where "entity" is the
# retired noun for a Record type; other products keep their own "entity".
# The retired type names (ChangeRequest, BRegLifecycleAction,
# BRegLifecycleAuthority) are matched by the same patterns with the separator
# optional. Both are POSIX extended regular expressions, matched by awk.
# shellcheck disable=SC2016 # the backticks are literal Markdown code marks
CROSS_PRODUCT_RETIRED='permissions\.entities|entityIds?([^a-z]|$)|extendEntities|[Cc]hange[ -]?[Rr]equests?|/requests/[<{:]|[Cc]hange[ -][Cc]ontrol|[Ll]ifecycle[ -]?[Aa]ctions?|[Ll]ifecycle[ -]?[Aa]uthorit(y|ies)|executeLifecycleAction|BRegPreparedLifecycle|lifecycle-promotion|fieldEncryptionBackfill|requestHistoryAfterProposalVersion|planRefusal|[Rr]ecovery[^.]*[`"]terminal[`"]|[`"]terminal[`"][^.]*[Rr]ecovery'
BREG_RETIRED='(^|[^A-Za-z])[Ee]ntit(y|ies)([^a-z]|$)|SSL_CERT_FILE'
# Retired Registry Evidence and Registry Casework vocabulary, refused on every
# page like CROSS_PRODUCT_RETIRED. No tool prints these and no configuration
# key spells them: an Evidence project is an editable project or a deployment
# project, a definition answers a question, and Casework pins a ReviewRequest.
EVIDENCE_CASEWORK_RETIRED='[Aa]uthoring [Ww]orkspaces?|[Bb]ounded [Qq]uestions?|[Rr]eview [Rr]ounds?'
# Spellings removed from a line before it is matched:
# - Registry Record v1's entityTypeIdentifier field, and its prose name;
# - HTTP entity tags;
# - Evidence's entity-reference value forms and their problem codes;
# - DHIS2 tracked entities;
# - Registry Manifest renderings and retired Relay tool names;
# - the Rust source types and functions cited by evidence anchors;
# - the configure/breg-change-control page slug in links.
ALLOWED='entityTypeIdentifier|[Ee]ntity type identifiers?|[Ee]ntity[ -]tags?|(audience-scoped-)?entity-reference(-list)?|[a-z_]*entity_reference[a-z_]*|[Tt]racked[ _-]?[Ee]ntit(y|ies)(_id)?|entity JSON Schemas?|SHACL entity shapes|get_metadata_entity_[a-z_]+|Entity(Extension)?Source|[a-z_]*entit(y|ies)[a-z_]*\(\)|breg-change-control'
# Pages that still carry retired vocabulary until a later rewrite removes it.
# Their lines are counted and reported, not refused.
BASELINE="$ROOT/scripts/check-stale-config-vocabulary.baseline"

is_breg_page() {
  case "$1" in
    src/data/breg-*.yaml) return 0 ;;
    src/data/*) return 1 ;;
    *breg*) return 0 ;;
  esac
  case "${1#src/content/docs/}" in
    explanation/configuration-defined-registry.* | \
      explanation/registry-modeling-patterns.* | \
      tutorials/extend-a-registry-with-a-module.* | \
      tutorials/derive-a-registry-from-publicschema.* | \
      tutorials/send-registry-events-to-a-webhook.*)
      return 0
      ;;
  esac
  return 1
}

is_exempt_page() {
  case "$1" in
    # Release history and retirement records name what was retired, and an
    # approved specification keeps the words it was approved with.
    src/content/docs/changelog.* | src/content/docs/decisions/* | src/content/docs/spec/*) return 0 ;;
    # Generated trees: change their sources instead.
    src/content/docs/products/* | src/content/docs/reference/cli/*) return 0 ;;
  esac
  return 1
}

if [[ ! -f "$BASELINE" ]]; then
  echo "pending-rewrite baseline not found: $BASELINE" >&2
  exit 2
fi

# Each page is preceded by an awk assignment naming its pattern set.
pages=()
while IFS= read -r -d '' file; do
  rel="${file#"$ROOT"/}"
  if is_exempt_page "$rel"; then
    continue
  elif is_breg_page "$rel"; then
    pages+=("mode=breg" "$file")
  else
    pages+=("mode=other" "$file")
  fi
done < <(
  find "$ROOT/src/content/docs" -type f \( -name '*.md' -o -name '*.mdx' \) -print0
  find "$ROOT/src/data" -maxdepth 1 -type f -name '*.yaml' -print0
)

# The awk program reads the baseline first, then every page. A retired
# spelling on a baselined page is counted and reported; anywhere else it
# fails the check.
retired_status=0
ROOT="$ROOT" CROSS_PRODUCT_RETIRED="$CROSS_PRODUCT_RETIRED" BREG_RETIRED="$BREG_RETIRED" \
  EVIDENCE_CASEWORK_RETIRED="$EVIDENCE_CASEWORK_RETIRED" ALLOWED="$ALLOWED" \
  awk '
    BEGIN {
      root = ENVIRON["ROOT"] "/"
      narrow = ENVIRON["CROSS_PRODUCT_RETIRED"] "|" ENVIRON["EVIDENCE_CASEWORK_RETIRED"]
      broad = narrow "|" ENVIRON["BREG_RETIRED"]
      allowed = ENVIRON["ALLOWED"]
      pending = 0
      failures = 0
    }
    mode == "baseline" {
      entry = $0
      sub(/#.*/, "", entry)
      gsub(/[ \t]+/, "", entry)
      if (entry != "" && !(entry in baselined)) {
        baselined[entry] = 1
        order[++pending] = entry
        count[entry] = 0
      }
      next
    }
    {
      page = FILENAME
      if (index(page, root) == 1) page = substr(page, length(root) + 1)
      seen[page] = 1
      text = $0
      gsub(allowed, "", text)
      retired = (mode == "breg") ? broad : narrow
      if (text !~ retired) next
      if (page in baselined) {
        count[page]++
      } else {
        print page ":" FNR ": " $0
        failures++
      }
    }
    END {
      for (i = 1; i <= pending; i++) {
        page = order[i]
        if (!(page in seen)) {
          printf "pending rewrite: %s: page not found; remove it from the baseline\n", page
        } else if (count[page] == 0) {
          printf "pending rewrite: %s: clean; remove it from the baseline\n", page
        } else {
          printf "pending rewrite: %s: %d line(s) with retired vocabulary\n", page, count[page]
        }
      }
      exit (failures > 0)
    }
  ' mode=baseline "$BASELINE" ${pages[@]+"${pages[@]}"} || retired_status=$?

if [[ "$retired_status" -eq 1 ]]; then
  echo "retired vocabulary found outside the pending-rewrite baseline ($BASELINE)" >&2
  exit 1
elif [[ "$retired_status" -ne 0 ]]; then
  echo "retired vocabulary search failed with exit code $retired_status" >&2
  exit "$retired_status"
fi
