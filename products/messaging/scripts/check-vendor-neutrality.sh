#!/usr/bin/env bash
set -euo pipefail

# Messaging's runtime, its generated configuration and OpenAPI document, and
# its routes stay free of any provider vendor name. A vendor package is
# example adopter material under products/messaging/examples/providers/,
# proven against MockHttpUpstream: it never becomes a Rust type, a config
# schema enum member, or a route.
#
# Unlike a neutrality gate that exempts test-only code, no module, doc
# comment, or test file is exempt here: a vendor name is not allowed even to
# name a test fixture, so every .rs file under the swept crates is read
# whole, with no comment or literal cut out of it first.
#
# grep -E rather than ripgrep: the hosted runner this gates is not
# guaranteed to carry ripgrep, and an absent search command exits 127, which
# a construct that only distinguishes match from no match reads as "found
# nothing". See products/evidence/scripts/check-source-neutrality.sh, the
# sibling gate that first documented this. Every root this gate names is
# checked to exist, and every grep status above 1 is a failure, because a
# gate that cannot fail is not a gate.

CDPATH=''
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)

swept_crate_roots=(
  "$repository_root/crates/registry-messaging"
  "$repository_root/crates/registry-messaging-core"
  "$repository_root/crates/registry-messaging-client"
  "$repository_root/crates/registry-messagingctl"
)

published_roots=(
  "$repository_root/products/messaging/generated"
)

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

for named_root in "${swept_crate_roots[@]}" "${published_roots[@]}"; do
  [[ -d "$named_root" ]] ||
    fail "This gate sweeps $named_root, which no longer exists: update the list it appears in."
done

sources=()
while IFS= read -r source_file; do
  sources+=("$source_file")
done < <(find "${swept_crate_roots[@]}" -type f -name '*.rs' | sort)

if [[ "${#sources[@]}" -eq 0 ]]; then
  fail 'The vendor-neutrality sweep found no Messaging runtime Rust to search.'
fi

published_files=()
while IFS= read -r published_file; do
  published_files+=("$published_file")
done < <(find "${published_roots[@]}" -type f | sort)

if [[ "${#published_files[@]}" -eq 0 ]]; then
  fail 'The vendor-neutrality sweep found no Messaging generated configuration to search.'
fi

# Case-insensitive and word-bounded: a boundary is the start or end of the
# text, or any non-alphanumeric byte, so "africa's talking" and
# "bandwidth.com" still bound correctly on their internal punctuation.
vendor_pattern='(^|[^[:alnum:]])(twilio|vonage|nexmo|sendgrid|mailgun|plivo|messagebird|infobip|africastalking|africa'\''s[[:space:]]talking|sinch|bandwidth\.com|amazon[[:space:]]ses|aws[[:space:]]sns|postmark|sparkpost|mailjet|brevo|sendinblue)([^[:alnum:]]|$)'

# grep reports 0 for a match, 1 for none, and above 1 for its own failure.
# The third outcome is a broken check rather than a clean tree, so it fails
# here. /dev/null keeps the file name on every reported line, whatever the
# list size.
sweep() {
  local message=$1
  shift
  local status=0 matches
  matches=$(grep -n -i -E -e "$vendor_pattern" /dev/null "$@") || status=$?
  case "$status" in
  0)
    printf '%s\n' "$matches" >&2
    fail "$message"
    ;;
  1) ;;
  *)
    fail "A vendor-neutrality sweep failed with status $status."
    ;;
  esac
}

sweep \
  'Messaging runtime Rust contains a provider vendor name. Vendor packages belong only under products/messaging/examples/providers/.' \
  "${sources[@]}"

sweep \
  'Messaging generated configuration or OpenAPI contains a provider vendor name.' \
  "${published_files[@]}"

printf 'Messaging vendor neutrality checks passed.\n'
