#!/usr/bin/env bash
set -euo pipefail

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/../../../.." && pwd)
profile="$repository_root/products/evidence/fixtures/interoperability/inji-oid4vci/profile.json"
receipt="$repository_root/products/evidence/fixtures/interoperability/inji-oid4vci/receipt.json"

command -v python3 >/dev/null 2>&1 || {
  printf 'Inji OID4VCI profile checking needs python3 on PATH.\n' >&2
  exit 1
}
command -v cargo >/dev/null 2>&1 || {
  printf 'Inji OID4VCI Registry-side checking needs cargo on PATH.\n' >&2
  exit 1
}

"$script_directory/inji-oid4vci-upstream.sh" --self-test

if [[ -n ${EVIDENCE_OID4VCI_BIN:-} ]]; then
  [[ $EVIDENCE_OID4VCI_BIN == /* && -x $EVIDENCE_OID4VCI_BIN ]] || {
    printf 'EVIDENCE_OID4VCI_BIN must name an absolute executable.\n' >&2
    exit 1
  }
  generated=$(mktemp "${TMPDIR:-/tmp}/registry-oid4vci-openapi.XXXXXX")
  trap 'rm -f -- "$generated"' EXIT HUP INT TERM
  "$EVIDENCE_OID4VCI_BIN" openapi --output "$generated"
  cmp "$repository_root/products/evidence/generated/registry-evidence-oid4vci.openapi.json" "$generated"
fi

python3 - "$profile" "$receipt" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
profile = json.loads(path.read_text(encoding="utf-8"))
receipt = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))

expected_revisions = {
    "wallet": "2fa12c3285b6523db340c3dd2333454b750b40a4",
    "kotlinClient": "f1d7ee2b14e996e18bfc7c40fbf89ec31b768951",
    "swiftClient": "dbe60eef9a8c7b71ba58ee81cc7d0e5a92af7c7c",
}
assert profile["schema"] == "registry.evidence-oid4vci-inji-interoperability/v1"
assert profile["testedOn"] == "2026-08-09"
assert profile["claim"] == "bounded-pinned-interoperability-evidence"
assert profile["upstreamReceipt"] == (
    "products/evidence/fixtures/interoperability/inji-oid4vci/receipt.json"
)
assert {
    name: component["revision"] for name, component in profile["upstream"].items()
} == expected_revisions
assert profile["metadata"] == {
    "format": "dc+sd-jwt",
    "bindingMethods": ["jwk", "did:jwk"],
    "proofType": "jwt",
    "proofSigningAlgorithms": ["ES256"],
    "credentialSigningAlgorithms": ["ES256"],
    "anonymousPreAuthorizedGrant": True,
    "nonceEndpointRequired": True,
    "batchSize": 4,
}
assert profile["wire"] == {
    "grantType": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "proofKeyReference": "did:jwk#0",
    "proofExpiration": "optional-and-enforced-when-present",
    "requestShape": "credential_configuration_id-plus-proofs.jwt-array",
    "responseShape": "credentials-array-of-credential-objects",
}

# This is a behavior manifest, never a captured exchange. Close the top-level
# shape and reject member names that would turn it into storage for live wire
# material or holder/source data.
assert set(profile) == {
    "schema", "testedOn", "claim", "upstreamReceipt", "upstream", "metadata", "wire",
    "registryCoverage", "negativeCases", "exclusions",
}
assert receipt["schema"] == (
    "registry.evidence-oid4vci-inji-interoperability-receipt/v1"
)
assert receipt["testedOn"] == profile["testedOn"]
assert receipt["result"] == "pass"
assert receipt["receipt"] == "PASS: pinned Inji OID4VCI source and client tests"
assert receipt["results"]["injiWallet"] == {
    "revision": expected_revisions["wallet"],
    "command": (
        "npx jest --runInBand machines/Issuers/IssuersService.test.ts "
        "--coverage=false"
    ),
    "testsPassed": 41,
    "testsFailed": 0,
}
assert receipt["results"]["injiVciClientKotlin"]["revision"] == (
    expected_revisions["kotlinClient"]
)
assert receipt["results"]["injiVciClientKotlin"]["result"] == "build-successful"
assert receipt["results"]["injiVciClientSwift"] == {
    "revision": expected_revisions["swiftClient"],
    "scheme": "VCIClientTests",
    "testsPassed": 12,
    "testsFailed": 0,
}
forbidden_members = {
    "access_token", "c_nonce", "credential", "credentialOffer",
    "credentialOfferUri", "d", "pre-authorized_code", "proofs",
    "selectorValues", "subjectId", "transactionCode",
}

def member_names(value):
    if isinstance(value, dict):
        for name, child in value.items():
            yield name
            yield from member_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from member_names(child)

assert forbidden_members.isdisjoint(member_names(profile))
assert forbidden_members.isdisjoint(member_names(receipt))
PY

if [[ -n ${EVIDENCE_OID4VCI_INTEROP_TEST_BIN:-} ]]; then
  [[ $EVIDENCE_OID4VCI_INTEROP_TEST_BIN == /* && -x $EVIDENCE_OID4VCI_INTEROP_TEST_BIN ]] || {
    printf 'EVIDENCE_OID4VCI_INTEROP_TEST_BIN must name an absolute executable.\n' >&2
    exit 1
  }
  "$EVIDENCE_OID4VCI_INTEROP_TEST_BIN" --nocapture --test-threads=1
else
  (
    cd "$repository_root"
    CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_DEV_DEBUG=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      cargo test --locked -p registry-evidence-oid4vci --test inji_interoperability -- \
        --nocapture --test-threads=1
  )
fi

printf 'PASS: sanitized Inji OID4VCI profile and Registry-side interoperability tests\n'
