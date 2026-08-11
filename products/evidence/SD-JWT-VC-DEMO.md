# Evidence SD-JWT VC demo

Status: deterministic local operator demo

This demo issues one Evidence assertion in both governed later-verifiable
formats, then re-verifies the credential offline. It is deterministic and
credential-free: a local mock stands in for the upstream source and an
in-memory test JWKS authenticates the requester. No DHIS2, OpenCRVS, or other
live provider is contacted, and nothing is written outside
`products/evidence/.sd-jwt-vc-demo/`, which is gitignored and owner-only.

What it proves: the same authorization, minimization, and audit path releases
the same assertion as a signed flattened JWS and as an SD-JWT VC; the credential
carries one root disclosure for its unprojected supported value and nothing
else; and a relying party who kept the original request can verify the stored
credential later with no network and no running server.

What it does not prove: wallet interoperability, presentation, key-binding, or
any live provider deployment. Those are outside the Version 1 boundary in
[CONCEPT.md](CONCEPT.md) and the frozen profile in
[contracts/sd-jwt-vc-profile.yaml](contracts/sd-jwt-vc-profile.yaml).

## Run it

One command, from the repository root:

```bash
products/evidence/scripts/sd-jwt-vc-demo.sh
```

It needs `cargo`, `curl`, and `jq`. The first run compiles the crate, so allow a
few minutes; later runs take seconds. The script is idempotent: rerunning it
replaces the previous artifacts.

The script starts the demo server, performs every request with plain `curl`,
waits for the server's own checks, and finishes with the shipped offline
verifier. Its six steps are:

1. fetch the exact issuer metadata from `/.well-known/jwt-vc-issuer`, then its
   governed key set from `/.well-known/evidence/jwks.json`;
2. request the signed default with `Accept: application/jose+json`;
3. request the same assertion with `Accept: application/dc+sd-jwt`;
4. decode the credential's protected header and disclosures;
5. re-verify the stored credential offline with `evidence verify --sd-jwt-vc`;
6. edit one disclosure and re-verify, which must fail.

Every step prints the exact command it runs before running it, so the transcript
doubles as the copy-pasteable version of this walkthrough. The bearer token is
the one thing never printed: the demo passes it to `curl` on standard input, and
the printed form shows `$EVIDENCE_ACCESS_TOKEN` rather than its value.

Expected output, abbreviated:

```text
1. Fetch the exact issuer metadata and its governed key set (no token)
   $ curl \
       --header 'Accept: application/json' \
       --output 'products/evidence/.sd-jwt-vc-demo/issuer-metadata.json' \
       ... \
       http://127.0.0.1:18081/.well-known/jwt-vc-issuer
   HTTP 200 application/json
   issuer: urn:example:fixture:provider:evidence
   jwks_uri: urn:example:fixture:provider:evidence/.well-known/evidence/jwks.json
2. Request the signed default (Accept: application/jose+json)
   $ curl \
       --request 'POST' \
       --header 'Authorization: Bearer $EVIDENCE_ACCESS_TOKEN' \
       --header 'Content-Type: application/json' \
       --header 'Accept: application/jose+json' \
       --data-binary '@products/evidence/.sd-jwt-vc-demo/request.json' \
       ... \
       http://127.0.0.1:18081/v1/evidence
   HTTP 200 application/jose+json
3. Request the same assertion as an SD-JWT VC (Accept: application/dc+sd-jwt)
   $ curl \
       ... the same request with Accept: application/dc+sd-jwt \
       http://127.0.0.1:18081/v1/evidence
   HTTP 200 application/dc+sd-jwt

PASS: the same assertion was released as a signed JWS and as an SD-JWT VC, ...

4. The credential: an issuer-signed JWT, one root disclosure for this value,
   and a trailing tilde where a key-binding JWT would go
   1 disclosure(s), no key-binding JWT
   protected header: {"alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo","typ":"dc+sd-jwt"}
   disclosures (salt, claim name, claim value):
     ["7MNkDxEPeSWvyGbI2ziaRw","urn:example:fixture:concept:adult-status",true]

5. Re-verify the stored credential offline, no network and no server
   $ cargo run --locked --quiet -p registry-evidence -- verify --sd-jwt-vc ...
verified-at: 2026-08-02T13:49:03Z
authentic: yes
currently-valid: yes
{ ... the verified Evidence payload ... }

6. Tamper with one disclosure and re-verify: selective disclosure is not
   an invitation to edit the claim after issuance
   $ cargo run --locked --quiet -p registry-evidence -- verify --sd-jwt-vc ...
   rejected: evidence: stored response verification failed (disclosure)
```

Anything else is not a pass. The `PASS:` line comes from the server harness
itself, which independently verifies the credential against the signed
transaction, checks that protected source and selector material is absent, and
checks that both releases wrote durable audit events recording their own
response protection mode.

## What the demo bundle enables

The demo runs the acceptance bundle with one deliberate change: both the
immutable bundle and the one complete matched grant list `sd-jwt-vc` alongside
`signed-jws` and `unsigned-json`. Both gates are required and are never unioned.
Enabling the format in the bundle alone leaves the request refused with the
ordinary `evidence.denied` problem, before any credential or source access, and
without revealing which layer refused.

```yaml
# the immutable bundle
responseFormats: [signed-jws, unsigned-json, sd-jwt-vc]

# and the one matched grant
- requirement: urn:example:fixture:requirement:adult-status:v1
  purpose: fixture-eligibility
  audienceFrom: authenticated-requester
  responseFormats: [signed-jws, unsigned-json, sd-jwt-vc]
```

Production reference bundles declare `responseFormats: [signed-jws]`. The
credential format is an operator decision per deployment and per grant, not a
client choice.

## Driving it by hand

To watch the exchange yourself, run the server in terminal 1:

```bash
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --locked -p registry-evidence \
  sd_jwt_vc_demo_serves_a_credential_for_curl \
  -- --ignored --nocapture
```

Wait for `Evidence SD-JWT VC demo server is ready`. It listens only on
`127.0.0.1:18081`. Then work in terminal 2, from the repository root.

The server shuts down as soon as it has verified the credential, so fetch the
public metadata first. It needs no token:

```bash
curl --fail-with-body --silent \
  --output products/evidence/.sd-jwt-vc-demo/issuer-metadata.json \
  http://127.0.0.1:18081/.well-known/jwt-vc-issuer

curl --fail-with-body --silent \
  --output products/evidence/.sd-jwt-vc-demo/trusted.jwks.json \
  http://127.0.0.1:18081/.well-known/evidence/jwks.json
```

Then load the short-lived synthetic bearer token and request the signed default
before the credential: a relying party's expectations come from the transaction
it accepted, never from the credential it is about to check. Both requests pass
the token to `curl` through standard input, so it never reaches a command line,
the process table, or your shell history.

```bash
set -a
. products/evidence/.sd-jwt-vc-demo/session.env
set +a

for accept in application/jose+json application/dc+sd-jwt; do
  case "$accept" in
  application/jose+json) output=response.jws.json ;;
  *) output=credential.txt ;;
  esac
  curl --config - <<CURL_CONFIG
url = "http://127.0.0.1:18081/v1/evidence"
request = "POST"
header = "Authorization: Bearer $EVIDENCE_ACCESS_TOKEN"
header = "Content-Type: application/json"
header = "Accept: $accept"
data-binary = "@products/evidence/.sd-jwt-vc-demo/request.json"
output = "products/evidence/.sd-jwt-vc-demo/$output"
write-out = "HTTP %{http_code} %{content_type}\n"
silent
show-error
fail-with-body
CURL_CONFIG
done

unset EVIDENCE_ACCESS_TOKEN
```

`session.env` holds only that bearer token, which is why no token value appears
in this document. You may inspect the file locally, but do not paste its
contents into chat, a ticket, or a terminal that records input.

## Reading the credential

This demo's serialization is the issuer-signed JWT, then one root disclosure
for its unprojected supported value, ending with a tilde where a key-binding
JWT would go. A configured reviewed structured value instead has one nested
disclosure per direct field. No key-binding JWT is issued and none is expected.

```text
<issuer-signed JWT>~<disclosure>~
```

The protected header carries exactly `alg`, `kid`, and `typ: dc+sd-jwt`. The
payload carries the Evidence assertion's own fields plus `_sd` (the sorted,
deduplicated disclosure digests), `_sd_alg: sha-256`, and `vct`. Each disclosure
is the base64url encoding of `[salt, claim name, claim value]`, and its digest
is the base64url encoding of the SHA-256 of those encoded ASCII bytes.

Selector profiles, selector values, source identity, source responses, adapter
identity, grant identifiers, and requester identity never appear in the
credential, in a disclosure, or in credential-visible metadata. The disclosure
set is exactly the assertion's supported values.

The subject identifier is an audience-scoped pseudonym
(`urn:evidence:subject:v1_...`). The same person requested for a different
audience yields a different identifier by design, so the credential is not a
general-purpose multi-verifier credential and must not be marketed as one.

## Verifying it later

Offline re-verification needs three files and no network:

```bash
cargo run --locked -p registry-evidence -- verify \
  --sd-jwt-vc products/evidence/.sd-jwt-vc-demo/credential.txt \
  --jwks products/evidence/.sd-jwt-vc-demo/trusted.jwks.json \
  --policy products/evidence/.sd-jwt-vc-demo/verification-policy.yaml
```

The format is named by the operator. The command never infers a format from a
file's contents, so a stored response is never re-verified under the other
format's rules. Naming both formats, or neither, is a usage error.

The policy document is the demo's stand-in for state a relying party retains
independently: the nonce from the request it sent, and the expectations from the
transaction it accepted. Copying values out of the credential under verification
and passing them back as expectations proves nothing. The demo writes it after
verifying the signed default:

```yaml
audience: https://relying.invalid/procedure
clockSkewSeconds: 30
configurationRevision: sha256:bcfc829bb1...
evidenceType: urn:example:fixture:evidence-type:adult-status:v1
expectedOutputs:
  - concept: urn:example:fixture:concept:adult-status
    form: boolean
expectedSubjects:
  - binding: urn:evidence:subject:v1_3QKF0SHXxkQ9...
    role: subject
issuedBy: urn:example:fixture:issuer:authority
maximumAssertionLifetimeSeconds: 172800
providedBy: urn:example:fixture:provider:evidence
purpose: fixture-eligibility
requestNonce: AZ_CwmSORo8gHKmIY1sSLQAAAAAAAAAAAAAAAAAAAAA
requirement: urn:example:fixture:requirement:adult-status:v1
```

One policy document governs both formats, because the same Evidence payload is
verified whichever serialization carried it. The full contract is in
[contracts/verification-policy.schema.yaml](contracts/verification-policy.schema.yaml).

Exit codes: `0` authentic and currently valid, `3` authentic but no longer
current, `1` everything else. Failures report only a closed class, never a field
value, which is why step 6 prints `(disclosure)` and not the claim it rejected.

## Related material

- [FIRST-CURL-TEST.md](FIRST-CURL-TEST.md): the signed and unsigned formats over
  the same deterministic path.
- [contracts/sd-jwt-vc-profile.yaml](contracts/sd-jwt-vc-profile.yaml): the
  frozen profile, its verifier rules, and its named security negatives.
- [fixtures/conformance/sd-jwt-vc-cases.yaml](fixtures/conformance/sd-jwt-vc-cases.yaml):
  the golden wire fixture, reproduced by the production issuance path in tests.
- [SOURCE-TESTING.md](SOURCE-TESTING.md): the live DHIS2 and OpenCRVS demo
  checks, which are separate, opt-in, ignored, and read-only.
