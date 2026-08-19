# First Evidence server curl

Status: Ready for deterministic local operator test

This checkpoint curls the Evidence server itself. DHIS2 and OpenCRVS are not
called. A deterministic local source returns synthetic data so the result
proves authenticated requester-scoped definition discovery plus the Evidence
assertion route, bearer authentication, authorization, request-nonce
validation and echo, response-format negotiation, selector handling,
source request, Rhai extraction and derivation, minimum-disclosure output gate,
signing, JWS verification, and both durable audit events.

The harness uses the production Evidence router and runtime with two deliberate
test substitutions: an in-memory test JWKS authenticates the requester, and a
local mock stands in for the upstream source. Those substitutions keep the
first curl reproducible and credential-free. Production OIDC JWKS retrieval,
the `evidence serve` startup command, and live provider compatibility are later
checkpoints and are not implied by this pass.

## Run the server

From the repository root, run this in terminal 1:

```bash
CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 \
CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --locked -p registry-evidence \
  first_curl_exercises_and_verifies_the_evidence_server \
  -- --ignored --nocapture
```

Wait until the harness prints `Evidence first-curl server is ready`. It listens
only on `127.0.0.1:18080` and creates an ignored, owner-only directory at
`products/evidence/.first-curl/`. The directory contains the exact synthetic
request plus `session.env`, which contains only a short-lived synthetic bearer
token. It does not read `products/evidence/.env`.

## Discover available Evidence

Load the short-lived synthetic bearer token, then ask the Evidence server what
this authenticated caller can request:

```bash
set -a
. products/evidence/.first-curl/session.env
set +a

curl --fail-with-body \
  --request GET \
  --header "Authorization: Bearer ${EVIDENCE_ACCESS_TOKEN}" \
  --header 'Accept: application/json' \
  --output products/evidence/.first-curl/definitions.json \
  --write-out 'HTTP %{http_code}\n' \
  http://127.0.0.1:18080/v1/evidence-definitions

jq . products/evidence/.first-curl/definitions.json
```

The response lists four complete, requester-authorized definitions. Each item
contains the requirement, Evidence Type, purpose, reference frameworks,
subject roles, selector profile and value origin, safe selector field contract,
and output concepts. It does not expose source identifiers, URLs, scripts,
credentials, authority-profile names, requester tags, selector values, or
codelist values. Discovery performs no provider call and writes no evidence-data
audit event.

## Request Evidence

Inspect the complete request:

```bash
jq . products/evidence/.first-curl/request.json
```

Every request carries a required `requestNonce`: the canonical unpadded
base64url encoding of exactly 32 random bytes, so exactly 43 characters. The
harness writes one into `request.json`. When you compose a request by hand,
generate a fresh value per request and never reuse, hand-edit, or derive it
from identifiers, selectors, secrets, or document digests:

```bash
openssl rand 32 | basenc --base64url | tr -d '=\n'
```

Evidence echoes the exact value into the Evidence payload under
`requestNonce` and covers it by the signature. Keep your copy of the request so
a verifier can compare the echoed nonce with the value it sent. Evidence does
not store the nonce, does not reject reuse, and makes no replay-prevention
claim.

### Optional unsigned variant

The first-curl bundle and its matched grant both permit `unsigned-json`, so you
may ask the same route for a visibly unsigned envelope. Run this before the
signed request in the next section, because the harness shuts down as soon as
it verifies the signed response:

```bash
curl --fail-with-body \
  --request POST \
  --header "Authorization: Bearer ${EVIDENCE_ACCESS_TOKEN}" \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/vnd.registrystack.evidence-unsigned+json' \
  --data-binary @products/evidence/.first-curl/request.json \
  --output products/evidence/.first-curl/response-unsigned.json \
  --write-out 'HTTP %{http_code}\n' \
  http://127.0.0.1:18080/v1/evidence

jq . products/evidence/.first-curl/response-unsigned.json
```

The envelope carries `"integrityProtection": "none"` and a
`"not-cryptographically-verifiable"` warning around the same closed Evidence
object. It is transport-authenticated convenience data for development and for
consumers that cannot process JWS, never later-verifiable evidence and never a
fallback when signing fails.

Unsigned output is governed, not a client choice. It succeeds only when the
immutable bundle and the one complete matched grant both permit it; otherwise
the request is refused with the ordinary `evidence.denied` problem before
credentials or source access, without revealing which layer refused. The
production reference bundles declare `responseFormats: [signed-jws]`, so the
same header there returns that refusal. A duplicate, combined, parameterized,
weighted, or unknown `Accept` returns the
`format.unsupported` problem with HTTP 406 before source access.

### Signed request

Then run this plain curl. There is no curl config, wrapper, proxy, redirect, or
hidden request option:

```bash
curl --fail-with-body \
  --request POST \
  --header "Authorization: Bearer ${EVIDENCE_ACCESS_TOKEN}" \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/jose+json' \
  --data-binary @products/evidence/.first-curl/request.json \
  --output products/evidence/.first-curl/response.json \
  --write-out 'HTTP %{http_code}\n' \
  http://127.0.0.1:18080/v1/evidence

unset EVIDENCE_ACCESS_TOKEN
jq . products/evidence/.first-curl/response.json
```

Every HTTP choice is visible in the command. `session.env` prevents only the
short-lived bearer value from being committed into this document. You may
inspect that local file, but do not paste its token into chat.

The curl prints:

```text
HTTP 200
```

`jq` then prints the actual flattened JWS response. In parallel, the server
harness validates the explicit discovery response, reads the assertion response
file, verifies the JWS against the running Evidence JWKS, checks the expected
minimized boolean, confirms protected source and selector fields are absent,
confirms both audit events are durable, shuts down, and ends with:

```text
PASS: authenticated discovery listed four safe request shapes, Evidence returned HTTP 200, its JWS verified, adult-status was true, minimization held, and both audit events were durable.
```

If you also ran the optional unsigned variant, its `response-unsigned.json`
output is present, so the harness additionally verifies that leg and ends with
the four-audit-event form instead:

```text
PASS: authenticated discovery listed four safe request shapes, Evidence returned HTTP 200 in both formats, the JWS verified, the unsigned envelope was self-identifying and rejected by the JWS verifier, adult-status was true, minimization held, and all four audit events were durable.
```

Either `PASS:` line is a full pass; which one you see depends only on whether the
optional unsigned leg ran (two audit events for the signed leg alone, four when
the unsigned leg also ran). Anything else is not a pass. Do not paste
`session.env` or its bearer token
into chat. The responses are retained at
`products/evidence/.first-curl/definitions.json`,
`products/evidence/.first-curl/response.json`, and, if you ran the optional
variant, `products/evidence/.first-curl/response-unsigned.json` for local
inspection and are gitignored.

## Local provider credentials

Optional live-provider work uses `products/evidence/.env`. The real file is
gitignored, owner-only, and contains the supplied DHIS2 public-demo credentials
plus the existing OpenCRVS system-client values and approved demo selector from
the local `.opencrvs.env`. The tracked `.env.example` lists the exact keys.

The Evidence runtime does not load credentials from environment variables.
When a live Evidence deployment is prepared, a launcher must copy only the
selected profile's values from `.env` into the runtime's owner-only secret files
and then start Evidence. This preserves the Version 1 file-secret boundary.

Do not source `.env` into an interactive shell, print it, pass its values on a
command line, commit it, or send it in chat. Provider calls remain read-only and
must use one approved demo record. A server-level DHIS2 or OpenCRVS checkpoint
is not ready until its deployment-specific selector and mapping are confirmed.

## What may wait until after this curl

The following may wait for this first deterministic Evidence-server curl, but
not for Version 1 completion:

- prepare an ephemeral production-startup harness that runs `evidence serve`
  with HTTPS OIDC JWKS and the file-secret boundary;
- run the Evidence server against one bounded DHIS2 demo record and one bounded
  OpenCRVS demo record using `.env`, then verify each returned JWS;
- rerun the final Evidence package, contract, neutrality, generated-artifact,
  and ignored live-source gates on one stable revision;
- stage the exact Evidence scope. Workspace-wide gates remain outside the
  current Evidence-only instruction.

Lower-priority review notes may also wait: decide whether governed requirements
need human-readable labels, add the pre-implementation decision-to-contract
index, clarify that the provider-side two-result limit is governed adapter
policy rather than a Rust domain rule, and correct the narrower selector
wording in the scratch review note. The deprecated unkeyed platform audit trait
method is unused by Evidence and belongs to shared platform maintenance.
