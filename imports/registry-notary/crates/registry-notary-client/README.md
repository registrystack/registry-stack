# registry-notary-client

Typed Rust HTTP client for Registry Notary.

Use this crate when Rust application code needs to call Registry Notary without
reimplementing request shapes, purpose handling, route-specific retry,
bounded-response reads, JWKS refresh behavior, or redacted error mapping.

## Quick Start

```rust
use registry_notary_client::RegistryNotaryClient;

let client = RegistryNotaryClient::builder("https://notary.example.gov")
    .bearer_token("access-token")
    .default_purpose("benefits_eligibility")
    .user_agent("benefits-api/1.0")
    .build()?;
```

Evaluate one target:

```rust
let response = client
    .evaluate_target("Person")
    .target_identifier("national_id", "person-1")
    .target_identifier_issuer("civil_registry")
    .relationship("self")
    .claims(["person-is-alive"])
    .disclosure("predicate")
    .send()
    .await?;

if let Some(result) = response.body.first_result() {
    println!("{} = {:?}", result.claim_id, result.satisfied);
}
```

## Main API

- `RegistryNotaryClient::builder(base_url)` creates a client.
- `evaluate_target(target_type)` starts the ergonomic evaluation builder.
- `evaluate_request`, `batch_evaluate_request`, `render_request`, and
  `issue_credential_request` accept core wire request types. `render_request`
  extracts `evaluation_id` into the route path before sending the body.
- `health`, `ready`, `admin_reload`, `openapi_json`, `metrics`, `list_claims`,
  `get_claim`, and `list_formats` cover operational, discovery, claim catalog,
  and format routes.
- `service_document`, `issuer_jwks`, `refresh_jwks`, and `raw_issuer_jwks`
  cover discovery and key rotation workflows.
- `credential_status` and `update_credential_status` cover minimal credential
  lifecycle status.
- `oid4vci_*` methods are available with the `oid4vci` feature.
- `federation_evaluate_jws` is available with the `federation` feature.
- `verify_sd_jwt_vc`, `verify_credential_response`, and
  `verify_oid4vci_credential` are available with the `verifier` feature. These
  methods are explicit and opt-in; response decoding never verifies
  credentials implicitly.
- `facade::NotaryClientHandle` is available with the `json-facade` feature for
  binding authors.

See [`docs/client-sdk-guide.md`](../../docs/client-sdk-guide.md) for examples in
Rust, Python, and Node.js.

## Features

- `oid4vci`: OpenID4VCI endpoint helpers.
- `federation`: delegated evaluation JWS submission.
- `json-facade`: canonical wire-shape JSON facade.
- `verifier`: explicit SD-JWT VC verification against trusted issuer JWKS.
- `test-support`: test-only HTTP client override and loopback HTTP allowance.

## Explicit SD-JWT VC Verification

Enable the `verifier` feature to verify credential material after a caller has
chosen the trust policy:

```rust
use registry_notary_client::{HolderBindingPolicy, VerifyOptions};

let options = VerifyOptions::new("did:web:notary.example")
    .expected_vct("https://credentials.example/vct/person-is-alive")
    .holder_binding(HolderBindingPolicy::Required);

let verified = client
    .verify_credential_response(&credential.body, options)
    .await?;
```

Verification resolves the JWS `kid` against the client's trusted issuer JWKS,
uses the normal JWKS TTL cache, forces one refresh on `key.unknown`, and then
stops. It checks the allowed algorithm list, header type, issuer, `vct`,
`exp`/`nbf`/`iat` with bounded skew, disclosure digests, and required
holder-binding confirmation. When an SD-JWT VC presentation includes a
key-binding JWT, the verifier separates it from disclosures and verifies its
holder proof signature against `cnf.jwk`. Verifier errors expose stable
redacted codes such as `signature.invalid`, `key.unknown`, `algorithm.disallowed`,
`claim.issuer_mismatch`, `claim.time_invalid`,
`disclosure.digest_mismatch`, and `holder_binding.required`.

Python and Node wrappers do not expose verifier wrappers in this first phase;
use the Rust verifier or perform verification in application-specific wallet
code.

## Safety Contract

The client:

- rejects multiple auth modes at build time;
- requires HTTPS for non-loopback hosts, with HTTP loopback allowed only in
  debug or `test-support` builds;
- disables redirects and ignores proxy environment variables;
- bounds every response body;
- returns successful response status in `NotaryResponse<T>`;
- captures `X-Request-Id` before body decoding;
- rejects `Idempotency-Key` on routes that do not honor it;
- retries only GET routes and idempotent batch evaluation;
- redacts raw Problem Details `detail`, compact credentials, holder proofs,
  nonces, SD-JWT disclosures, token material, and credential response bodies
  from `Debug`, `Display`, and portable errors.

## Wire Contract

Request types come from `registry-notary-core` where the server wire contract is
shared. Batch evaluation uses `registry_notary_core::BatchEvaluateResponse`
directly. Client-owned wrappers such as `Evaluation` and
`CredentialIssueResponse` exist for ergonomic accessors or redacted formatting,
not as compatibility workarounds.

## Verification

```bash
cargo test -p registry-notary-client
cargo test -p registry-notary-client --features json-facade,oid4vci,federation,verifier
cargo doc -p registry-notary-client --no-deps --all-features
```
