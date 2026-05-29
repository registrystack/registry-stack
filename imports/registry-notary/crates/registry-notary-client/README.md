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

Evaluate one subject:

```rust
let response = client
    .evaluate("person-1")
    .id_type("national_id")
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
- `evaluate(subject_id)` starts the ergonomic evaluation builder.
- `evaluate_dto`, `batch_evaluate_dto`, `render_dto`, and
  `issue_credential_dto` accept core wire DTOs.
- `service_document`, `issuer_jwks`, `refresh_jwks`, and `raw_issuer_jwks`
  cover discovery and key rotation workflows.
- `credential_status` and `update_credential_status` cover minimal credential
  lifecycle status.
- `oid4vci_*` methods are available with the `oid4vci` feature.
- `federation_evaluate_jws` is available with the `federation` feature.
- `facade::NotaryClientHandle` is available with the `json-facade` feature for
  binding authors.

See [`docs/client-sdk-guide.md`](../../docs/client-sdk-guide.md) for examples in
Rust, Python, and Node.js.

## Features

- `oid4vci`: OpenID4VCI endpoint helpers.
- `federation`: delegated evaluation JWS submission.
- `json-facade`: canonical wire-shape JSON facade.
- `test-support`: test-only HTTP client override and loopback HTTP allowance.

## Safety Contract

The client:

- rejects multiple auth modes at build time;
- requires HTTPS for non-loopback hosts;
- disables redirects and ignores proxy environment variables;
- bounds every response body;
- returns successful response status in `NotaryResponse<T>`;
- captures `X-Request-Id` before body decoding;
- rejects `Idempotency-Key` on routes that do not honor it;
- retries only GET routes and idempotent batch evaluation;
- redacts raw Problem Details `detail`, compact credentials, holder proofs,
  nonces, SD-JWT disclosures, token material, and credential response bodies
  from `Debug`, `Display`, and portable errors.

## DTO Contract

Request DTOs come from `registry-notary-core` where the server wire contract is
shared. Batch evaluation uses `registry_notary_core::BatchEvaluateResponse`
directly. Client-owned wrappers such as `Evaluation` and
`CredentialIssueResponse` exist for ergonomic accessors or redacted formatting,
not as compatibility workarounds.

## Verification

```bash
cargo test -p registry-notary-client
cargo test -p registry-notary-client --features json-facade,oid4vci,federation
cargo doc -p registry-notary-client --no-deps --all-features
```
