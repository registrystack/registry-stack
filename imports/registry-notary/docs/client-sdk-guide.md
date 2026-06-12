# Registry Notary Client SDK Guide

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** consultation, evaluation, credential · **Audience:** integrator

Registry Notary ships a typed Rust client plus Python and Node.js wrappers. Use
these clients instead of hand-written HTTP calls when application code needs the
Notary wire contract, purpose handling, bounded response reads, route-aware
retry behavior, JWKS refresh behavior, and redacted error mapping.

## Packages

| Runtime | Package | Surface |
| --- | --- | --- |
| Rust | `registry-notary-client` | Primary typed client and optional JSON facade |
| Python | `registry-notary` | Dictionary-friendly sync and async wrapper |
| Node.js | `@registry-notary/client` | Promise client with TypeScript declarations |

The Rust crate is the source of truth. Python and Node expose the main
application, discovery, OID4VCI, and federation helpers, but keep JSON as
dictionaries or plain objects. Rust additionally exposes operational, admin,
format, and explicit SD-JWT VC verifier helpers.

## Common Concepts

### Base URL

Use the service root URL. A path prefix is allowed and is preserved when routes
are joined.

Clients require HTTPS for non-loopback hosts. Rust allows HTTP loopback only in
debug or `test-support` builds. Python and Node local workflows may use
`http://127.0.0.1`, `http://localhost`, or `http://[::1]`.

Python also exposes an explicit lab/internal escape hatch for Docker Compose
and private service-network deployments:
`allow_insecure_internal_http=True`. Use it only when transport is already
protected by the deployment boundary or a local development network. Production
service URLs should remain HTTPS.

### Authentication

Configure exactly one auth mode:

- Bearer token, sent as `Authorization: Bearer <token>`.
- API key, sent as `X-Api-Key`.
- Rust only: dynamic `AuthProvider`.

Supplying more than one auth mode is a build-time error. Debug output redacts
configured auth material.

### Scopes

The credential behind your auth mode carries a `scopes` list, and every claim
declares a `required_scope` on its source bindings that is enforced before
evaluation. Scope strings are operator-defined `<namespace>:<operation>` values
(for example `civil_registry:evidence_verification` or
`registry_notary:credential_issue`); there is no fixed global registry of scope
names. When you connect to a deployment you do not operate, ask the operator
which scopes the claims you need require and request a credential carrying
exactly those scopes. `GET /v1/claims` (`list_claims` in every SDK) confirms
which claims your credential can see before the first evaluation; a `403` on
evaluation means the credential lacks that claim's `required_scope`.

### Purpose

Evaluation routes can carry a data purpose in the `Data-Purpose` header and in
the request body `purpose` field. If both are present, they must match exactly.
The client rejects mismatches before sending the request.

Set a client default purpose when most calls share one purpose. Override per
call through request options when needed.

### Request Metadata

Request options support:

- `purpose`, mapped to `Data-Purpose`.
- `request_id`, mapped to `X-Request-Id`.
- `traceparent`, mapped to W3C trace context.
- `idempotency_key`, mapped to `Idempotency-Key` only for batch evaluation.
- `accept`, for Rust, JSON facade, and selected Python request helpers that
  need an explicit `Accept`. Node does not expose a public accept override.

### Retry Contract

Retries are disabled by default. When enabled, they are still route-aware:

- GET routes may retry transport errors, 429, or 503 according to the policy.
- `POST /v1/batch-evaluations` may retry only when an `Idempotency-Key` is
  supplied.
- Evaluation, render, credential issuance, OID4VCI credential, and federation
  submission are never retried because those POST routes are not deduplicated by
  the server.

`Retry-After` seconds are honored. Rust, Python, and Node also handle HTTP-date
`Retry-After` by using the response `Date` header as the reference clock when it
is present.

### Response Metadata

All typed Rust methods return `NotaryResponse<T>` with:

- `body`: decoded response body.
- `status`: HTTP status returned by the server.
- `request_id`: server `X-Request-Id`, when present.
- `retry_after`: server `Retry-After`, when present.

Python and Node expose equivalent fields on errors. Successful Python and Node
helpers return the response body directly.

### Error Handling And Redaction

Rust returns `NotaryClientError`. Python and Node expose:

- `NotaryError`
- `NotaryTransportError`
- `NotaryProblemError`

Safe fields for logs are `status`, `code`, `title`, `retryable`, and `request_id`. Do not
log raw request bodies, requester or target identifiers, holder proofs,
credential bodies, SD-JWT disclosures, nonces, Authorization, `X-Api-Key`, or
Problem Details `detail`.

The Rust `portable()` error envelope is intended for language bindings and FFI.
It intentionally excludes sensitive detail strings.

The stable application problem `code` values for policy mapping live in the
[problem code registry in the API reference](api-reference.md#problem-code-registry).

## Rust

### Install

> Note: the `path = "crates/..."` dependencies below assume you are building
> inside the Registry Notary workspace checkout. The workspace crates are not
> published to crates.io. An external integrator without the checkout should
> use a `git` dependency pinned to a release tag (for example `v0.3.1`) or a
> commit:
>
> ```toml
> [dependencies]
> registry-notary-client = { git = "https://github.com/jeremi/registry-notary", tag = "vX.Y.Z" }
> registry-notary-core = { git = "https://github.com/jeremi/registry-notary", tag = "vX.Y.Z" }
> ```

```toml
[dependencies]
registry-notary-client = { path = "crates/registry-notary-client" }
registry-notary-core = { path = "crates/registry-notary-core" }
```

Enable optional routes when needed:

```toml
registry-notary-client = {
  path = "crates/registry-notary-client",
  features = ["oid4vci", "federation", "json-facade"]
}
```

### Create A Client

```rust
use registry_notary_client::RegistryNotaryClient;

let client = RegistryNotaryClient::builder("https://notary.example.gov")
    .bearer_token("access-token")
    .default_purpose("benefits_eligibility")
    .user_agent("benefits-api/1.0")
    .build()?;
```

API key auth:

```rust
let client = RegistryNotaryClient::builder("https://notary.example.gov")
    .api_key("service-key")
    .build()?;
```

### High-Level Evaluation

Evaluation requests use the canonical requester/target evidence model. The
target is the entity being evaluated; optional requester context identifies the
actor or represented party, and relationship explains why the requester may ask
about that target.

```rust
let response = client
    .evaluate_target("Person")
    .target_identifier("national_id", "person-1")
    .target_identifier_issuer("civil_registry")
    .relationship("self")
    .claims(["person-is-alive", "age-over-18"])
    .disclosure("predicate")
    .send()
    .await?;

if let Some(result) = response.body.result_for("person-is-alive") {
    println!("satisfied: {:?}", result.satisfied);
}
```

### Raw Request Evaluation

> Note: the raw-DTO examples construct `registry-notary-core` types directly and
> assume building inside the workspace checkout. Integrators who only consume the
> client over HTTP can use the high-level builder or JSON facade shown elsewhere
> in this guide.

```rust
use registry_notary_client::RequestOptions;
use registry_notary_core::{
    ClaimRef, EvidenceEntity, EvidenceIdentifier, EvidenceRelationship, EvaluateRequest,
};

let request = EvaluateRequest {
    requester: None,
    target: Some(EvidenceEntity {
        entity_type: "Person".to_string(),
        id: None,
        identifiers: vec![EvidenceIdentifier {
            scheme: "national_id".to_string(),
            value: "person-1".to_string(),
            issuer: Some("civil_registry".to_string()),
            country: None,
        }],
        attributes: Default::default(),
        assurance: None,
        profile: None,
    }),
    relationship: Some(EvidenceRelationship {
        relationship_type: "self".to_string(),
        attributes: Default::default(),
    }),
    on_behalf_of: None,
    claims: vec![ClaimRef::new("person-is-alive")],
    disclosure: Some("predicate".to_string()),
    format: None,
    purpose: Some("benefits_eligibility".to_string()),
};

let options = RequestOptions::builder()
    .request_id("req-123")
    .traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    .build();

let response = client.evaluate_request(request, options).await?;
```

### Batch Evaluation

Batch evaluation is the only POST route that accepts `Idempotency-Key` through
the client.

```rust
use registry_notary_client::{RequestOptions, RetryPolicy};
use registry_notary_core::{
    BatchEvaluateItemRequest, BatchEvaluateRequest, ClaimRef, EvidenceEntity,
    EvidenceIdentifier, EvidenceRelationship,
};
use std::time::Duration;

let client = RegistryNotaryClient::builder("https://notary.example.gov")
    .retry_policy(RetryPolicy {
        max_attempts: 3,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(2),
        retry_transport_errors: true,
        retry_rate_limited: true,
        retry_unavailable: true,
    })
    .build()?;

let request = BatchEvaluateRequest {
    items: vec![BatchEvaluateItemRequest {
        requester: None,
        target: EvidenceEntity {
            entity_type: "Person".to_string(),
            id: None,
            identifiers: vec![EvidenceIdentifier {
                scheme: "national_id".to_string(),
                value: "person-1".to_string(),
                issuer: Some("civil_registry".to_string()),
                country: None,
            }],
            attributes: Default::default(),
            assurance: None,
            profile: None,
        },
        relationship: Some(EvidenceRelationship {
            relationship_type: "self".to_string(),
            attributes: Default::default(),
        }),
        on_behalf_of: None,
        purpose: None,
    }],
    claims: vec![ClaimRef::new("person-is-alive")],
    disclosure: None,
    format: None,
    purpose: Some("benefits_eligibility".to_string()),
};

let options = RequestOptions::builder()
    .purpose("benefits_eligibility")
    .idempotency_key("batch-2026-05-29-001")
    .build();

let response = client.batch_evaluate_request(request, options).await?;
println!("succeeded: {}", response.body.summary.succeeded);
```

### Discovery And JWKS

```rust
let service = client.service_document(RequestOptions::default()).await?;
let jwks = client.issuer_jwks(RequestOptions::default()).await?;

// Force refresh after an unknown kid during verification.
let refreshed = client.refresh_jwks(RequestOptions::default()).await?;
```

`issuer_jwks` uses a short in-process cache when called without request
options. `raw_issuer_jwks` bypasses that cache.

### Render And Credential Issuance

The render route carries `evaluation_id` in the path. Rust accepts the core
`RenderRequest` DTO and moves `evaluation_id` into
`/v1/evaluations/{evaluation_id}/render` before sending the body. Python and
Node raw helpers accept canonical snake_case JSON, require a mapping/object,
extract `evaluation_id`, and send the remaining fields as the route body.

```rust
use registry_notary_core::{CredentialIssueRequest, RenderRequest};

let rendered = client
    .render_request(
        RenderRequest {
            evaluation_id: "eval-1".to_string(),
            format: "application/vnd.registry-notary.claim-result+json".to_string(),
            disclosure: Some("predicate".to_string()),
            claims: None,
            purpose: Some("benefits_eligibility".to_string()),
        },
        RequestOptions::default(),
    )
    .await?;

let credential = client
    .issue_credential_request(
        CredentialIssueRequest {
            evaluation_id: "eval-1".to_string(),
            credential_profile: None,
            format: None,
            claims: None,
            disclosure: None,
            holder: None,
        },
        RequestOptions::builder()
            .purpose("benefits_eligibility")
            .build(),
    )
    .await?;
```

Credential bodies are present in `credential.body`, but redacted from `Debug`.

### Explicit Credential Verification

Enable the Rust `verifier` feature when relying-party or wallet code needs to
verify SD-JWT VC credential material. Verification is explicit and opt-in:
transport methods continue to return decoded response bodies without hidden
network refreshes or trust-policy decisions.

```toml
registry-notary-client = {
  path = "crates/registry-notary-client",
  features = ["verifier"]
}
```

```rust
use registry_notary_client::{HolderBindingPolicy, VerifyOptions};

let options = VerifyOptions::new("did:web:notary.example")
    .expected_vct("https://credentials.example/vct/person-is-alive")
    .holder_binding(HolderBindingPolicy::Required);

let verified = client
    .verify_credential_response(&credential.body, options)
    .await?;
```

The verifier resolves the JWS `kid` only from trusted issuer JWKS, reuses the
client's short JWKS TTL cache, and forces one refresh on `key.unknown`. It does
not loop indefinitely. `VerifyOptions` lets callers set expected issuer,
accepted algorithms, expected `vct`, clock skew, and holder-binding policy.
Selective-disclosure presentations may include a subset of disclosures; each
presented disclosure must hash to a digest in the credential. When a
presentation includes a key-binding JWT, the verifier separates it from
disclosures and verifies its holder proof signature against the credential
`cnf.jwk`.

Verifier errors are redacted and safe for policy mapping by code. Stable codes
include `signature.invalid`, `key.unknown`, `algorithm.disallowed`,
`claim.issuer_mismatch`, `claim.vct_mismatch`, `claim.time_invalid`,
`disclosure.digest_mismatch`, `holder_binding.required`, and
`holder_binding.kid_mismatch`, and `holder_binding.proof_invalid`.

Python and Node do not expose verifier wrappers in this first phase. Callers in
those runtimes should use the Rust verifier through their application boundary
or perform verification in wallet-specific code.

### Credential Status

```rust
let status = client
    .credential_status("credential-1", RequestOptions::default())
    .await?;

let updated = client
    .update_credential_status("credential-1", "revoked", RequestOptions::default())
    .await?;
```

### OID4VCI

Enable the `oid4vci` feature.

```rust
let metadata = client
    .oid4vci_issuer_metadata(RequestOptions::default())
    .await?;

let offer = client
    .oid4vci_credential_offer(Some("person_is_alive_sd_jwt"), RequestOptions::default())
    .await?;
```

The client wraps endpoints only. It does not generate holder proofs or manage
holder keys.

### Federation

Enable the `federation` feature.

```rust
let compact_response_jws = client
    .federation_evaluate_jws("eyJ...", RequestOptions::default())
    .await?;
```

The client submits an already-signed JWT. It does not mint or sign federation
requests.

### JSON Facade

Enable `json-facade` when building language wrappers. The facade accepts and
returns canonical wire JSON with snake_case fields.

```rust
use registry_notary_client::facade::NotaryClientHandle;

let handle = NotaryClientHandle::new(client);
let response = handle
    .evaluate_json(
        serde_json::json!({
            "target": {
                "type": "Person",
                "identifiers": [{
                    "scheme": "national_id",
                    "value": "person-1",
                    "issuer": "civil_registry"
                }]
            },
            "relationship": { "type": "self" },
            "claims": ["person-is-alive"],
            "purpose": "benefits_eligibility"
        }),
        serde_json::json!({})
    )
    .await?;
```

## Python

`bindings/python/registry_notary` is the supported Python client package for
downstream applications. Its public names for application integrations are:
`RegistryNotaryClient`, `RetryPolicy`, `evaluate`,
`evaluate_request`, `batch_evaluate_request`, `list_claims`, `get_claim`,
`issuer_jwks`, `raw_issuer_jwks`, `render_request`,
`issue_credential_request`, and `credential_status`.

### Install

The package is not currently published to PyPI. Install it directly from the
git repository pinned to a release tag or commit (for example `v0.3.1`):

```bash
python -m pip install "git+https://github.com/jeremi/registry-notary.git@vX.Y.Z#subdirectory=bindings/python"
```

From a local checkout, `python -m pip install -e bindings/python` works as
well.

### Create A Client

```python
from registry_notary import RegistryNotaryClient

client = RegistryNotaryClient(
    base_url="https://notary.example.gov",
    bearer_token="access-token",
    default_purpose="benefits_eligibility",
    user_agent="benefits-api/1.0",
)
```

For internal lab or Compose service names that intentionally use cleartext
HTTP, make the exception explicit:

```python
client = RegistryNotaryClient(
    base_url="http://registry-notary:8080",
    default_purpose="benefits_eligibility",
    allow_insecure_internal_http=True,
)
```

### Evaluate

```python
result = client.evaluate(
    target_id="person-1",
    identifier_scheme="national_id",
    claims=["person-is-alive"],
)
```

Use `evaluate_request` for the full canonical wire shape, including
relationship context and optional fields such as `disclosure` or `format`:

```python
result = client.evaluate_request({
    "target": {
        "type": "Person",
        "identifiers": [{
            "scheme": "national_id",
            "value": "person-1",
            "issuer": "civil_registry",
        }],
    },
    "relationship": {"type": "self"},
    "claims": [{"id": "person-is-alive", "version": "2026-05"}],
    "disclosure": "predicate",
    "purpose": "benefits_eligibility",
})
```

For citizen self-attestation, omit identity fields and let the server derive the
requester, target, and `self` relationship from the verified token binding:

```python
result = client.evaluate_request({
    "claims": [{"id": "person-is-alive", "version": "2026-05"}],
    "disclosure": "predicate",
})
```

Claim references may be plain strings or pinned objects with `id` and
`version`. The same versioned claim reference shape is supported for single
evaluation and batch evaluation.

Async evaluation helpers are prefixed with `a`, for example `aevaluate` and
`aevaluate_request`.

### Batch With Retry

```python
from registry_notary import RetryPolicy

client = RegistryNotaryClient(
    base_url="https://notary.example.gov",
    retry_policy=RetryPolicy(
        max_attempts=3,
        base_delay=0.1,
        max_delay=2.0,
        retry_transport_errors=True,
        retry_rate_limited=True,
        retry_unavailable=True,
    ),
)

result = client.batch_evaluate_request(
    {
        "items": [{
            "target": {
                "type": "Person",
                "identifiers": [{
                    "scheme": "national_id",
                    "value": "person-1",
                    "issuer": "civil_registry",
                }],
            },
            "relationship": {"type": "self"},
        }],
        "claims": ["person-is-alive"],
        "purpose": "benefits_eligibility",
    },
    idempotency_key="batch-2026-05-29-001",
)
```

### Render And Credential Issuance

Raw render requests use canonical snake_case JSON and must include
`evaluation_id`. The Python wrapper rejects non-mapping inputs before it reads
or sends any fields.

```python
rendered = client.render_request({
    "evaluation_id": "eval-1",
    "format": "application/vnd.registry-notary.claim-result+json",
    "disclosure": "predicate",
})

credential = client.issue_credential_request({
    "evaluation_id": "eval-1",
    "credential_profile": "person_is_alive_sd_jwt",
})
```

### Discovery, Status, OID4VCI, Federation

```python
claims = client.list_claims()
claim = client.get_claim("person-is-alive")
jwks = client.issuer_jwks()
client.refresh_jwks()
key = client.get_jwk("key-1")
status = client.credential_status("credential-1")

metadata = client.oid4vci_issuer_metadata()
offer = client.oid4vci_credential_offer("person_is_alive_sd_jwt")
nonce = client.oid4vci_nonce()

response_jws = client.federation_evaluate_jws("eyJ...")
```

### Python Errors

```python
from registry_notary.errors import NotaryProblemError, NotaryTransportError

try:
    client.evaluate(
        target_id="person-1",
        identifier_scheme="national_id",
        claims=["person-is-alive"],
    )
except NotaryProblemError as exc:
    print(exc.status, exc.code, exc.request_id)
except NotaryTransportError:
    print("transport failure")
```

Problem detail strings are not exposed.

## Node.js

### Install

The package is not currently published to the npm registry. With pnpm you can
install it directly from the git repository pinned to a release tag or commit
(for example `v0.3.1`):

```bash
pnpm add "github:jeremi/registry-notary#vX.Y.Z&path:bindings/node"
```

npm does not support installing from a subdirectory of a git repository, so
with npm install it from a checkout pinned to a release tag or commit:

```bash
npm install ./bindings/node
```

### Create A Client

```js
import { RegistryNotaryClient } from "@registry-notary/client";

const client = new RegistryNotaryClient({
  baseUrl: "https://notary.example.gov",
  bearerToken: "access-token",
  defaultPurpose: "benefits_eligibility",
  userAgent: "benefits-api/1.0",
});
```

### Evaluate

High-level Node helpers use camelCase at the wrapper boundary:

```js
const result = await client.evaluate({
  target: {
    type: "Person",
    identifiers: [{ scheme: "national_id", value: "person-1", issuer: "civil_registry" }],
  },
  relationship: { type: "self" },
  claims: ["person-is-alive"],
  disclosure: "predicate",
});
```

Raw helpers preserve canonical wire shape:

```js
const result = await client.evaluateRequest({
  target: {
    type: "Person",
    identifiers: [{ scheme: "national_id", value: "person-1", issuer: "civil_registry" }],
  },
  relationship: { type: "self" },
  claims: ["person-is-alive"],
  purpose: "benefits_eligibility",
});
```

Render uses the route-shaped API. `renderRequest` requires a plain request
object with snake_case `evaluation_id`, removes `evaluation_id` from the JSON
body, and posts the rest to `/v1/evaluations/{evaluation_id}/render`.

```js
const rendered = await client.renderRequest({
  evaluation_id: "eval-1",
  format: "application/vnd.registry-notary.claim-result+json",
  disclosure: "predicate",
});
```

### Abort And Retry

```js
const controller = new AbortController();

const client = new RegistryNotaryClient({
  baseUrl: "https://notary.example.gov",
  retryPolicy: {
    maxAttempts: 3,
    baseDelayMs: 100,
    maxDelayMs: 2000,
    retryTransportErrors: true,
    retryRateLimited: true,
    retryUnavailable: true,
  },
});

const result = await client.batchEvaluate(
  {
    items: [{
      target: {
        type: "Person",
        identifiers: [{ scheme: "national_id", value: "person-1", issuer: "civil_registry" }],
      },
      relationship: { type: "self" },
    }],
    claims: ["person-is-alive"],
    purpose: "benefits_eligibility",
  },
  {
    idempotencyKey: "batch-2026-05-29-001",
    signal: controller.signal,
  },
);
```

### Discovery, Status, OID4VCI, Federation

```js
const claims = await client.listClaims();
const claim = await client.getClaim("person-is-alive");
const jwks = await client.issuerJwks();
await client.refreshJwks();
const key = await client.getJwk("key-1");
const status = await client.credentialStatus("credential-1");

const metadata = await client.oid4vciIssuerMetadata();
const offer = await client.oid4vciCredentialOffer("person_is_alive_sd_jwt");
const nonce = await client.oid4vciNonce();

const responseJws = await client.federationEvaluateJws("eyJ...");
```

### Node Errors

```js
import { NotaryProblemError, NotaryTransportError } from "@registry-notary/client";

try {
  await client.evaluate({
    target: { type: "Person", identifiers: [{ scheme: "national_id", value: "person-1" }] },
    relationship: { type: "self" },
    claims: ["person-is-alive"],
  });
} catch (error) {
  if (error instanceof NotaryProblemError) {
    console.log(error.status, error.code, error.requestId);
  } else if (error instanceof NotaryTransportError) {
    console.log("transport failure");
  }
}
```

## API Method Matrix

The route to client method mapping for each runtime lives in the
[route to client method matrix in the API reference](api-reference.md#route-to-client-method-matrix).

## Verification Commands

```bash
cargo test -p registry-notary-client
cargo test -p registry-notary-client --features json-facade,oid4vci,federation
cargo doc -p registry-notary-client --no-deps --all-features
python3 -m unittest discover -s bindings/python/tests
npm test --prefix bindings/node
npm run check:types --prefix bindings/node
```
