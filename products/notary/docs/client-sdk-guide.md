# Registry Notary Client SDK Guide

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** consultation, evaluation, credential · **Audience:** integrator

Registry Notary ships a typed Rust client plus Python and Node.js wrappers. Use
these clients instead of hand-written HTTP calls when application code needs the
Notary wire contract, purpose handling, bounded response reads, route-aware
retry behavior, JWKS refresh behavior, and redacted error mapping.

This guide starts with the first integration path: discover a claim, evaluate it
for one target, read the result, and handle errors safely. Later sections cover
batch evaluation, rendering, credential issuance, OID4VCI, federation, and
Rust-only verifier helpers.

## Start here

Before the first SDK call, collect these values from the deployment operator or
from your own application workflow.

| Need | Example | Where it comes from |
| --- | --- | --- |
| Service base URL | `https://self-attested-notary.lab.registrystack.org` | Hosted lab manifest or Registry Notary operator |
| Auth credential | `SELF_ATTESTED_EVIDENCE_CLIENT_TOKEN` | Hosted lab manifest or Registry Notary operator |
| Claim id | `applicant-declaration` | `list_claims` or operator docs |
| Target identifier | `applicant_id` and `demo-applicant` | Your application or case record |
| Purpose | `application-processing` | Your product, policy, or workflow |

Use `list_claims` first when you are unsure which claim ids your credential can
see. A later `403` on evaluation usually means the credential lacks the
`required_scope` for one of the requested claims.

The quickstart uses the public hosted lab backend so the examples are runnable
as written. The lab publishes current demo service URLs and caller credentials
at `https://lab.registrystack.org/api/lab.json`. These are public demo
credentials, not production secret-handling guidance.

Read the `self-attested-evidence` entry from `lab.json` and export the values manually:

```bash
export REGISTRY_NOTARY_BASE_URL="<service_url from the self-attested-evidence entry>"
export REGISTRY_NOTARY_API_KEY="<token from the self-attested-evidence entry>"
export REGISTRY_NOTARY_PURPOSE="<default_purpose from the self-attested-evidence entry>"
```

The lab UI at `https://lab.registrystack.org` shows the same values.

### Key terms

- **Claim:** A named question Notary can evaluate, such as
  `applicant-declaration`.
- **Target:** The person, organization, or record being evaluated.
- **Requester:** The actor asking for the evaluation.
- **Relationship:** Why the requester may ask about the target, such as `self`.
- **Purpose:** The reason for processing, sent in request metadata and usually
  recorded in audit evidence.
- **Disclosure:** The detail level requested in the response. `predicate`
  asks for a minimized true, false, or unknown style result.

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

The packages are not currently published to public package registries. Pin
integrations to a release tag or commit.

```toml
[dependencies]
registry-notary-client = { git = "https://github.com/registrystack/registry-stack", tag = "vX.Y.Z" }
registry-notary-core = { git = "https://github.com/registrystack/registry-stack", tag = "vX.Y.Z" }
```

```bash
python -m pip install "git+https://github.com/registrystack/registry-stack.git@vX.Y.Z#subdirectory=products/notary/bindings/python"
```

```bash
pnpm add "github:registrystack/registry-stack#vX.Y.Z&path:products/notary/bindings/node"
```

npm does not support installing from a subdirectory of a git repository. With
npm, install the Node package from a checkout pinned to a release tag or
commit:

```bash
npm install ./bindings/node
```

From an app that depends on a local Registry Notary checkout, use path installs
instead:

```toml
[dependencies]
registry-notary-client = { path = "/path/to/registry-notary/crates/registry-notary-client" }
registry-notary-core = { path = "/path/to/registry-notary/crates/registry-notary-core" }
```

```bash
python -m pip install -e /path/to/registry-notary/bindings/python
pnpm add /path/to/registry-notary/bindings/node
```

### Verifying a workspace checkout

```bash
cargo test -p registry-notary-client
cargo test -p registry-notary-client --features json-facade,oid4vci,federation
cargo doc -p registry-notary-client --no-deps --all-features
python3 -m unittest discover -s bindings/python/tests
npm test --prefix bindings/node
npm run check:types --prefix bindings/node
```

## First evaluation

This quickstart asks the retained Notary-only lab service to evaluate the
`applicant-declaration` claim for `demo-applicant`. Use it when your application
already knows the target identifier and wants a minimized self-attested claim
result without consulting Relay or a registry source.

The examples set `default_purpose` or `defaultPurpose` on the client. You can
also set purpose per call when different workflows share the same client.

### Python

```python
import os

from registry_notary import RegistryNotaryClient
from registry_notary.errors import NotaryProblemError, NotaryTransportError

client = RegistryNotaryClient(
    base_url=os.environ["REGISTRY_NOTARY_BASE_URL"],
    api_key=os.environ["REGISTRY_NOTARY_API_KEY"],
    default_purpose=os.environ["REGISTRY_NOTARY_PURPOSE"],
    user_agent="benefits-api/1.0",
)

claims = client.list_claims()
print([claim["id"] for claim in claims.get("data", [])])

try:
    result = client.evaluate_request({
        "target": {
            "type": "Person",
            "identifiers": [{
                "scheme": "applicant_id",
                "value": "demo-applicant",
            }],
        },
        "relationship": {"type": "self"},
        "claims": ["applicant-declaration"],
        "disclosure": "predicate",
        "purpose": os.environ["REGISTRY_NOTARY_PURPOSE"],
    })
except NotaryProblemError as exc:
    print(exc.status, exc.code, exc.request_id)
except NotaryTransportError:
    print("transport failure")
else:
    first = result["results"][0]
    print(first["claim_id"], first.get("satisfied"))
```

What this does:

- `list_claims` confirms which claim ids this credential can see.
- `target` identifies the entity being evaluated.
- `relationship` tells Notary why this requester may ask about the target.
- `claims` names the claim ids to evaluate.
- `disclosure` asks for a minimized claim answer.
- `purpose` must match the configured default purpose when both are present.

Python also has a shorter helper for the common one-target case:

```python
result = client.evaluate(
    target_id="demo-applicant",
    identifier_scheme="applicant_id",
    target_type="Person",
    claims=["applicant-declaration"],
)
```

Use `evaluate_request` when you need the full canonical wire shape, including
relationship context, version-pinned claim references, `disclosure`, `format`,
or explicit `purpose`.

### Node.js

```js
import {
  NotaryProblemError,
  NotaryTransportError,
  RegistryNotaryClient,
} from "@registry-notary/client";

const client = new RegistryNotaryClient({
  baseUrl: process.env.REGISTRY_NOTARY_BASE_URL,
  apiKey: process.env.REGISTRY_NOTARY_API_KEY,
  defaultPurpose: process.env.REGISTRY_NOTARY_PURPOSE,
  userAgent: "benefits-api/1.0",
});

const claims = await client.listClaims();
console.log(claims.data?.map((claim) => claim.id) ?? []);

try {
  const result = await client.evaluate({
    target: {
      type: "Person",
      identifiers: [{ scheme: "applicant_id", value: "demo-applicant" }],
    },
    relationship: { type: "self" },
    claims: ["applicant-declaration"],
    disclosure: "predicate",
    purpose: process.env.REGISTRY_NOTARY_PURPOSE,
  });

  const first = result.results[0];
  console.log(first.claimId, first.satisfied);
} catch (error) {
  if (error instanceof NotaryProblemError) {
    console.log(error.status, error.code, error.requestId);
  } else if (error instanceof NotaryTransportError) {
    console.log("transport failure");
  } else {
    throw error;
  }
}
```

The high-level Node helpers accept camelCase object keys and return camelCase
response keys. Use `evaluateRequest` when you want to send canonical snake_case
wire JSON and receive snake_case response JSON.

```js
const result = await client.evaluateRequest({
  target: {
    type: "Person",
    identifiers: [{ scheme: "applicant_id", value: "demo-applicant" }],
  },
  relationship: { type: "self" },
  claims: ["applicant-declaration"],
  disclosure: "predicate",
  purpose: process.env.REGISTRY_NOTARY_PURPOSE,
});
```

### Rust

```rust
use registry_notary_client::RegistryNotaryClient;

let base_url = std::env::var("REGISTRY_NOTARY_BASE_URL")?;
let api_key = std::env::var("REGISTRY_NOTARY_API_KEY")?;
let purpose = std::env::var("REGISTRY_NOTARY_PURPOSE")?;

let client = RegistryNotaryClient::builder(base_url)
    .api_key(api_key)
    .default_purpose(purpose.clone())
    .user_agent("benefits-api/1.0")
    .build()?;

let claims = client.list_claims(Default::default()).await?;

let response = client
    .evaluate_target("Person")
    .target_identifier("applicant_id", "demo-applicant")
    .relationship("self")
    .claims(["applicant-declaration"])
    .disclosure("predicate")
    .purpose(purpose.clone())
    .send()
    .await?;

if let Some(result) = response.body.result_for("applicant-declaration") {
    println!("satisfied: {:?}", result.satisfied);
}
```

Rust returns `NotaryResponse<T>`, so response metadata is available next to the
decoded body:

```rust
println!("status: {}", response.status);
println!("request id: {:?}", response.request_id);
```

## Understanding the request

The SDKs protect the same wire model. Most integration confusion comes from the
request fields, not from the language syntax.

### Target, requester, relationship

The target is the entity being evaluated. Most application calls include a
target with one or more identifiers:

```json
{
  "target": {
    "type": "Person",
    "identifiers": [
      {
        "scheme": "national_id",
        "value": "person-1",
        "issuer": "civil_registry"
      }
    ]
  }
}
```

Requester context is optional. Include it when the caller is asking about a
different target or acting on behalf of someone else. Use `relationship` to
explain the permission context, such as `self`, `guardian`, `case_worker`, or a
deployment-specific value.

For token-bound self-attestation flows, omit identity fields and let the server
derive the requester, target, and `self` relationship from the verified token
binding:

```python
result = client.evaluate_request({
    "claims": [{"id": "person-is-alive", "version": "2026-05"}],
    "disclosure": "predicate",
})
```

### Claims and scopes

Claim references may be plain strings or pinned objects with `id` and
`version`. The same versioned claim reference shape is supported for single
evaluation and batch evaluation.

```json
{
  "claims": [
    "person-is-alive",
    { "id": "age-over-18", "version": "2026-05" }
  ]
}
```

The credential behind your auth mode carries a `scopes` list, and every claim
declares its required scopes as part of the evidence service policy. Scope strings are
operator-defined `<namespace>:<operation>` values, for example
`civil_registry:evidence_verification` or `registry_notary:credential_issue`.
There is no fixed global registry of scope names.

When you connect to a deployment you do not operate, ask the operator which
scopes the claims you need require. `GET /v1/claims`, exposed as `list_claims`
or `listClaims`, confirms which claims your credential can see before the first
evaluation.

### Purpose

Evaluation routes can carry a data purpose in the `Data-Purpose` header and in
the request body `purpose` field. If both are present, they must match exactly.
The client rejects mismatches before sending the request.

Set a client default purpose when most calls share one purpose. Override per
call through request options when needed.

### Disclosure and format

Use `disclosure` to request the amount of detail your workflow is allowed to
receive. `predicate` is the common minimized answer for policy gates. Other
disclosure modes and formats are deployment-specific and should be selected
from operator guidance or claim metadata.

## Understanding the response

Successful Python and Node helpers return the decoded response body directly.
Rust returns `NotaryResponse<T>` with the decoded body plus metadata.

A single evaluation response is an object with `results`. Each result represents
one claim answer. This example is abbreviated because real responses include
provenance and matching metadata.

```json
{
  "results": [
    {
      "evaluation_id": "eval-1",
      "claim_id": "person-is-alive",
      "claim_version": "2026-05",
      "target_ref": {
        "type": "Person",
        "handle": "target-1",
        "identifier_schemes": ["national_id"]
      },
      "value": null,
      "satisfied": true,
      "disclosure": "predicate",
      "format": "application/vnd.registry-notary.claim-result+json",
      "issued_at": "2026-05-29T00:00:00Z",
      "expires_at": null,
      "provenance": {}
    }
  ]
}
```

Inspect these fields first:

- `evaluation_id`: save this if you plan to render or issue a credential later.
- `claim_id`: identifies which requested claim this result belongs to.
- `satisfied`: `true`, `false`, or absent when the claim does not map to a
  boolean predicate.
- `value`: a minimized value when the requested disclosure and claim format
  allow it.
- `provenance`: evidence metadata. Do not log it blindly.

## Which method should I use?

| Task | Rust | Python | Node.js |
| --- | --- | --- | --- |
| See claims available to my credential | `list_claims` | `list_claims` | `listClaims` |
| Evaluate one target with helper fields | `evaluate_target(...).send()` | `evaluate` | `evaluate` |
| Send canonical wire JSON | `evaluate_request` | `evaluate_request` | `evaluateRequest` |
| Evaluate many targets safely | `batch_evaluate_request` | `batch_evaluate_request` | `batchEvaluate` or `batchEvaluateRequest` |
| Render an evaluation | `render_request` | `render_request` | `renderRequest` |
| Issue a credential | `issue_credential_request` | `issue_credential_request` | `issueCredentialRequest` |
| Check credential status | `credential_status` | `credential_status` | `credentialStatus` |
| Read issuer JWKS | `issuer_jwks` | `issuer_jwks` | `issuerJwks` |
| Verify SD-JWT VC material | verifier feature | not exposed | not exposed |

Use the high-level helpers when your app is doing the common thing. Use the raw
or request-shaped helpers when you need exact wire JSON, versioned claim
references, route-shaped request bodies, or language binding code.

## Common recipes

### Create a client

Configure exactly one auth mode:

- Bearer token, sent as `Authorization: Bearer <token>`.
- API key, sent as `X-Api-Key`.
- Rust only: dynamic `AuthProvider`.

Supplying more than one auth mode is a client construction error. Debug output
redacts configured auth material.

```rust
let client = RegistryNotaryClient::builder("https://notary.example.gov")
    .bearer_token("access-token")
    .build()?;
```

```rust
let client = RegistryNotaryClient::builder("https://notary.example.gov")
    .api_key("service-key")
    .build()?;
```

```python
client = RegistryNotaryClient(
    base_url="https://notary.example.gov",
    bearer_token="access-token",
)
```

```js
const client = new RegistryNotaryClient({
  baseUrl: "https://notary.example.gov",
  bearerToken: "access-token",
});
```

### Send a full canonical evaluation

Use the canonical request shape when the high-level helper hides fields your
workflow cares about. The Python and Node raw helpers preserve canonical
snake_case JSON.

```python
result = client.evaluate_request(
    {
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
    },
    request_id="req-123",
    traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
)
```

```js
const result = await client.evaluateRequest(
  {
    target: {
      type: "Person",
      identifiers: [{ scheme: "national_id", value: "person-1", issuer: "civil_registry" }],
    },
    relationship: { type: "self" },
    claims: [{ id: "person-is-alive", version: "2026-05" }],
    disclosure: "predicate",
    purpose: "benefits_eligibility",
  },
  {
    requestId: "req-123",
    traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
  },
);
```

Rust callers can also construct core DTOs directly. This is most useful inside
the Registry Notary workspace or when the application already depends on
`registry-notary-core`.

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
    .purpose("benefits_eligibility")
    .request_id("req-123")
    .traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    .build();

let response = client.evaluate_request(request, options).await?;
```

### Batch with retry

Use batch evaluation when several targets share the same claim set. Batch
evaluation is the only POST route that accepts `Idempotency-Key` through the
client. Retries are allowed for this route only when an idempotency key is
supplied. `POST /v1/evaluations`, `POST /v1/evaluations/{evaluation_id}/render`,
and `POST /v1/credentials` reject a request that carries `Idempotency-Key`
with `400 Bad Request`; do not send that header outside batch evaluation.

One request may contain at most 100 items, and the deployment or any selected
claim may advertise a lower limit. The Rust typed client rejects more than 100
items before transport. All clients surface a server-side lower-limit rejection
as HTTP 413 with `batch.too_large`.

For a high-volume workload, split targets into stable ordered slices of no more
than 100, or smaller slices when member results are large. Assign one unique
idempotency key to each slice and persist that key with the slice definition.
Every retry after a timeout, cancellation, process restart, or lost response
must send the identical slice with the same key. Do not reuse a key for the
next slice. Items in the HTTP 200 response remain in request order and may be a
mix of `succeeded` and `failed`; retrying a completed slice replays that result
instead of dispatching its registry consultations again.

```python
from registry_notary import RetryPolicy

client = RegistryNotaryClient(
    base_url="https://notary.example.gov",
    bearer_token="access-token",
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

```js
const controller = new AbortController();

const client = new RegistryNotaryClient({
  baseUrl: "https://notary.example.gov",
  bearerToken: "access-token",
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

### Render an evaluation

Render when you already have an `evaluation_id` and need a configured evidence
format for display, export, or downstream exchange.

Rust accepts the core `RenderRequest` DTO and moves `evaluation_id` into
`/v1/evaluations/{evaluation_id}/render` before sending the body. Python and
Node raw helpers accept canonical snake_case JSON, require a mapping or object,
extract `evaluation_id`, and send the remaining fields as the route body.

```python
rendered = client.render_request({
    "evaluation_id": "eval-1",
    "format": "application/vnd.registry-notary.claim-result+json",
    "disclosure": "predicate",
})
```

```js
const rendered = await client.renderRequest({
  evaluation_id: "eval-1",
  format: "application/vnd.registry-notary.claim-result+json",
  disclosure: "predicate",
});
```

```rust
use registry_notary_core::RenderRequest;

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
```

### Issue a credential

Issue a credential when a successful evaluation should become a credential
artifact, such as an SD-JWT VC. Credential bodies are sensitive. Do not log
them, and note that Rust redacts credential bodies from `Debug`.

The evaluation must be newly created from non-delegated registry-backed claims
and retain an exact compiler pin for every claim in each selected root's
dependency closure, plus one execution record for every unique Relay
consultation ULID. Source-free, delegated, and older stored evaluations remain
renderable but are not issuable. Re-evaluate after upgrading before calling
either the direct issuance or OID4VCI credential endpoint.

```python
credential = client.issue_credential_request({
    "evaluation_id": "eval-1",
    "credential_profile": "person_is_alive_sd_jwt",
})
```

```js
const credential = await client.issueCredentialRequest({
  evaluation_id: "eval-1",
  credential_profile: "person_is_alive_sd_jwt",
});
```

```rust
use registry_notary_core::CredentialIssueRequest;

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

### Discovery and JWKS

Use discovery for claim catalogs, service metadata, and issuer keys. The JWKS
helpers use a short in-process cache when called without request options.
`raw_issuer_jwks` or `rawIssuerJwks` bypasses that cache.

```python
claims = client.list_claims()
claim = client.get_claim("person-is-alive")
service = client.service_document()
jwks = client.issuer_jwks()
client.refresh_jwks()
key = client.get_jwk("key-1")
```

```js
const claims = await client.listClaims();
const claim = await client.getClaim("person-is-alive");
const service = await client.serviceDocument();
const jwks = await client.issuerJwks();
await client.refreshJwks();
const key = await client.getJwk("key-1");
```

```rust
let service = client.service_document(RequestOptions::default()).await?;
let jwks = client.issuer_jwks(RequestOptions::default()).await?;

// Force refresh after an unknown kid during verification.
let refreshed = client.refresh_jwks(RequestOptions::default()).await?;
```

### Credential status

```python
status = client.credential_status("credential-1")
```

```js
const status = await client.credentialStatus("credential-1");
```

```rust
let status = client
    .credential_status("credential-1", RequestOptions::default())
    .await?;

let updated = client
    .update_credential_status("credential-1", "revoked", RequestOptions::default())
    .await?;
```

### OID4VCI

The client wraps issuer metadata and the credential endpoint. It does not start
the browser login, redeem a pre-authorized code, generate holder proofs, or
manage holder keys. Start the issuer-initiated journey at
`/oid4vci/offer/start` and let the wallet redeem the rendered offer. Call the
credential helper only after the wallet has a Notary access token and the
transaction-bound proof nonce returned by the token response.

```python
metadata = client.oid4vci_issuer_metadata()
credential = client.oid4vci_credential({
    "credential_configuration_id": "person_is_alive_sd_jwt",
    "proof": {"proof_type": "jwt", "jwt": "eyJ..."},
})
```

```js
const metadata = await client.oid4vciIssuerMetadata();
const credential = await client.oid4vciCredential({
  credential_configuration_id: "person_is_alive_sd_jwt",
  proof: { proof_type: "jwt", jwt: "eyJ..." },
});
```

In Rust, enable the `oid4vci` feature:

```toml
registry-notary-client = {
  git = "https://github.com/registrystack/registry-stack",
  tag = "vX.Y.Z",
  features = ["oid4vci"]
}
```

```rust
let metadata = client
    .oid4vci_issuer_metadata(RequestOptions::default())
    .await?;
```

### Federation

The client submits an already-signed JWT. It does not mint or sign federation
requests.

```python
response_jws = client.federation_evaluate_jws("eyJ...")
```

```js
const responseJws = await client.federationEvaluateJws("eyJ...");
```

In Rust, enable the `federation` feature:

```toml
registry-notary-client = {
  git = "https://github.com/registrystack/registry-stack",
  tag = "vX.Y.Z",
  features = ["federation"]
}
```

```rust
let compact_response_jws = client
    .federation_evaluate_jws("eyJ...", RequestOptions::default())
    .await?;
```

## Production checklist

### Base URL

Use the service root URL. A path prefix is allowed and is preserved when routes
are joined.

Clients require HTTPS for non-loopback hosts. Rust allows HTTP loopback only in
debug or `test-support` builds. Python and Node local workflows may use
`http://127.0.0.1`, `http://localhost`, or `http://[::1]`.

Python also exposes an explicit lab/internal escape hatch for Docker Compose
and private service-network deployments:

```python
client = RegistryNotaryClient(
    base_url="http://registry-notary:8080",
    default_purpose="benefits_eligibility",
    allow_insecure_internal_http=True,
)
```

Use `allow_insecure_internal_http=True` only when transport is already
protected by the deployment boundary or a local development network. Production
service URLs should remain HTTPS.

### Request metadata

Request options support:

- `purpose`, mapped to `Data-Purpose`.
- `request_id` or `requestId`, mapped to `X-Request-Id`.
- `traceparent`, mapped to W3C trace context.
- `idempotency_key` or `idempotencyKey`, mapped to `Idempotency-Key` only for
  batch evaluation.
- `accept`, for Rust, JSON facade, and selected Python request helpers that
  need an explicit `Accept`. Node does not expose a public accept override.

### Retry contract

Retries are disabled by default. When enabled, they are route-aware:

- GET routes may retry transport errors, 429, or 503 according to the policy.
- `POST /v1/batch-evaluations` may retry only when an `Idempotency-Key` is
  supplied.
- Evaluation, render, credential issuance, OID4VCI credential, and federation
  submission are never retried because those POST routes are not deduplicated by
  the server.

`Retry-After` seconds are honored. Rust, Python, and Node also handle HTTP-date
`Retry-After` by using the response `Date` header as the reference clock when it
is present.

### Response metadata

All typed Rust methods return `NotaryResponse<T>` with:

- `body`: decoded response body.
- `status`: HTTP status returned by the server.
- `request_id`: server `X-Request-Id`, when present.
- `retry_after`: server `Retry-After`, when present.

Python and Node expose equivalent fields on errors. Successful Python and Node
helpers return the response body directly.

### Error handling and redaction

Rust returns `NotaryClientError`. Python and Node expose:

- `NotaryError`
- `NotaryTransportError`
- `NotaryProblemError`

Safe fields for logs are `status`, `code`, `title`, `retryable`, and
`request_id`. Do not log raw request bodies, requester or target identifiers,
holder proofs, credential bodies, SD-JWT disclosures, nonces, Authorization,
`X-Api-Key`, or Problem Details `detail`.

Problem detail strings are not exposed by the Python wrapper. The Rust
`portable()` error envelope is intended for language bindings and FFI. It
intentionally excludes sensitive detail strings.

The stable application problem `code` categories for policy mapping live in the
[problem categories in the API reference](api-reference.md#problem-categories).

### Troubleshooting

| Symptom | Likely cause | Check |
| --- | --- | --- |
| `401` | Missing, expired, or wrong auth credential | Token/API key source and configured auth mode |
| `403` | Credential lacks a claim's `required_scope` | `list_claims`, operator scope mapping |
| Client rejects before send | Body `purpose` and header/default purpose differ | Request body and client options |
| Batch did not retry | Missing idempotency key or retry policy disabled | `idempotency_key`/`idempotencyKey`, retry settings |
| Render request fails | `evaluation_id` missing or empty | Use an id from a previous evaluation result |
| Unknown signing key | JWKS cache does not have the `kid` | `refresh_jwks`/`refreshJwks` or Rust verifier refresh path |

## Runtime reference

### Rust features

Enable optional routes only when needed:

```toml
registry-notary-client = {
  git = "https://github.com/registrystack/registry-stack",
  tag = "vX.Y.Z",
  features = ["oid4vci", "federation", "json-facade"]
}
```

In a workspace checkout, the same feature selection can use path dependencies:

```toml
registry-notary-client = {
  path = "crates/registry-notary-client",
  features = ["oid4vci", "federation", "json-facade"]
}
```

### Rust JSON facade

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

### Rust credential verification

Enable the Rust `verifier` feature when relying-party or wallet code needs to
verify SD-JWT VC credential material. Verification is explicit and opt-in:
transport methods continue to return decoded response bodies without hidden
network refreshes or trust-policy decisions.

```toml
registry-notary-client = {
  git = "https://github.com/registrystack/registry-stack",
  tag = "vX.Y.Z",
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

Selective-disclosure presentations may include a subset of disclosures. Each
presented disclosure must hash to a digest in the credential. When a
presentation includes a key-binding JWT, the verifier separates it from
disclosures and verifies its holder proof signature against the credential
`cnf.jwk`. When required holder binding is paired with
`VerifyOptions::key_binding_challenge`, the trailing key-binding JWT is
mandatory and must match the expected audience and nonce.

Verifier errors are redacted and safe for policy mapping by code. Stable codes
include `signature.invalid`, `key.unknown`, `algorithm.disallowed`,
`claim.issuer_mismatch`, `claim.vct_mismatch`, `claim.time_invalid`,
`disclosure.digest_mismatch`, `holder_binding.required`,
`holder_binding.kid_mismatch`, and `holder_binding.proof_invalid`.

Python and Node do not expose verifier wrappers. Callers in
those runtimes should use the Rust verifier through their application boundary
or perform verification in wallet-specific code.

### Python async helpers

Async evaluation helpers are prefixed with `a`, for example `aevaluate` and
`aevaluate_request`. The package also exposes async forms for batch evaluation,
rendering, and credential issuance:

```python
result = await client.aevaluate_request({
    "claims": ["person-is-alive"],
    "disclosure": "predicate",
})
```

### Node abort signals

Node request helpers accept `signal` in request options. The high-level
`evaluate` and `batchEvaluate` helpers also accept `signal` on the request
object for convenience.

```js
const controller = new AbortController();

const result = await client.evaluate({
  target: { type: "Person", identifiers: [{ scheme: "national_id", value: "person-1" }] },
  claims: ["person-is-alive"],
  signal: controller.signal,
});
```

### Discovery, status, OID4VCI, federation

```js
const claims = await client.listClaims();
const claim = await client.getClaim("person-is-alive");
const jwks = await client.issuerJwks();
await client.refreshJwks();
const key = await client.getJwk("key-1");
const status = await client.credentialStatus("credential-1");

const metadata = await client.oid4vciIssuerMetadata();

const responseJws = await client.federationEvaluateJws("eyJ...");
```

### Node errors

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

## API method matrix

The route families used by each runtime are listed under
[main surfaces in the API reference](api-reference.md#main-surfaces).
