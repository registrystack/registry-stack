# Client SDK Guide

Registry Notary includes a Rust client and Python and Node.js bindings. Use the
clients when application code should not reimplement the wire contract, purpose
handling, bounded response reads, or redacted error mapping.

## Status

The Rust client is the primary typed client. Python and Node.js bindings are
available under `bindings/`. Rust keeps OID4VCI and federation feature-gated;
the pure Python and Node wrappers expose those HTTP endpoint helpers directly
without generating holder proofs or signing federation JWTs.

## Rust Client

Create a client:

```rust
use registry_notary_client::RegistryNotaryClient;

let client = RegistryNotaryClient::builder("https://notary.example.gov")
    .bearer_token(token)
    .default_purpose("benefits_eligibility")
    .user_agent("benefits-service/1.0")
    .build()?;
```

The client supports:

- health and readiness;
- admin reload;
- OpenAPI, service document, JWKS, and metrics;
- claim discovery;
- evaluate and batch evaluate;
- render;
- direct credential issuance;
- credential status and admin status update;
- OID4VCI methods when the feature is enabled;
- federation JWS evaluation when the feature is enabled.

## Ergonomic Evaluate

```rust
let result = client
    .evaluate("person-1")
    .id_type("national_id")
    .claims(["person-is-alive"])
    .purpose("benefits_eligibility")
    .disclosure("predicate")
    .send()
    .await?;
```

## Safety Defaults

The client:

- rejects multiple auth modes at build time;
- redacts secrets in debug and errors;
- disables redirects;
- ignores proxy environment variables;
- uses bounded response reads;
- uses route-specific body limits;
- caches JWKS briefly for default JWKS fetches;
- keeps retry behavior conservative.

## Purpose Handling

Set a default purpose on the client when most requests share one purpose. Route
options can override it. Do not send conflicting purpose values in both headers
and request bodies.

## Python Binding

The Python package under `bindings/python` exposes high-level and raw evaluate
helpers, async evaluate, discovery and JWKS helpers, OID4VCI endpoint wrappers,
federation JWS submission, route-aware retry policy, and redacted Problem
Details mapping.

Use the binding for Python application code that should not reimplement the
wire contract or error parsing.

## Node.js Binding

The Node package under `bindings/node` is a promise-based client with
TypeScript declarations. It exposes the same core routes as the Python binding,
adds high-level camelCase conversion, supports `AbortSignal`, and includes
discovery/JWKS, OID4VCI, federation, and route-aware retry helpers.

Useful package scripts:

```bash
npm test
npm run check:types
```

## Error Handling

Client errors are designed not to expose secrets, tokens, holder material, raw
source rows, or sensitive Problem Details internals.

Application logs should include workflow-level context such as operation name
and status class, not raw request bodies, subject ids, holder proofs, source
errors, or tokens.

## Done Check

A client integration is ready when it uses one auth mode, sends one purpose
value, handles Problem Details without leaking sensitive fields, tests success
and denial paths, and avoids direct HTTP calls for routes covered by the client.
