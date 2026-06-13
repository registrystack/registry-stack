# OpenFn Registry Notary Caller Integration

Demo integration package for OpenFn workflows that call Registry Notary as a
trust decision service. This is not an official OpenFn adaptor.

This package is intentionally separate from the OpenFn source-sidecar helper in
`crates/registry-notary-openfn-sidecar/workers/adaptors/registry-notary`.

## Template

`jobs/evaluate-claim-http.js` shows the first safe HTTP workflow shape. It uses
a local helper instead of `@openfn/language-http` for the Notary request because
`@openfn/language-http@7.3.1` can log non-2xx response bodies before workflow
code can redact Problem Details `detail`.

- prepare a minimized `POST /v1/evaluations` body;
- send `Authorization`, `Data-Purpose`, and `X-Request-Id`;
- propagate `traceparent` when upstream workflow state provides one;
- read `EvaluationResponse.results` as an array;
- take `evaluation_id` from the selected `ClaimResultView`;
- branch through helper output;
- strip request material, raw subject identifiers, and secret-backed
  configuration from final state.

## Auditability And Signature Boundary

The helper exposes audit correlation fields in final workflow state:
`request_id`, `evaluation_id`, `purpose`, selected claim id, branch, and an
HMAC `target_fingerprint`. It also forwards `traceparent` to Notary when the
incoming OpenFn state contains one.

This demo does not verify cryptographic signatures on evaluation responses.
If a workflow consumes an issued SD-JWT VC credential, verify that credential
separately against trusted JWKS and caller policy. The Rust Notary client has
`registry_notary_client::verifier::verify_sd_jwt_vc`; this JavaScript demo does
not wrap it.

OpenFn dependency:

```text
@openfn/language-common@3.3.3
@openfn/compiler@1.2.5
@openfn/runtime@1.9.3
```

Demo profile assumption: matching-error collapse is enabled. Production
workflows should expect `evidence.not_available` unless the operator has
explicitly exposed granular matching errors in a controlled profile.

## Verification

```sh
npm ci --ignore-scripts --no-audit --no-fund
node --check src/index.js
node --check jobs/evaluate-claim-http.js
npm test
```
