# registry-evidence-client

Relying-party client for requesting and verifying signed Evidence Version 1
responses.

This is adopter tooling beside the Evidence runtime, like `registryctl` is for
the rest of the stack. It sits outside the frozen Version 1 runtime contract and
it re-implements no part of evaluation, signing, or verification: every
judgement about a response is made by `registry-evidence-verifier`.

## What It Provides

- `EvidenceClient::prepare`: generates the request nonce and closes the
  verification policy before any byte leaves the process.
- `EvidenceClient::send` and `EvidenceClient::verify`, or
  `EvidenceClient::request_and_verify` for both at once. `send` returns the exact
  response bytes so a relying party can retain what it verified.
- `EvidenceClient::discover`: the requester-scoped definitions document, for
  authoring a relying procedure against the shapes a deployment will accept.
- `EvidenceClient::fetch_jwks`: the deployment's published key set, for an
  out-of-band pinning workflow only.
- `TokenProvider` and `StaticToken` for the bearer credential the deployment's
  resource-server authentication expects.

## Typical Use

```rust,no_run
use std::sync::Arc;

use registry_evidence_client::{
    EvidenceClient, EvidenceClientConfig, EvidenceClientError, PreparedEvidenceRequest,
    StaticToken, VerifiedEvidence,
};

/// `trusted_jwks` is the key set the integrator reviewed and pinned out of band.
/// The prepared request carries the nonce and the closed policy that will judge
/// the answer.
async fn accept(
    base_url: url::Url,
    access_token: &str,
    trusted_jwks: registry_evidence_client::JwksDocument,
    prepared: &PreparedEvidenceRequest,
) -> Result<VerifiedEvidence, EvidenceClientError> {
    let client = EvidenceClient::new(EvidenceClientConfig::new(
        base_url,
        Arc::new(StaticToken::new(access_token)?),
        trusted_jwks,
    ))?;
    client.request_and_verify(prepared).await
}
```

## Security Notes

- The published key set is discovery, not a trust anchor. Verification always
  uses the key set pinned at construction. Nothing here fetches keys at
  verification time, because a key set taken from the same origin as the
  response it would verify establishes nothing about that response.
- One prepared request is one exchange, enforced rather than advised. Neither this
  crate nor its HTTP client retries anything, and a second `send` with the same
  prepared request fails locally before any I/O: a second attempt is a second
  `prepare` with a fresh nonce, because a policy accepts exactly the answer to the
  request it was closed for, and a deployment never uniqueness-checks a nonce, so
  a resend would earn a second source access and a second audit entry there.
  Verifying is exempt: it is offline and idempotent, so a retained response may be
  re-verified as often as the relying party likes.
- Subject bindings are keyed values the deployment computes with a secret only it
  holds, so a relying party cannot derive the binding for a subject it has never
  seen. `SubjectExpectations::Pinned` is the only setting under which a verified
  response proves the assertion is about the subject the relying party meant.
  `SubjectExpectations::AcceptFirstUse` accepts the deployment's own answer to
  the identity question once, enforces every other expectation, and exposes the
  accepted bindings so the caller persists them and pins them from then on. It
  adopts bindings only for exactly the roles the request asked about, once each,
  so a response that renames, adds, or drops a role is refused.
- Credentials are held in a buffer that is wiped on drop, marked sensitive on the
  outbound header, and never placed in an error, a `Debug` rendering, or a log
  line. Response bytes and header values are withheld from diagnostics too; a
  failure carries the deployment's operation identifier for support correlation.
- Every response is read under a caller-configured byte bound before it is
  parsed.

## Testing

```sh
cargo test -p registry-evidence-client
```

The integration suite starts a real Evidence deployment over loopback HTTP and
drives the whole exchange through it, so discovery, the request contract, the
problem contract, and verification are proven against the runtime rather than
against a stub.

## License

Apache-2.0.
