# Call Registry Notary From An OpenFn Workflow

> **Page type:** How-to · **Product:** Registry Notary · **Layer:** evaluation · **Audience:** integrator

This guide shows the caller-side OpenFn pattern: an OpenFn workflow calls
Registry Notary to evaluate a configured claim, then branches on the Notary
result. This is separate from the source adapter sidecar source path, where
Registry Notary calls a private OpenFn-powered sidecar to read upstream source
data.

Use this pattern when a workflow needs a governed claim answer before it takes
an action, and the workflow should not receive or copy source registry rows.

## Boundary

OpenFn owns workflow orchestration:

- triggers;
- system-to-system delivery;
- case routing;
- notifications;
- workflow run history.

Registry Notary owns the evidence decision:

- caller authentication;
- purpose and claim policy;
- source matching;
- disclosure;
- credential issuance;
- Notary audit and provenance.

The workflow should treat Notary as a trust decision service, not as a raw data
source.

## OpenFn Adaptor

The current OpenFn language adaptor lives in:

```text
https://github.com/jeremi/openfn-language-registry-stack
```

When that repository is configured as an OpenFn local adaptor repository,
Lightning and the worker load the Notary package as:

```text
@openfn/language-registry-notary@local
```

Configure an OpenFn credential with:

- `notary_base_url`: Registry Notary service base URL.
- `token`: bearer token for the Notary caller credential.
- `openfn_request_fingerprint_key`: local OpenFn HMAC key used by the helper
  for replay-safe request fingerprints. It is not sent to Registry Notary.
- `openfn_target_fingerprint_key`: optional separate HMAC key for the
  `target_fingerprint` audit value.

For local development in this repository, the older runnable helper and
workflow template still live in:

```text
demo/openfn-notary-caller/
```

The adaptor and local template use a safe helper rather than `@openfn/language-http`
for the Notary request. In `@openfn/language-http@7.3.1`, non-2xx responses can
log response bodies before workflow code can redact Problem Details `detail`.
The helper prepares a minimized `POST /v1/evaluations` request. It:

- sends `Authorization`, `Data-Purpose`, and `X-Request-Id`;
- propagates `traceparent` when upstream workflow state provides one;
- keeps the body `purpose` equal to the `Data-Purpose` header;
- reads `EvaluationResponse.results` as an array;
- selects a claim with `results.find((item) => item.claim_id === claimId)`;
- takes `evaluation_id` from the selected claim result;
- maps 2xx result bodies separately from non-2xx Problem Details;
- strips request material and secret-backed configuration from final state.

## Minimal Workflow

The first workflow should read like a claim gate, not like a raw HTTP call:

```js
const evaluationOptions = {
  claimId: "farmer-registered",
  purpose: "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
  disclosure: "predicate",
  target: {
    type: "Farmer",
    identifiers: [{ scheme: "farmer_id", valueFrom: "farmer_id" }],
  },
};

execute(
  fn((state) => callNotaryEvaluation(state, evaluationOptions)),
  fn((state) => {
    const approved = state.data.notary.branch === "satisfied";

    return {
      ...state,
      data: {
        decision: {
          status: approved ? "approved" : "manual_review",
          notary_evaluation_id: state.data.notary.evaluation_id,
          notary_request_id: state.data.notary.request_id,
        },
      },
    };
  }),
);
```

The public Registry Stack lab publishes current demo service URLs and caller
tokens at:

```text
https://lab.registrystack.org/api/lab.json
```

Use the `agri-evidence` credential for the agriculture Notary examples. The
lab UI at `https://lab.registrystack.org` shows the same public demo
credentials.
For SDK-style environment variables, run
`registryctl lab env --credential agri-evidence`; it reads the same manifest
entry and emits the Notary base URL, bearer token, and purpose URI.

## Value Claims

When a workflow needs a fact such as farmed land size, model that fact as a
Registry Notary value claim instead of querying the source Relay from OpenFn.
The Notary remains the evidence boundary, and OpenFn consumes only the
minimized claim result:

```js
const evaluationOptions = {
  claimId: "farmer-registration-and-land-size",
  purpose: "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
  disclosure: "value",
  target: {
    type: "Farmer",
    identifiers: [{ scheme: "farmer_id", valueFrom: "farmer_id" }],
  },
};

execute(
  fn((state) => callNotaryEvaluation(state, evaluationOptions)),
  fn((state) => {
    const evidence = state.data.notary.value;
    const farmedAreaHa = Number(evidence.farmed_land_size_hectares ?? 0);
    const approved =
      evidence.is_registered_farmer === true &&
      evidence.active_holding === true &&
      farmedAreaHa >= 1 &&
      farmedAreaHa <= 3;

    return {
      ...state,
      data: {
        decision: {
          status: approved ? "approved" : "manual_review",
          evidence: {
            holding_id: evidence.holding_id,
            farmed_area_ha: farmedAreaHa,
            district: evidence.district,
            notary_evaluation_id: state.data.notary.evaluation_id,
          },
        },
      },
    };
  }),
);
```

Composite value claims like this must be configured in the Notary deployment.
Do not replace them with direct Relay reads when the workflow needs a certified
trust decision.

## Auditability And Verification Boundary

The OpenFn caller helper preserves correlation data that operators need for
audit review:

- caller `X-Request-Id`;
- incoming `traceparent`, when present;
- Notary response `x-request-id`, or Problem Details `request_id` when a
  response header is unavailable;
- selected claim id;
- selected `evaluation_id`;
- Notary purpose;
- HMAC target fingerprint.

The helper does not verify a cryptographic signature on the evaluation
response. `POST /v1/evaluations` is treated as an authenticated service call
that returns a decision plus audit correlation fields.

When the workflow consumes an issued SD-JWT VC credential, signature
verification is a separate caller responsibility. The Rust client exposes this
through `registry_notary_client::verifier::verify_sd_jwt_vc`, which verifies the
compact credential against caller-supplied trusted JWKS and policy options.
That verifier is not wrapped by this JavaScript OpenFn demo.

Run the focused checks:

```sh
npm ci --ignore-scripts --no-audit --no-fund --prefix demo/openfn-notary-caller
node --check demo/openfn-notary-caller/src/index.js
node --check demo/openfn-notary-caller/jobs/evaluate-claim-http.js
npm test --prefix demo/openfn-notary-caller
```

## Branching

The helper maps these branches:

| Branch | Source | Meaning |
| --- | --- | --- |
| `satisfied` | 2xx result body | Requested claim is satisfied |
| `not_satisfied` | 2xx result body | Requested claim evaluated false |
| `not_found` | Problem Details | Granular target not found |
| `ambiguous` | Problem Details | Granular target match ambiguous |
| `evidence_not_available` | Problem Details | Collapsed matching or evidence failure |
| `policy_denied` | Problem Details | Purpose, profile, requester, or relationship policy denial |
| `source_unavailable` | Problem Details | Evidence source unavailable |
| `retryable_infrastructure` | Transport or Problem Details | Retryable infrastructure status |
| `idempotency_conflict` | Problem Details | Reused idempotency key with different request |
| `invalid_request` | Problem Details | Malformed or unsupported request |

Deployment profiles may collapse granular matching outcomes to
`evidence.not_available` to avoid oracle behavior. Workflow logic must not
assume that granular `target.not_found` or `target.match_ambiguous` codes are
visible in production.

The demo assumes matching-error collapse is enabled and treats
`evidence.not_available` as the default production-safe failure branch.

## Replay Safety

OpenFn platform retries can replay an entire job. The template avoids duplicate
Notary evaluations by skipping `POST /v1/evaluations` when workflow state
already contains a safe Notary result for the same claim, purpose, and
target fingerprint.

Do not enable automatic retries for non-idempotent Notary POST routes:

- `POST /v1/evaluations`
- `POST /v1/evaluations/{evaluation_id}/render`
- `POST /v1/credentials`
- `POST /oid4vci/credential`
- `POST /federation/v1/evaluations`

For batch evaluation, use `POST /v1/batch-evaluations` with an
`Idempotency-Key`. Treat `idempotency.conflict` as an implementer or operator
alert, not as a loopable retry.
