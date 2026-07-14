# Notary GITB Conformance Suite

> **Status:** active design note
> **Product:** Registry Notary
> **Layer:** runtime interoperability
> **Audience:** maintainer, operator, standards reviewer

This suite is the target shape for testing Registry Notary as a system under
test through the ISA ITB/GITB stack. It separates hygiene checks from runtime
interoperability checks so OpenAPI validation or health probes are not mistaken
for end-to-end conformance.

## Definition of Done

- The suite runs against a disposable Notary instance plus either a disposable
  Relay consultation fixture for registry-backed claims or a source-free
  self-attestation fixture, not a shared operator environment.
- Required credentials are supplied through environment variables or GITB
  actor/session parameters. No API keys, bearer tokens, issuer keys, Relay
  workload tokens, or replay secrets are committed.
- Every scenario records the Notary base URL, selected deployment profile,
  configured claim IDs, credential profile IDs, and expected auth mode.
- At least one positive authenticated evaluation and one negative auth case are
  runnable before any public runtime-conformance claim is made.
- Results distinguish hygiene checks from runtime interoperability checks.
- SD-JWT VC verification uses the existing verifier harness logic or an
  equivalent custom GITB service before credential issuance is marked covered.

## Scenario Set

| ID | Scenario | Type | Done when |
| --- | --- | --- | --- |
| `health-live` | `GET /healthz` returns `200` | hygiene | HTTP status and response body are recorded. |
| `discovery-auth-denied` | unauthenticated `GET /.well-known/evidence-service` returns `401` | runtime auth | The response is RFC 9457-style problem JSON with an auth error code. |
| `discovery-authenticated` | authenticated `GET /.well-known/evidence-service` returns service metadata | runtime discovery | Response includes `service_id`, configured claims, and credential capabilities. |
| `claims-authenticated` | authenticated `GET /v1/claims` returns configured claims | runtime discovery | Response includes the configured positive-evaluation claim. |
| `evaluation-positive` | authenticated `POST /v1/evaluations` succeeds for a compiler-pinned Relay fixture or source-free self-attestation | runtime evaluation | Response contains the expected claim result and no raw Relay output or self-attested input spillover. |
| `evaluation-auth-denied` | unauthenticated `POST /v1/evaluations` returns `401` | runtime auth | No Relay consultation or claim evaluation is started. |
| `credential-issue` | authenticated `POST /v1/credentials` issues `application/dc+sd-jwt` | runtime credential | Credential response verifies against the configured public issuer key. |
| `credential-status` | `GET /v1/credentials/{id}/status` returns the configured status response | runtime status | Enabled status lookup is reachable without exposing unrelated credential data. |
| `federation-positive` | signed `POST /federation/v1/evaluations` succeeds for one trusted peer | runtime federation | Peer signature, purpose, replay key, and result are checked. |
| `federation-replay-denied` | repeated signed federation request is denied | runtime federation | Replay denial is deterministic and audited. |

## First Runnable Slice

The first implementation wave should cover only:

- `health-live`
- `discovery-auth-denied`
- `discovery-authenticated`
- `claims-authenticated`
- `evaluation-positive`
- `evaluation-auth-denied`

Done for the first slice means:

- a fixture Notary config and either its compiler-pinned Relay fixture or its
  source-free self-attestation inputs can be started from a clean checkout;
- `/.well-known/evidence-service` is intentionally authenticated and returns
  `401` without credentials;
- the same route returns metadata with a configured API key or bearer token;
- one evaluation succeeds against the configured Relay consultation or
  self-attestation fixture;
- the unauthenticated evaluation attempt returns `401` and produces no positive
  result;
- the test report includes exact request paths, response status codes, and saved
  redacted response bodies.

Credential issuance, credential status, federation, replay, and SD-JWT VC
verification are later waves. They must not be described as GITB-covered until
their scenarios are runnable and produce saved reports.

## Evidence Boundary

OpenAPI 3.1 validation, `/healthz`, and JSON-schema checks are useful hygiene
evidence. They do not prove runtime interoperability. Public wording must not
claim Registry Notary GITB conformance until the runtime scenarios above are
implemented, run, and reviewed.
