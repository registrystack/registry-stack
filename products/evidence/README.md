# Evidence

Status: implemented Version 1 contracts, runtime, reference deployments, and
reproducible Evidence-specific verification gates.

Evidence is a greenfield, sector-neutral minimum-disclosure assertion service.
Given authenticated authority, an authorized purpose, a predefined requirement,
and the configured selector data needed by an authoritative provider, it returns
the smallest sufficient JSON assertion in an authorized response format.
Evidence is not a Registry Notary mode, rewrite, or reduced configuration.

The approved Version 1 product boundary is one `registry-evidence` crate, one
`evidence` binary, one serving process, and one operator-controlled trust domain.
A process may host multiple evidence definitions only when they share that trust
domain. Governed configuration, Rhai scripts, schemas, codelists, and fixtures
are one trusted, immutable, startup-only evidence bundle. A separate closed
runtime file owns only process-local listener, filesystem, audit-storage,
secret-mount, and TLS-trust bindings and cannot override governed semantics.

The following contracts define and verify the implemented Version 1 boundary:

- [Product concept](CONCEPT.md): product boundary, data model, trust and privacy
  invariants, native API, and Version 1 acceptance set.
- [Implementation schedule and Definition of Done](IMPLEMENTATION.md): phases,
  exit gates, required tests, verification, and stop boundary.
- [Source-testing contract](SOURCE-TESTING.md): deterministic mock matrix,
  optional public-demo smoke tests, credential handling, and failure
  interpretation.
- [Operator contract](OPERATOR-CONTRACT.md): supported deployment shape,
  requester authority and purpose duties, required configuration and secrets,
  readiness, audit, key, and verification obligations.
- [Trusted request-adapter reference](reference/request-adapter/ADAPTER-API.md):
  complete Rhai API, configuration and fixture contracts, and deployable DHIS2
  and OpenCRVS-shaped reference projects.

Any normative schemas, examples, and generated public artifacts live in their
own tracked contract directories. Generated files must be reproduced by their
documented generator and never edited by hand.

## Version 1 boundary

Version 1 supports assertion evidence through one synchronous JSON operation
with signed flattened JWS as the mandatory default format. Rust owns
authentication, authorization, minimized preparation
inputs, fixed source execution, response projection, bounded Rhai execution,
output validation, evidence construction, response protection, and audit. Rhai owns
reviewed request query/body rendering, source extraction, and
requirement-specific derivation using only deterministic, bounded,
domain-neutral primitives supplied by Rust.

Adult status, residence region, professional licence status, and legal-parent
relationship are coequal full-path acceptance definitions. All four must pass
the same offline and production path on one revision before Version 1 can be
called implemented. None may become a Rust domain type, built-in operation,
special route, or preferred implementation phase.

Version 1 does not include documents, holder credentials, OID4VCI, SD-JWT,
nonce or replay storage beyond stateless request-nonce echo and comparison,
server-issued challenges, OOTS execution, federation, delegated agents, MCP,
workflow, public or federated catalogs, runtime policy, runtime bundle mutation,
multi-source fulfillment, source planning, an application database, a message
broker, or workers. It must not depend on `registry-notary*`.

DHIS2 and OpenCRVS are compatibility-shaped test profiles only. Their names and
behavior may appear in tests, sanitized fixtures, test-only bundles, and local
smoke documentation. Production Rust, Cargo metadata, public configuration,
routes, CLI options, and generated public contracts must remain source-product
neutral.

## Discovering available evidence

An authenticated caller lists the complete Evidence request shapes it can
currently invoke with `GET /v1/evidence-definitions`. The response is computed
from the immutable deployed bundle and the caller's verified token. It contains
only combinations that match exactly one authority path, including requirement,
Evidence Type, purpose, output concepts, subject roles, selector profiles,
value origins, and safe selector field validation metadata. An unentitled
caller receives an empty list. An ambiguous authority shape is omitted because
the corresponding evidence request would be denied.

This is requester-scoped discovery, not a public or process-wide catalog. The
response excludes source URLs and identifiers, paths, projections, scripts,
adapter parameters, credentials, internal authority-profile names and tags,
selector values, codelist values, and definitions unavailable to that caller.
Discovery performs no provider request and creates no evidence-data audit
event. Metadata never grants authority; `POST /v1/evidence` authenticates and
authorizes the complete tuple again.

The generated OpenAPI defines both operations, and the running service publishes
that same document unauthenticated at `GET /openapi.json`. Operators still
publish static onboarding material through their API catalog, developer portal,
configuration repository, or bilateral process for token acquisition, human
descriptions, legal context, endpoint trust, and verifier policy. The public
JWKS at `/.well-known/evidence/jwks.json` supplies verification keys only. The
complete contract and change rules are in
[the operator contract](OPERATOR-CONTRACT.md#discovery-of-available-evidence).

## Requesting evidence

`POST /v1/evidence` takes one complete request naming the requirement, purpose,
subjects, and a required `requestNonce`. The nonce is the canonical unpadded
base64url encoding of exactly 32 random bytes, so exactly 43 characters, and
must be freshly generated for every request. Evidence echoes it into the
Evidence payload under `requestNonce` and covers it by the signature, so a
caller that retained the value it sent can confirm the assertion answers that
request. Evidence never stores it, never rejects reuse, and never uses it for
authorization, rate limits, scripts, source requests, logs, metrics, traces, or
audit. Callers must not encode identifiers, selectors, secrets, or document
digests in it.

Signed flattened JWS is the default and the only later-verifiable format. A
missing `Accept`, `*/*`, or the exact `application/jose+json` all select it. The
exact `application/vnd.registrystack.evidence-unsigned+json` selects a visibly
unsigned envelope, and only when both the immutable bundle and the one complete
matched grant permit that format; otherwise the request is refused with the
ordinary `not_authorized` problem before credentials or source access, without
revealing which layer refused. A duplicate, combined, parameterized, weighted,
or unknown `Accept` returns the `response_format_not_acceptable` problem with
HTTP 406 before source access. Unsigned output is transport-authenticated
convenience data for development and for consumers that cannot process JWS. It
is never later-verifiable evidence and never a fallback when signing fails.

## Current verification

From the monorepo root, the Evidence-specific reproducible gate is:

```sh
cargo fmt --check
cargo check --locked -p registry-evidence --all-targets
cargo test --locked -p registry-evidence
cargo clippy --locked -p registry-evidence --all-targets -- -D warnings
products/evidence/scripts/check-contracts.sh
products/evidence/scripts/check-source-neutrality.sh
```

Generated JSON Schema and OpenAPI artifacts are under `generated/`. The
contract gate recreates them from Rust in a temporary directory and requires an
exact diff. The complete workspace and dependency-policy gates remain those in
[the implementation schedule](IMPLEMENTATION.md).

## Security

Changes to authentication, authorization, disclosure, audit, configuration
trust, signing, source credentials, or selector handling require explicit
security review notes naming the threat, Rust enforcement point, and negative
test. Report suspected vulnerabilities through the repository process in
`SECURITY.md`, not a public issue.
