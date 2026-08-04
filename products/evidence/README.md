# Evidence

Status: implemented Version 1 contracts, runtime, reference deployments, and
reproducible Evidence-specific verification gates.

Evidence is a greenfield, sector-neutral minimum-disclosure assertion service.
Given authenticated authority, an authorized purpose, a predefined requirement,
and the configured selector data needed by an authoritative provider, it returns
the smallest sufficient JSON assertion in an authorized response format.

The approved Version 1 product boundary is one `registry-evidence` crate, one
`evidence` binary, one serving process, and one operator-controlled trust domain.
The runtime depends on one portable library beside it,
`registry-evidence-verifier`, which owns the response formats, the Evidence
payload contract, and relying-party verification, so client tooling can verify a
signed response without the runtime. A process may host multiple evidence
definitions only when they share that trust domain. Governed configuration, Rhai
scripts, schemas, codelists, and fixtures are one trusted, immutable,
startup-only evidence bundle. A separate closed runtime file owns only
process-local listener, filesystem, audit-storage, secret-mount, and TLS-trust
bindings and cannot override governed semantics.

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
- [SD-JWT VC demo](SD-JWT-VC-DEMO.md): one deterministic local run that issues
  the same assertion in both later-verifiable formats and re-verifies the
  credential offline with `curl` and the `evidence` binary.
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

Version 1 serializes the same assertion as an SD-JWT VC when the bundle and the
matched grant both permit that response format, under the frozen profile in
`contracts/sd-jwt-vc-profile.yaml`. It does not include documents, credential
lifecycle, status lists, OID4VCI, presentation verification,
nonce or replay storage beyond stateless request-nonce echo and comparison,
server-issued challenges, OOTS execution, federation, delegated agents, MCP,
workflow, public or federated catalogs, runtime policy, runtime bundle mutation,
multi-source fulfillment, source planning, an application database, a message
broker, or workers.

DHIS2 and OpenCRVS are compatibility-shaped test profiles only. Their names and
behavior may appear in tests, sanitized fixtures, test-only bundles, and local
smoke documentation. Production Rust, Cargo metadata, public configuration,
routes, CLI options, and generated public contracts must remain source-product
neutral.

## Adopter tooling

`evidencectl`, built from the `registry-evidencectl` crate, is adopter tooling
beside the runtime, like `registryctl` for the rest of the stack. It sits
outside the frozen Version 1 runtime contract: it generates key material,
starts incomplete OpenAPI-assisted authoring workspaces, compiles a reviewed
production candidate, and drives fixture runs for complete projects. It shells
out to the `evidence` binary for every Evidence semantic decision and never
re-implements evaluation, signing, or verification. Its source remains covered
by the same source-product and domain-neutrality checks as the runtime.

`evidencectl new <dir> --openapi <file-or-url> --profile local` retains the
OpenAPI document exactly as `source.openapi.yaml` and creates empty
`questions/`, `derivations/`, and `fixtures/` directories. `--generate-keys`
adds owner-only disposable local key material that is not bound to a runtime.
The command does not select an API operation, invent a question, fixture,
policy, production target, Mint configuration, or deployable bundle.

`evidencectl source suggest` drafts one source from an OpenAPI description:
it derives a closed response schema, an extraction script, and the facts schema
from the chosen operation, the projection the operator selects, and an optional
sample response, leaving an explicit `TODO` wherever a bound cannot be derived
so `evidence check` rejects the draft until a human resolves it.

```bash
evidencectl source suggest --openapi ./api.yaml --project ./deployment-project
```

`--openapi` also takes the URL a description is published at, which is read
under the same rule the runtime applies to the source URLs it will itself call:
`https` anywhere, plain `http` only to a numeric loopback host, and never a
credential in the URL. A description behind authentication is fetched with your
own client and passed as a file.

### Production build and handoff

An authored question may include optional `governance` metadata. Local `dev`
continues to work without it, using its explicit local defaults. When present,
`dev` uses the declared requirement semantics while retaining local assurance
and local authentication. A production build requires every question to carry
that metadata, stable concept identifiers, and one project-relative fixture.
It never invents requirement, framework, Evidence Type, concept, or
disclosure-family URIs.

The explicit production target contains only `governance.yaml` and
`runtime.yaml`. The former contributes the bundle-owned service,
authentication, audit, signing, rate-limit, response-format, and authority
values; it may not override compiler-owned selectors, sources, or requirements.
The latter is copied unchanged and binds the completed candidate to one target
host. Secret values and absolute secret paths do not belong in either authored
governance input.

`evidencectl build --project <editable-project> --target <production-target>
--output <new-candidate-directory>` is create-only. It reads regular files
without following symlinks, compiles one closed bundle, uses private temporary
validation material, runs `evidence check` and every referenced fixture through
the real `evidence` binary, and publishes atomically only on success. It makes
no network request, opens no listener, writes no production audit event, and
never copies local `.evidence` state, credentials, tokens, responses, or
private keys into the candidate.

The candidate contains `runtime.yaml` and `bundle/`; the bundle may contain
adapters, derivations, schemas, codelists, fixtures, and public keys where
referenced. The operator independently provisions the signing, audit,
subject-binding, and source secrets, then runs one grouped handoff:

```sh
evidencectl doctor --project '<candidate>'
evidencectl fixtures run --project '<candidate>'
evidence --runtime '<candidate>/runtime.yaml' serve
```

An existing OIDC issuer and Registry Mint are equal issuer choices from
Evidence's perspective. Mint remains separately authored and checked with
`mint check`. When selected, `evidencectl doctor --mint-config <mint.yaml>`
performs only a read-only mechanical comparison of issuer, JWKS URI, audience,
algorithm, token type, and configured claim names. It does not register a
client, decide authority, copy Mint files, or mint a token.

The initial deployment proof uses released bare binaries. Docker Compose is a
documented adapter, not build output: it mounts the reviewed bundle unchanged,
uses a separate container runtime file and secret mounts, preserves audit
storage, and keeps Evidence private behind operator TLS. Container, Helm,
Kubernetes, Terraform, cloud packaging, approval, promotion, and deployment
commands remain outside this build command.

## Installing the toolset

Releases that include the Evidence toolset publish reproducible bare binaries
named `<bin>-<tag>-<os>-<arch>` (for example `evidence-v1.2.0-linux-amd64`)
plus a `SHA256SUMS` file that is cosign-signed at promotion. Older releases do
not carry these assets. To install the newest release that does:

```sh
curl -fsSL https://github.com/registrystack/registry-stack/releases/latest/download/evidencectl-install.sh | bash
```

To pin a release, run that release's own installer asset:

```sh
tag=vX.Y.Z
curl -fsSL "https://github.com/registrystack/registry-stack/releases/download/${tag}/evidencectl-${tag}-install.sh" | bash
```

Every published installer carries the release it belongs to, so neither form
needs a tag in the environment and both refuse an `EVIDENCECTL_VERSION` naming
a different release. A copy taken from this repository carries none and
installs nothing until `EVIDENCECTL_VERSION` names one.

The installer installs the three-binary Evidence toolset, the `evidence`
runtime, `evidencectl` adopter tooling, and the `mint` token issuer, together
or not at all, verifying every asset against `SHA256SUMS` before anything
reaches the install directory. It supports Linux amd64, Linux arm64, and
macOS arm64. It checks integrity, not authenticity: for a higher-assurance
install, follow [`release/VERIFY.md`](../../release/VERIFY.md) for the pinned
tag, then rerun the installer with `EVIDENCECTL_ASSET_DIR` pointed at that
verified directory.

Three environment variables configure the installer: `EVIDENCECTL_VERSION`
names a `vMAJOR.MINOR.PATCH` release or workflow-produced development tag for
a copy that carries none,
`EVIDENCECTL_INSTALL_DIR` sets the install directory (default `~/.local/bin`),
and `EVIDENCECTL_ASSET_DIR` installs from a locally verified asset directory
instead of downloading.

### Manual development build

To test the current protected `main` revision before the next release, run the
**Registry Evidence Development Build** workflow manually from the `main`
branch. It requires successful protected-main CI, builds the same three-binary
toolset for Linux amd64, Linux arm64, and macOS arm64, and creates a unique
prerelease named `v<workspace-version>-dev.<run>.<attempt>`.

The workflow summary and prerelease notes contain the exact install command:

```sh
curl -fsSL "https://github.com/registrystack/registry-stack/releases/download/<development-tag>/evidencectl-install.sh" | bash
```

Development prereleases use unique source-bound tags, and the workflow never
overwrites them. They are unsupported. Their installer checks each binary
against the included `SHA256SUMS`; those checksums are not signed, and the
prerelease is not a Registry Stack release. Use a normal released version for
production or release verification.

To build the toolset from source instead:

```sh
cargo build --release --locked -p registry-evidence -p registry-evidencectl -p registry-mint
```

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

Signed flattened JWS is the default format. A missing `Accept`, `*/*`, or the
exact `application/jose+json` all select it. The exact
`application/vnd.registrystack.evidence-unsigned+json` selects a visibly
unsigned envelope, and the exact `application/dc+sd-jwt` selects the same
assertion serialized as an SD-JWT VC. Every format other than the default is
released only when both the immutable bundle and the one complete matched grant
permit it; otherwise the request is refused with the ordinary `not_authorized`
problem (HTTP 403) before credentials or source access, without revealing which
layer refused. Every authorization refusal shares this one generic 403, so it is
never an oracle for which check failed. A duplicate, combined, parameterized,
weighted, or unknown `Accept` returns the `response_format_not_acceptable`
problem with HTTP 406 before source access. Unsigned output is
transport-authenticated convenience data for development and for consumers that
cannot process JWS. It is never later-verifiable evidence and never a fallback
when signing fails.

The SD-JWT VC format is a second encoding of the one stateless assertion the
signed default carries, under the frozen profile in
[the SD-JWT VC profile](contracts/sd-jwt-vc-profile.yaml). It is not a
credential lifecycle: no issuance session, no holder binding ceremony, no
status list, no revocation, and no presentation or key-binding verification. The
shipped verifier checks an SD-JWT VC for exactly what it checks for a signed
JWS, namely issuer authenticity against a pinned key set and the output
contract, and it never falls back to the credential format when signing fails.
[The SD-JWT VC demo](SD-JWT-VC-DEMO.md) issues one assertion in both formats and
re-verifies the credential offline with `curl` and the `evidence` binary.

## Current verification

From the monorepo root, the Evidence-specific reproducible gate is:

```sh
cargo fmt --check
cargo check --locked -p registry-evidence -p registry-evidencectl --all-targets
cargo test --locked -p registry-evidence -p registry-evidencectl
cargo clippy --locked -p registry-evidence -p registry-evidencectl --all-targets -- -D warnings
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
