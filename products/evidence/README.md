# Evidence

Evidence evaluates fixed, authorized requests against authoritative sources and
returns minimum-disclosure assertions. Callers select a public Requirement URI,
a purpose and the subject selectors required by that definition. An optional
`expectedConfigurationRevision` refuses a stale definition before protected
source effects.

One `evidence` process serves one operator-controlled trust domain. The immutable
bundle contains compiled definitions, source contracts, reviewed Functions,
schemas, signing identity and target bindings. A separate runtime file binds
process resources, secret mounts, signer transport, audit storage and TLS trust.
Complete target authority is activated separately with durable history. Its
grants stay inside the package ceilings; a running process retains its activated
snapshot until restart.

Rust owns authentication, complete-grant authorization, selector minimization,
fixed source execution, bounded Function execution, output validation, signing
and audit. Reviewed Rhai Functions prepare requests, extract private facts and
derive only declared outputs. Authorization and selector checks precede secret
resolution and source access. Durable access audit precedes acquisition, and the
terminal disclosure audit gates the exact serialized response.

The default representation is signed flattened JWS. Unsigned JSON and SD-JWT VC
require explicit package and matched-grant permission. Holder-bound assertions
and bounded holder batches retain their separate key-confirmation and
presentation-verification rules. `registry-evidence-verifier` provides portable
offline verification without the serving runtime or source access. The optional
OID4VCI adapter is a separate consumer; Evidence has no wallet or OID4VCI runtime
dependency.

Sources use fixed HTTP JSON contracts or bounded SQLite extracts. Acquisition
can be direct, search followed by fetch, or an explicitly bounded fetch set.
Request and source batching preserve per-item authorization, disclosure and
audit boundaries. Authenticated context and task grants establish only the
explicit authority and selector origins their verified contracts permit.
Evidence needs no Base Registry Engine (BReg), Casework or Coordinator service or database. Assertions
establish claims and bindings, and confer no review approval or downstream write
authority.

Adult status, residence region, professional licence status, legal-parent
relationship and operator activity are example definitions. They are authored
through the same model and execution path. Source-product names in sanitized
compatibility fixtures grant no special production behavior.

The maintained runtime contracts include the [operator contract](OPERATOR-CONTRACT.md),
[source-testing contract](SOURCE-TESTING.md), [wire and security contracts](contracts/README.md)
and [trusted Function ABI](reference/request-adapter/ADAPTER-API.md). Generated
contracts and authoring schemas are reproduced by their documented generators.
Use the normalized examples below for the current authoring journey.

## Adopter tooling

Start with the runnable [standalone HTTP project](examples/standalone/README.md)
or [operator activity project](examples/operator-active/README.md). They cover
normalized authoring, complete access grants, local setup, signed requests,
independent offline verification and a deployment handoff.

`evidencectl` uses one `evidence.yaml` EvidenceProject containing
AssertionDefinitions, named Sources, named Functions and selector profiles.
Each definition declares its semantic URIs, subjects, acquisition plan, output
allowlist, validity, binding and grant ceiling. Function assets use
`source-prepare/v1`, `source-extract/v1` or `assertion-derive/v1`; their interfaces
and typed call sites are available through `explain` and generated types.

A separate EvidenceTarget declares the deployment's connections, authentication,
keys, secrets, audit destination and authority document. Its AccessProfiles match
verified identities, and each AccessGrant supplies one complete tuple inside the
package ceilings. Local development uses those same grants. Grants never combine
to create broader authority.

`evidencectl init <dir> --openapi <file-or-url> --profile local` retains the API
description for source authoring. `source suggest` and the source import commands
produce reviewed source contracts and named Function assets. The author supplies
the fixed assertion semantics and resolves any reported review markers.
`evidencectl init <dir> --transport sqlite-extract --profile local` creates a
runnable synthetic SQLite project. `init --starter <dir> --profile local` copies
a reviewed normalized project.

```sh
evidencectl check '<project>' --target '<target.yaml>'
evidencectl test '<project>' --target '<target.yaml>'
evidencectl explain '<project>' --target '<target.yaml>'
evidencectl types '<project>' --language typescript --output '<new-file.ts>'
```

`check` validates the same authoring model used by the compiler and editor.
With a complete target public key it also compiles and delegates a static bundle
check. Missing deployment inputs are reported explicitly. `--production` requires
production or evidence-grade assurance; `--deny-warnings` refuses warnings.
Checks resolve no secrets and make no dependency request. Fixtures execute the
bounded source/extraction/derivation path using supplied synthetic responses.

`evidencectl check --file <file>` checks one tooling file offline, including a
client profile, local access client registration, reviewed contracts, development state or source-import document.
Diagnostics identify files, fields and available source spans. The common exit
classes are `0` success, `1` refusal, `2` usage and `3` operational failure.
Use global `--format json` for machine-readable reports.

Register a local client with `access client add <id> --access-profile <profile>
--generate-local-key`, then use `dev start <project> --target <target.yaml>`.
The local lifecycle starts the pinned stock OAuth issuer and Evidence. Request
preparation retains authorization privately and closes verifier expectations
before the response exists. Stop and clean with `dev stop` and `dev clean`.
An explicitly configured shared issuer can be selected with `--issuer-project`;
Evidence still verifies its own clients, resources, scopes and complete grants.

Source descriptions accept HTTPS or numeric loopback HTTP and reject embedded
credentials, queries and fragments. Fetch an authenticated API description with
your own client and pass its local file. Source credentials grant no Evidence
caller authority.

### Package and deployment handoff

```sh
evidencectl package '<project>' --target '<target.yaml>' --output '<new-candidate-directory>'
```

Packaging is create-only. It reads regular files without following symlinks,
compiles the closed package, delegates static runtime validation and every
referenced fixture, and publishes the candidate atomically after success.
Fixture signing uses disposable validation material without accessing the
operator signer. Compilation opens no public listener and performs no live
source request. Private local state, credentials, tokens, responses and private
keys stay outside the candidate.

The candidate contains an immutable `bundle/` with `SHA256SUMS`, a compiled
`runtime.yaml`, and a separate `compiled-authority.yaml`. The runtime declares a
stable installed package path outside the build output. Install the bundle at
that path and provision the referenced secrets and signer transport, then run:

```sh
evidence authority activate --runtime-config '<candidate>/runtime.yaml' --document '<candidate>/compiled-authority.yaml'
evidencectl doctor --runtime-config /absolute/path/to/candidate/runtime.yaml
evidence serve --runtime-config '<candidate>/runtime.yaml'
```

Authority activation derives its revision and digest, checks the package
ceilings, and atomically records durable history. A serving process uses one
captured authority snapshot; restart it to adopt a later activation. Each release
audit binds the active authority revision and effective grant intersection.
`explain --target` exposes the same values without secrets or identity values.

Doctor performs the runtime-owned startup preflight without opening the public
listener or requesting an assertion. It can briefly hold the audit writer lock;
`--without-audit-lock` supports inspection beside a serving instance. Fixture
success establishes deterministic behavior; deployment preflight checks the
mounted runtime dependencies.

Configure the external issuer with the exact issuer, JWKS URI, resource audience,
algorithms, token type, scopes and claim mappings declared by the target.
Production issuer registration remains an operator responsibility. Assertions
carry verified claims, subject, purpose, validity and binding. Review approval
and downstream write authority remain with their owning systems.

Registry Stack publishes the `ghcr.io/registrystack/evidence` runtime image.
Pin the digest from the selected release. The image runs as UID and GID 65532.
Mount the Evidence runtime, reviewed bundle, secrets, and trust files at the
absolute paths named by the runtime, with only the audit directory writable
under `/var/lib/registry-evidence/audit`.

Docker Compose is a documented adapter, not build output: it mounts the
reviewed bundle unchanged, uses a separate container runtime file and secret
mounts, preserves audit storage, and keeps Evidence private behind operator
TLS. Helm, Kubernetes, Terraform, cloud packaging, approval, promotion, and
deployment commands remain outside this build command.

### Relying-party client library

`registry-evidence-client` is the Rust SDK for the application side of the
contract. It generates the request nonce and closes the verification policy
before any byte leaves the process, sends the request over the public HTTP
contract, and hands every judgement about the response to
`registry-evidence-verifier`, so it adds no Evidence semantics of its own.
`registry-evidence-client-node` binds that crate for Node.js callers through
napi-rs and `registry-evidence-client-py` binds it for Python callers through
PyO3; each is a thin surface plus a JSON conversion layer over the same Rust
decisions. Neither binding is published to a package registry: the npm package
is private and PyPI publishing is out of scope for the crate. Registry Stack
releases starting at v0.17.0 carry platform-specific Node tarballs and Python wheels as GitHub
Release assets for Linux amd64, Linux arm64, and macOS arm64. The release
candidate builds and runs an offline smoke against every package before the
packages enter the signed release checksum closure.

Install the Node package from the matching
`evidence-client-node-<tag>-<platform>.tgz` asset with `npm install <path>`.
The Node platform labels are `linux-amd64-glibc`, `linux-arm64-glibc`, and
`macos-arm64`; musl-based Linux distributions such as Alpine are not
supported by these packages.
Install the matching `registry_evidence_client-<version>-<wheel-tag>.whl`
asset with `python -m pip install <path>`. Linux wheels use the build runner's
glibc baseline or newer. Registry Stack does not publish these packages to npm
or PyPI.

Each crate documents its own surface and test commands:
[`registry-evidence-client`](../../crates/registry-evidence-client/README.md),
[`registry-evidence-client-node`](../../crates/registry-evidence-client-node/README.md),
and
[`registry-evidence-client-py`](../../crates/registry-evidence-client-py/README.md).

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
runtime, `evidencectl` adopter tooling, and the `evidence-oid4vci` wallet
delivery adapter, together
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
cargo build --release --locked -p registry-evidence -p registry-evidencectl -p registry-evidence-oid4vci
```

## Discovering available evidence

An authenticated caller lists the complete Evidence request shapes it can
currently invoke with `GET /v1/evidence-definitions`. The response is computed
from the immutable deployed bundle and the caller's verified token. It contains
only combinations that match exactly one authority path, including requirement,
Evidence Type, purpose, effective audience and response formats, stable
definition and concept handles, required and optional output status, list
cardinality, subject roles, selector profiles, value origins, and safe selector
field validation metadata. An unentitled caller receives an empty list. An
ambiguous authority shape is omitted because the corresponding evidence request
would be denied.

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
JWKS at `/.well-known/evidence/jwks.json` supplies verification keys only. For
profile-driven clients, `GET /.well-known/oauth-protected-resource` binds the
exact public Evidence origin to one authorization-server issuer, the Evidence
JWKS location, and header-only bearer transport. It carries no requester-scoped
definition or entitlement data. The complete contract and change rules are in
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
permit it; otherwise the request is refused with the ordinary `evidence.denied`
problem (HTTP 403) before credentials or source access, without revealing which
layer refused. Every authorization refusal shares this one generic 403, so it is
never an oracle for which check failed. A duplicate, combined, parameterized,
weighted, or unknown `Accept` returns the `format.unsupported`
problem with HTTP 406 before source access. Unsigned output is
transport-authenticated convenience data for development and for consumers that
cannot process JWS. It is never later-verifiable evidence and never a fallback
when signing fails.

The SD-JWT VC format is a second encoding of the one stateless assertion the
signed default carries, under the frozen RFC 9901 and SD-JWT VC draft 18 profile in
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
cargo check --locked \
  -p registry-evidence -p registry-evidence-verifier \
  -p registry-evidence-client -p registry-evidence-client-node \
  -p registry-evidence-client-py -p registry-evidencectl \
  --all-targets
cargo test --locked \
  -p registry-evidence -p registry-evidence-verifier \
  -p registry-evidence-client -p registry-evidence-client-node \
  -p registry-evidence-client-py -p registry-evidencectl
cargo clippy --locked \
  -p registry-evidence -p registry-evidence-verifier \
  -p registry-evidence-client -p registry-evidence-client-node \
  -p registry-evidence-client-py -p registry-evidencectl \
  --all-targets -- -D warnings
products/evidence/scripts/check-contracts.sh
products/evidence/scripts/check-source-neutrality.sh
products/evidence/scripts/check-verifier-portability.sh
```

The two bindings also carry their own JavaScript and Python suites, which this
gate does not run; each binding's README states the commands, and root CI runs
them in its client-bindings job. On macOS, `cargo test` for
`registry-evidence-client-py` needs the interpreter's library directory on the
dynamic linker path, as
[the Python binding README](../../crates/registry-evidence-client-py/README.md)
describes.

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
