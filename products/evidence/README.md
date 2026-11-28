# Evidence

Evidence evaluates fixed, authorized requests against authoritative sources and
returns minimum-disclosure assertions. Callers select a public Requirement URI,
a purpose and the subject selectors required by that definition. An optional
`expectedConfigurationRevision` refuses a stale definition before protected
source effects.

One `evidence` process serves one operator-controlled trust domain. The immutable
bundle contains compiled definitions, digest-pinned Adapter packs, thin Source
bindings, reviewed derivation Functions, schemas, signing identity and target
bindings. A separate runtime file binds
process resources, secret mounts, signer transport, audit storage and TLS trust.
Complete target authority is activated separately with durable history. Its
grants stay inside the package ceilings; a running process retains its activated
snapshot until restart.

Rust owns authentication, complete-grant authorization, selector minimization,
bounded Adapter pack execution, bounded derivation Function execution, output
validation, signing and audit. One reviewed Adapter pack route owns each complete
provider acquisition and returns a schema-validated private FactSet. The only
authored Evidence Function interface is `assertion-derive/v1`; it derives only
declared outputs from those facts and its explicitly declared selector inputs.
Authorization and selector checks precede secret resolution and source access.
Durable access audit precedes acquisition, and the terminal disclosure audit
gates the exact serialized response.

The default representation is signed flattened JWS. Unsigned JSON and SD-JWT VC
require explicit package and matched-grant permission. `registry-evidence-verifier`
provides portable offline verification without the serving runtime or source
access. The optional OID4VCI adapter is a separate consumer. The default
`wallet-presentation` Cargo feature links `registry-evidence-presentation`, which
verifies a credential a holder presented from a wallet without I/O.

Each AssertionDefinition names one Source. That Source binds a pinned Adapter
pack version and route to one target connection, and maps only authorized
selector fields into the route's closed inputs. The route owns the complete
bounded sequence of provider operations and the projection to private facts.
Request-batch evaluation runs that same Source independently for each item.
Evidence needs no Base Registry Engine (BReg), Casework or Coordinator service
or database. Assertions establish claims and bindings, and confer no review
approval or downstream write authority.

The maintained runtime contracts include the [operator contract](OPERATOR-CONTRACT.md),
[wire and security contracts](contracts/README.md) and the
[trusted derivation Function ABI](https://docs.registrystack.org/reference/evidence-request-adapter-api/). Generated
contracts and authoring schemas are reproduced by their documented generators.

## Start a development run

Set `STARTER` to the absolute path of the reviewed
[standalone Evidence starter](examples/standalone/). Its assertion scenario reads a
synthetic HTTP source. Run the following commands in the same shell.

```sh
evidencectl init ./evidence --profile local --starter "$STARTER"
python3 ./evidence/serve-source.py --port 8081 &
SOURCE_PID=$!
trap 'kill "$SOURCE_PID" 2>/dev/null' EXIT
curl --fail --silent --show-error --retry 10 --retry-connrefused http://127.0.0.1:8081/healthz
rstack dev start ./evidence
```

Keep the shell open while the run needs the source. Stop the run before closing the shell.

## Adopter tooling

Start with the runnable [standalone HTTP project](examples/standalone/README.md)
or [operator activity project](examples/operator-active/README.md). They cover
normalized authoring, complete access grants, local setup, signed requests,
independent offline verification and a deployment handoff.

`evidencectl` uses one `evidence.yaml` EvidenceProject and a separate
EvidenceTarget that declares the deployment's connections, authentication, keys,
secrets, audit destination and authority document. Each AccessGrant supplies one
complete tuple inside the package ceilings, and grants never combine to create
broader authority.

`evidencectl init <dir> --openapi <file-or-url> --profile local` retains the API
description for source authoring, and `source suggest` emits a reviewed Adapter
pack closure plus its thin Source binding. Generated pack code remains ordinary
reviewed project input. `evidencectl init <dir> --transport sqlite-extract
--profile local` creates a runnable synthetic SQLite project.
`init --starter <dir> --profile local` copies a reviewed normalized project.

The [source recipe catalog](source-recipes/README.md) provides reusable DHIS2
Tracker and OpenCRVS event-search exports with synthetic fixture projects.
Import and customize them through the existing source lifecycle; bind origins
and credentials in the target and supply the assertion's own meaning and grants.

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
Checks resolve no secrets and make no dependency request.

`explain` shows each definition's Source, pinned pack and route, named connection,
acquisition posture, minimized selector-to-input bindings, typed private fact
names, derivation Function and declared output names. The JSON report's
`assertionDefinitions` entries also carry each definition's `validitySeconds`.

`evidencectl check --file <file>` checks one tooling file offline, including a
client profile, reviewed contracts, development state or source-import document.
Diagnostics identify files, fields and available source spans. The common exit
classes are `0` success, `1` refusal, `2` usage and `3` operational failure.
Use global `--format json` for machine-readable reports.

Run a project locally with `rstack dev start`, from a `dev.yaml` plan beside the
project. The run is its own token issuer and starts Evidence, so it needs no
Docker and no database. `rstack dev token <run> --as <person>` writes the header
file for a synthetic caller, and `rstack dev stop` stops the run.

`evidencectl api PATH --url URL --header @FILE` sends a request with that header
file, without writing the bearer header to the terminal. It sends the header only
to the named Evidence origin. It follows the shared
[`registry-cli-api` security boundary](../../crates/registry-cli-api/README.md#security-boundary),
which supplies transport and credentials but no Evidence authority. The
runtime still decides authentication, complete-grant authorization, selector
minimization, audit, and disclosure.

### Package and deployment handoff

```sh
evidencectl package '<project>' --target '<target.yaml>' --output '<new-candidate-directory>'
```

Packaging is create-only and publishes the candidate atomically after success.
Compilation opens no public listener and performs no live source request. Private
local state, credentials, tokens, responses and private keys stay outside the
candidate.

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
captured authority snapshot; restart it to adopt a later activation.

Doctor performs the runtime-owned startup preflight without opening the public
listener or requesting an assertion. It can briefly hold the audit writer lock;
`--without-audit-lock` supports inspection beside a serving instance.

Registry Stack publishes the `ghcr.io/registrystack/evidence` runtime image.
Pin the digest from the selected release. The image runs as UID and GID 65532.
Mount the Evidence runtime, reviewed bundle, secrets, and trust files at the
absolute paths named by the runtime, with only the audit directory writable
under `/var/lib/registry-evidence/audit`.

### Relying-party client library

`registry-evidence-client` is the Rust SDK for the application side of the
contract. It generates the request nonce and closes the verification policy
before any byte leaves the process, sends the request over the public HTTP
contract, and hands every judgement about the response to
`registry-evidence-verifier`. `registry-evidence-client-node` binds that crate for
Node.js callers through napi-rs and `registry-evidence-client-py` binds it for
Python callers through PyO3. Neither binding is published to a package registry.
Registry Stack releases starting at v0.17.0 carry platform-specific Node tarballs
and Python wheels as GitHub Release assets for Linux amd64, Linux arm64, and
macOS arm64.

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

`evidencectl-install.sh` installs the standalone Evidence toolset described here.
The `rstack-vX.Y.Z-install.sh` installer used by the tutorials installs the
`rstack` launcher and its release-pinned managed components, `evidence` among them.

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

Outside an `rstack` managed generation, `evidencectl` selects its runtime in
this order: an explicit `--evidence-bin` where the command accepts it,
`EVIDENCE_BIN`, an executable `evidence` beside the running `evidencectl`, then
`PATH`. Keeping the installed toolset together therefore takes precedence
over an older runtime elsewhere on `PATH`. The selected runtime must still
report exactly the same version as `evidencectl`; a mismatch names both
versions and the override needed to select the matching runtime.

Three environment variables configure the installer: `EVIDENCECTL_VERSION`
names a `vMAJOR.MINOR.PATCH` release or workflow-produced development tag for
a copy that carries none,
`EVIDENCECTL_INSTALL_DIR` sets the install directory (default `~/.local/bin`),
and `EVIDENCECTL_ASSET_DIR` installs from a locally verified asset directory
instead of downloading.

### Manual development build

To test the current protected `main` revision before the next release, run the
**Registry Evidence Development Build** workflow manually from the `main` branch.
It creates a unique prerelease named `v<workspace-version>-dev.<run>.<attempt>`.
The workflow summary and prerelease notes contain the exact install command:

```sh
curl -fsSL "https://github.com/registrystack/registry-stack/releases/download/<development-tag>/evidencectl-install.sh" | bash
```

Development prereleases are unsupported. Their installer checks each binary
against the included `SHA256SUMS`, which is not signed, and the prerelease is not
a Registry Stack release.

To build the toolset from source instead:

```sh
cargo build --release --locked -p registry-evidence -p registry-evidencectl -p registry-evidence-oid4vci
```

## Discovering available evidence

An authenticated caller lists the Evidence request shapes it can currently invoke
with `GET /v1/evidence-definitions`. The response is requester-scoped, not a
public or process-wide catalog. It performs no provider request and creates no
evidence-data audit event, and metadata never grants authority: `POST /v1/evidence`
authenticates and authorizes the complete tuple again. The running service
publishes the generated OpenAPI document unauthenticated at `GET /openapi.json`.
The complete contract and change rules are in
[the operator contract](OPERATOR-CONTRACT.md#discovery-of-available-evidence).

## Public certificate check

An operator can activate one experimental public check, so that anyone holding
a certificate can check it without registering as a relying service.
`POST /v1/public-check` (and its `OPTIONS` preflight) takes `documentNumber` and
`checkCode`, needs no credential, and answers the status, the printed fields and
the evaluation time, unsigned. A wrong number and a wrong code get the same
`404`. The route exists only when the package declares `publicCheck` and the
target authority activates it. Evidence does not enforce the path restriction:
exposing the route only through a path-restricted proxy is the operator's duty. See
[the example](examples/public-check/README.md) and
[the operator contract](OPERATOR-CONTRACT.md#public-certificate-check).

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

Signed flattened JWS is the default format. The exact `Accept` values, the
intersection of bundle and grant permissions, and the `evidence.denied` and
`format.unsupported` refusals are in
[the operator contract](OPERATOR-CONTRACT.md#response-formats). Unsigned output is
never later-verifiable evidence and never a fallback when signing fails.

The SD-JWT VC format is a second encoding of the one stateless assertion the
signed default carries, under the frozen RFC 9901 and SD-JWT VC draft 18 profile in
[the SD-JWT VC profile](contracts/sd-jwt-vc-profile.yaml). A credential status
profile, approved but not served, will add a status list and revocation for a
requirement that declares credential status under version 2 of the profile. Its
codec and status check, its ledger module, and a PostgreSQL store for the OID4VCI
adapter exist as library code that the served runtime does not call.

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

The two bindings carry their own JavaScript and Python suites, which this gate
does not run. Each binding's README states the commands.

Two local demos run entirely against a mock source and need no credentials:

- First curl: `cargo test --locked -p registry-evidence first_curl_exercises_and_verifies_the_evidence_server -- --ignored --nocapture`
  starts the Evidence server on `127.0.0.1:18080` and writes the synthetic
  request and `session.env` to the ignored, owner-only `products/evidence/.first-curl/`.
  The bearer token in `session.env` is short-lived and synthetic; do not paste it anywhere.
- SD-JWT VC demo: `products/evidence/scripts/sd-jwt-vc-demo.sh` needs `cargo`,
  `curl` and `jq`, listens on `127.0.0.1:18081`, writes to the ignored
  `products/evidence/.sd-jwt-vc-demo/` and can be rerun, replacing its artifacts.
  Only the `PASS:` line it prints counts as a pass. The manual mode is the
  `sd_jwt_vc_demo_serves_a_credential_for_curl` test.
