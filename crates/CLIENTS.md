# Registry Stack client guidance

This guide covers the product clients, their maintained Node.js and Python
bindings, `registry-stack-client`, the unified
native-package facades, and shared `registry-record` DTOs. Apply the owning
product guide as well.

Apply package-specific guidance only when that package is present in the target
checkout. Current package metadata and `release/scripts/client_registry.py`
determine availability and public names; a component listed here is not a claim
that every checkout or release ships it.

## Ownership

| Area | Owns |
|---|---|
| `registry-{breg,casework,discovery,evidence,messaging,scheduling}-client` | Canonical Rust product HTTP and response contract |
| `registry-coordinator-client` / `registry-coordinator-client-node` | Canonical Rust and thin Node contract for controlled pilot admission, progress, inspection and original-receipt reconciliation; no Python binding in this slice |
| `registry-evidence-verifier` | Evidence response formats, payload contract, and relying-party verification |
| BReg, Casework, Discovery, Evidence, Messaging, and Scheduling `-client-node` / `-client-py` crates | Thin napi-rs / PyO3 bindings and language conversion over the Rust decisions |
| `registry-stack-client` | Curated Rust facade for BReg, Casework, Discovery, Evidence, Messaging, and Scheduling, with separate product, record, and auth modules |
| `registry-stack-client-node` | Public `@registrystack/client` facade and platform package definitions |
| `registry-stack-client-py` | Public `registry-stack-client` Python metadata and `registry_client` facade, assembled with all native bindings |
| `registry-record` | Neutral Registry Record DTOs and strict envelope decoding, without product authorization semantics |

Each product keeps its own routing, authentication, errors, continuations, and
verification rules. A facade or binding does not invent server capabilities
or unify distinct authority contracts. Shared HTTP/token primitives live in
`registry-platform-httputil`; package inventory and assembly live in
`release/scripts/client_registry.py` and the release tooling.

## Boundaries

- Keep requests explicit and bounded, preserve deployment prefixes, and retain
  product-owned route and query construction. Do not introduce ambient proxy
  use, redirects, automatic pagination, resource following, or retries. The
  one exception is the bounded same-key resend of an idempotency-keyed
  mutation whose outcome is unknown (a timeout or broken exchange after
  sending, or a 5xx answer other than a typed failure the product returns only
  with the attempt rolled back), and never after a 4xx status line:
  `registry_platform_httputil::client::retry_keyed_mutation` owns its loop and
  waits, the BReg, Casework, Messaging, and Scheduling clients expose the
  count as `with_max_mutation_retries` (2 by default, at most 2, 0 disables),
  and the resend repeats the caller's exact key, headers, and body. The other
  clients never resend. Reads and unkeyed operations are never resent, and
  neither are Casework's review request create and cancel, which go through
  the review client's single exchange. Those four clients treat a connection
  that was never established, a connect timeout included, as a known failure,
  and the Casework client's `mutation_class` is `Ambiguous` exactly when
  `is_outcome_unknown` holds.
  Acquire credentials only for operations the product contract protects.
- Evidence verification delegates to `registry-evidence-verifier`. Preserve
  request binding and the distinction between verified, raw, unsigned, and
  holder-bound results across language conversions. Portable verifier means
  independent of the service runtime, not unrestricted target support.
- Discovery selections remain inert public metadata. Structural validation or
  persistence cannot create trust; local acceptance must precede credentials
  and native provider access. Renewal cannot accept changed semantics silently.
- BReg writes require complete caller-filtered metadata bindings tied to the
  client origin, registry, dataset, entity, profile, revision, route, and
  operation. Opaque authority handles must not become caller-constructible
  permissions in a binding. Validate a mutation before token acquisition or
  I/O; never generate its idempotency key, and resend it only through the
  bounded same-key retry. Record ETags and lifecycle-action ETags are distinct.
- Messaging submissions take a caller-chosen idempotency key; a binding never
  generates one. Only the Rust client's bounded same-key retry resends a
  submission, and a cancellation is never resent. Message, template,
  and version names are checked by the Rust client before any request.
  Bindings add no Messaging semantics: the closed problem catalogue, message
  view, receipt, and template preview come from the Rust client unchanged. A
  429 limit refusal carries the bounded `Retry-After` wait the Rust client
  read; waiting and retrying stay the caller's decision.
- Scheduling holds, bookings, reschedules, and cancellations take a
  caller-chosen idempotency key; a binding never generates one. Only the Rust
  client's bounded same-key retry resends a capacity mutation. Bindings parse
  every instant they send as RFC 3339 before any request and add no Scheduling
  semantics: the closed problem catalogue and the hold, appointment, and
  availability documents come from the Rust client unchanged.
- Preserve strict duplicate-member rejection, bounded responses, product media
  types, trace/Problem validation, and value-free errors. Bindings must not
  expose URLs, headers, payloads, selectors, credentials, or transport chains
  through exception text or debug output.

Make ordinary composition easy through typed product namespaces and existing
HTTP contracts. A language facade should remove packaging and conversion work
from adopters while keeping consequential choices explicit, such as local
trust acceptance and the mutation retry count.

Coordinator sends one exchange per call, with no hidden retries. Its caller owns
durable admission retries and retains the original issuer, subject, flow, key,
and input. Client policy is separately checked on every request. Reconciliation
reads an original supported product receipt through the runtime's saved command;
it never resubmits it. Coordinator keeps its own bounded JSON problem contract,
without the trace or RFC 9457 requirements of other product clients. A backend
run remains backend-owned. Source-record authorization and explicit application
correlation are required before presenting progress to staff or citizens.

Local Node assembly can include the Coordinator binding with the explicit
`--include-coordinator` candidate option. Do not infer its inclusion when checking
historical or published package bytes, and do not publish a local candidate.

## Verification and generated surfaces

Read the changed client's README where present, its public API documentation
in `src/lib.rs`, and binding package metadata. Start with focused Rust tests,
then affected facade tests from the monorepo root:

```sh
cargo test --locked -p <changed-client-crate>
cargo test --locked -p registry-stack-client
```

For Node bindings, run from the changed `-client-node` directory:

```sh
npm ci
npm run build:debug
npm test
npm run check:types
cmp ../../LICENSE LICENSE
```

These gates leave the working tree clean when `CARGO_TARGET_DIR` is unset or
absolute. napi-rs runs Cargo from the binding's own directory, so a relative
`CARGO_TARGET_DIR` resolves there, once per binding, and builds inside the
tree. `build:debug` builds the addon without writing the committed `index.js`
or `index.d.ts`, and `check:types` generates both into ignored `.check` files and
requires them to match the committed ones byte for byte. When a napi-rs CLI bump
changes that output, `check:types` fails. Run `npm ci && npm run build` in each
of the six `-client-node` directories, which rewrites both files with the
pinned CLI (Discovery's loader normalizer included), and commit every
`index.js` and `index.d.ts` together with the bump.

For Python bindings, run from the changed `-client-py` directory, replacing
`<product>` with `breg`, `casework`, `discovery`, `evidence`, `messaging`, or
`scheduling`:

```sh
cargo build --locked -p registry-<product>-client-py --lib --features registry-<product>-client-py/extension-module
python3 -m unittest discover -s tests/python -v
cmp ../../LICENSE LICENSE
```

The Python test bootstraps ask `cargo metadata` for the target directory, so a
`CARGO_TARGET_DIR`, absolute or relative to the repository root, needs no
further setup.

On macOS, AWS-LC FIPS is a dynamic library, and System Integrity Protection
strips `DYLD_*` variables from protected executables such as `/bin/sh`, which
`npm test` runs through, and the system `python3`. Prepare the runtime library
path in the shell from the repository root first, then run the Node tests
directly with `node --test` instead of `npm test`, as
`.github/workflows/macos-contributor.yml` does. The Python bootstraps preload
the library from the helper's `REGISTRY_CARGO_RUNTIME_LIBRARY_PATH`.

```sh
. scripts/cargo-runtime-library-path.sh
registry_prepare_cargo_runtime "$PWD" --locked -p registry-<product>-client-node
(cd crates/registry-<product>-client-node && npm run build:debug && node --test __test__/*.test.js)
(cd crates/registry-<product>-client-py && python3 -m unittest discover -s tests/python -v)
```

In checkouts containing the unified Node.js and Python packages, those packages
are generated from the BReg, Casework, Discovery, Evidence, Messaging, and
Scheduling bindings. Published packages include Messaging from v0.38.0 and
Scheduling from v0.40.0; earlier release assembly preserves its
version-selected inventory. Source CI uses the explicit local
`--include-messaging` and `--include-scheduling` overrides when assembling the
current six bindings.
When changing that assembly,
confirm the facade directories, `sync-registry-client-node.py`, and
`test_assemble_registry_client_wheel.py` are present, then run from the monorepo
root:

```sh
python3 release/scripts/sync-registry-client-node.py --check
cd crates/registry-stack-client-node
npm ci
npm test
npm run check:types
cd ../..
python3 -m unittest release/scripts/test_assemble_registry_client_wheel.py
```

Where this assembly exists, regenerate the Node facade with
`sync-registry-client-node.py` when its source bindings change; do not hand-edit
copied product wrappers. Python assembly
combines the version-selected internal native wheels with the public facade;
the facade directory is not built directly. Follow current release inventory
for publication instead of assuming standalone package instructions apply.
For a checkout without unified native assembly, use the product binding checks
above and its current package metadata.

For changed wire surfaces, use owning product contract gates, including
`products/breg/scripts/check-client-contract.sh`. Evidence
client, verifier, binding, authoring, and language-server source also stays
under Evidence's neutrality checks. Package checks alone do not prove a
changed runtime authorization or disclosure boundary.
