# Registry Stack client guidance

This guide covers the seven product clients, the Node.js and Python bindings
maintained for six of them, `registry-stack-client`, the unified
native-package facades, and shared `registry-record` DTOs. Apply the owning
product guide as well.

Apply package-specific guidance only when that package is present in the target
checkout. Current package metadata and `release/scripts/client_registry.py`
determine availability and public names; a component listed here is not a claim
that every checkout or release ships it.

## Ownership

| Area | Owns |
|---|---|
| `registry-{breg,casework,discovery,evidence,messaging,relay,scheduling}-client` | Canonical Rust product HTTP and response contract |
| `registry-evidence-verifier` | Evidence response formats, payload contract, and relying-party verification |
| BReg, Casework, Discovery, Evidence, Messaging, and Relay `-client-node` / `-client-py` crates | Thin napi-rs / PyO3 bindings and language conversion over the Rust decisions |
| `registry-scheduling-client` | Rust-only Scheduling client over `registry-scheduling-core` wire types |
| `registry-stack-client` | Curated Rust facade for BReg, Casework, Discovery, Evidence, Messaging, and Relay, with separate product, record, and auth modules |
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
  use, redirects, automatic pagination, resource following, or hidden retries.
  Acquire credentials only for operations the product contract protects.
- Evidence verification delegates to `registry-evidence-verifier`. Preserve
  request binding and the distinction between verified, raw, unsigned, and
  holder-bound results across language conversions. Portable verifier means
  independent of the service runtime, not unrestricted target support.
- Discovery selections remain inert public metadata. Structural validation or
  persistence cannot create trust; local acceptance must precede credentials
  and native provider access. Renewal cannot accept changed semantics silently.
- Relay remains unsigned. Continuations and conditional responses retain their
  exact request/profile context and response validation rules.
- BReg writes require complete caller-filtered metadata bindings tied to the
  client origin, registry, dataset, entity, profile, revision, route, and
  operation. Opaque authority handles must not become caller-constructible
  permissions in a binding. Validate a mutation before token acquisition or
  I/O; never generate its idempotency key or retry it implicitly. Record ETags
  and lifecycle-action ETags are distinct.
- Messaging submissions take a caller-chosen idempotency key; a binding never
  generates one or retries a submission. Bindings add no Messaging semantics:
  the closed problem catalogue, message view, and receipt come from the Rust
  client unchanged.
- Preserve strict duplicate-member rejection, bounded responses, product media
  types, trace/Problem validation, and value-free errors. Bindings must not
  expose URLs, headers, payloads, selectors, credentials, or transport chains
  through exception text or debug output.

Make ordinary composition easy through typed product namespaces and existing
HTTP contracts. A language facade should remove packaging and conversion work
from adopters while keeping consequential choices, such as local trust
acceptance and mutation retries, explicit.

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

For Python bindings, run from the changed `-client-py` directory, replacing
`<product>` with `breg`, `casework`, `discovery`, `evidence`, `messaging`, or
`relay`:

```sh
cargo build --locked -p registry-<product>-client-py --lib --features registry-<product>-client-py/extension-module
python3 -m unittest discover -s tests/python -v
cmp ../../LICENSE LICENSE
```

In checkouts containing the unified Node.js and Python packages, those packages
are generated from the BReg, Casework, Discovery, Evidence, Messaging, and
Relay bindings.
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
combines six version-matched internal native wheels with the public facade;
the facade directory is not built directly. Follow current release inventory
for publication instead of assuming standalone package instructions apply.
For a checkout without unified native assembly, use the product binding checks
above and its current package metadata.

For changed wire surfaces, use owning product contract gates, including
`products/breg/scripts/check-client-contract.sh` and
`products/relay-v2/scripts/check-client-contract.sh` where applicable. Evidence
client, verifier, binding, authoring, and language-server source also stays
under Evidence's neutrality checks. Package checks alone do not prove a
changed runtime authorization or disclosure boundary.
