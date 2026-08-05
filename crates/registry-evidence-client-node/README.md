# registry-evidence-client-node

Node.js binding for `registry-evidence-client`, the Evidence relying-party
client, via [napi-rs](https://napi.rs). Every Evidence semantic decision
(request preparation, sending, and verification) is the wrapped Rust crate's
own; this crate is a thin `#[napi]` surface plus a JSON conversion layer, and
re-implements none of it.

Publishing this binding as `@registrystack/evidence-client` on npm is out of
scope for this crate; it currently exists to be built and tested locally and
in CI.

## JS surface

```js
const client = new EvidenceClient({ baseUrl, trustedJwks, token, ... });

const prepared = client.prepare(spec);       // synchronous, no I/O
const definitions = await client.discover();
const jwks = await client.fetchJwks();
const response = await client.send(prepared);
const verified = client.verify(prepared, response);        // synchronous
const verified = await client.requestAndVerify(prepared);
const verified = client.verifyAsOf(prepared, response, asOfMillis);
```

## Design notes

### Error mapping

A mapped failure surfaces to a caller as an `EvidenceClientError`, exported
from the package root. Its `kind` is always present; `status`, `code`,
`operation`, `retryAfterSeconds`, `transportKind`, and `tokenKind` are present
when the underlying failure carries them. `message` is human prose, not JSON:
read it, do not parse it. `kind` is one of: `configuration`, `nonce`, `token`,
`transport`, `denied`, `not_available`, `protocol`, `verification`.

Underneath, the native layer throws every mapped failure as a plain
`napi::Error` whose `message` is a JSON-stringified envelope; `client.js`
parses that envelope and reconstructs it as an `EvidenceClientError`. That JSON
form is how the native layer hands a failure to `client.js`, not a
caller-facing contract: do not `JSON.parse(error.message)`.

A failure that is not a recognized envelope (a serialization defect, a caught
panic, napi's own argument-type checking) is left exactly as thrown, so it
cannot be mistaken for one of the eight kinds above.

The `denied`/`protocol` split is a hazard worth calling out explicitly: HTTP
401, 403, and 429 all map to `denied` regardless of the response body's own
`code`, while every other non-2xx status (including 400, 500, and anything
else not specifically recognized) maps to `protocol`. A caller that only
checks `status` without also checking `kind` can misclassify a 429 rate limit
as a generic protocol failure, or vice versa. See
`registry-evidence-client`'s `problem.rs` for the authoritative mapping table.

A response that exceeds `maxResponseBytes` maps to `kind: "transport"` with
`transportKind: "response_too_large"`, not `kind: "protocol"`, even when the
response status itself was a plain 200: the size limit is enforced against the
transport, before any attempt to interpret the body as a problem response.

### Nonce and the golden fixture

`prepare()` generates a fresh request nonce on every call; there is no seam
to inject a fixed nonce from outside. `tests/golden_fixture.rs` and its
committed fixtures under `tests/fixtures/` exist because of this: they pin one
specific, already-issued signed response (with its own fixed nonce baked in)
so the conversion layer's verification path can be exercised deterministically
without needing a live signer. Regenerate the fixture only with:

```bash
cargo test -p registry-evidence-client-node --test golden_fixture -- --ignored regenerate_golden_fixture
```

never by hand-editing the fixture files. The JS tests under `__test__/` take
the opposite approach for their own live round trip: `helpers/live-signing.js`
signs a fresh Evidence payload with Node's built-in `crypto` (Ed25519) for
whatever nonce the prepared request actually generated, because neither
`registry-evidence-verifier` nor `registry-evidence-client` exposes its test
signer outside `cfg(test)`.

### Async bridging

`send` and `requestAndVerify` cannot be plain `async fn` methods taking a
class reference as a parameter: napi-rs's tokio bridge requires the generated
future to be `Send + 'static`, and a `Reference<T>` into a JS object is not
`Send`. Both methods are ordinary (non-async) `#[napi]` functions that clone
the `Arc`s they need synchronously, then hand an `async move` block built only
from those owned clones to `napi::Env::spawn_future`. `PreparedEvidenceRequest`
and `RawEvidenceResponse` cross as opaque classes wrapping an `Arc` around the
real Rust value for the same reason: cloning the `Arc` is cheap and, for a
prepared request, preserves the identity of the interior single-send guard
rather than resetting it.

### `unsafe_code` deviation

This crate opts out of the workspace's `[lints] workspace = true` (which sets
`unsafe_code = "forbid"`) and instead denies unsafe code in its own source
from `src/lib.rs` (`#![deny(unsafe_code)]`). napi-rs's generated FFI glue
(through the `napi`/`napi-derive` dependency, not this crate's own source)
registers entry points with unsafe code unconditionally, which the
workspace-wide forbid would reject outright.

### Configuration surface

- `trustedRootCertificates` accepts a PEM-encoded string only, not a Buffer or
  DER bytes.
- Exactly two token providers are supported: `token: { static: "..." }` and
  `token: { privateKeyJwt: { tokenEndpoint, clientId, clientKey, ... } }`. A
  caller-supplied custom token provider is out of scope for this binding.
- `verifyAsOf(prepared, response, asOfMillis)` judges a response as of an
  explicit instant rather than the live clock. A past instant is the direction
  that costs something: naming a stale instant accepts an assertion whose
  validity interval has since elapsed, because the question asked is whether
  it was acceptable *then*, and the answer stays yes forever. A live trust
  decision should call `verify`, not this.

## Testing

Rust unit tests (`cargo test -p registry-evidence-client-node`) cover the
conversion layer directly. JS tests (`npm test`, `node --test __test__/*.test.js`)
cover construction refusals, a live happy-path round trip against a local stub
server, the one-send guard, `discover`/`fetchJwks` against a stub, and error
mapping for denied/not-available/protocol/transport failures. Building the
native addon first (`npm run build:debug`) is required before running the JS
tests.

`npm run check:types` rebuilds the addon in release mode with `--dts` and
diffs the result against the committed `index.d.ts`, so a change to the
`#[napi]` surface that is not reflected in the committed declaration file
fails this check rather than silently drifting.
