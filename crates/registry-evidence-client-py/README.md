# registry-evidence-client-py

Python binding for `registry-evidence-client`, the Evidence relying-party
client, via [PyO3](https://pyo3.rs). Every Evidence semantic decision (request
preparation, sending, and verification) is the wrapped Rust crate's own; this
crate is a thin `#[pymodule]` surface plus a JSON conversion layer, and
re-implements none of it.

This crate publishes through the unified `registry-stack-client`
distribution, which imports as `registry_client`. Install the exact client
version that matches the Evidence deployment, and use its `evidence` namespace:

```sh
python -m pip install "registry-stack-client==<version>"
```

```python
from registry_client.evidence import EvidenceClient
```

PyPI carries manylinux wheels requiring glibc 2.17 or newer for Linux amd64 and
Linux arm64, plus a macOS arm64 wheel.

Registry Stack v0.22.0 through v0.26.0 published this binding on its own, as
the `registry-evidence-client` distribution imported as
`registry_evidence_client` (matching the crate's own `[lib]` name). Those
versions stay published and unchanged, and no later version joins them: from
v0.26.1 the maintained Python client is `registry-stack-client`.

## Python surface

Every method below is an ordinary blocking `def`, never `async def`. The
client owns a private current-thread tokio runtime and blocks on it for every
network call, releasing the GIL for the duration (via `py.detach`) so other
Python threads keep running.

```python
from registry_client.evidence import EvidenceClient

client = EvidenceClient(base_url, trusted_jwks, revoked_key_ids, token)

spec = {
    "response_format": "signed-jws",
    # requirement, subjects, and the remaining trusted procedure inputs
}
prepared = client.prepare(spec)              # synchronous, no I/O
definitions = client.discover()
jwks = client.fetch_jwks()
response = client.send(prepared)
verified = client.verify(prepared, response)
verified = client.request_and_verify(prepared)
verified = client.verify_as_of(prepared, response, as_of_unix_seconds)

batch_spec = {
    # requirement, purpose, and shared verification expectations
    "items": [
        {"subjects": subjects_a, "subject_expectations": "accept_first_use"},
        {"subjects": subjects_b, "subject_expectations": pinned_subjects_b},
    ],
}
prepared_batch = client.prepare_batch(batch_spec)  # synchronous, no I/O
raw_batch = client.send_batch(prepared_batch)
verified_batch = client.verify_batch(prepared_batch, raw_batch)
# Or: client.request_and_verify_batch(prepared_batch)
```

Request-batch results retain request order. Each item is either
`{"status": "available", "verified": VerifiedEvidence}` or exactly
`{"status": "not_available"}`. Rust verifies every available member against
the policy and nonce at the same position before the binding returns any item.
The prepared and raw batch classes have no public constructors, and a prepared
batch can be sent only once.

`response_format` is required on every request specification. Use
`"signed-jws"` for a flattened JWS JSON response or `"sd-jwt-vc"` for the
keyless SD-JWT VC response. `prepare()` closes that choice before any I/O,
`send()` uses its corresponding HTTP `Accept` value, and verification never
guesses a format from the returned bytes. The shipped type stub exposes
`EvidenceResponseFormat` and `EvidenceRequestSpec` for these inputs.

`token` is either a bare string (a static token) or a mapping with exactly one
key, `"private_key_jwt"`. There is no caller-supplied token provider; that is
out of scope for this binding, same as the Node binding.

Holder-bound issuance is supported: `prepare()` accepts public `holder_keys`,
and `SdJwtVcBatchResponse` parses the ordered credential envelope returned for
them. The binding stops at issuance. It exposes no trace_id for a holder to
create a selective-disclosure presentation or key-binding proof, and no
relying-party trace_id to verify that presentation. Use the
`registry-evidence-verifier` Rust crate or `evidence verify-presentation` for
the verification half of that workflow.

`trusted_jwks` and `revoked_key_ids` are both required trust inputs.
`revoked_key_ids` contains current service-key RFC 7638 thumbprints and
overrides a matching key even when it remains in `trusted_jwks` or in an older
prepared request's policy.

## Design notes

### Error mapping

A mapped failure surfaces to a caller as an `EvidenceClientError`, exported
from the package root, with one subclass per stable kind:
`ConfigurationError`, `NonceError`, `TokenError`, `TransportError`,
`DeniedError`, `NotAvailableError`, `ProtocolError`, `VerificationError`. Every
instance carries `kind`; `status`, `code`, `trace_id`,
`retry_after_seconds`, `transport_kind` (on a `TransportError`, and on a
`TokenError` whose `token_kind` is `"transport"`), and `token_kind` (only on a
`TokenError`) are set as attributes only when the underlying failure carries
them. `str(error)` is human prose, not JSON: read it, do not parse it.

The `denied`/`protocol` split is a hazard worth calling out explicitly: HTTP
401, 403, and 429 all map to `denied` regardless of the response body's own
`code`, while every other non-2xx status (including 400, 500, and anything
else not specifically recognized) maps to `protocol`. A caller that only
checks `status` without also checking `kind` can misclassify a 429 rate limit
as a generic protocol failure, or vice versa. See
`registry-evidence-client`'s `problem.rs` for the authoritative mapping table.

A response that exceeds its size bound maps to `kind: "transport"` with
`transport_kind: "response_too_large"`, not `kind: "protocol"`, even when the
response status itself was a plain 200: the size limit is enforced against the
transport, before any attempt to interpret the body as a problem response.

Which bound applies depends on the call. `max_response_bytes` bounds the signed
response body that `send()` and `request_and_verify()` read, and its default
follows what the verifier will accept as a signed response.
`max_metadata_bytes` bounds the documents `discover()` and `fetch_jwks()` read,
neither of which is signed or verified. Tightening one does not tighten the
other.

No string reaching Python carries unbounded remote text; no exception carries
response bytes, a credential, a header value, a selector value, or a subject
binding.

### Panics

PyO3 already catches panics that cross the FFI boundary: every generated
trampoline (behind `#[pymethods]`, `#[pyfunction]`, and `#[pymodule]`) wraps
the call in `std::panic::catch_unwind` and translates a caught panic into
PyO3's own `PanicException`, before this crate adds anything of its own. See
`pyo3-0.29.1/src/impl_/trampoline.rs` (the `trampoline` function) in the
vendored source for the exact mechanism. The client's own request nonce is
generated through `getrandom::fill`, which reports entropy failure as an
ordinary error and cannot panic. Aside from `to_py_err`'s `set_attr!` calls,
which can only panic under allocation failure, the one latent panic path is
upstream and left unguarded on purpose: the private-key-JWT token provider's
`jti` claim, generated with `Ulid::new()`, reaches `rand::rng()` and panics if
OS entropy is unavailable. It is reachable only in a deployment configured for
private-key-JWT; short of that same allocation-failure-only path, a
static-authorization deployment has no reachable panic at all. This crate adds no
guard of its own for it: the trampoline above already turns any such panic
into an ordinary Python exception rather than a process abort.

### The `unsafe_code` lint

Unlike the Node binding (`registry-evidence-client-node`, which opts out of
the workspace's `unsafe_code = "forbid"` because napi-rs's generated glue
contains unsafe code attributed to the invoking crate), this crate inherits
`[lints] workspace = true` unmodified. Confirmed by building
`-p registry-evidence-client-py` both without and with the `extension-module`
feature: PyO3's proc macros do not expand to unsafe code inside this crate;
the actual FFI calls live inside `pyo3`/`pyo3-ffi`'s own compiled sources,
under their own crate's lint settings, not this one's.

### Nonce and the golden fixture

`prepare()` generates a fresh request nonce on every call; there is no seam to
inject a fixed nonce from outside. `tests/golden_fixture.rs` and its committed
fixtures under `tests/fixtures/` exist because of this: they pin one specific,
already-issued signed response (with its own fixed nonce baked in) so the
conversion layer's verification path can be exercised deterministically
without needing a live signer. Regenerate the fixture only with:

```bash
cargo test -p registry-evidence-client-py --test golden_fixture -- --ignored regenerate_golden_fixture
```

never by hand-editing the fixture files. The Python test suite deliberately
has no signed-response round trip of its own: `EvidenceClient::send()` never
parses or verifies the response body (only `verify()`/`verify_as_of()` do), so
every Python-level error and construction test can use fake or unsigned
response bytes. The one genuine signed round trip against the real compiled
Python surface lives in `tests/happy_path.rs`, which drives it directly
through PyO3 rather than through a second, separately-maintained signer.

### `verify_as_of`

`verify_as_of(prepared, response, as_of_unix_seconds)` judges a response as of
an explicit instant rather than the live clock. A past instant is the
direction that costs something: naming a stale instant accepts an assertion
whose validity interval has since elapsed, because the question asked is
whether it was acceptable *then*, and the answer stays yes forever. A live
trust decision should call `verify`, not this.

## Building

Building requires `python3` on `PATH` at build time (PyO3's build script
locates the interpreter to configure the target ABI); this is true for both
`cargo build` and `maturin`.

For local development, install the package into a virtualenv with:

```bash
uv run maturin develop
```

The `auto-initialize` dev-dependency feature (see `Cargo.toml`) links every
test binary this crate produces directly against libpython, so the dynamic
linker has to find it at process startup. `build.rs` records the build-time
interpreter's own library directory as an rpath for that build, which is why
`cargo test -p registry-evidence-client-py` needs no `DYLD_LIBRARY_PATH` (macOS)
or `LD_LIBRARY_PATH` (Linux) of its own, even for an interpreter outside the
linker's default search path. Rebuilding after the interpreter moves is enough
to follow it; the rpath is a build-time constant, not a lookup. The shipped
wheel never carries that rpath: `maturin` always builds through this crate's
`extension-module` feature, where libpython is left to the loading process.

## Testing

Rust unit tests (`cargo test -p registry-evidence-client-py`) cover the
conversion layer directly, plus a golden fixture and a live happy-path/
request-batch/nonce-mismatch/one-send-guard round trip against the real compiled Python
surface (`tests/happy_path.rs`), driven straight through PyO3 without
shelling out to a `python3` process.

The Python suite under `tests/python/` (`python3 -m unittest discover -s
crates/registry-evidence-client-py/tests/python`) covers construction
refusals, error mapping for denied/not-available/protocol/transport failures,
discovery (`discover`/`fetch_jwks`) against a stub server, singular and batch
one-send guards, exact batch wire and malformed-member handling, a GIL-release
concurrency proof, and a stub-drift check against the committed `.pyi`. Every
file in that suite imports `tests/python/bootstrap.py` first,
which runs:

```bash
cargo build --locked -p registry-evidence-client-py --lib --features registry-evidence-client-py/extension-module
```

then copies the resulting dylib to a scratch directory as
`registry_evidence_client.so` and puts that directory on `sys.path`, so the
suite never depends on `maturin`, `pip install -e`, or any packaging step.

No test path invokes `maturin`, on a developer's machine or in CI. Two things
do: `uv run maturin develop` above, for local development, and
`.github/workflows/evidence-dev.yml`, which builds the wheel published with
each Evidence development prerelease and smokes it from a fresh virtual
environment. That workflow stamps the prerelease version into `pyproject.toml`
before building, so this crate's own copy of the workspace version stays the
released one.
