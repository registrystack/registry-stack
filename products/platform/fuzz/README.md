# Platform fuzz targets

cargo-fuzz harnesses for untrusted-input parse boundaries in `registry-platform-*`
crates. These live outside the main workspace (see the root `Cargo.toml`
`exclude` list) so a broken or slow fuzz build never blocks
`cargo check --workspace`.

## Targets

- `authcommon_parsers` — bearer token and API key fingerprint parsing
  (`registry-platform-authcommon`).
- `oid4vci_request_and_proof` — OID4VCI credential/token request and
  proof-of-possession JWT parsing (`registry-platform-oid4vci`).
- `sdjwt_holder_proof` — SD-JWT holder-proof JWT verification
  (`registry-platform-sdjwt`).
- `sdjwt_issuance` — SD-JWT issuance input parsing (`registry-platform-sdjwt`).

Each target fuzzes the crate's real exported deserializer or entry point
directly, never a locally re-declared mirror struct that could drift from the
product type.

## Running locally

From `products/platform/`:

```bash
cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60 -rss_limit_mb=1024
```

Requires the nightly toolchain and `cargo-fuzz` (pinned to 0.13.2 in CI;
`cargo install cargo-fuzz --version 0.13.2` matches). `fuzz/Cargo.lock` pins
this crate's dependencies independently of the main workspace lockfile.

## Corpus

`fuzz/corpus/<target>/` holds hand-written seeds (valid and near-valid inputs),
committed to git under descriptive filenames. The `.gitignore` here excludes
`artifacts/`, `target/`, and libFuzzer's generated 40-hex-character corpus
entries; if a generated input is worth keeping permanently, copy it into the
seed corpus under a descriptive name instead of committing the raw generated
filename.

## CI wiring

The active root workflows provide two event-specific checks:

- `.github/workflows/ci.yml` runs a required one-minute smoke for each target
  when a pull request changes a platform crate, fuzz harness, or shared Cargo
  dependency input.
- `.github/workflows/nightly-security.yml` runs the platform smoke as part of
  the scheduled security suite.

Both use the nightly toolchain, pinned `cargo-fuzz` 0.13.2, the committed seed
corpus, `-max_total_time=60`, and `-rss_limit_mb=1024`, and upload crash
artifacts only on failure. A crash at these trust boundaries may be a security
finding and should route through `SECURITY.md`; automation must not file a
public issue containing the input.
