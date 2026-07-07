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
- `sts_subject_token` — OAuth2 token-exchange request and authorization-details
  JSON, plus the JOSE header-decode, algorithm/`typ` enforcement, and
  kid-lookup path exercised by `OidcSubjectTokenVerifier::verify_subject_token`
  (`registry-platform-sts`, `registry-platform-oidc`). The verifier is wired to
  a loopback JWKS URI; `FetchUrlPolicy::strict()` rejects loopback hosts during
  URL validation before any socket opens, so every fuzz iteration runs fully
  offline while still exercising the real verifier, not a mock.

Each target fuzzes the crate's real exported deserializer or entry point
directly, never a locally re-declared mirror struct that could drift from the
product type.

## Running locally

```
cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60 -rss_limit_mb=1024
```

Requires the nightly toolchain and `cargo-fuzz` (pinned to 0.13.2 in CI;
`cargo install cargo-fuzz --version 0.13.2` matches). `fuzz/Cargo.lock` pins
this crate's dependencies independently of the main workspace lockfile.

## Corpus

`fuzz/corpus/<target>/` holds hand-written seeds (valid and near-valid inputs),
committed to git under descriptive filenames. Files libFuzzer generates during
a run are excluded via `.gitignore` (`artifacts/`, `target/`) and should not be
committed; if a generated input is worth keeping permanently, copy it into the
seed corpus under a descriptive name instead of committing the raw generated
filename.

## Proposed CI wiring (not yet implemented)

No CI job runs these targets beyond ad hoc local proving runs. Issue #26
tracks a crash/corpus regression pattern (persisted corpus plus
previous-crash replay) that hasn't landed yet; adding a CI job ahead of that
pattern would give a false sense of regression coverage without one. Once #26
lands, the intended shape is:

- **Per-PR smoke** (fast, required): for each target,
  `cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60 -rss_limit_mb=1024`
  against the committed seed corpus only, no persisted state. Catches build
  breakage and obvious crashes on every PR that touches a fuzzed crate.
- **Nightly long run** (scheduled, best-effort): each target run for longer
  (10-30 minutes) against a corpus directory persisted across runs, so
  coverage accumulates instead of resetting every run. On crash, upload the
  crash artifact and the minimized failing input as a workflow artifact and
  fail the run loudly. Do not auto-file public issues from a fuzz crash; a
  crash in these boundaries may be a security finding and should route
  through `SECURITY.md` like any other suspected vulnerability.

This mirrors the existing `.github/workflows/nightly-security.yml`
`platform-fuzz` job's invocation shape (nightly toolchain, `cargo-fuzz`
0.13.2, `-rss_limit_mb=1024`, `-print_final_stats=1`), extended with corpus
persistence and crash-artifact upload once the regression pattern exists.
