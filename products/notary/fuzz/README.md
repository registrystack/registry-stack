# Notary fuzz targets

cargo-fuzz harnesses for untrusted-input parse boundaries in Notary crates.
This crate declares its own empty `[workspace]` table and is also listed in
the root `Cargo.toml` `exclude` list, so a broken or slow fuzz build never
blocks `cargo check --workspace`.

## Targets

- `core_request_bodies` — evaluation, credential-issue, and render request
  body parsing (`registry-notary-core`).
Each target fuzzes the crate's real exported entry point directly, never a
locally re-declared mirror struct that could drift from the product type.

## Running locally

```bash
cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60 -rss_limit_mb=1024
```

Requires the nightly toolchain and `cargo-fuzz` (pinned to 0.13.2 in CI;
`cargo install cargo-fuzz --version 0.13.2` matches). `fuzz/Cargo.lock` pins
this crate's dependencies independently of the main workspace lockfile.

## Corpus

`fuzz/corpus/<target>/` holds hand-written seeds (valid and near-valid inputs),
committed to git under descriptive filenames. The `.gitignore` here also
excludes libFuzzer's generated 40-hex-character corpus entries; if a
generated input is worth keeping permanently, copy it into the seed corpus
under a descriptive name instead of committing the raw generated filename.

## CI wiring

`.github/workflows/nightly-security.yml` runs a smoke pass for every committed
target when the nightly security workflow runs. The job uses the nightly
toolchain, `cargo-fuzz` 0.13.2, `-max_total_time=60`, `-rss_limit_mb=1024`, and
uploads `fuzz/artifacts/` on failure.

Issue #26 tracks the fuller crash/corpus regression pattern (persisted corpus
plus previous-crash replay) for the manifest fuzz work and shared CI shape. Once
that pattern lands, the intended shape is:

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

The nightly smoke is not a replacement for the persisted-corpus regression
track; it proves the committed targets and corpora keep building and do not
crash immediately.
