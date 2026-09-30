# Evidence fuzz targets

cargo-fuzz harnesses for untrusted-input boundaries in the Evidence verifier
and authoring crates. These live outside the main workspace (see the root
`Cargo.toml` `exclude` list) so a broken or slow fuzz build never blocks
`cargo check --workspace`.

## Targets

- `verifier_flattened_jws`: flattened-JWS response verification. Each input
  runs as an untrusted serialized response (strict parse, protected-header
  contract, ES256 signature), as the raw payload of an authentically signed
  response (strict payload parse and payload contract), and, when it parses as
  Evidence, as a re-serialized signed assertion (policy comparison)
  (`registry-evidence-verifier`).
- `verifier_sd_jwt_vc`: SD-JWT VC response verification. Inputs that parse as
  Evidence are issued as a signed credential (holder-bound ones with a
  confirmed test holder key) and verified through the issuer-signed
  credential check, disclosure resolution, the rebuilt payload contract, and
  the policy comparison; every other input exercises the compact split and
  the stages before the signature check (`registry-evidence-verifier`).
- `authoring_openapi`: OpenAPI description parsing, operation resolution,
  and schema flattening into candidate leaves
  (`registry-evidence-authoring`).
- `authoring_project`: project marker, question, answer, and access-policy
  documents, their validation findings, and authored derivation source
  (`registry-evidence-authoring`).

The verifier targets sign inputs with the test key the verifier crate's own
tests use, through the crate's `fixtures` feature, so verification reaches
the parsing and policy stages behind the signature check instead of stopping
at it. Each target's fixture signs and verifies a canonical assertion at
startup and fails loudly if that round trip breaks, because a silently
invalid fixture would hollow out the target while it kept reporting clean
runs.

Not yet covered: the SD-JWT VC targets never mutate the disclosure tail
behind a valid issuer signature (the disclosures they verify are the ones the
fixture issuer produced), and no target reaches holder presentation or
key-binding JWT verification. The Evidence runtime's request parsing is not
fuzzed here either.

## Running locally

From `products/evidence/`:

```bash
cargo +nightly fuzz run --fuzz-dir fuzz <target> -- -max_total_time=60 -rss_limit_mb=1024
```

Requires the nightly toolchain and `cargo-fuzz` (pinned to 0.13.2 in CI;
`cargo install cargo-fuzz --version 0.13.2` matches). `fuzz/Cargo.lock` pins
this crate's dependencies independently of the main workspace lockfile.

## Corpus

`fuzz/corpus/<target>/` holds hand-written seeds (valid and near-valid
inputs), committed to git under descriptive filenames. The `.gitignore` here
excludes `artifacts/`, `target/`, and libFuzzer's generated 40-hex-character
corpus entries; if a generated input is worth keeping permanently, copy it
into the seed corpus under a descriptive name instead of committing the raw
generated filename.

## CI wiring

The active root workflows provide two event-specific checks:

- `.github/workflows/ci.yml` runs a required one-minute smoke for each
  target in the merge queue, on pushes to main, and in full sweeps, whenever
  the changed paths reach the Evidence packages.
- `.github/workflows/nightly-security.yml` runs every target nightly as part
  of the scheduled security suite.

Both use the nightly toolchain, pinned `cargo-fuzz` 0.13.2, the committed
seed corpus, `-max_total_time=60`, and `-rss_limit_mb=1024`, and upload crash
artifacts only on failure. A crash at these trust boundaries may be a security
finding and should route through `SECURITY.md`; automation must not file a
public issue containing the input.
