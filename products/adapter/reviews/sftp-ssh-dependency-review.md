# SFTP SSH library dependency review (the `sftp` job source)

Reviewed: 2026-10-31, read-only. No dependency was added; `Cargo.lock`
carries no SSH library (verified: `russh`, `ssh2`, and `thrussh` appear
nowhere in the lock). Status: proposed for Jeremi's decision. The
governed-ingestion brief stops the `sftp` component here: a new
cryptographic dependency is his call.

## Scope and need

The `sftp` job source (`products/adapter/CONCEPT.md` section 8.10, the
`sftp` row; section 17.6 item 2) needs an SSH transport: client key
exchange, host-key verification against pinned keys, channel operation,
and SFTP file reads. No SSH protocol exists in the workspace today. The
component is feature-gated and unclaimed until its acceptance row passes,
so nothing forces a timing on this decision.

## The posture any candidate must meet

`release/notes/dependency-vetting-aws-lc-fips.md` fixes the rule the
candidate is measured against:

- The FIPS backend is always on. `aws-lc-rs` 1.18.2 carries the `fips`
  workspace feature, linking `aws-lc-fips-sys` 0.14.2, and "no build of
  Registry Stack selects the non-FIPS module, and there is no runtime
  detection".
- Every new direct runtime consumer of cryptography needs a dependency
  review of the crate and its feature graph ("do not add another direct
  runtime consumer without re-reviewing").
- `deny.toml` accepts the `OpenSSL` license only for the vendored
  OpenSSL-derived code inside `aws-lc-fips-sys`. A candidate that drags a
  second C crypto stack (OpenSSL proper, mbedtls, wolfSSL) reopens the
  license surface and the validation story, not just the advisory
  surface.
- Sources are crates.io only (`allow-git = []`, `unknown-git = "deny"`),
  and `cargo deny check` must stay green with the candidate added.

An SSH transport is cryptographic in its own right: key exchange, host
key signatures, ciphers, and MACs are SSH-protocol cryptography, not TLS.
Even a perfect FIPS story for `aws-lc-rs` does not automatically cover
them; the question is which crypto the SSH library itself uses and
whether that path is acceptable inside the always-on posture.

## Candidates

### `russh` (and `russh-sftp` for the file layer)

- Pure Rust, safe Rust, async on tokio, client and server; the ecosystem's
  default for new Rust SSH work and actively developed (0.64.x line in
  2026, hosted at `github.com/Eugeny/russh`).
- Cryptography is abstracted behind its own traits; the shipped default
  is `ring`-family primitives, and `ring` 0.17.14 is already in the
  lockfile (through `rustls` and `tokio-postgres-rustls`'s `ring`
  feature). `aws-lc-rs` is API-compatible with `ring` by design, which is
  the documented path rustls itself took for FIPS support.
- What is not established: whether `russh`'s trait layer accepts an
  `aws-lc-rs`-backed implementation today, and whether any of its key
  exchange, cipher, or MAC implementations are validated under any CMVP
  module. No FIPS audit of `russh` was found. `ring` itself is not a
  validated module.
- Licenses: MIT/Apache-2.0 family; no `OpenSSL` term. No new C build
  inputs; no cmake/Go/bindgen additions.

### `ssh2` (libssh2 bindings)

- Maintained under the `rust-lang` GitHub org, synchronous, a safe
  wrapper over the C `libssh2`.
- `libssh2` brings its own crypto (an OpenSSL-compatible or WinCNG
  backend; the vendored `libssh2-sys` path compiles C and links a crypto
  library the workspace does not already validate). That is a second C
  crypto stack beside the always-on `aws-lc-fips-sys`, which is exactly
  the outcome the vetting note's controls forbid growing.
- Sync API also fits poorly with the engine's tokio runtime (would need
  `spawn_blocking` around every SFTP read).

### Process boundary: drive the system `sftp`/`ssh` binary

- No new Rust dependency at all; host-key pinning and batch mode come
  from OpenSSH configuration, which most institutions already operate.
- Cost: the engine's bounds (byte counts, deadlines, cancellation) become
  process-supervision limits instead of in-process bounds; the FIPS
  posture moves to whatever OpenSSL the host binary links; the deployment
  gains a host dependency the product does not ship. The root
  `AGENTS.md` boundary "outside its tests, a runtime never drives another
  product's CLI" concerns Registry Stack products, not system utilities,
  so this shape is legal, but it trades a reviewed dependency for an
  operational one.

## Assessment against `deny.toml`

- `russh`: crates.io source; MIT/Apache-2.0 licences already allowed; no
  wildcard; `ring` already allowed with its clarified expression. The
  open question is the crypto trait backing, not the licence or source.
- `ssh2`: crates.io source; `libssh2-sys` carries an Apache-2.0/MIT
  wrapper around C code under BSD-style notices, but the crypto backend
  it links reopens the `OpenSSL`-adjacent licence surface for code that
  is not the validated FIPS module, and the vetting note's control
  ("no build selects a non-FIPS module") is weakened by a second crypto
  path compiled into a runtime binary.
- System binary: no `deny.toml` change; no crate.

## Options

- (a) `russh` + `russh-sftp`, feature-gated, with a spike that answers
  the aws-lc-rs backend question before adoption; if the spike fails,
  the component documents the divergence (SSH cryptography under `ring`
  primitives for the SFTP transport only, stated plainly) and Jeremi
  decides whether that is acceptable for an unclaimed, feature-gated
  source.
- (b) `ssh2` over libssh2. Rejected as presented: a second C crypto
  stack inside a runtime binary contradicts the always-on posture for no
  advantage a small IT team would notice.
- (c) System OpenSSH binary behind the endpoint. No new dependency;
  bounds move to process supervision; posture becomes the host's.
- (d) Do not build `sftp` until an adopter names it. The component
  remains a contract row with the semantics already written
  (`CONCEPT.md` 8.10) and no code, which is the state today.

## Recommendation

(d) until an adopter names SFTP, then (a) with the backend spike as the
first step. Confidence is medium on the technical ordering and this is a
policy call, so it is Jeremi's. The `sftp` port-table row and its
acceptance row already say what the component must do; only the transport
library waits on this decision.

## If (a) is chosen, the follow-ups this review names

1. A spike proving which key exchange and host-key verification paths
   `russh` takes under an `aws-lc-rs`-backed implementation, recorded
   like the rustls provider choice.
2. A `deny.toml` entry naming the wrapper and its reason, following the
   `saphyr-parser` precedent.
3. An advisory re-run (`cargo deny check`) and the licence surface check
   for the added subgraph.
4. A review trigger list modeled on the aws-lc note's, including "the
   locked `russh` version or its crypto trait surface changes".

## Sources

- `deny.toml` in this repository (licence allows, the `ring`
  clarification, crates.io-only sources, YAML reader bans as the wrapper
  precedent).
- `release/notes/dependency-vetting-aws-lc-fips.md` (the always-on FIPS
  posture, its controls, and its review triggers).
- `Cargo.lock` (ring 0.17.14, aws-lc-rs 1.18.2, aws-lc-fips-sys 0.14.2
  present; no SSH crate).
- Ecosystem status as researched on 2026-10-31: [russh](https://github.com/Eugeny/russh)
  (pure-Rust, trait-abstracted crypto, active), [rustls with the AWS
  libcrypto backend and FIPS support](https://www.memorysafety.org/blog/rustls-with-aws-crypto-back-end-and-fips),
  [aws-lc-rs](https://crates.io/crates/aws-lc-rs) as the ring-compatible
  FIPS path, and the `ssh2`/libssh2 binding under the rust-lang org.
  These are reconnaissance, not verification: nothing was built or run.
