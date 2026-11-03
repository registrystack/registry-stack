# `lapin`, `russh` and `russh-sftp` dependency vetting

Reviewed: 2026-11-03

Decision: accept the exactly pinned `lapin` 4.12.3, `russh` 0.65.0 and
`russh-sftp` 3.0.1 for the Adapter ingestion-job host's two default-off source
transports, subject to the scoped accepted risks and the review trigger below.
This is not a certification of either protocol client.

## Scope and need

The job host (`registry-adapter-job`, `publish = false`, source-build only)
reads items from two transports that no existing workspace crate provides:

- RabbitMQ, through `lapin` over verified TLS, behind the `job-rabbitmq`
  feature. The source settles each delivery manually after the durable item
  outcome.
- SFTP, through in-process `russh` and `russh-sftp`, behind the `job-sftp`
  feature. The host key is pinned before any credential is resolved or sent.

Neither feature is in `default`, and neither is linked by the facade or the
engine's default build. The selection rationale is in
`products/adapter/CONCEPT.md` (the job-source decisions); these crates are
runtime dependencies of the job host only.

## Package and source

| Crate | Version | Source | Licence | Features enabled |
|---|---|---|---|---|
| `lapin` | `=4.12.3` | crates.io, <https://github.com/amqp-rs/lapin> | MIT | `tokio`, `rustls--aws_lc_rs`, `rustls-native-certs`; default features off |
| `russh` | `=0.65.0` | crates.io, <https://github.com/warp-tech/russh> | Apache-2.0 | `aws-lc-rs`; default features off |
| `russh-sftp` | `=3.0.1` | crates.io, <https://github.com/AspectUnk/russh-sftp> | Apache-2.0 | defaults |

All three licences are compatible with the repository licence. The exact pins
sit in the workspace `Cargo.toml` and the resolved versions in `Cargo.lock`.
`lapin` and its `amq-protocol` family are maintained under the `amqp-rs`
organisation; `russh` is published from the `warp-tech` organisation; `russh-sftp` is a
smaller project layered on `russh`. Maintenance health was read
from the repositories' declared metadata only; this review ran no network
queries, so recent release cadence and open advisories are not recorded here.

## Transitive impact and the called-out items

The two features add a substantial graph to `Cargo.lock`. Three items warrant
a scoped decision:

1. **Pre-release `ssh-key` 0.7.0-rc.11, via `russh`.** A release candidate sits
   in the SFTP host-key comparison and the private-key credential decode
   (`russh::keys::decode_secret_key` and `PublicKey` in
   `crates/registry-adapter-job/src/sftp_source.rs`). Accepted risk: the
   transport is default-off and source-build only, the host key is pinned and
   compared before a credential is sent, and the version is fixed by the exact
   `russh` pin. Revisit when `russh` moves to a stable `ssh-key`.
2. **Legacy PKCS#12 crypto (`p12-keystore` with `des`, `rc2` and `sha1`), via
   `lapin` -> `amq-protocol-tcp` -> `tcp-stream`.** The crates are compiled
   in, but the RabbitMQ source builds its TLS configuration with
   `identity: None` (`rabbitmq_source.rs`), so no PKCS#12 client identity is
   ever loaded by Registry Stack. Accepted risk: dead-by-configuration code,
   not a reachable path. Revisit if the source ever accepts a client
   certificate bundle.
3. **Second majors of `ed25519` (2.2.3 and 3.0.0), `ed25519-dalek` (2.2.0 and
   3.0.0), `curve25519-dalek` (4.1.3 and 5.0.0) and `sha1` (0.10.7 and
   0.11.0).** Duplicate versions are a size and review cost, not a known
   fault. Accepted until `russh` and the existing signing path converge.

AWS-LC backs the selected cipher paths for both transports. Key exchange and
signatures also use RustCrypto, so this is not a whole-session FIPS validation
claim.

## Security posture

`cargo deny check` and `cargo audit` were not run for this note. The reviewer
who adds a release artifact that enables either feature runs both and records
the result here.

## Review trigger

Before any release artifact enables `job-sftp` or `job-rabbitmq`: rerun
`cargo deny check` and `cargo audit` with the feature enabled, confirm the
`ssh-key` pre-release is still the only pre-release in the SSH path, and
re-decide items 1 to 3 above. Broker redelivery, dead-letter and SFTP
recovery behavior need actual broker and server acceptance tests, separately
from this dependency review.
