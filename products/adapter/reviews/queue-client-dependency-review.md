# Queue client dependency review (the queue source)

Reviewed: 2026-10-31, read-only. No dependency was added; `Cargo.lock`
carries no Kafka or AMQP client (verified: `rdkafka`, `rskafka`,
`kafka`, and `lapin` appear nowhere in the lock). Status: findings for
Jeremi's queue choice. The queue is a source, not a trigger: a message is
acknowledged (or a Kafka offset committed) only after the destination
acknowledges the hand-off, and redelivery is the re-read. Nothing here
changes that contract.

## The posture any candidate must meet

Same measuring stick as the SFTP review
(`sftp-ssh-dependency-review.md`): the FIPS backend is always on
(`aws-lc-rs` 1.18.2 with the `fips` workspace feature, linking
`aws-lc-fips-sys` 0.14.2), `deny.toml` accepts the `OpenSSL` licence only
for the vendored OpenSSL-derived code inside that module, sources are
crates.io only, and every new direct runtime consumer of cryptography
needs its own review. A candidate that drags a second compiled crypto
stack (system OpenSSL, wolfSSL, mbedtls) reopens both the licence surface
and the validation story.

## Kafka candidates

### `rdkafka` (librdkafka bindings)

- The production default for Rust Kafka: async, full protocol coverage
  (consumer groups, commits, transactions, admin), maintained at
  `github.com/fede1024/rust-rdkafka`, compatible with every Kafka back
  to 0.8.x.
- TLS lives in librdkafka, which links OpenSSL (features `ssl` /
  `ssl-vendored`). There is no rustls path. A FIPS story exists only by
  building and linking a FIPS-validated OpenSSL ourselves: a second C
  crypto stack beside `aws-lc-fips-sys`, a native build input the
  release tooling does not carry, and exactly the outcome the
  always-on-posture controls forbid growing.
- Also brings cmake/build machinery for the vendored C on hosts without
  system librdkafka.

### Pure-Rust Kafka clients

- `rskafka` (InfluxData): minimal async client, rustls-native, aimed at
  simple produce/consume workloads; no consumer-group or transaction
  surface of rdkafka's depth. Our queue contract needs: subscribe,
  bounded fetch, offset commit after destination acknowledgement. A
  minimal client that commits offsets per poll is plausibly enough;
  consumer-group rebalancing is where the small clients are thinnest.
- `rs-kafka` (kafka-rs lineage): rustls instead of OpenSSL by design,
  supports only maintained Kafka versions; the older `kafka-rust`
  project is widely recorded as discontinued, so lineage health needs a
  direct look before any adoption.
- Newer entries (`Kafkang`, `kafkit_client` targeting Kafka 4.0+): too
  young to carry an institutional pilot source; noted, not assessed.
- rustls can be backed by `aws-lc-rs` with the `fips` feature, the same
  provider path the workspace already runs. That is the only candidate
  family whose TLS story composes with the always-on posture without a
  second crypto stack.

## AMQP candidate

### `lapin` (AMQP 0-9-1, RabbitMQ)

- Actively maintained (3.6.0 line, Clever Cloud / lapinou team),
  production-proven since 2020, runtime-agnostic async, the de facto
  Rust RabbitMQ client.
- TLS is connector-pluggable: the documented path is `native-tls` (which
  on macOS links SecurityFramework and on Linux OpenSSL), and a
  `tokio-rustls` connector can be wrapped in, which would keep the
  crypto story on rustls and therefore on `aws-lc-rs`.
- AMQP 0-9-1 acknowledgements map directly onto the queue contract
  (ack after the destination acknowledges; nack/requeue is the
  re-read). Operationally, RabbitMQ is a smaller footprint institution-side
  than a Kafka cluster, which matters to the small-IT-team posture.

## Assessment against `deny.toml`

- `rdkafka`: crates.io source; the binding is MIT/Apache-2.0, but
  librdkafka's OpenSSL linkage reopens the second-crypto-stack question
  the licence table exists to contain. Not admissible as presented; a
  FIPS-OpenSSL build of librdkafka would be its own dependency review.
- Pure-Rust Kafka clients: crates.io sources, MIT/Apache-2.0, no new
  licence terms; rustls is already in the graph. The open question is
  maturity for consumer groups and offset commits, not policy.
- `lapin`: crates.io, MIT/Apache-2.0; admissible with the rustls
  connector path pinned in its review (native-tls default declined).

## Options

- (a) `rdkafka` when Kafka is certain and its operation is already
  institutional: strongest protocol coverage, but it needs its own
  FIPS-OpenSSL dependency review and accepts a second crypto stack.
- (b) A pure-Rust rustls Kafka client (`rskafka` first): composes with
  the always-on posture as-is; a spike must prove consumer-group
  subscribe and post-acknowledgement offset commits against a real
  broker before adoption.
- (c) `lapin` for RabbitMQ/AMQP: mature, connector-pluggable onto
  rustls, operationally light; chosen if the institution runs RabbitMQ
  rather than Kafka.
- (d) No queue until an adopter names the broker. The queue source stays
  a contract row and the trigger seam stays built for the interval
  trigger only.

## Recommendation

(d) until the broker is named, then (c) if the site runs RabbitMQ and
(b) with a maturity spike if Kafka is named; (a) only with its own
FIPS-OpenSSL review. Confidence is medium on the technical ordering; the
broker choice itself is Jeremi's and this review takes no side between
Kafka and AMQP.

## If a client is chosen, the follow-ups this review names

1. A spike against a real broker proving: bounded fetch, offset/ack
   commit only after the destination acknowledges, and crash-resume
   redelivery (the re-read).
2. A `deny.toml` entry naming the wrapper and its reason, following the
   `saphyr-parser` precedent, plus the licence surface check.
3. For any non-rustls TLS path: a dedicated FIPS dependency review like
   the aws-lc note.

## Sources

- `deny.toml` and `release/notes/dependency-vetting-aws-lc-fips.md` in
  this repository (the posture rules).
- `Cargo.lock` in this repository (no queue client present).
- Reconnaissance of 2026-10-31, not verification: [rust-rdkafka](https://github.com/fede1024/rust-rdkafka)
  (librdkafka binding, OpenSSL TLS), [rskafka](https://github.com/influxdata/rskafka)
  and its [design note](https://www.influxdata.com/blog/building-simple-pure-rust-async-apache-kafka-client)
  (minimal pure-Rust, rustls), [rustls](https://github.com/rustls/rustls)
  (aws-lc-rs FIPS provider path), [lapin on crates.io](https://crates.io/crates/lapin/3.6.0)
  and [docs.rs](https://docs.rs/lapin) (maintenance state, connector-based
  TLS). Nothing was built or run against a broker.
