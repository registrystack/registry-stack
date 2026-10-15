# Committed product events

A reviewed Workflow can react to an authenticated event captured by another
product after its transaction commits. Products own their event vocabulary,
projection and disclosure. Coordinator verifies the shared signed envelope,
maps typed input and admits one ordinary durable Run. Every later product call
uses its own configured authorization.

The [native acceptance runner](../../scripts/test-breg-events.py) creates
synthetic BReg and Coordinator projects through the maintained tooling. It
checks a new record, a direct patch and an Action whose committed effect patches
that record. Each accepted event causes a separately authorized current-record
read. The runner uses BReg-generated event data schemas and exact schema IDs,
rather than declaring a BReg payload parser in Coordinator.

The runner also checks a lost acknowledgment and producer retry, exact replay
after Coordinator restart, invalid signature refusal, and a refused source write
that captures no event. A second pure observer Workflow receives a conforming
synthetic Scheduling-shaped projection through the same intake. This is an
alternate producer transport fixture; it does not run Scheduling.

From the repository root, build the four executables from the same source:

```sh
cargo build --locked -p registry-breg -p registry-bregctl -p registry-coordinator \
  --features registry-breg/runtime,registry-bregctl/schema,registry-coordinator/schema \
  --bin breg --bin bregctl --bin coordinator --bin coordinatorctl
```

Docker, `psql` and a disposable loopback PostgreSQL database are required. Set
`COORDINATOR_TEST_DATABASE_URL` through your private environment configuration.
Use the actual Cargo target directory when it differs from `target`:

```sh
python3 products/coordinator/scripts/test-breg-events.py \
  --bin-dir target/debug --output /private/tmp/coordinator-product-events
```

When using a frozen native bundle, pass its matching `--build-manifest` to verify
the selected executable hashes and use its retained runtime library on macOS.
The output directory must be new. It contains private fixture configuration,
logs and a value-free `result.json`. The runner stops its owned services and
removes the Coordinator schema and role it created. It leaves the supplied
PostgreSQL database itself intact. BReg's native development tooling owns its
separate disposable registry database and issuer session.

Authored `workflow.eventTriggers` selects a logical source, exact event type,
exact data schema, typed event schema and ordinary input Mapping. Deployment
`eventSources` supplies the producer URI and a protected HMAC key reference.
Its `signingKeyRef` resolves the raw HMAC-SHA-256 secret bytes, at least 32
bytes, through an enabled secret provider.
The accepted Run pins the active reviewed Workflow snapshot. Event input never
chooses a principal, connection or credential.

Intake accepts at most 1 MiB, the Version 1 signable bound, and the admitted
event must fit the 128 KiB structured value profile, so use minimized producer
projections. A signed event over that profile is refused with `event.too-large`
(413), whose detail lists each bound. The producer refreshes its signed delivery time for each attempt; the receiver
allows 30 seconds of delivery-time skew.

Stable event identity deduplicates retries and operator replay even when the
transport generation or active Workflow revision changes. The entire event is
bound, including projected fields that the mapping ignores. Exact historical
replay returns its original Run; conflicting bytes refuse admission. Signature
freshness applies to the refreshed delivery time, so a retained event can be
delivered after an outage without rewriting its immutable commit time.

To revoke ingress, remove its active triggers and runtime source binding.
Already admitted Runs keep their original effect connection bindings and can
continue or be inspected after that source is removed. Recovery-only serving
disables intake and does not require event signing keys to be available.

Select meaningful producer transitions and guard writes back to the source.
Each Run is finite, but ordinary product API mutations may emit fresh root
events: this example makes no cross-product ancestry or feedback-loop
suppression claim. An accepted event also does not establish downstream
eligibility, renew an approval or undo a cancelled Run.
