# Base Registry Engine

Base Registry Engine is the domain-neutral, configuration-compiled Registry Stack
system of record. The crate owns the governed model, deterministic compiler,
generated contract artifacts, PostgreSQL runtime, and HTTP service.

The default feature set is I/O-free so authoring tools can compile and inspect
a Registry project without initializing runtime resources. The `runtime`
feature enables the server binary and runtime integrations.

Domain concepts are configuration. Production code must not embed household,
farmer, disability, business, or other adopter-specific record types.

## Focused PostgreSQL performance measurements

With `BREG_TEST_DATABASE_URL` set to a disposable PostgreSQL administrator,
the opt-in measurements use the ordinary test harness to create and remove
isolated databases and constrained roles:

```bash
CARGO_INCREMENTAL=0 cargo test --locked --release -p registry-breg \
  --features postgres-test --test postgres_kernel --test postgres_read \
  benchmark_ -- --ignored --nocapture --test-threads=1
```

`benchmark_record_transaction` measures pool checkout and guarded transaction
begin/rollback while alternating authority on one reused connection.
`benchmark_audited_record_get` measures a projected GET through the real router,
PostgreSQL RLS, and durable attempt/terminal audit, checking every response.
Both exclude setup and warmup and print five samples of mean, p50, p95, and p99
latency. Run them serially on an otherwise quiet host to compare changes.

These measure local sequential latency. They exclude JWT verification, network
transport, concurrent saturation, and large dataset access. Use the
[product load-test environment](../../products/breg/loadtest/README.md) for
workload and capacity investigation.
