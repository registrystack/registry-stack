// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the durable Evidence audit chain.
//!
//! These measure the real filesystem path through `DurableJsonlSink`, because
//! the cost that decides service throughput is the per-record `fsync` issued
//! while the chain-state mutex is held, not the chain hashing.
//!
//! Covers:
//! - one sequential append, the latency floor a request pays per audit record;
//! - concurrent appends, which show whether added concurrency raises append
//!   throughput or merely queues behind the same serialized `fsync`;
//! - event construction and serialization alone, for scale against the I/O.
//!
//! The `record_bytes` line printed on startup reports the on-disk size of one
//! representative record, which is what sizes the audit file against its
//! configured ceiling.

use std::{hint::black_box, sync::Arc};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use registry_evidence::audit::{
    AuditAuthority, AuditDecision, AuditPhase, AuditSubject, AuthorityKind, EvidenceAuditEvent,
    EvidenceAuditLog, ResponseProtection,
};
use tokio::{runtime::Runtime, task::JoinSet};

/// Far above anything an individual benchmark run appends, so the file-size
/// ceiling never interferes with the measurement.
const BENCH_MAXIMUM_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const BENCH_SECRET: [u8; 64] = [0x5a; 64];
const CONCURRENCY_LEVELS: [usize; 4] = [1, 8, 32, 128];

/// Build a pseudonym of the shape the runtime actually writes, so records are
/// representative in size rather than artificially short.
fn pseudonym(seed: u8) -> String {
    let digest: String = (0u8..32)
        .map(|byte| format!("{:02x}", byte ^ seed))
        .collect();
    format!("hmac-sha256:v1:{digest}")
}

fn sample_event() -> EvidenceAuditEvent {
    EvidenceAuditEvent::new(
        "evidence.request.evaluate".to_string(),
        AuditPhase::AccessAttempt,
        "adult-status".to_string(),
        "2026-08-01T00:00:00Z/1".to_string(),
        "age-verification".to_string(),
        pseudonym(0x11),
        AuditAuthority {
            kind: AuthorityKind::Statutory,
            grant_pseudonym: Some(pseudonym(0x22)),
        },
        vec![AuditSubject {
            role: "subject".to_string(),
            selector_profile: "national-identifier".to_string(),
            selector_bundle_pseudonym: Some(pseudonym(0x33)),
        }],
        ResponseProtection::Signed,
        AuditDecision::Authorized,
        12,
    )
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// Initialize a durable log over a fresh temporary file. The `TempDir` is
/// returned because dropping it would delete the file out from under the sink.
fn durable_log(runtime: &Runtime) -> (tempfile::TempDir, Arc<EvidenceAuditLog>) {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("audit.jsonl");
    let log = runtime.block_on(async {
        EvidenceAuditLog::initialize(path, BENCH_MAXIMUM_FILE_BYTES, BENCH_SECRET.to_vec(), 1)
            .await
            .expect("initialize audit log")
    });
    (directory, Arc::new(log))
}

/// Report the on-disk size of a single record. This is the number that decides
/// how quickly a deployment reaches its configured audit file ceiling.
fn report_record_bytes(runtime: &Runtime) {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("audit.jsonl");
    runtime.block_on(async {
        let log =
            EvidenceAuditLog::initialize(&path, BENCH_MAXIMUM_FILE_BYTES, BENCH_SECRET.to_vec(), 1)
                .await
                .expect("initialize audit log");
        log.append(sample_event()).await.expect("append");
    });
    let bytes = std::fs::metadata(&path).expect("metadata").len();
    eprintln!("audit/record_bytes: {bytes}");
}

/// One append at a time: the per-record cost a request pays, dominated by the
/// `fsync` in the sink write path.
fn benchmark_sequential_append(c: &mut Criterion) {
    let runtime = runtime();
    report_record_bytes(&runtime);
    let (_directory, log) = durable_log(&runtime);

    let mut group = c.benchmark_group("audit/durable_append");
    group.throughput(Throughput::Elements(1));
    group.bench_function("sequential", |b| {
        b.to_async(&runtime)
            .iter(|| async { log.append(black_box(sample_event())).await.expect("append") });
    });
    group.finish();
}

/// Many appends in flight at once. Because the sink holds its state mutex
/// across the blocking write and `fsync`, throughput here is expected to stay
/// flat as concurrency rises: the extra callers queue rather than batch.
fn benchmark_concurrent_append(c: &mut Criterion) {
    let runtime = runtime();
    let (_directory, log) = durable_log(&runtime);

    let mut group = c.benchmark_group("audit/durable_append_concurrent");
    for concurrency in CONCURRENCY_LEVELS {
        group.throughput(Throughput::Elements(concurrency as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&runtime).iter(|| {
                    let log = Arc::clone(&log);
                    async move {
                        let mut appends = JoinSet::new();
                        for _ in 0..concurrency {
                            let log = Arc::clone(&log);
                            appends.spawn(async move {
                                log.append(sample_event()).await.expect("append")
                            });
                        }
                        while let Some(result) = appends.join_next().await {
                            black_box(result.expect("join"));
                        }
                    }
                });
            },
        );
    }
    group.finish();
}

/// Event construction and JSON serialization with no I/O, for scale against
/// the durable append measurements.
fn benchmark_event_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit/event");
    group.bench_function("construct", |b| b.iter(|| black_box(sample_event())));
    let event = sample_event();
    group.bench_function("serialize", |b| {
        b.iter(|| serde_json::to_value(black_box(&event)).expect("serialize"));
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_sequential_append,
        benchmark_concurrent_append,
        benchmark_event_serialization
}
criterion_main!(benches);
