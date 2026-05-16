// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for ETag helpers in `src/api/entity.rs`.
//!
//! Covers:
//! - `strong_etag` with short, medium (typical), and long input sets.
//! - `entity_etag` which wraps `strong_etag` with an optional ingest version.
//! - `if_none_match_matches` for exact single-token hit, hit deep in a
//!   comma-separated list, and no-match cases.

use std::hint::black_box;

use axum::http::{header, HeaderMap, HeaderValue};
use criterion::{criterion_group, criterion_main, Criterion};
use data_gate::api::entity::{entity_etag, if_none_match_matches, strong_etag};

// ---------------------------------------------------------------------------
// strong_etag benchmarks
// ---------------------------------------------------------------------------

fn benchmark_strong_etag_short(c: &mut Criterion) {
    // Short: kind + dataset_id only.
    c.bench_function("etag/strong_etag_short", |b| {
        b.iter(|| strong_etag(black_box(&["entity", "ds"])));
    });
}

fn benchmark_strong_etag_medium(c: &mut Criterion) {
    // Medium: typical production inputs for a collection ETag.
    c.bench_function("etag/strong_etag_medium", |b| {
        b.iter(|| {
            strong_etag(black_box(&[
                "entity",
                "collection",
                "clinic_capacity",
                "facility",
                "01HZXK3PQJR8M2N4WVBT6SCDE7",
                r#"{"limit":100}"#,
            ]))
        });
    });
}

fn benchmark_strong_etag_long(c: &mut Criterion) {
    // Long: same as medium but with a wide variant string (many filter params).
    let variant = r#"{"after":"zzz-facility-id-99999","filters":{"region_code":"north_central","status":"active","capacity_tier":"high"},"limit":500}"#;
    c.bench_function("etag/strong_etag_long", |b| {
        b.iter(|| {
            strong_etag(black_box(&[
                "entity",
                "collection",
                "clinic_capacity",
                "facility",
                "01HZXK3PQJR8M2N4WVBT6SCDE7",
                variant,
            ]))
        });
    });
}

// ---------------------------------------------------------------------------
// entity_etag benchmarks
// ---------------------------------------------------------------------------

fn benchmark_entity_etag_some_version(c: &mut Criterion) {
    c.bench_function("etag/entity_etag_with_version", |b| {
        b.iter(|| {
            entity_etag(
                black_box("collection"),
                black_box("clinic_capacity"),
                black_box("facility"),
                black_box(Some("01HZXK3PQJR8M2N4WVBT6SCDE7")),
                black_box(r#"{"limit":100}"#),
            )
        });
    });
}

fn benchmark_entity_etag_no_version(c: &mut Criterion) {
    // Returns None immediately when ingest_version is None.
    c.bench_function("etag/entity_etag_no_version", |b| {
        b.iter(|| {
            entity_etag(
                black_box("collection"),
                black_box("clinic_capacity"),
                black_box("facility"),
                black_box(None),
                black_box(r#"{"limit":100}"#),
            )
        });
    });
}

// ---------------------------------------------------------------------------
// if_none_match_matches benchmarks
// ---------------------------------------------------------------------------

fn benchmark_inm_exact_match(c: &mut Criterion) {
    let etag = strong_etag(&[
        "entity",
        "collection",
        "clinic_capacity",
        "facility",
        "01HZXK3PQJR8M2N4WVBT6SCDE7",
        r#"{"limit":100}"#,
    ]);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_NONE_MATCH,
        HeaderValue::from_str(&etag).expect("valid etag header"),
    );

    c.bench_function("etag/if_none_match_exact", |b| {
        b.iter(|| if_none_match_matches(black_box(&headers), black_box(&etag)));
    });
}

fn benchmark_inm_list_hit(c: &mut Criterion) {
    // ETag appears as the 5th token in a comma-separated list.
    let etag = strong_etag(&[
        "entity",
        "collection",
        "clinic_capacity",
        "facility",
        "01HZXK3PQJR8M2N4WVBT6SCDE7",
        r#"{"limit":100}"#,
    ]);
    let stale_a = strong_etag(&["entity", "collection", "ds", "e", "01AAA", "{}"]);
    let stale_b = strong_etag(&["entity", "collection", "ds", "e", "01BBB", "{}"]);
    let stale_c = strong_etag(&["entity", "collection", "ds", "e", "01CCC", "{}"]);
    let stale_d = strong_etag(&["entity", "collection", "ds", "e", "01DDD", "{}"]);
    let list = format!("{stale_a}, {stale_b}, {stale_c}, {stale_d}, {etag}");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_NONE_MATCH,
        HeaderValue::from_str(&list).expect("valid header"),
    );

    c.bench_function("etag/if_none_match_list_hit", |b| {
        b.iter(|| if_none_match_matches(black_box(&headers), black_box(&etag)));
    });
}

fn benchmark_inm_no_match(c: &mut Criterion) {
    let current_etag = strong_etag(&[
        "entity",
        "collection",
        "clinic_capacity",
        "facility",
        "01HZXK3PQJR8M2N4WVBT6SCDE7",
        r#"{"limit":100}"#,
    ]);
    let stale_etag = strong_etag(&[
        "entity",
        "collection",
        "clinic_capacity",
        "facility",
        "01AAAAAAAAAAAAAAAAAAAAAAAAA",
        r#"{"limit":100}"#,
    ]);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_NONE_MATCH,
        HeaderValue::from_str(&stale_etag).expect("valid header"),
    );

    c.bench_function("etag/if_none_match_no_match", |b| {
        b.iter(|| if_none_match_matches(black_box(&headers), black_box(&current_etag)));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_strong_etag_short,
        benchmark_strong_etag_medium,
        benchmark_strong_etag_long,
        benchmark_entity_etag_some_version,
        benchmark_entity_etag_no_version,
        benchmark_inm_exact_match,
        benchmark_inm_list_hit,
        benchmark_inm_no_match
}
criterion_main!(benches);
