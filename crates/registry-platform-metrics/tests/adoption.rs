// SPDX-License-Identifier: Apache-2.0
//! Each test rebuilds a representative scrape of one hand-rolled exposition
//! with the primitive and compares it byte for byte with the text that
//! exposition writes today. The recording code in each test is the shape an
//! adopting product would use; the expected text is what its current renderer
//! emits for the same events.

use std::time::Duration;

use registry_platform_metrics::{
    CounterVec, Exposition, HistogramVec, LabelSpace, MetricKind, SumCountOrder,
};

fn seconds(milliseconds: u64) -> f64 {
    Duration::from_millis(milliseconds).as_secs_f64()
}

// registry-evidence-oid4vci: crates/registry-evidence-oid4vci/src/observability.rs

const OID4VCI_BUCKETS: [f64; 8] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0, 5.0];
const OID4VCI_OUTCOMES: [&[&str]; 18] = [
    &["offer-created"],
    &["offer-authorization-refused"],
    &["store-saturated"],
    &["store-fault"],
    &["code-redeemed"],
    &["code-claim-refused"],
    &["token-claimed"],
    &["token-claim-refused"],
    &["nonce-minted"],
    &["nonce-invalid"],
    &["nonce-tampered"],
    &["nonce-expired"],
    &["proof-refused"],
    &["credential-issued"],
    &["evidence-refused"],
    &["evidence-not-available"],
    &["evidence-unavailable"],
    &["cleanup-expired"],
];

#[test]
fn evidence_oid4vci_scrape_is_reproduced() {
    let request_labels = ["route", "method", "status", "error"];
    let requests = CounterVec::new(
        "evidence_oid4vci_http_requests_total",
        "Delivery requests by closed outcome class.",
        LabelSpace::bounded(&request_labels, 512).unwrap(),
    )
    .unwrap();
    let durations = HistogramVec::new(
        "evidence_oid4vci_http_request_duration_seconds",
        "Delivery request latency.",
        &OID4VCI_BUCKETS,
        LabelSpace::bounded(&request_labels, 512).unwrap(),
    )
    .unwrap();
    let outcomes = CounterVec::new(
        "evidence_oid4vci_outcomes_total",
        "Closed protocol and upstream outcome classes.",
        LabelSpace::closed_zero_filled(&["outcome"], &OID4VCI_OUTCOMES).unwrap(),
    )
    .unwrap();

    let key = ["unmatched", "other", "client-error", "other"];
    requests.inc(&key).unwrap();
    durations.observe(&key, seconds(20)).unwrap();
    outcomes.inc(&["nonce-tampered"]).unwrap();

    let mut out = Exposition::new();
    requests.write(&mut out).unwrap();
    durations
        .write(&mut out, SumCountOrder::SumThenCount)
        .unwrap();
    outcomes.write(&mut out).unwrap();
    out.header(
        "evidence_oid4vci_store_entries",
        Some("Entries in the fullest independently bounded offer, ledger, or token keyspace."),
        MetricKind::Gauge,
    )
    .unwrap();
    out.sample("evidence_oid4vci_store_entries", &[], 7_usize)
        .unwrap();
    out.header(
        "evidence_oid4vci_store_capacity",
        Some("Refusal threshold for each independently bounded offer, ledger, or token keyspace."),
        MetricKind::Gauge,
    )
    .unwrap();
    out.sample("evidence_oid4vci_store_capacity", &[], 256_usize)
        .unwrap();
    out.header(
        "evidence_oid4vci_cleanup_expired_total",
        Some("Expired in-memory entries released by cleanup."),
        MetricKind::Counter,
    )
    .unwrap();
    out.sample("evidence_oid4vci_cleanup_expired_total", &[], 0_u64)
        .unwrap();

    let expected = "\
# HELP evidence_oid4vci_http_requests_total Delivery requests by closed outcome class.
# TYPE evidence_oid4vci_http_requests_total counter
evidence_oid4vci_http_requests_total{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\"} 1
# HELP evidence_oid4vci_http_request_duration_seconds Delivery request latency.
# TYPE evidence_oid4vci_http_request_duration_seconds histogram
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"0.005\"} 0
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"0.01\"} 0
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"0.025\"} 1
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"0.05\"} 1
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"0.1\"} 1
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"0.25\"} 1
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"1\"} 1
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"5\"} 1
evidence_oid4vci_http_request_duration_seconds_bucket{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\",le=\"+Inf\"} 1
evidence_oid4vci_http_request_duration_seconds_sum{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\"} 0.02
evidence_oid4vci_http_request_duration_seconds_count{route=\"unmatched\",method=\"other\",status=\"client-error\",error=\"other\"} 1
# HELP evidence_oid4vci_outcomes_total Closed protocol and upstream outcome classes.
# TYPE evidence_oid4vci_outcomes_total counter
evidence_oid4vci_outcomes_total{outcome=\"offer-created\"} 0
evidence_oid4vci_outcomes_total{outcome=\"offer-authorization-refused\"} 0
evidence_oid4vci_outcomes_total{outcome=\"store-saturated\"} 0
evidence_oid4vci_outcomes_total{outcome=\"store-fault\"} 0
evidence_oid4vci_outcomes_total{outcome=\"code-redeemed\"} 0
evidence_oid4vci_outcomes_total{outcome=\"code-claim-refused\"} 0
evidence_oid4vci_outcomes_total{outcome=\"token-claimed\"} 0
evidence_oid4vci_outcomes_total{outcome=\"token-claim-refused\"} 0
evidence_oid4vci_outcomes_total{outcome=\"nonce-minted\"} 0
evidence_oid4vci_outcomes_total{outcome=\"nonce-invalid\"} 0
evidence_oid4vci_outcomes_total{outcome=\"nonce-tampered\"} 1
evidence_oid4vci_outcomes_total{outcome=\"nonce-expired\"} 0
evidence_oid4vci_outcomes_total{outcome=\"proof-refused\"} 0
evidence_oid4vci_outcomes_total{outcome=\"credential-issued\"} 0
evidence_oid4vci_outcomes_total{outcome=\"evidence-refused\"} 0
evidence_oid4vci_outcomes_total{outcome=\"evidence-not-available\"} 0
evidence_oid4vci_outcomes_total{outcome=\"evidence-unavailable\"} 0
evidence_oid4vci_outcomes_total{outcome=\"cleanup-expired\"} 0
# HELP evidence_oid4vci_store_entries Entries in the fullest independently bounded offer, ledger, or token keyspace.
# TYPE evidence_oid4vci_store_entries gauge
evidence_oid4vci_store_entries 7
# HELP evidence_oid4vci_store_capacity Refusal threshold for each independently bounded offer, ledger, or token keyspace.
# TYPE evidence_oid4vci_store_capacity gauge
evidence_oid4vci_store_capacity 256
# HELP evidence_oid4vci_cleanup_expired_total Expired in-memory entries released by cleanup.
# TYPE evidence_oid4vci_cleanup_expired_total counter
evidence_oid4vci_cleanup_expired_total 0
";
    assert_eq!(out.finish(), expected);
}

// registry-evidence: crates/registry-evidence/src/observability.rs

const EVIDENCE_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];
const DEPENDENCY_OUTCOMES: [&str; 15] = [
    "success",
    "cancelled",
    "credential",
    "concurrency",
    "timeout",
    "transport",
    "unauthorized",
    "forbidden",
    "rate-limited",
    "server-error",
    "protocol",
    "verification",
    "statement",
    "signing",
    "serialization",
];

fn dependency_histogram(name: &str) -> HistogramVec {
    let declared: Vec<[&str; 1]> = DEPENDENCY_OUTCOMES.iter().map(|o| [*o]).collect();
    let declared: Vec<&[&str]> = declared.iter().map(|o| o.as_slice()).collect();
    HistogramVec::new(
        name,
        "Dependency attempt latency including cancellation.",
        &EVIDENCE_BUCKETS,
        LabelSpace::closed(&["outcome"], &declared).unwrap(),
    )
    .unwrap()
}

/// The dependency block interleaves each outcome's counter sample with its
/// histogram samples, count before sum, under headers written up front.
fn write_dependency(
    out: &mut Exposition,
    dependency: &str,
    identity: (&str, &str),
    histogram: &HistogramVec,
) {
    let counter = format!("evidence_{dependency}_requests_total");
    let duration = format!("evidence_{dependency}_request_duration_seconds");
    for (values, snapshot) in histogram.snapshots() {
        let labels = [identity, ("outcome", values[0].as_str())];
        out.sample(&counter, &labels, snapshot.count).unwrap();
        out.histogram(
            &duration,
            &labels,
            histogram.bounds(),
            &snapshot,
            SumCountOrder::CountThenSum,
        )
        .unwrap();
    }
}

#[test]
fn evidence_request_series_and_gauge_are_reproduced() {
    let labels = ["route", "method", "status", "error"];
    let requests = CounterVec::new(
        "evidence_http_requests_total",
        "Requests served by the Evidence boundary.",
        LabelSpace::bounded(&labels, 512).unwrap(),
    )
    .unwrap();
    let durations = HistogramVec::new(
        "evidence_http_request_duration_seconds",
        "Request duration at the Evidence boundary.",
        &EVIDENCE_BUCKETS,
        LabelSpace::bounded(&labels, 512).unwrap(),
    )
    .unwrap();
    for key in [
        [
            "/v1/evidence",
            "POST",
            "client-error",
            "evidence.invalid-request",
        ],
        ["/health", "GET", "success", "none"],
    ] {
        requests.inc(&key).unwrap();
        durations.observe(&key, seconds(30)).unwrap();
    }
    let mut out = Exposition::new();
    requests.write(&mut out).unwrap();
    durations
        .write(&mut out, SumCountOrder::SumThenCount)
        .unwrap();
    out.header(
        "evidence_rate_limiter_tracked_keys",
        Some("Pseudonym keys currently tracked by the rate limiter."),
        MetricKind::Gauge,
    )
    .unwrap();
    out.sample("evidence_rate_limiter_tracked_keys", &[], 42_usize)
        .unwrap();

    let expected = "\
# HELP evidence_http_requests_total Requests served by the Evidence boundary.
# TYPE evidence_http_requests_total counter
evidence_http_requests_total{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\"} 1
evidence_http_requests_total{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\"} 1
# HELP evidence_http_request_duration_seconds Request duration at the Evidence boundary.
# TYPE evidence_http_request_duration_seconds histogram
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"0.005\"} 0
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"0.01\"} 0
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"0.025\"} 0
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"0.05\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"0.1\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"0.25\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"0.5\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"1\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"5\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\",le=\"+Inf\"} 1
evidence_http_request_duration_seconds_sum{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\"} 0.03
evidence_http_request_duration_seconds_count{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"0.005\"} 0
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"0.01\"} 0
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"0.025\"} 0
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"0.05\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"0.1\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"0.25\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"0.5\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"1\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"5\"} 1
evidence_http_request_duration_seconds_bucket{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\",le=\"+Inf\"} 1
evidence_http_request_duration_seconds_sum{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\"} 0.03
evidence_http_request_duration_seconds_count{route=\"/v1/evidence\",method=\"POST\",status=\"client-error\",error=\"evidence.invalid-request\"} 1
# HELP evidence_rate_limiter_tracked_keys Pseudonym keys currently tracked by the rate limiter.
# TYPE evidence_rate_limiter_tracked_keys gauge
evidence_rate_limiter_tracked_keys 42
";
    assert_eq!(out.finish(), expected);
}

#[test]
fn evidence_source_diagnostics_are_reproduced() {
    // One governed source whose identifier needs escaping, one that is quiet.
    let sources = ["pe\"ople", "zeta"];
    let lookup_outcomes = ["match", "no-match", "ambiguous", "unresolved"];
    let mut declared: Vec<[&str; 2]> = Vec::new();
    for source in sources {
        for outcome in lookup_outcomes {
            declared.push([source, outcome]);
        }
    }
    let declared: Vec<&[&str]> = declared.iter().map(|pair| pair.as_slice()).collect();
    let lookups = CounterVec::new(
        "evidence_source_lookups_total",
        "Completed pack lookups by closed outcome.",
        LabelSpace::closed(&["source", "outcome"], &declared).unwrap(),
    )
    .unwrap();
    lookups.inc(&["pe\"ople", "match"]).unwrap();
    lookups.inc(&["pe\"ople", "ambiguous"]).unwrap();
    lookups.inc(&["pe\"ople", "no-match"]).unwrap();
    assert!(lookups.inc(&["request-controlled", "match"]).is_err());

    let source_requests = dependency_histogram("evidence_source_request_duration_seconds");
    source_requests
        .observe(&["timeout"], seconds(6000))
        .unwrap();
    source_requests.observe(&["success"], seconds(30)).unwrap();
    let signer_requests = dependency_histogram("evidence_signer_request_duration_seconds");
    signer_requests.observe(&["success"], seconds(1)).unwrap();

    let mut out = Exposition::new();
    out.header(
        "evidence_build_info",
        Some("Running version and captured governed identities."),
        MetricKind::Gauge,
    )
    .unwrap();
    out.sample(
        "evidence_build_info",
        &[
            ("version", "0.45.1"),
            ("bundle", "bundle\\1"),
            ("authority", "package"),
        ],
        1_u64,
    )
    .unwrap();
    for dependency in ["source", "signer"] {
        let counter = format!("evidence_{dependency}_requests_total");
        let duration = format!("evidence_{dependency}_request_duration_seconds");
        out.header(
            &counter,
            Some("Completed dependency attempts by closed outcome."),
            MetricKind::Counter,
        )
        .unwrap();
        out.header(
            &duration,
            Some("Dependency attempt latency including cancellation."),
            MetricKind::Histogram,
        )
        .unwrap();
    }
    write_dependency(&mut out, "source", ("source", "pe\"ople"), &source_requests);
    write_dependency(&mut out, "signer", ("signer", "active"), &signer_requests);
    lookups.write(&mut out).unwrap();

    // One dependency outcome: the counter sample, then buckets, +Inf, count, sum.
    let block = |dependency: &str, labels: &str, counts: [u64; 9], sum: &str| -> String {
        let prefix = format!("evidence_{dependency}_request_duration_seconds");
        let bounds = [
            "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "5",
        ];
        let mut text = format!("evidence_{dependency}_requests_total{{{labels}}} 1\n");
        for (bound, count) in bounds.into_iter().zip(counts) {
            text.push_str(&format!(
                "{prefix}_bucket{{{labels},le=\"{bound}\"}} {count}\n"
            ));
        }
        text.push_str(&format!(
            "{prefix}_bucket{{{labels},le=\"+Inf\"}} 1\n{prefix}_count{{{labels}}} 1\n{prefix}_sum{{{labels}}} {sum}\n"
        ));
        text
    };
    let mut expected = String::from(
        "\
# HELP evidence_build_info Running version and captured governed identities.
# TYPE evidence_build_info gauge
evidence_build_info{version=\"0.45.1\",bundle=\"bundle\\\\1\",authority=\"package\"} 1
# HELP evidence_source_requests_total Completed dependency attempts by closed outcome.
# TYPE evidence_source_requests_total counter
# HELP evidence_source_request_duration_seconds Dependency attempt latency including cancellation.
# TYPE evidence_source_request_duration_seconds histogram
# HELP evidence_signer_requests_total Completed dependency attempts by closed outcome.
# TYPE evidence_signer_requests_total counter
# HELP evidence_signer_request_duration_seconds Dependency attempt latency including cancellation.
# TYPE evidence_signer_request_duration_seconds histogram
",
    );
    // Declared order: success before timeout, whatever order they were seen.
    expected.push_str(&block(
        "source",
        "source=\"pe\\\"ople\",outcome=\"success\"",
        [0, 0, 0, 1, 1, 1, 1, 1, 1],
        "0.03",
    ));
    expected.push_str(&block(
        "source",
        "source=\"pe\\\"ople\",outcome=\"timeout\"",
        [0; 9],
        "6",
    ));
    expected.push_str(&block(
        "signer",
        "signer=\"active\",outcome=\"success\"",
        [1; 9],
        "0.001",
    ));
    expected.push_str(
        "\
# HELP evidence_source_lookups_total Completed pack lookups by closed outcome.
# TYPE evidence_source_lookups_total counter
evidence_source_lookups_total{source=\"pe\\\"ople\",outcome=\"match\"} 1
evidence_source_lookups_total{source=\"pe\\\"ople\",outcome=\"no-match\"} 1
evidence_source_lookups_total{source=\"pe\\\"ople\",outcome=\"ambiguous\"} 1
",
    );
    assert_eq!(out.finish(), expected);
}

#[test]
fn evidence_shape_drift_counter_is_reproduced() {
    let drift = CounterVec::new(
        "evidence_source_shape_drift_total",
        "Source responses whose shape departed from the declared projection.",
        LabelSpace::closed_zero_filled(&["source"], &[&["source-a"], &["source-b"]]).unwrap(),
    )
    .unwrap();
    drift.inc(&["source-a"]).unwrap();
    drift.inc(&["source-a"]).unwrap();
    assert!(drift.inc(&["not-governed"]).is_err());
    let mut out = Exposition::new();
    drift.write(&mut out).unwrap();
    assert_eq!(
        out.finish(),
        "# HELP evidence_source_shape_drift_total Source responses whose shape departed from the declared projection.\n\
         # TYPE evidence_source_shape_drift_total counter\n\
         evidence_source_shape_drift_total{source=\"source-a\"} 2\n\
         evidence_source_shape_drift_total{source=\"source-b\"} 0\n"
    );
}

// registry-messaging: crates/registry-messaging/src/metrics.rs

#[test]
fn messaging_scrape_is_reproduced() {
    let requests = CounterVec::new(
        "messaging_http_requests_total",
        "Answered HTTP requests.",
        LabelSpace::bounded(&["route", "method", "status"], 512).unwrap(),
    )
    .unwrap();
    requests
        .inc(&["/v1/messages/{message_id}", "GET", "4xx"])
        .unwrap();
    requests.inc(&["unmatched", "other", "2xx"]).unwrap();
    let refusals = CounterVec::new(
        "messaging_authentication_refusals_total",
        "Bearer credentials refused before a caller was resolved.",
        LabelSpace::bounded(&["reason"], 8).unwrap(),
    )
    .unwrap();
    refusals.inc(&["unavailable"]).unwrap();
    refusals.inc(&["claims"]).unwrap();
    let callbacks = CounterVec::new(
        "messaging_provider_callbacks_total",
        "Provider delivery callbacks, by what became of them.",
        LabelSpace::closed_zero_filled(
            &["outcome"],
            &[
                &["unverified"],
                &["unreadable"],
                &["ignored"],
                &["applied"],
                &["unchanged"],
                &["unmatched"],
                &["ambiguous"],
                &["unavailable"],
            ],
        )
        .unwrap(),
    )
    .unwrap();
    callbacks.inc(&["unmatched"]).unwrap();
    callbacks.inc(&["unmatched"]).unwrap();
    let attempts = CounterVec::new(
        "messaging_provider_attempts_total",
        "Provider attempts, by the outcome the attempt history records.",
        LabelSpace::closed_zero_filled(
            &["outcome"],
            &[
                &["accepted"],
                &["transient"],
                &["permanent"],
                &["maybe-sent"],
            ],
        )
        .unwrap(),
    )
    .unwrap();
    attempts.inc(&["maybe-sent"]).unwrap();
    let limits = CounterVec::new(
        "messaging_limit_refusals_total",
        "Submissions, attempts, and provider callbacks a limit refused, by the limit.",
        LabelSpace::closed_zero_filled(
            &["limit"],
            &[&["rate"], &["daily"], &["pacing"], &["callback"]],
        )
        .unwrap(),
    )
    .unwrap();
    limits.inc(&["daily"]).unwrap();
    let retention = CounterVec::new(
        "messaging_retention_runs_total",
        "Retention sweeps this process ran, by outcome.",
        LabelSpace::closed_zero_filled(&["outcome"], &[&["erased"], &["idle"], &["failed"]])
            .unwrap(),
    )
    .unwrap();
    retention.inc(&["failed"]).unwrap();

    let render = |depth: Option<(i64, i64, i64)>| {
        let mut out = Exposition::new();
        for counter in [
            &requests, &refusals, &callbacks, &attempts, &limits, &retention,
        ] {
            counter.write(&mut out).unwrap();
        }
        out.header(
            "messaging_dispatch_jobs",
            Some("Messages waiting to be sent, being sent, or held unknown, sampled at scrape."),
            MetricKind::Gauge,
        )
        .unwrap();
        if let Some((pending, leased, unknown)) = depth {
            for (state, count) in [
                ("pending", pending),
                ("leased", leased),
                ("unknown", unknown),
            ] {
                out.sample("messaging_dispatch_jobs", &[("state", state)], count)
                    .unwrap();
            }
        }
        out.finish()
    };

    let head = "\
# HELP messaging_http_requests_total Answered HTTP requests.
# TYPE messaging_http_requests_total counter
messaging_http_requests_total{route=\"/v1/messages/{message_id}\",method=\"GET\",status=\"4xx\"} 1
messaging_http_requests_total{route=\"unmatched\",method=\"other\",status=\"2xx\"} 1
# HELP messaging_authentication_refusals_total Bearer credentials refused before a caller was resolved.
# TYPE messaging_authentication_refusals_total counter
messaging_authentication_refusals_total{reason=\"claims\"} 1
messaging_authentication_refusals_total{reason=\"unavailable\"} 1
# HELP messaging_provider_callbacks_total Provider delivery callbacks, by what became of them.
# TYPE messaging_provider_callbacks_total counter
messaging_provider_callbacks_total{outcome=\"unverified\"} 0
messaging_provider_callbacks_total{outcome=\"unreadable\"} 0
messaging_provider_callbacks_total{outcome=\"ignored\"} 0
messaging_provider_callbacks_total{outcome=\"applied\"} 0
messaging_provider_callbacks_total{outcome=\"unchanged\"} 0
messaging_provider_callbacks_total{outcome=\"unmatched\"} 2
messaging_provider_callbacks_total{outcome=\"ambiguous\"} 0
messaging_provider_callbacks_total{outcome=\"unavailable\"} 0
# HELP messaging_provider_attempts_total Provider attempts, by the outcome the attempt history records.
# TYPE messaging_provider_attempts_total counter
messaging_provider_attempts_total{outcome=\"accepted\"} 0
messaging_provider_attempts_total{outcome=\"transient\"} 0
messaging_provider_attempts_total{outcome=\"permanent\"} 0
messaging_provider_attempts_total{outcome=\"maybe-sent\"} 1
# HELP messaging_limit_refusals_total Submissions, attempts, and provider callbacks a limit refused, by the limit.
# TYPE messaging_limit_refusals_total counter
messaging_limit_refusals_total{limit=\"rate\"} 0
messaging_limit_refusals_total{limit=\"daily\"} 1
messaging_limit_refusals_total{limit=\"pacing\"} 0
messaging_limit_refusals_total{limit=\"callback\"} 0
# HELP messaging_retention_runs_total Retention sweeps this process ran, by outcome.
# TYPE messaging_retention_runs_total counter
messaging_retention_runs_total{outcome=\"erased\"} 0
messaging_retention_runs_total{outcome=\"idle\"} 0
messaging_retention_runs_total{outcome=\"failed\"} 1
# HELP messaging_dispatch_jobs Messages waiting to be sent, being sent, or held unknown, sampled at scrape.
# TYPE messaging_dispatch_jobs gauge
";
    assert_eq!(render(None), head);
    assert_eq!(
        render(Some((3, 1, 2))),
        format!(
            "{head}messaging_dispatch_jobs{{state=\"pending\"}} 3\nmessaging_dispatch_jobs{{state=\"leased\"}} 1\nmessaging_dispatch_jobs{{state=\"unknown\"}} 2\n"
        )
    );
}

// registry-casework: crates/registry-casework/src/metrics.rs

#[test]
fn casework_scrape_is_reproduced() {
    let render = |readings: Option<[i64; 3]>| {
        let mut out = Exposition::new();
        out.header("casework_database_up", None, MetricKind::Gauge)
            .unwrap();
        out.sample("casework_database_up", &[], u8::from(readings.is_some()))
            .unwrap();
        if let Some(values) = readings {
            for (name, value) in [
                "casework_open_review_requests",
                "casework_open_review_tasks",
                "casework_due_review_tasks",
            ]
            .into_iter()
            .zip(values)
            {
                out.header(name, None, MetricKind::Gauge).unwrap();
                out.sample(name, &[], value).unwrap();
            }
        }
        out.finish()
    };
    assert_eq!(
        render(Some([4, 9, 2])),
        "# TYPE casework_database_up gauge\ncasework_database_up 1\n\
         # TYPE casework_open_review_requests gauge\ncasework_open_review_requests 4\n\
         # TYPE casework_open_review_tasks gauge\ncasework_open_review_tasks 9\n\
         # TYPE casework_due_review_tasks gauge\ncasework_due_review_tasks 2\n"
    );
    assert_eq!(
        render(None),
        "# TYPE casework_database_up gauge\ncasework_database_up 0\n"
    );
}

// registry-coordinator: crates/registry-coordinator/src/metrics.rs

#[test]
fn coordinator_scrape_is_reproduced() {
    let admitted = CounterVec::new(
        "coordinator_runs_admitted_total",
        "Runs whose admission committed.",
        LabelSpace::closed_zero_filled(&[], &[&[]]).unwrap(),
    )
    .unwrap();
    admitted.inc(&[]).unwrap();
    admitted.inc(&[]).unwrap();
    let finished = CounterVec::new(
        "coordinator_runs_finished_total",
        "Committed moves of a run into a terminal state, by that state.",
        LabelSpace::closed_zero_filled(
            &["state"],
            &[
                &["finished"],
                &["failed"],
                &["cancelled"],
                &["cancelled-after-effect"],
                &["expired"],
            ],
        )
        .unwrap(),
    )
    .unwrap();
    finished.inc(&["cancelled-after-effect"]).unwrap();
    let attempts = CounterVec::new(
        "coordinator_step_attempts_total",
        "Step attempts the worker made, by what each came to.",
        LabelSpace::closed_zero_filled(
            &["outcome"],
            &[
                &["accepted"],
                &["transient"],
                &["permanent"],
                &["maybe-sent"],
                &["unavailable"],
            ],
        )
        .unwrap(),
    )
    .unwrap();
    attempts.inc(&["accepted"]).unwrap();
    let refusals = CounterVec::new(
        "coordinator_authentication_refusals_total",
        "Bearer credentials refused before a caller was resolved.",
        LabelSpace::closed_zero_filled(&["reason"], &[&["refused"], &["policy"], &["unavailable"]])
            .unwrap(),
    )
    .unwrap();
    refusals.inc(&["policy"]).unwrap();

    let mut out = Exposition::new();
    for counter in [&admitted, &finished, &attempts, &refusals] {
        counter.write(&mut out).unwrap();
    }
    out.header(
        "coordinator_dispatch_jobs",
        Some("Steps waiting to run, running, or held unknown, sampled at scrape."),
        MetricKind::Gauge,
    )
    .unwrap();
    for (state, count) in [("pending", 5_i64), ("leased", 0), ("unknown", 1)] {
        out.sample("coordinator_dispatch_jobs", &[("state", state)], count)
            .unwrap();
    }
    assert_eq!(
        out.finish(),
        "\
# HELP coordinator_runs_admitted_total Runs whose admission committed.
# TYPE coordinator_runs_admitted_total counter
coordinator_runs_admitted_total 2
# HELP coordinator_runs_finished_total Committed moves of a run into a terminal state, by that state.
# TYPE coordinator_runs_finished_total counter
coordinator_runs_finished_total{state=\"finished\"} 0
coordinator_runs_finished_total{state=\"failed\"} 0
coordinator_runs_finished_total{state=\"cancelled\"} 0
coordinator_runs_finished_total{state=\"cancelled-after-effect\"} 1
coordinator_runs_finished_total{state=\"expired\"} 0
# HELP coordinator_step_attempts_total Step attempts the worker made, by what each came to.
# TYPE coordinator_step_attempts_total counter
coordinator_step_attempts_total{outcome=\"accepted\"} 1
coordinator_step_attempts_total{outcome=\"transient\"} 0
coordinator_step_attempts_total{outcome=\"permanent\"} 0
coordinator_step_attempts_total{outcome=\"maybe-sent\"} 0
coordinator_step_attempts_total{outcome=\"unavailable\"} 0
# HELP coordinator_authentication_refusals_total Bearer credentials refused before a caller was resolved.
# TYPE coordinator_authentication_refusals_total counter
coordinator_authentication_refusals_total{reason=\"refused\"} 0
coordinator_authentication_refusals_total{reason=\"policy\"} 1
coordinator_authentication_refusals_total{reason=\"unavailable\"} 0
# HELP coordinator_dispatch_jobs Steps waiting to run, running, or held unknown, sampled at scrape.
# TYPE coordinator_dispatch_jobs gauge
coordinator_dispatch_jobs{state=\"pending\"} 5
coordinator_dispatch_jobs{state=\"leased\"} 0
coordinator_dispatch_jobs{state=\"unknown\"} 1
"
    );
}

// registry-breg: crates/registry-breg/src/metrics.rs

#[test]
fn breg_scrape_is_reproduced() {
    let labels = ["route", "method", "status"];
    let requests = CounterVec::new(
        "breg_http_requests_total",
        "Requests served by the Registry boundary.",
        LabelSpace::bounded(&labels, 512).unwrap(),
    )
    .unwrap();
    let durations = HistogramVec::new(
        "breg_http_request_duration_seconds",
        "Request duration at the Registry boundary.",
        &EVIDENCE_BUCKETS,
        LabelSpace::bounded(&labels, 512).unwrap(),
    )
    .unwrap();
    let key = ["/health", "GET", "success"];
    requests.inc(&key).unwrap();
    durations.observe(&key, seconds(30)).unwrap();

    let mut out = Exposition::new();
    requests.write(&mut out).unwrap();
    durations
        .write(&mut out, SumCountOrder::SumThenCount)
        .unwrap();

    out.header(
        "breg_pool_connections",
        Some("Runtime pool connections by state."),
        MetricKind::Gauge,
    )
    .unwrap();
    for (state, count) in [
        ("maximum-size", 16_usize),
        ("size", 4),
        ("available", 3),
        ("waiting", 0),
    ] {
        out.sample("breg_pool_connections", &[("state", state)], count)
            .unwrap();
    }
    out.header(
        "breg_worker_last_success_age_seconds",
        Some("Seconds since each background worker last completed an iteration without failure; absent until the first."),
        MetricKind::Gauge,
    )
    .unwrap();
    out.sample(
        "breg_worker_last_success_age_seconds",
        &[("worker", "review")],
        Duration::from_millis(1500).as_secs_f64(),
    )
    .unwrap();
    out.header(
        "breg_queue_oldest_pending_age_seconds",
        Some("Seconds the oldest due item in each queue has waited to be claimed, sampled at scrape; zero when none is due."),
        MetricKind::Gauge,
    )
    .unwrap();
    for (queue, age) in [
        ("hook-delivery", 0.0_f64),
        ("review-submission", 90.5),
        ("review-application", 0.0),
    ] {
        out.sample(
            "breg_queue_oldest_pending_age_seconds",
            &[("queue", queue)],
            age,
        )
        .unwrap();
    }
    out.header(
        "breg_proposal_application_blocked_jobs",
        Some("Application jobs closed or held by a package change on the current submitted proposal, sampled at scrape."),
        MetricKind::Gauge,
    )
    .unwrap();
    out.sample("breg_proposal_application_blocked_jobs", &[], 2_i64)
        .unwrap();
    let timer_families = [
        (
            "breg_record_timer_observed_live_lease_owners",
            "Distinct observed current live lease owners, not a census of running replicas.",
        ),
        (
            "breg_record_timer_oldest_due_lag_seconds",
            "Seconds since the oldest sampled current due timer became due according to PostgreSQL; absent when none is due.",
        ),
        (
            "breg_record_timer_current_occurrences",
            "Current timer occurrences in the bounded sample by closed state and block kind.",
        ),
        (
            "breg_record_timer_current_executed_attempts",
            "Cumulative executed attempts recorded on the bounded current-occurrence sample; a gauge, not a monotonic retry counter.",
        ),
        (
            "breg_record_timer_retained_attempts",
            "Retained value-free attempt details for the bounded current-occurrence sample.",
        ),
        (
            "breg_record_timer_stale_current_occurrences",
            "Current unfinished occurrences whose cached policy revision differs from the open binding.",
        ),
        (
            "breg_record_timer_control_compatible",
            "Whether the durable timer protocol, bound instance epoch, and active package match this process.",
        ),
        (
            "breg_record_timer_counts_truncated",
            "Whether current occurrence, attempt, or lease-owner counts reached the bounded sample ceiling.",
        ),
    ];
    for (name, help) in timer_families {
        out.header(name, Some(help), MetricKind::Gauge).unwrap();
    }
    out.sample("breg_record_timer_observed_live_lease_owners", &[], 2_i64)
        .unwrap();
    out.sample("breg_record_timer_oldest_due_lag_seconds", &[], 12.5_f64)
        .unwrap();
    let states = [
        "pending",
        "leased",
        "completed",
        "refused",
        "blocked",
        "cancelled",
        "superseded",
        "missed",
    ];
    let counts = [1_i64, 2, 3, 4, 2, 5, 6, 7];
    let block_counts = [("technical", 1_i64), ("configuration", 1)];
    for (state, count) in states.into_iter().zip(counts) {
        if state == "blocked" {
            for (block_kind, blocked) in block_counts {
                out.sample(
                    "breg_record_timer_current_occurrences",
                    &[("state", state), ("block_kind", block_kind)],
                    blocked,
                )
                .unwrap();
            }
        } else {
            out.sample(
                "breg_record_timer_current_occurrences",
                &[("state", state), ("block_kind", "none")],
                count,
            )
            .unwrap();
        }
    }
    out.sample("breg_record_timer_current_executed_attempts", &[], 8_i64)
        .unwrap();
    out.sample("breg_record_timer_retained_attempts", &[], 7_i64)
        .unwrap();
    out.sample("breg_record_timer_stale_current_occurrences", &[], 1_i64)
        .unwrap();
    out.sample(
        "breg_record_timer_control_compatible",
        &[("state", "paused")],
        u8::from(true),
    )
    .unwrap();
    out.sample("breg_record_timer_counts_truncated", &[], u8::from(false))
        .unwrap();
    out.header(
        "breg_active_package_info",
        Some("The package this process verified at startup, by digest."),
        MetricKind::Gauge,
    )
    .unwrap();
    let digest = format!("sha256:{}", "ab".repeat(32));
    out.sample(
        "breg_active_package_info",
        &[("package_digest", &digest)],
        1_u64,
    )
    .unwrap();

    let expected = format!(
        "\
# HELP breg_http_requests_total Requests served by the Registry boundary.
# TYPE breg_http_requests_total counter
breg_http_requests_total{{route=\"/health\",method=\"GET\",status=\"success\"}} 1
# HELP breg_http_request_duration_seconds Request duration at the Registry boundary.
# TYPE breg_http_request_duration_seconds histogram
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"0.005\"}} 0
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"0.01\"}} 0
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"0.025\"}} 0
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"0.05\"}} 1
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"0.1\"}} 1
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"0.25\"}} 1
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"0.5\"}} 1
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"1\"}} 1
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"5\"}} 1
breg_http_request_duration_seconds_bucket{{route=\"/health\",method=\"GET\",status=\"success\",le=\"+Inf\"}} 1
breg_http_request_duration_seconds_sum{{route=\"/health\",method=\"GET\",status=\"success\"}} 0.03
breg_http_request_duration_seconds_count{{route=\"/health\",method=\"GET\",status=\"success\"}} 1
# HELP breg_pool_connections Runtime pool connections by state.
# TYPE breg_pool_connections gauge
breg_pool_connections{{state=\"maximum-size\"}} 16
breg_pool_connections{{state=\"size\"}} 4
breg_pool_connections{{state=\"available\"}} 3
breg_pool_connections{{state=\"waiting\"}} 0
# HELP breg_worker_last_success_age_seconds Seconds since each background worker last completed an iteration without failure; absent until the first.
# TYPE breg_worker_last_success_age_seconds gauge
breg_worker_last_success_age_seconds{{worker=\"review\"}} 1.5
# HELP breg_queue_oldest_pending_age_seconds Seconds the oldest due item in each queue has waited to be claimed, sampled at scrape; zero when none is due.
# TYPE breg_queue_oldest_pending_age_seconds gauge
breg_queue_oldest_pending_age_seconds{{queue=\"hook-delivery\"}} 0
breg_queue_oldest_pending_age_seconds{{queue=\"review-submission\"}} 90.5
breg_queue_oldest_pending_age_seconds{{queue=\"review-application\"}} 0
# HELP breg_proposal_application_blocked_jobs Application jobs closed or held by a package change on the current submitted proposal, sampled at scrape.
# TYPE breg_proposal_application_blocked_jobs gauge
breg_proposal_application_blocked_jobs 2
# HELP breg_record_timer_observed_live_lease_owners Distinct observed current live lease owners, not a census of running replicas.
# TYPE breg_record_timer_observed_live_lease_owners gauge
# HELP breg_record_timer_oldest_due_lag_seconds Seconds since the oldest sampled current due timer became due according to PostgreSQL; absent when none is due.
# TYPE breg_record_timer_oldest_due_lag_seconds gauge
# HELP breg_record_timer_current_occurrences Current timer occurrences in the bounded sample by closed state and block kind.
# TYPE breg_record_timer_current_occurrences gauge
# HELP breg_record_timer_current_executed_attempts Cumulative executed attempts recorded on the bounded current-occurrence sample; a gauge, not a monotonic retry counter.
# TYPE breg_record_timer_current_executed_attempts gauge
# HELP breg_record_timer_retained_attempts Retained value-free attempt details for the bounded current-occurrence sample.
# TYPE breg_record_timer_retained_attempts gauge
# HELP breg_record_timer_stale_current_occurrences Current unfinished occurrences whose cached policy revision differs from the open binding.
# TYPE breg_record_timer_stale_current_occurrences gauge
# HELP breg_record_timer_control_compatible Whether the durable timer protocol, bound instance epoch, and active package match this process.
# TYPE breg_record_timer_control_compatible gauge
# HELP breg_record_timer_counts_truncated Whether current occurrence, attempt, or lease-owner counts reached the bounded sample ceiling.
# TYPE breg_record_timer_counts_truncated gauge
breg_record_timer_observed_live_lease_owners 2
breg_record_timer_oldest_due_lag_seconds 12.5
breg_record_timer_current_occurrences{{state=\"pending\",block_kind=\"none\"}} 1
breg_record_timer_current_occurrences{{state=\"leased\",block_kind=\"none\"}} 2
breg_record_timer_current_occurrences{{state=\"completed\",block_kind=\"none\"}} 3
breg_record_timer_current_occurrences{{state=\"refused\",block_kind=\"none\"}} 4
breg_record_timer_current_occurrences{{state=\"blocked\",block_kind=\"technical\"}} 1
breg_record_timer_current_occurrences{{state=\"blocked\",block_kind=\"configuration\"}} 1
breg_record_timer_current_occurrences{{state=\"cancelled\",block_kind=\"none\"}} 5
breg_record_timer_current_occurrences{{state=\"superseded\",block_kind=\"none\"}} 6
breg_record_timer_current_occurrences{{state=\"missed\",block_kind=\"none\"}} 7
breg_record_timer_current_executed_attempts 8
breg_record_timer_retained_attempts 7
breg_record_timer_stale_current_occurrences 1
breg_record_timer_control_compatible{{state=\"paused\"}} 1
breg_record_timer_counts_truncated 0
# HELP breg_active_package_info The package this process verified at startup, by digest.
# TYPE breg_active_package_info gauge
breg_active_package_info{{package_digest=\"{digest}\"}} 1
"
    );
    assert_eq!(out.finish(), expected);
}
