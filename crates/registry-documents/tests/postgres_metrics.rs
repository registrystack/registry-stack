// SPDX-License-Identifier: Apache-2.0

//! Database-backed tests of the Document Store's private metrics listener:
//! each queue gauge reads the rows it counts, the oldest overdue age leaves
//! back-off out, a read that fails is counted and its gauges are omitted
//! while the others still render, the serving listener never answers
//! `/metrics`, and the metrics listener answers it over a real socket.

mod support;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use registry_documents::runtime::{prepare_with_verifier, Prepared};
use support::{
    pdf, request, reservation, Api, Deployment, FakeVerifier, APP, APPROVE, CITIZEN,
    DATABASE_STORAGE, DISABLED_VERIFIER, UNAVAILABLE,
};
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;

/// A loopback port nothing holds, for a `metricsListener.bind`.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(verifier: &Arc<FakeVerifier>) -> (Deployment, Prepared, Api, u16) {
    let mut deployment = Deployment::new(DATABASE_STORAGE, DISABLED_VERIFIER).await;
    let port = free_port();
    deployment.configure(&format!("metricsListener:\n  bind: 127.0.0.1:{port}\n"));
    deployment.migrate().await;
    let prepared = prepare_with_verifier(&deployment.runtime, verifier.clone())
        .await
        .expect("the runtime prepares");
    let api = Api::new(&prepared);
    (deployment, prepared, api, port)
}

/// One uploaded document, whose verification job is pending.
async fn upload(api: &Api, seed: u8) -> String {
    let content = pdf(256, seed);
    let reserved = api
        .reserve(
            APP,
            "citizen-delivery",
            CITIZEN.subject,
            &content,
            "application/pdf",
        )
        .await;
    let (_document, version, path) = reservation(&reserved);
    let put = api
        .put(APP, &path, "application/pdf", Body::from(content))
        .await;
    assert_eq!(put.status, 200, "{}", String::from_utf8_lossy(&put.body));
    version
}

/// The exposition the metrics router answers for one scrape.
async fn scrape(prepared: &Prepared) -> String {
    scrape_on(
        prepared
            .metrics_app()
            .expect("a metrics listener is configured"),
    )
    .await
}

async fn scrape_on(app: axum::Router) -> String {
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

fn has(exposition: &str, line: &str) -> bool {
    exposition.lines().any(|candidate| candidate == line)
}

#[tokio::test]
async fn every_queue_gauge_reads_its_rows_and_the_oldest_overdue_age_skips_back_off() {
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (deployment, prepared, api, _) = start(&verifier).await;
    let overdue = upload(&api, 1).await;
    let backing_off = upload(&api, 2).await;
    let dead = upload(&api, 3).await;
    deployment
        .execute(&format!(
            "UPDATE documents_verification_jobs
                SET next_attempt_at = transaction_timestamp() - interval '300 seconds'
              WHERE version_id = '{overdue}';
             UPDATE documents_verification_jobs
                SET next_attempt_at = transaction_timestamp() + interval '1 hour'
              WHERE version_id = '{backing_off}';
             UPDATE documents_verification_jobs
                SET state = 'dead-lettered', attempt = 8, next_attempt_at = NULL,
                    dead_lettered_at = transaction_timestamp()
              WHERE version_id = '{dead}';
             INSERT INTO documents_erasure_jobs
                    (version_id, part, generation, state, attempt, next_attempt_at)
             VALUES ('{overdue}', 'a', 1, 'pending', 0,
                     transaction_timestamp() - interval '120 seconds'),
                    ('{overdue}', 'b', 1, 'pending', 0,
                     transaction_timestamp() + interval '1 hour');"
        ))
        .await;

    let exposition = scrape(&prepared).await;
    for line in [
        r#"documents_verification_jobs{state="pending"} 2"#,
        r#"documents_verification_jobs{state="dead-lettered"} 1"#,
        r#"documents_verification_jobs{state="leased"} 0"#,
        r#"documents_erasure_jobs{state="pending"} 2"#,
        r#"documents_erasure_jobs{state="dead-lettered"} 0"#,
        r#"documents_hook_deliveries{state="pending"} 0"#,
        r#"documents_hook_oldest_overdue_age_seconds 0"#,
    ] {
        assert!(has(&exposition, line), "missing {line}\n{exposition}");
    }
    let age = |name: &str| -> i64 {
        exposition
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name} ")))
            .unwrap_or_else(|| panic!("missing {name}\n{exposition}"))
            .parse()
            .unwrap()
    };
    let verification = age("documents_verification_oldest_overdue_age_seconds");
    assert!(
        (300..330).contains(&verification),
        "the back-off row is left out: {verification}"
    );
    let erasure = age("documents_erasure_oldest_overdue_age_seconds");
    assert!((120..150).contains(&erasure), "{erasure}");
    assert!(
        has(
            &exposition,
            r#"documents_metrics_sample_failures_total{sample="erasure-jobs"} 0"#
        ),
        "{exposition}"
    );
}

#[tokio::test]
async fn a_hook_delivery_is_counted_by_state_and_aged_from_its_eligibility() {
    let verifier = FakeVerifier::new("binding-a", APPROVE);
    let (deployment, prepared, api, _) = start(&verifier).await;
    upload(&api, 4).await;
    assert_eq!(prepared.verify_due().await, 1);
    deployment
        .execute(
            "UPDATE registry_webhook_delivery_state
                SET next_attempt_at = transaction_timestamp() - interval '90 seconds'",
        )
        .await;

    let exposition = scrape(&prepared).await;
    assert!(
        has(
            &exposition,
            r#"documents_hook_deliveries{state="pending"} 1"#
        ),
        "{exposition}"
    );
    let age: i64 = exposition
        .lines()
        .find_map(|line| line.strip_prefix("documents_hook_oldest_overdue_age_seconds "))
        .expect("the hook age")
        .parse()
        .unwrap();
    assert!((90..120).contains(&age), "{age}");
}

#[tokio::test]
async fn a_failed_read_is_counted_once_and_omits_only_its_gauges() {
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (deployment, prepared, api, _) = start(&verifier).await;
    upload(&api, 5).await;
    deployment
        .execute("ALTER TABLE documents_erasure_jobs RENAME TO documents_erasure_jobs_away")
        .await;

    let exposition = scrape(&prepared).await;
    assert!(
        has(
            &exposition,
            r#"documents_metrics_sample_failures_total{sample="erasure-jobs"} 1"#
        ),
        "{exposition}"
    );
    let samples = |prefix: &str| {
        exposition
            .lines()
            .filter(|line| line.starts_with(prefix))
            .count()
    };
    assert_eq!(
        samples("documents_erasure_jobs{"),
        0,
        "an unread queue is omitted, never zero\n{exposition}"
    );
    assert_eq!(
        samples("documents_erasure_oldest_overdue_age_seconds"),
        0,
        "{exposition}"
    );
    assert!(
        has(
            &exposition,
            r#"documents_verification_jobs{state="pending"} 1"#
        ),
        "the other reads still run\n{exposition}"
    );

    deployment
        .execute("ALTER TABLE documents_erasure_jobs_away RENAME TO documents_erasure_jobs")
        .await;
    let recovered = scrape(&prepared).await;
    assert!(
        has(&recovered, r#"documents_erasure_jobs{state="pending"} 0"#),
        "{recovered}"
    );
    assert!(
        has(
            &recovered,
            r#"documents_metrics_sample_failures_total{sample="erasure-jobs"} 1"#
        ),
        "the counter keeps the one failure\n{recovered}"
    );
}

#[tokio::test]
async fn the_serving_router_counts_by_template_and_never_answers_metrics() {
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (_deployment, prepared, api, _) = start(&verifier).await;
    let refused = api
        .call(
            request(CITIZEN, axum::http::Method::GET, "/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(refused.status, 404);
    upload(&api, 6).await;

    let exposition = scrape(&prepared).await;
    assert!(
        has(
            &exposition,
            r#"documents_http_requests_total{route="unmatched",method="GET",status="4xx"} 1"#
        ),
        "{exposition}"
    );
    assert!(
        exposition.lines().any(
            |line| line.starts_with("documents_http_requests_total{route=\"/")
                && line.contains(r#"status="2xx""#)
        ),
        "{exposition}"
    );
    assert!(
        !exposition.contains("sha256") && !exposition.contains(CITIZEN.subject),
        "no label carries content or an owner"
    );
}

#[tokio::test]
async fn the_metrics_listener_answers_over_a_socket_and_the_serving_listener_does_not() {
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (_deployment, prepared, _api, port) = start(&verifier).await;
    let address = prepared.metrics_addr().unwrap().expect("a bound address");
    assert_eq!(address.port(), port);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.serve_until(async move {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::new();
    let answer = client
        .get(format!("http://{address}/metrics"))
        .send()
        .await
        .expect("the metrics listener answers");
    assert_eq!(answer.status(), 200);
    assert_eq!(
        answer.headers()["content-type"],
        "text/plain; version=0.0.4"
    );
    let other = client
        .get(format!("http://{address}/v1/documents"))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 404);
    stop.send(()).unwrap();
    server.await.unwrap().expect("a clean stop");
}

#[tokio::test]
async fn a_failed_read_logs_its_error_class_and_never_the_driver_message() {
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (deployment, prepared, _api, _) = start(&verifier).await;
    deployment
        .execute("ALTER TABLE documents_erasure_jobs RENAME TO documents_erasure_jobs_away")
        .await;
    let logs = registry_platform_testing::CapturedDiagnosticLogs::default();

    let exposition = scrape(&prepared)
        .with_subscriber(logs.subscriber_with_max_level(tracing::Level::WARN))
        .await;

    assert!(
        has(
            &exposition,
            r#"documents_metrics_sample_failures_total{sample="erasure-jobs"} 1"#
        ),
        "{exposition}"
    );
    let text = logs.text();
    assert!(
        text.contains("sqlstate-42P01"),
        "the class is logged\n{text}"
    );
    assert!(
        !text.contains("does not exist") && !text.contains("documents_erasure_jobs"),
        "the driver message and relation name are never logged\n{text}"
    );
}

/// The sessions still waiting on a lock while running a read of `table` in
/// this deployment's schema. A query the client merely abandoned keeps
/// waiting on the server; one the server cancelled does not.
async fn sessions_waiting_on_a_lock(deployment: &Deployment, table: &str) -> i64 {
    let pattern = format!("%{}.{table}%", deployment.schema);
    let give_up = Instant::now() + Duration::from_secs(3);
    loop {
        let waiting: i64 = deployment
            .admin
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                  WHERE wait_event_type = 'Lock' AND query LIKE $1",
                &[&pattern],
            )
            .await
            .expect("count the waiting sessions")
            .get(0);
        if waiting == 0 || Instant::now() >= give_up {
            return waiting;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_read_that_waits_on_a_lock_is_cancelled_on_the_server_and_counted_once() {
    let verifier = FakeVerifier::new("binding-a", UNAVAILABLE);
    let (deployment, prepared, api, _) = start(&verifier).await;
    upload(&api, 7).await;
    deployment
        .execute(&format!(
            "BEGIN; LOCK TABLE {}.documents_verification_jobs IN ACCESS EXCLUSIVE MODE;",
            deployment.schema
        ))
        .await;
    let started = Instant::now();

    let exposition = scrape_on(prepared.metrics_app_within(Duration::from_millis(600))).await;

    let elapsed = started.elapsed();
    let waiting = sessions_waiting_on_a_lock(&deployment, "documents_verification_jobs").await;
    deployment.execute("ROLLBACK").await;
    assert_eq!(
        waiting, 0,
        "the server cancels the read; a client that only abandons it leaves it waiting"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the scrape returns near its budget: {elapsed:?}"
    );
    assert_eq!(
        exposition
            .lines()
            .filter(|line| line.starts_with("documents_verification_jobs{"))
            .count(),
        0,
        "the stuck read's gauges are omitted, never zero\n{exposition}"
    );
    // The stuck read used the whole shared deadline, so the reads after it
    // have no time left: each is counted failed once and never queries.
    for sample in ["verification-jobs", "erasure-jobs", "hook-deliveries"] {
        assert!(
            has(
                &exposition,
                &format!(r#"documents_metrics_sample_failures_total{{sample="{sample}"}} 1"#)
            ),
            "{sample}\n{exposition}"
        );
    }
}
