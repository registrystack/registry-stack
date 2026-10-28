// SPDX-License-Identifier: Apache-2.0

//! Private health and metrics acceptance for native Record-timer workers.

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/record_timer_native.rs"]
#[allow(dead_code)]
mod record_timer_native;

use std::time::{Duration, Instant};

use record_timer_native::NativeTimerHarness;

const METRIC_CANARIES: [&str; 6] = [
    "native future activation canary",
    "zone-a",
    "raw-handler-failure-detail-canary",
    "unknown-technical-code-canary",
    "record-timer-native-deployment",
    "service-events",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_timer_metrics_are_current_bounded_and_value_free() {
    let mut harness = NativeTimerHarness::start().await;
    let result = bounded_current_metrics(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timer_metrics_preserve_later_block_kinds_after_bounded_terminal_history() {
    let mut harness = NativeTimerHarness::start().await;
    let result = bounded_metrics_preserve_later_blocks(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timer_metric_sample_failure_is_omitted_and_diagnosed() {
    let mut harness = NativeTimerHarness::start().await;
    let result = unavailable_timer_sample(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timer_worker_progress_is_registered_only_for_a_real_worker() {
    let mut harness = NativeTimerHarness::start().await;
    let result = native_worker_progress(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timer_readiness_refuses_mismatch_and_admits_supported_holds() {
    let mut harness = NativeTimerHarness::start().await;
    let result = timer_readiness(&mut harness).await;
    finish_result(harness, result).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timer_control_compatibility_includes_the_process_package_binding() {
    let mut harness = NativeTimerHarness::start().await;
    let result = package_bound_control_compatibility(&mut harness).await;
    finish_result(harness, result).await;
}

async fn bounded_current_metrics(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .fixture_only_set_timer_control("paused", 1, 0)
        .await?;
    harness.fixture_only_seed_timer_metrics(true).await?;

    let before = harness.database_now().await?;
    let body = harness.scrape_metrics(0).await?;
    let after = harness.database_now().await?;
    expect_metric(&body, "breg_record_timer_observed_live_lease_owners", 2.0)?;
    expect_metric(&body, "breg_record_timer_current_executed_attempts", 62.0)?;
    expect_metric(&body, "breg_record_timer_retained_attempts", 1.0)?;
    // The fixture also changes one generation's policy activation without
    // changing its revisions. Only the separate revision-drift row is stale.
    expect_metric(&body, "breg_record_timer_stale_current_occurrences", 1.0)?;
    expect_metric(&body, "breg_record_timer_counts_truncated", 1.0)?;
    expect_metric(
        &body,
        "breg_record_timer_control_compatible{state=\"paused\"}",
        1.0,
    )?;
    expect_metric(
        &body,
        "breg_record_timer_current_occurrences{state=\"blocked\",block_kind=\"technical\"}",
        1.0,
    )?;
    expect_metric(
        &body,
        "breg_record_timer_current_occurrences{state=\"blocked\",block_kind=\"configuration\"}",
        1.0,
    )?;

    let lag = metric_value(&body, "breg_record_timer_oldest_due_lag_seconds")?;
    let elapsed = (after - before)
        .to_std()
        .map_err(|_| "database clock moved backward during live metrics scrape".to_owned())?
        .as_secs_f64();
    if !(16.0..=21.0 + elapsed).contains(&lag) {
        return Err(format!(
            "timer due lag did not follow the live PostgreSQL clock: lag={lag}, elapsed={elapsed}"
        ));
    }
    let help = "observed current live lease owners, not a census of running replicas";
    if !body.to_ascii_lowercase().contains(help) {
        return Err("observed lease-owner metric did not disclaim fleet census".to_owned());
    }
    for canary in METRIC_CANARIES {
        if body.contains(canary) {
            return Err(format!(
                "private timer metrics disclosed a forbidden value class: {canary}"
            ));
        }
    }
    Ok(())
}

async fn bounded_metrics_preserve_later_blocks(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .fixture_only_set_timer_control("paused", 1, 0)
        .await?;
    harness
        .fixture_only_seed_terminal_history_before_later_blocks()
        .await?;

    let body = harness.scrape_metrics(0).await?;
    expect_metric(&body, "breg_record_timer_counts_truncated", 1.0)?;
    expect_metric(
        &body,
        "breg_record_timer_current_occurrences{state=\"cancelled\",block_kind=\"none\"}",
        10_000.0,
    )?;
    expect_metric(
        &body,
        "breg_record_timer_current_occurrences{state=\"pending\",block_kind=\"none\"}",
        10_000.0,
    )?;
    expect_metric(
        &body,
        "breg_record_timer_current_occurrences{state=\"blocked\",block_kind=\"technical\"}",
        10_000.0,
    )?;
    expect_metric(
        &body,
        "breg_record_timer_current_occurrences{state=\"blocked\",block_kind=\"configuration\"}",
        1.0,
    )?;
    Ok(())
}

async fn unavailable_timer_sample(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    harness
        .fixture_only_set_timer_control("paused", 1, 0)
        .await?;
    harness.fixture_only_seed_timer_metrics(false).await?;
    let available = harness.scrape_metrics(0).await?;
    metric_value(&available, "breg_record_timer_observed_live_lease_owners")?;

    harness.expect_non_info_code(0, "metrics.timer_sample.failed", 1)?;
    let unavailable = harness.scrape_with_timer_attempt_read_revoked(0).await?;
    for family in [
        "breg_record_timer_observed_live_lease_owners",
        "breg_record_timer_oldest_due_lag_seconds",
        "breg_record_timer_current_occurrences",
        "breg_record_timer_current_executed_attempts",
        "breg_record_timer_stale_current_occurrences",
        "breg_record_timer_control_compatible",
        "breg_record_timer_counts_truncated",
    ] {
        if unavailable.lines().any(|line| {
            line.strip_prefix(family)
                .is_some_and(|suffix| suffix.starts_with(' ') || suffix.starts_with('{'))
        }) {
            return Err(format!(
                "unavailable timer sample was rendered as data instead of omitted: {family}"
            ));
        }
    }
    if !unavailable.contains("breg_pool_connections")
        || !unavailable.contains("breg_active_package_info")
    {
        return Err("timer sample failure suppressed independent metric families".to_owned());
    }
    let recovered = harness.scrape_metrics(0).await?;
    metric_value(&recovered, "breg_record_timer_observed_live_lease_owners")?;
    Ok(())
}

async fn native_worker_progress(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    wait_for_timer_worker_progress(harness).await
}

async fn wait_for_timer_worker_progress(harness: &NativeTimerHarness) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let body = harness.scrape_metrics(0).await?;
            let samples = body
                .lines()
                .filter(|line| {
                    line.starts_with(
                        "breg_worker_last_success_age_seconds{worker=\"record-timer\"}",
                    )
                })
                .collect::<Vec<_>>();
            if samples.len() == 1 {
                let age = samples[0]
                    .split_ascii_whitespace()
                    .nth(1)
                    .ok_or_else(|| "record-timer worker sample omitted its value".to_owned())?
                    .parse::<f64>()
                    .map_err(|_| "record-timer worker sample was not numeric".to_owned())?;
                if age.is_finite() && age >= 0.0 {
                    return Ok(());
                }
                return Err("record-timer worker age was outside its finite range".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| "record-timer worker progress metric did not appear".to_owned())?
}

async fn timer_readiness(harness: &mut NativeTimerHarness) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    wait_for_timer_worker_progress(harness).await?;
    let client = harness.client(0)?;
    let create = harness.create_binding(&client).await?;
    let created = harness
        .create_scheduled_service(
            &client,
            &create,
            harness.database_now().await? + chrono::Duration::seconds(60),
        )
        .await?;
    let record_id = created.value.data.record_identifier.clone();

    for state in ["paused", "adoption-hold"] {
        harness.fixture_only_set_timer_control(state, 1, 0).await?;
        expect_probe(harness, "/health", 200, state).await?;
        expect_probe(harness, "/ready", 200, state).await?;
    }
    let corruption_started = Instant::now();
    harness
        .fixture_only_set_timer_control("running", 2, 0)
        .await?;
    harness
        .wait_for_log_code(
            0,
            "record_timer.worker.iteration_failed",
            Duration::from_secs(8),
        )
        .await?;
    // Leave the fault active past the former 250 ms idle interval. The final
    // warning ceiling is derived from this measured interval and the fixed
    // one-second failure retry, so CI scheduling delay cannot make it brittle.
    tokio::time::sleep(Duration::from_millis(1_250)).await;
    expect_probe(harness, "/health", 200, "unsupported protocol").await?;
    expect_probe(harness, "/ready", 503, "unsupported protocol").await?;

    harness
        .fixture_only_set_timer_control("running", 1, 1)
        .await?;
    expect_probe(harness, "/health", 200, "bound-instance mismatch").await?;
    expect_probe(harness, "/ready", 503, "bound-instance mismatch").await?;

    harness
        .fixture_only_set_timer_control("running", 1, 0)
        .await?;
    let corruption_elapsed = corruption_started.elapsed();
    let expected_warning_maximum = usize::try_from(
        corruption_elapsed
            .as_millis()
            .div_ceil(1_000)
            .saturating_add(2),
    )
    .map_err(|_| "timer failure-warning bound exceeded the host integer range".to_owned())?;
    harness.expect_non_info_code_range(
        0,
        "record_timer.worker.iteration_failed",
        1,
        expected_warning_maximum,
    )?;
    harness.expect_non_info_code_range(
        0,
        "review.worker.iteration_failed",
        0,
        expected_warning_maximum,
    )?;
    expect_probe(harness, "/ready", 200, "restored supported control").await?;
    let evidence = harness.timer_evidence(&record_id).await?;
    if evidence.state != "pending" || evidence.executed_attempt_count != 0 {
        return Err(format!(
            "supported holds or readiness mismatches consumed timer work: {evidence:?}"
        ));
    }
    Ok(())
}

async fn package_bound_control_compatibility(
    harness: &mut NativeTimerHarness,
) -> Result<(), String> {
    harness.enable_metrics_for_new_replicas()?;
    harness.start_replicas(1).await?;
    let identity = harness.run_identity();

    let initial = harness.scrape_metrics(0).await?;
    expect_metric(
        &initial,
        "breg_record_timer_control_compatible{state=\"running\"}",
        1.0,
    )?;
    expect_process_package_info(&initial, &identity.package_digest)?;

    let mismatch_started = Instant::now();
    harness.fixture_only_set_active_package_match(false).await?;
    expect_probe(harness, "/health", 200, "different active package").await?;
    expect_probe(harness, "/ready", 503, "different active package").await?;
    let mismatched = harness.scrape_metrics(0).await?;
    harness.fixture_only_set_active_package_match(true).await?;
    let warning_maximum = usize::try_from(
        mismatch_started
            .elapsed()
            .as_millis()
            .div_ceil(1_000)
            .saturating_add(2),
    )
    .map_err(|_| "package mismatch warning bound exceeded the host integer range".to_owned())?;
    harness.expect_non_info_code_range(
        0,
        "record_timer.worker.iteration_failed",
        0,
        warning_maximum,
    )?;
    harness.expect_non_info_code_range(0, "review.worker.iteration_failed", 0, warning_maximum)?;
    // Package identity also fences the hook delivery worker. Its maintained
    // poll interval is 100 ms, so bound both the identity refusal and the
    // enclosing iteration warning by the measured corruption interval.
    let hook_warning_maximum = usize::try_from(
        mismatch_started
            .elapsed()
            .as_millis()
            .div_ceil(100)
            .saturating_add(4),
    )
    .map_err(|_| {
        "package mismatch hook-warning bound exceeded the host integer range".to_owned()
    })?;
    harness.expect_non_info_code_range(
        0,
        "hook.claim.identity_refused",
        0,
        hook_warning_maximum,
    )?;
    harness.expect_non_info_code_range(
        0,
        "hook.worker.iteration_failed",
        0,
        hook_warning_maximum,
    )?;
    expect_probe(harness, "/ready", 200, "restored active package").await?;
    let restored = harness.scrape_metrics(0).await?;

    expect_metric(
        &mismatched,
        "breg_record_timer_control_compatible{state=\"running\"}",
        0.0,
    )?;
    expect_process_package_info(&mismatched, &identity.package_digest)?;
    expect_metric(
        &restored,
        "breg_record_timer_control_compatible{state=\"running\"}",
        1.0,
    )?;
    expect_process_package_info(&restored, &identity.package_digest)?;
    Ok(())
}

async fn expect_probe(
    harness: &NativeTimerHarness,
    path: &str,
    expected: u16,
    context: &str,
) -> Result<(), String> {
    let actual = harness.probe_status(0, path).await?;
    if actual != expected {
        return Err(format!(
            "{context} returned HTTP {actual} from {path}, expected {expected}"
        ));
    }
    Ok(())
}

fn expect_metric(body: &str, name: &str, expected: f64) -> Result<(), String> {
    let actual = metric_value(body, name)?;
    if actual != expected {
        return Err(format!(
            "timer metric {name} was {actual}, expected {expected}"
        ));
    }
    Ok(())
}

fn metric_value(body: &str, name: &str) -> Result<f64, String> {
    let prefix = format!("{name} ");
    let samples = body
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    if samples.len() != 1 {
        return Err(format!(
            "timer metric {name} had {} samples, expected one",
            samples.len()
        ));
    }
    samples[0]
        .parse::<f64>()
        .map_err(|_| format!("timer metric {name} was not numeric"))
}

fn expect_process_package_info(body: &str, digest: &str) -> Result<(), String> {
    let exact = format!("breg_active_package_info{{package_digest=\"{digest}\"}} 1");
    let samples = body
        .lines()
        .filter(|line| line.starts_with("breg_active_package_info{"))
        .collect::<Vec<_>>();
    if samples != [exact.as_str()] {
        return Err(format!(
            "process package metric changed during database package mismatch: {samples:?}"
        ));
    }
    Ok(())
}

async fn finish_result(harness: NativeTimerHarness, result: Result<(), String>) {
    let identity = harness.run_identity();
    let succeeded = result.is_ok();
    let cleanup = harness.finish(succeeded).await;
    println!(
        "record-timer-metrics package_id={} package_digest={}",
        identity.package_id, identity.package_digest
    );
    for process in identity.processes {
        println!(
            "record-timer-metrics instance_id={} replica_id={} launch_id={} pid={} executable={} arguments={:?}",
            process.instance_id,
            process.replica_id,
            process.launch_id,
            process.pid,
            process.executable.display(),
            process.arguments
        );
    }
    match (result, cleanup) {
        (Ok(()), Ok(None)) => {}
        (Ok(()), Ok(Some(path))) => panic!(
            "successful timer metrics test unexpectedly retained logs at {}",
            path.display()
        ),
        (Ok(()), Err(cleanup)) => panic!("timer metrics cleanup failed: {cleanup}"),
        (Err(error), Ok(retained)) => panic!(
            "{error}; bounded native-process logs retained at {}",
            retained
                .as_deref()
                .map(std::path::Path::display)
                .map(|path| path.to_string())
                .unwrap_or_else(|| "<unavailable>".to_owned())
        ),
        (Err(error), Err(cleanup)) => panic!("{error}; {cleanup}"),
    }
}
