// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

/// Numeric-only samples keep synthetic record values and claim context out of
/// benchmark output. Runs report latency distributions without timing assertions.
pub fn report_latency(workload: &str, sample: usize, durations: &[Duration]) {
    let mut nanos: Vec<u128> = durations.iter().map(Duration::as_nanos).collect();
    nanos.sort_unstable();
    let percentile = |percent: usize| nanos[(nanos.len() * percent).div_ceil(100) - 1];
    let mean = nanos.iter().sum::<u128>() / nanos.len() as u128;
    println!(
        "breg_performance workload={workload} sample={sample} operations={} mean_ns={mean} p50_ns={} p95_ns={} p99_ns={}",
        nanos.len(),
        percentile(50),
        percentile(95),
        percentile(99),
    );
}
