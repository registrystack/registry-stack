//! Run with `cargo bench --locked -p registry-mint --bench replay_cache`.
//!
//! Synthetic, single-threaded replay-cache costs, excluding assertion parsing,
//! signature verification, signing, and durable audit. Inputs are prepared
//! before timing. No timing threshold is a correctness gate.

use std::{hint::black_box, time::Instant};

use registry_mint::replay::{ReplayCache, ReplayError};

const SAMPLES: usize = 5;
const OPERATIONS: usize = 512;

fn measure(operations: usize, mut operation: impl FnMut(usize)) -> u128 {
    let start = Instant::now();
    for index in 0..operations {
        operation(index);
    }
    start.elapsed().as_nanos() / operations as u128
}

fn report(name: &str, entries: usize, mut samples: Vec<u128>) {
    samples.sort_unstable();
    println!(
        "replay/{name} entries={entries} median_ns={} min_ns={} max_ns={} samples={}",
        samples[samples.len() / 2],
        samples[0],
        samples[samples.len() - 1],
        samples.len(),
    );
}

fn benchmark(entries: usize) {
    let keys: Vec<_> = (0..entries)
        .map(|index| format!("client-registered\0assertion-{index:026}"))
        .collect();
    let replacements: Vec<_> = (0..OPERATIONS)
        .map(|index| format!("client-registered\0replacement-{index:026}"))
        .collect();
    let mut fill = Vec::new();
    let mut duplicate = Vec::new();
    let mut saturated = Vec::new();
    let mut expire_cohort = Vec::new();
    let mut staggered = Vec::new();

    for _ in 0..SAMPLES {
        let cache = ReplayCache::new(entries);
        fill.push(measure(entries, |index| {
            assert_eq!(cache.remember(black_box(&keys[index]), 300, 0), Ok(()));
        }));
        duplicate.push(measure(OPERATIONS, |index| {
            assert_eq!(
                cache.remember(black_box(&keys[index % entries]), 300, 0),
                Err(ReplayError::AlreadyUsed)
            );
        }));
        saturated.push(measure(OPERATIONS, |index| {
            assert_eq!(
                cache.remember(black_box(&replacements[index]), 300, 0),
                Err(ReplayError::Saturated)
            );
        }));
        expire_cohort.push(measure(1, |_| {
            assert_eq!(
                cache.remember(black_box(&replacements[0]), 600, 300),
                Ok(())
            );
        }));
        assert_eq!(cache.len(), 1);

        let cache = ReplayCache::new(entries);
        for (index, key) in keys.iter().enumerate() {
            let expiry = if index < OPERATIONS {
                index as i64 + 1
            } else {
                600
            };
            cache.remember(key, expiry, 0).unwrap();
        }
        // One entry expires before each call; unlike the cohort case, a cache
        // cannot avoid cleanup simply because the clock has not advanced.
        staggered.push(measure(OPERATIONS, |index| {
            assert_eq!(
                cache.remember(
                    black_box(&replacements[index]),
                    index as i64 + 601,
                    index as i64 + 1,
                ),
                Ok(())
            );
        }));
        assert_eq!(cache.len(), entries);
    }

    report("fill_per_insert", entries, fill);
    report("live_duplicate", entries, duplicate);
    report("saturated", entries, saturated);
    report("expire_cohort_total", entries, expire_cohort);
    report("staggered_expiry", entries, staggered);
}

fn main() {
    for entries in [1_024, 8_192, 100_000] {
        benchmark(entries);
    }
}
