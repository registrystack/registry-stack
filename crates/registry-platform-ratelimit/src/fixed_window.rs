//! A keyed fixed window counter: a per-key ceiling over a rolling window.

use std::{collections::HashMap, time::Duration};

use thiserror::Error;
use tokio::time::Instant;

use crate::{validate_key, MAX_TRACKED_KEYS};

#[derive(Debug, Clone, Copy)]
pub struct FixedWindowConfig {
    pub window: Duration,
    pub limit: u32,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FixedWindowError {
    #[error("fixed window configuration is invalid")]
    Configuration,
    #[error("fixed window capacity is unavailable")]
    Capacity,
    #[error("fixed window count exceeded")]
    Exceeded,
}

#[derive(Debug)]
struct Window {
    started_at: Instant,
    count: u32,
}

/// A keyed fixed window counter.
///
/// Each key gets its own window: the first [`Self::record`] after the window
/// has elapsed (or for a new key) starts a fresh window with a count of one.
/// [`Self::check`] answers whether the key is currently over `limit` without
/// recording anything, so a caller can gate on the budget before doing the
/// work that would consume it.
#[derive(Debug)]
pub struct FixedWindowCounter {
    config: FixedWindowConfig,
    windows: tokio::sync::Mutex<HashMap<String, Window>>,
}

impl FixedWindowCounter {
    pub fn new(config: FixedWindowConfig) -> Result<Self, FixedWindowError> {
        if config.limit == 0 || config.window.is_zero() {
            return Err(FixedWindowError::Configuration);
        }
        Ok(Self {
            config,
            windows: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Check the budget for `key` without recording anything.
    ///
    /// Call [`Self::record`] only when the event this counter tracks actually
    /// occurs.
    pub async fn check(&self, key: &str) -> Result<(), FixedWindowError> {
        validate_key(key).map_err(|_| FixedWindowError::Configuration)?;
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        prune(&mut windows, now, self.config.window);
        match windows.get(key) {
            Some(window)
                if now.duration_since(window.started_at) < self.config.window
                    && window.count >= self.config.limit =>
            {
                Err(FixedWindowError::Exceeded)
            }
            _ => Ok(()),
        }
    }

    /// Record one occurrence for `key`, refusing once the window's count
    /// exceeds `limit`.
    pub async fn record(&self, key: &str) -> Result<(), FixedWindowError> {
        validate_key(key).map_err(|_| FixedWindowError::Configuration)?;
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        prune(&mut windows, now, self.config.window);
        if !windows.contains_key(key) && windows.len() >= MAX_TRACKED_KEYS {
            return Err(FixedWindowError::Capacity);
        }
        let window = windows.entry(key.to_owned()).or_insert(Window {
            started_at: now,
            count: 0,
        });
        if now.duration_since(window.started_at) >= self.config.window {
            window.started_at = now;
            window.count = 0;
        }
        window.count = window.count.saturating_add(1);
        if window.count > self.config.limit {
            return Err(FixedWindowError::Exceeded);
        }
        Ok(())
    }

    /// Total keys currently tracked, toward [`MAX_TRACKED_KEYS`].
    pub async fn tracked_key_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

fn prune(windows: &mut HashMap<String, Window>, now: Instant, window: Duration) {
    if windows.len() < MAX_TRACKED_KEYS / 2 {
        return;
    }
    // Retained twice as long as the window itself, so an entry mid-window at
    // the moment pruning runs is never dropped out from under an active
    // count.
    let retention = window.saturating_mul(2);
    windows.retain(|_, window| now.duration_since(window.started_at) < retention);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter() -> FixedWindowCounter {
        FixedWindowCounter::new(FixedWindowConfig {
            window: Duration::from_secs(60),
            limit: 2,
        })
        .expect("counter builds")
    }

    #[test]
    fn zero_limit_is_refused_at_construction() {
        assert_eq!(
            FixedWindowCounter::new(FixedWindowConfig {
                window: Duration::from_secs(60),
                limit: 0,
            })
            .unwrap_err(),
            FixedWindowError::Configuration
        );
    }

    #[test]
    fn zero_window_is_refused_at_construction() {
        assert_eq!(
            FixedWindowCounter::new(FixedWindowConfig {
                window: Duration::ZERO,
                limit: 1,
            })
            .unwrap_err(),
            FixedWindowError::Configuration
        );
    }

    #[tokio::test]
    async fn an_invalid_key_is_refused() {
        let counter = counter();
        assert_eq!(
            counter.record("").await.unwrap_err(),
            FixedWindowError::Configuration
        );
        assert_eq!(
            counter.check("has space").await.unwrap_err(),
            FixedWindowError::Configuration
        );
    }

    #[tokio::test]
    async fn window_is_enforced_and_separate_per_key() {
        let counter = counter();
        counter.record("key-a").await.expect("first");
        counter.record("key-a").await.expect("second");
        assert_eq!(
            counter.check("key-a").await,
            Err(FixedWindowError::Exceeded)
        );
        assert_eq!(
            counter.record("key-a").await,
            Err(FixedWindowError::Exceeded)
        );
        counter
            .check("key-b")
            .await
            .expect("another key has an independent budget");
    }

    #[tokio::test]
    async fn a_new_window_opens_once_the_configured_duration_elapses() {
        let counter = FixedWindowCounter::new(FixedWindowConfig {
            window: Duration::from_millis(20),
            limit: 1,
        })
        .expect("counter builds");
        counter.record("key").await.expect("first window");
        assert_eq!(counter.record("key").await, Err(FixedWindowError::Exceeded));
        tokio::time::sleep(Duration::from_millis(30)).await;
        counter.record("key").await.expect("a fresh window opened");
    }

    #[tokio::test]
    async fn tracked_key_count_reports_distinct_keys_and_ignores_reuse() {
        let counter = counter();
        assert_eq!(counter.tracked_key_count().await, 0);

        counter.record("key-a").await.expect("first key");
        counter.record("key-b").await.expect("second key");
        assert_eq!(counter.tracked_key_count().await, 2);

        counter.record("key-a").await.expect("existing key");
        assert_eq!(counter.tracked_key_count().await, 2);
    }

    #[tokio::test]
    async fn a_new_key_is_refused_once_the_tracked_key_cap_is_reached() {
        let counter = FixedWindowCounter::new(FixedWindowConfig {
            window: Duration::from_secs(60),
            limit: 1,
        })
        .expect("counter builds");
        {
            let mut windows = counter.windows.lock().await;
            let now = Instant::now();
            for index in 0..crate::MAX_TRACKED_KEYS {
                windows.insert(
                    format!("filler-{index}"),
                    Window {
                        started_at: now,
                        count: 0,
                    },
                );
            }
        }
        assert_eq!(
            counter.record("new-key").await.unwrap_err(),
            FixedWindowError::Capacity
        );
        counter
            .record("filler-0")
            .await
            .expect("an already-tracked key is unaffected by the cap");
    }

    #[tokio::test]
    async fn pruning_evicts_idle_keys_once_the_map_is_half_full_of_the_cap() {
        let counter = FixedWindowCounter::new(FixedWindowConfig {
            window: Duration::from_secs(60),
            limit: 1,
        })
        .expect("counter builds");
        let stale_at = Instant::now()
            .checked_sub(Duration::from_secs(121))
            .expect("test clock has enough headroom to subtract");
        {
            let mut windows = counter.windows.lock().await;
            for index in 0..(crate::MAX_TRACKED_KEYS / 2) {
                windows.insert(
                    format!("stale-{index}"),
                    Window {
                        started_at: stale_at,
                        count: 1,
                    },
                );
            }
        }
        counter.record("fresh-key").await.expect("fresh key");
        assert_eq!(counter.tracked_key_count().await, 1);
    }
}
