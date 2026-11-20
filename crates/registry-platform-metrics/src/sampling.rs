// SPDX-License-Identifier: Apache-2.0
//! The rule every database-sampled gauge follows.
//!
//! All reads of one scrape share one [`ScrapeDeadline`]. Each read runs in a
//! read-only transaction whose `SET LOCAL statement_timeout` comes from
//! [`ScrapeDeadline::statement_timeout_milliseconds`], so a slow query is
//! cancelled on the server and not only abandoned by the client: dropping a
//! database client future does not cancel the query. A failed read is logged
//! by its [`sample_error_class`] and counted once, its gauges are omitted,
//! and the reads after it still run. [`ScrapeDeadline::run`] wraps each read:
//! a read that starts with the budget spent fails as `no-time-left` without
//! querying.

use std::time::{Duration, Instant};

/// The longest one scrape may spend on all of its database reads together.
pub const SCRAPE_BUDGET: Duration = Duration::from_secs(5);

/// The error class of a read that ran past the scrape deadline.
pub const CLASS_TIMEOUT: &str = "timeout";

/// The error class of a read that could not get a pool connection.
pub const CLASS_POOL: &str = "pool";

/// The error class of a read that started with no time left.
pub const CLASS_NO_TIME_LEFT: &str = "no-time-left";

/// The one deadline the reads of a scrape share.
#[derive(Clone, Copy, Debug)]
pub struct ScrapeDeadline {
    at: Instant,
}

impl ScrapeDeadline {
    /// A deadline [`SCRAPE_BUDGET`] after `now`.
    #[must_use]
    pub fn from(now: Instant) -> Self {
        Self::with_budget(now, SCRAPE_BUDGET)
    }

    /// A deadline `budget` after `now`, never later than [`SCRAPE_BUDGET`].
    #[must_use]
    pub fn with_budget(now: Instant, budget: Duration) -> Self {
        Self {
            at: now + budget.min(SCRAPE_BUDGET),
        }
    }

    /// The instant the scrape's reads must have finished by.
    #[must_use]
    pub fn at(self) -> Instant {
        self.at
    }

    /// The time left at `now`, zero once the deadline has passed.
    #[must_use]
    pub fn remaining_at(self, now: Instant) -> Duration {
        self.at.saturating_duration_since(now)
    }

    /// The server-side statement timeout for a read that starts at `now`:
    /// the whole milliseconds left, so it never outlasts the deadline.
    /// `None` when under a millisecond is left (`statement_timeout = 0`
    /// would mean no limit), and the read counts as failed.
    #[must_use]
    pub fn statement_timeout_milliseconds_at(self, now: Instant) -> Option<u64> {
        let milliseconds = self.remaining_at(now).as_millis();
        u64::try_from(milliseconds).ok().filter(|ms| *ms > 0)
    }

    /// Run `read` so it cannot outlast the deadline. A read that would start
    /// with no time left (under a millisecond) is never polled, so it takes
    /// no pool connection and sends no query, and fails as
    /// [`CLASS_NO_TIME_LEFT`]. A read still running at the deadline is
    /// dropped and fails as [`CLASS_TIMEOUT`]. Pass an unpolled future: its
    /// work starts only when this runs it.
    ///
    /// # Errors
    ///
    /// The read's own error class, [`CLASS_NO_TIME_LEFT`] or
    /// [`CLASS_TIMEOUT`].
    pub async fn run<T>(
        self,
        read: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        if self.statement_timeout_milliseconds().is_none() {
            return Err(CLASS_NO_TIME_LEFT.to_owned());
        }
        tokio::time::timeout_at(tokio::time::Instant::from_std(self.at), read)
            .await
            .unwrap_or_else(|_| Err(CLASS_TIMEOUT.to_owned()))
    }

    /// [`Self::statement_timeout_milliseconds_at`] at the current instant.
    #[must_use]
    pub fn statement_timeout_milliseconds(self) -> Option<u64> {
        self.statement_timeout_milliseconds_at(Instant::now())
    }
}

/// The SQLSTATE of a statement the server cancelled for running past its
/// `statement_timeout`.
const QUERY_CANCELED: &str = "57014";

/// The closed class of a database error: `timeout` when the server cancelled
/// the statement at its `statement_timeout`, `sqlstate-<code>` when the
/// server answered otherwise, `connection-closed` when the connection
/// dropped, `query` otherwise. It names no query text, value or row.
#[must_use]
pub fn sample_error_class(sqlstate: Option<&str>, connection_closed: bool) -> String {
    if sqlstate == Some(QUERY_CANCELED) {
        CLASS_TIMEOUT.to_owned()
    } else if let Some(code) = sqlstate {
        format!("sqlstate-{code}")
    } else if connection_closed {
        "connection-closed".to_owned()
    } else {
        "query".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn the_deadline_is_at_most_the_budget() {
        let now = Instant::now();
        assert_eq!(ScrapeDeadline::from(now).at(), now + SCRAPE_BUDGET);
        assert_eq!(
            ScrapeDeadline::with_budget(now, Duration::from_secs(60)).at(),
            now + SCRAPE_BUDGET
        );
        assert_eq!(
            ScrapeDeadline::with_budget(now, Duration::from_secs(1)).at(),
            now + Duration::from_secs(1)
        );
    }

    #[test]
    fn the_statement_timeout_is_the_time_left_and_never_more() {
        let now = Instant::now();
        let deadline = ScrapeDeadline::from(now);
        assert_eq!(deadline.statement_timeout_milliseconds_at(now), Some(5_000));
        let later = now + Duration::from_millis(3_250);
        assert_eq!(
            deadline.statement_timeout_milliseconds_at(later),
            Some(1_750)
        );
        // Whole milliseconds, rounded down: 1.6 ms left is 1 ms, 0.6 ms is none.
        assert_eq!(
            deadline.statement_timeout_milliseconds_at(now + Duration::from_micros(4_998_400)),
            Some(1)
        );
        assert_eq!(
            deadline.statement_timeout_milliseconds_at(now + Duration::from_micros(4_999_400)),
            None
        );
    }

    #[test]
    fn no_time_left_has_no_statement_timeout() {
        let now = Instant::now();
        let deadline = ScrapeDeadline::from(now);
        assert_eq!(
            deadline.statement_timeout_milliseconds_at(now + SCRAPE_BUDGET),
            None
        );
        assert_eq!(
            deadline
                .statement_timeout_milliseconds_at(now + SCRAPE_BUDGET + Duration::from_secs(9)),
            None
        );
        assert_eq!(
            deadline.remaining_at(now + SCRAPE_BUDGET + Duration::from_secs(9)),
            Duration::ZERO
        );
    }

    #[test]
    fn the_error_class_names_the_sqlstate_or_the_kind_of_failure() {
        assert_eq!(sample_error_class(Some("57014"), false), "timeout");
        assert_eq!(sample_error_class(Some("42P01"), false), "sqlstate-42P01");
        assert_eq!(sample_error_class(None, true), "connection-closed");
        assert_eq!(sample_error_class(None, false), "query");
    }

    #[tokio::test]
    async fn a_spent_deadline_fails_without_starting_the_read() {
        let started = AtomicBool::new(false);
        let deadline = ScrapeDeadline::with_budget(Instant::now(), Duration::ZERO);
        let result = deadline
            .run(async {
                started.store(true, Ordering::SeqCst);
                Ok::<_, String>(1)
            })
            .await;
        assert_eq!(result, Err(CLASS_NO_TIME_LEFT.to_owned()));
        assert!(!started.load(Ordering::SeqCst), "the read must not start");
    }

    #[tokio::test]
    async fn a_read_with_time_left_returns_its_value_or_its_class() {
        let deadline = ScrapeDeadline::from(Instant::now());
        assert_eq!(deadline.run(async { Ok::<_, String>(7) }).await, Ok(7));
        assert_eq!(
            deadline
                .run(async { Err::<u8, _>("sqlstate-42P01".to_owned()) })
                .await,
            Err("sqlstate-42P01".to_owned())
        );
    }

    #[tokio::test]
    async fn a_read_that_runs_past_the_deadline_is_a_timeout() {
        let deadline = ScrapeDeadline::with_budget(Instant::now(), Duration::from_millis(50));
        let result = deadline
            .run(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok::<_, String>(())
            })
            .await;
        assert_eq!(result, Err(CLASS_TIMEOUT.to_owned()));
    }
}
