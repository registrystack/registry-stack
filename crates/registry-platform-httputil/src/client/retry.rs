//! Bounded same-key retry for idempotency-keyed mutations.
//!
//! A product client classifies each attempt with its own error model; this
//! module owns only the loop, the retry budget, and the wait between attempts.

use std::{future::Future, time::Duration};

/// Same-key retries a client makes, by default, for one idempotency-keyed
/// mutation whose outcome is unknown.
pub const DEFAULT_MUTATION_RETRIES: u8 = 2;
/// Most same-key retries a client may be configured to make for one mutation.
pub const MAXIMUM_MUTATION_RETRIES: u8 = 2;
/// Longest server-requested `Retry-After` wait, in seconds, a same-key retry
/// honors. A longer requested wait ends the retries and returns the answer.
pub const MAXIMUM_MUTATION_RETRY_AFTER_SECONDS: u64 = 5;

const FIRST_RETRY_DELAY: Duration = Duration::from_millis(250);

/// How one attempt of an idempotency-keyed mutation ended.
#[derive(Debug)]
pub enum KeyedMutationAttempt<T, E> {
    /// The attempt settled: a value, or an error a resend cannot change, such
    /// as a deterministic refusal or a request that never left the client.
    Settled(Result<T, E>),
    /// The outcome is unknown and resending the identical request under the
    /// same key may settle it: a timeout or broken exchange after the request
    /// was sent, or a 5xx answer. `retry_after_seconds` is the server's
    /// delta-seconds `Retry-After`, when it sent exactly one.
    Retryable {
        error: E,
        retry_after_seconds: Option<u64>,
    },
    /// The outcome is unknown, but a resend would be answered the same way,
    /// such as an oversized or unparseable success answer.
    Unknown(E),
}

/// Run one idempotency-keyed mutation, resending the identical request under
/// the same key at most `max_retries` times while its outcome stays unknown.
/// A count above [`MAXIMUM_MUTATION_RETRIES`] is treated as that maximum.
///
/// Every `attempt` must send byte-identical content with the same key and
/// headers. Retry number `n` (zero-based) waits `250 ms * 2^n`, or the server's
/// `Retry-After` when that is longer and at most
/// [`MAXIMUM_MUTATION_RETRY_AFTER_SECONDS`]; a longer requested wait ends the
/// retries. A settled error that follows an unknown outcome does not prove the
/// earlier attempt left no effect, so the earlier unknown error is returned in
/// its place.
pub async fn retry_keyed_mutation<T, E, F, Fut>(max_retries: u8, mut attempt: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = KeyedMutationAttempt<T, E>>,
{
    let max_retries = max_retries.min(MAXIMUM_MUTATION_RETRIES);
    let mut retries = 0u8;
    let mut earlier_unknown = None;
    loop {
        match attempt().await {
            KeyedMutationAttempt::Settled(Ok(value)) => return Ok(value),
            KeyedMutationAttempt::Settled(Err(error)) => {
                return Err(earlier_unknown.unwrap_or(error));
            }
            KeyedMutationAttempt::Unknown(error) => return Err(error),
            KeyedMutationAttempt::Retryable {
                error,
                retry_after_seconds,
            } => {
                if retries >= max_retries {
                    return Err(error);
                }
                let Some(delay) = retry_delay(retries, retry_after_seconds) else {
                    return Err(error);
                };
                tokio::time::sleep(delay).await;
                retries += 1;
                earlier_unknown = Some(error);
            }
        }
    }
}

fn retry_delay(retry: u8, retry_after_seconds: Option<u64>) -> Option<Duration> {
    let backoff = FIRST_RETRY_DELAY.saturating_mul(1u32 << retry.min(16));
    match retry_after_seconds {
        Some(seconds) if seconds > MAXIMUM_MUTATION_RETRY_AFTER_SECONDS => None,
        Some(seconds) => Some(backoff.max(Duration::from_secs(seconds))),
        None => Some(backoff),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Failure {
        Unknown(u32),
        Refused(u32),
    }

    async fn run(
        max_retries: u8,
        outcomes: &[KeyedMutationAttemptSpec],
    ) -> (Result<u32, Failure>, u32) {
        let calls = Cell::new(0u32);
        let result = retry_keyed_mutation(max_retries, || {
            let call = calls.get();
            calls.set(call + 1);
            let spec = outcomes[usize::try_from(call).expect("small index")];
            async move { spec.attempt(call) }
        })
        .await;
        (result, calls.get())
    }

    #[derive(Clone, Copy)]
    enum KeyedMutationAttemptSpec {
        Success,
        Refused,
        Retryable,
        Unknown,
    }

    impl KeyedMutationAttemptSpec {
        fn attempt(self, call: u32) -> KeyedMutationAttempt<u32, Failure> {
            match self {
                Self::Success => KeyedMutationAttempt::Settled(Ok(call)),
                Self::Refused => KeyedMutationAttempt::Settled(Err(Failure::Refused(call))),
                Self::Retryable => KeyedMutationAttempt::Retryable {
                    error: Failure::Unknown(call),
                    retry_after_seconds: None,
                },
                Self::Unknown => KeyedMutationAttempt::Unknown(Failure::Unknown(call)),
            }
        }
    }

    use KeyedMutationAttemptSpec::{Refused, Retryable, Success, Unknown};

    #[tokio::test]
    async fn a_settled_first_attempt_is_returned_without_a_retry() {
        assert_eq!(run(2, &[Success]).await, (Ok(0), 1));
        assert_eq!(run(2, &[Refused]).await, (Err(Failure::Refused(0)), 1));
    }

    #[tokio::test]
    async fn an_unknown_outcome_is_resent_until_it_settles() {
        assert_eq!(run(2, &[Retryable, Success]).await, (Ok(1), 2));
        assert_eq!(run(2, &[Retryable, Retryable, Success]).await, (Ok(2), 3));
    }

    #[tokio::test]
    async fn the_retry_budget_is_honored_and_zero_disables_it() {
        assert_eq!(
            run(2, &[Retryable, Retryable, Retryable, Success]).await,
            (Err(Failure::Unknown(2)), 3)
        );
        assert_eq!(
            run(1, &[Retryable, Retryable, Success]).await,
            (Err(Failure::Unknown(1)), 2)
        );
        assert_eq!(
            run(0, &[Retryable, Success]).await,
            (Err(Failure::Unknown(0)), 1)
        );
    }

    #[tokio::test]
    async fn a_retry_count_above_the_maximum_is_clamped() {
        assert_eq!(
            run(
                u8::MAX,
                &[Retryable, Retryable, Retryable, Retryable, Success]
            )
            .await,
            (Err(Failure::Unknown(2)), 3)
        );
    }

    #[tokio::test]
    async fn an_unknown_outcome_a_resend_cannot_change_is_not_resent() {
        assert_eq!(
            run(2, &[Unknown, Success]).await,
            (Err(Failure::Unknown(0)), 1)
        );
        assert_eq!(
            run(2, &[Retryable, Unknown, Success]).await,
            (Err(Failure::Unknown(1)), 2)
        );
    }

    #[tokio::test]
    async fn a_refusal_after_an_unknown_outcome_keeps_the_outcome_unknown() {
        assert_eq!(
            run(2, &[Retryable, Refused, Success]).await,
            (Err(Failure::Unknown(0)), 2)
        );
        assert_eq!(
            run(2, &[Retryable, Retryable, Refused]).await,
            (Err(Failure::Unknown(1)), 3)
        );
    }

    #[tokio::test]
    async fn a_requested_wait_above_the_bound_ends_the_retries() {
        let calls = Cell::new(0u32);
        let result: Result<u32, Failure> = retry_keyed_mutation(2, || {
            calls.set(calls.get() + 1);
            async {
                KeyedMutationAttempt::Retryable {
                    error: Failure::Unknown(0),
                    retry_after_seconds: Some(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS + 1),
                }
            }
        })
        .await;
        assert_eq!(result, Err(Failure::Unknown(0)));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn the_wait_doubles_and_honors_a_bounded_retry_after() {
        assert_eq!(retry_delay(0, None), Some(Duration::from_millis(250)));
        assert_eq!(retry_delay(1, None), Some(Duration::from_millis(500)));
        assert_eq!(retry_delay(0, Some(0)), Some(Duration::from_millis(250)));
        assert_eq!(retry_delay(1, Some(3)), Some(Duration::from_secs(3)));
        assert_eq!(
            retry_delay(0, Some(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS)),
            Some(Duration::from_secs(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS))
        );
        assert_eq!(
            retry_delay(0, Some(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS + 1)),
            None
        );
        assert!(retry_delay(u8::MAX, None).is_some());
    }
}
