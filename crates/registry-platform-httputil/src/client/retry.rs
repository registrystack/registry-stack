//! Bounded same-key retry for idempotency-keyed mutations.
//!
//! A product client judges each error with its own error model; this module
//! owns the rule that turns that judgement into a resend decision, the loop,
//! the retry budget, and the wait between attempts.

use std::{future::Future, time::Duration};

use http::{header::RETRY_AFTER, HeaderMap, StatusCode};

/// Same-key retries a client makes, by default, for one idempotency-keyed
/// mutation whose outcome is unknown.
pub const DEFAULT_MUTATION_RETRIES: u8 = 2;
/// Most same-key retries a client may be configured to make for one mutation.
pub const MAXIMUM_MUTATION_RETRIES: u8 = 2;
/// Longest server-requested `Retry-After` wait, in seconds, a same-key retry
/// honors. A longer requested wait ends the retries and returns the answer.
pub const MAXIMUM_MUTATION_RETRY_AFTER_SECONDS: u64 = 5;

const FIRST_RETRY_DELAY: Duration = Duration::from_millis(250);

/// The `Retry-After` field of one answer, as a same-key retry reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAfter {
    /// The answer carried no `Retry-After` field.
    Absent,
    /// Exactly one RFC 9110 delta-seconds field, zero included.
    Seconds(u64),
    /// A field the client cannot honor: an HTTP-date, a duplicate field line,
    /// or any other value outside delta-seconds. The server asked for a wait,
    /// but not one this client can measure, so it ends the retries.
    Unusable,
}

impl RetryAfter {
    /// Read the `Retry-After` field of an answer.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut values = headers.get_all(RETRY_AFTER).iter();
        let value = match (values.next(), values.next()) {
            (None, _) => return Self::Absent,
            (Some(value), None) => value,
            (Some(_), Some(_)) => return Self::Unusable,
        };
        let Ok(value) = value.to_str() else {
            return Self::Unusable;
        };
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Self::Unusable;
        }
        value.parse().map_or(Self::Unusable, Self::Seconds)
    }
}

/// How one attempt of an idempotency-keyed mutation ended.
#[derive(Debug)]
pub enum KeyedMutationAttempt<T, E> {
    /// The attempt settled: a value, or an error a resend cannot change, such
    /// as a deterministic refusal or a request that never left the client.
    Settled(Result<T, E>),
    /// The outcome is unknown and resending the identical request under the
    /// same key may settle it: a timeout or broken exchange after the request
    /// was sent, or a 5xx answer. `retry_after` is that answer's
    /// `Retry-After` field, [`RetryAfter::Absent`] when no answer arrived.
    Retryable { error: E, retry_after: RetryAfter },
    /// The outcome is unknown, but a resend would be answered the same way,
    /// such as an oversized or unparseable success answer.
    Unknown(E),
}

/// Classify one attempt of an idempotency-keyed mutation for
/// [`retry_keyed_mutation`].
///
/// `status` and `retry_after` describe the answer, or are `None` and
/// [`RetryAfter::Absent`] when the send failed before one arrived. The
/// product client supplies two judgements of its own error:
/// `outcome_unknown`, whether the mutation may have taken effect, and
/// `resend_may_settle`, whether resending the identical request could settle
/// it. A known failure settles the mutation. An unknown outcome on a 4xx
/// answer is never resent: the status line has already refused the request,
/// so a failure reading the rest of the answer, such as a timeout or a
/// broken exchange, leaves only the refusal's detail unread. Otherwise an unknown outcome is resent when the answer carried a 5xx
/// status, whatever stage of decoding failed, or when `resend_may_settle`
/// holds. Any other unknown outcome would be answered the same way again, so
/// it is returned without a resend.
pub fn classify_keyed_attempt<T, E>(
    result: Result<T, E>,
    status: Option<StatusCode>,
    retry_after: RetryAfter,
    outcome_unknown: fn(&E) -> bool,
    resend_may_settle: fn(&E) -> bool,
) -> KeyedMutationAttempt<T, E> {
    let error = match result {
        Ok(value) => return KeyedMutationAttempt::Settled(Ok(value)),
        Err(error) => error,
    };
    if !outcome_unknown(&error) {
        return KeyedMutationAttempt::Settled(Err(error));
    }
    if status.is_some_and(|status| status.is_client_error()) {
        return KeyedMutationAttempt::Unknown(error);
    }
    if status.is_some_and(|status| status.is_server_error()) || resend_may_settle(&error) {
        KeyedMutationAttempt::Retryable { error, retry_after }
    } else {
        KeyedMutationAttempt::Unknown(error)
    }
}

/// Run one idempotency-keyed mutation, resending the identical request under
/// the same key at most `max_retries` times while its outcome stays unknown.
/// A count above [`MAXIMUM_MUTATION_RETRIES`] is treated as that maximum.
///
/// Every `attempt` must send byte-identical content with the same key and
/// headers. Retry number `n` (zero-based) waits `250 ms * 2^n`, or the server's
/// `Retry-After` when that is longer and at most
/// [`MAXIMUM_MUTATION_RETRY_AFTER_SECONDS`]; a longer requested wait, or a
/// [`RetryAfter::Unusable`] one, ends the retries. A settled error that
/// follows an unknown outcome does not prove the earlier attempt left no
/// effect, so the earlier unknown error is returned in its place.
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
            KeyedMutationAttempt::Retryable { error, retry_after } => {
                if retries >= max_retries {
                    return Err(error);
                }
                let Some(delay) = retry_delay(retries, retry_after) else {
                    return Err(error);
                };
                tokio::time::sleep(delay).await;
                retries += 1;
                earlier_unknown = Some(error);
            }
        }
    }
}

fn retry_delay(retry: u8, retry_after: RetryAfter) -> Option<Duration> {
    let backoff = FIRST_RETRY_DELAY.saturating_mul(1u32 << retry.min(16));
    match retry_after {
        RetryAfter::Unusable => None,
        RetryAfter::Seconds(seconds) if seconds > MAXIMUM_MUTATION_RETRY_AFTER_SECONDS => None,
        RetryAfter::Seconds(seconds) => Some(backoff.max(Duration::from_secs(seconds))),
        RetryAfter::Absent => Some(backoff),
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
                    retry_after: RetryAfter::Absent,
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
    async fn a_requested_wait_above_the_bound_or_unusable_ends_the_retries() {
        for retry_after in [
            RetryAfter::Seconds(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS + 1),
            RetryAfter::Unusable,
        ] {
            let calls = Cell::new(0u32);
            let result: Result<u32, Failure> = retry_keyed_mutation(2, || {
                calls.set(calls.get() + 1);
                async move {
                    KeyedMutationAttempt::Retryable {
                        error: Failure::Unknown(0),
                        retry_after,
                    }
                }
            })
            .await;
            assert_eq!(result, Err(Failure::Unknown(0)), "{retry_after:?}");
            assert_eq!(calls.get(), 1, "{retry_after:?}");
        }
    }

    fn retry_after(values: &[&'static str]) -> RetryAfter {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(RETRY_AFTER, http::HeaderValue::from_static(value));
        }
        RetryAfter::from_headers(&headers)
    }

    #[test]
    fn only_one_delta_seconds_field_is_a_usable_wait() {
        assert_eq!(retry_after(&[]), RetryAfter::Absent);
        assert_eq!(retry_after(&["0"]), RetryAfter::Seconds(0));
        assert_eq!(retry_after(&["3"]), RetryAfter::Seconds(3));
        assert_eq!(retry_after(&["60"]), RetryAfter::Seconds(60));
        for unusable in [
            &["Wed, 21 Oct 2026 07:28:00 GMT"][..],
            &["1", "1"],
            &[""],
            &["soon"],
            &["1.5"],
            &["+1"],
            &["-1"],
            &["18446744073709551616"],
        ] {
            assert_eq!(retry_after(unusable), RetryAfter::Unusable, "{unusable:?}");
        }
        let mut opaque = HeaderMap::new();
        opaque.insert(
            RETRY_AFTER,
            http::HeaderValue::from_bytes(b"\xff").expect("an opaque field value"),
        );
        assert_eq!(RetryAfter::from_headers(&opaque), RetryAfter::Unusable);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Classified {
        unknown: bool,
        resend_may_settle: bool,
    }

    fn classify(
        result: Result<u32, Classified>,
        status: Option<u16>,
        retry_after: RetryAfter,
    ) -> KeyedMutationAttempt<u32, Classified> {
        classify_keyed_attempt(
            result,
            status.map(|status| StatusCode::from_u16(status).expect("a status code")),
            retry_after,
            |error| error.unknown,
            |error| error.resend_may_settle,
        )
    }

    const KNOWN: Classified = Classified {
        unknown: false,
        resend_may_settle: false,
    };
    const UNKNOWN: Classified = Classified {
        unknown: true,
        resend_may_settle: false,
    };
    const SETTLEABLE: Classified = Classified {
        unknown: true,
        resend_may_settle: true,
    };

    #[test]
    fn a_value_or_a_known_failure_settles_the_mutation() {
        assert!(matches!(
            classify(Ok(7), Some(201), RetryAfter::Absent),
            KeyedMutationAttempt::Settled(Ok(7))
        ));
        for status in [None, Some(409), Some(500), Some(503)] {
            assert!(
                matches!(
                    classify(Err(KNOWN), status, RetryAfter::Seconds(1)),
                    KeyedMutationAttempt::Settled(Err(KNOWN))
                ),
                "{status:?}"
            );
        }
    }

    #[test]
    fn an_unknown_outcome_on_a_5xx_answer_or_one_a_resend_may_settle_is_retryable() {
        for (error, status) in [
            (UNKNOWN, Some(500)),
            (UNKNOWN, Some(503)),
            (SETTLEABLE, Some(502)),
            (SETTLEABLE, None),
            (SETTLEABLE, Some(201)),
        ] {
            assert!(
                matches!(
                    classify(Err(error), status, RetryAfter::Seconds(2)),
                    KeyedMutationAttempt::Retryable {
                        error: classified,
                        retry_after: RetryAfter::Seconds(2),
                    } if classified == error
                ),
                "{error:?} {status:?}"
            );
        }
    }

    #[test]
    fn an_unknown_outcome_on_a_4xx_answer_is_never_resent() {
        for error in [UNKNOWN, SETTLEABLE] {
            for status in [400, 409, 429, 499] {
                assert!(
                    matches!(
                        classify(Err(error), Some(status), RetryAfter::Seconds(1)),
                        KeyedMutationAttempt::Unknown(classified) if classified == error
                    ),
                    "{error:?} {status}"
                );
            }
        }
    }

    #[test]
    fn any_other_unknown_outcome_is_not_resent() {
        for status in [None, Some(201), Some(302), Some(409)] {
            assert!(
                matches!(
                    classify(Err(UNKNOWN), status, RetryAfter::Absent),
                    KeyedMutationAttempt::Unknown(UNKNOWN)
                ),
                "{status:?}"
            );
        }
    }

    #[test]
    fn the_wait_doubles_and_honors_a_bounded_retry_after() {
        use RetryAfter::{Absent, Seconds};
        assert_eq!(retry_delay(0, Absent), Some(Duration::from_millis(250)));
        assert_eq!(retry_delay(1, Absent), Some(Duration::from_millis(500)));
        assert_eq!(retry_delay(0, Seconds(0)), Some(Duration::from_millis(250)));
        assert_eq!(retry_delay(1, Seconds(0)), Some(Duration::from_millis(500)));
        assert_eq!(retry_delay(1, Seconds(3)), Some(Duration::from_secs(3)));
        assert_eq!(
            retry_delay(0, Seconds(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS)),
            Some(Duration::from_secs(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS))
        );
        assert_eq!(
            retry_delay(0, Seconds(MAXIMUM_MUTATION_RETRY_AFTER_SECONDS + 1)),
            None
        );
        assert_eq!(retry_delay(0, RetryAfter::Unusable), None);
        assert!(retry_delay(u8::MAX, Absent).is_some());
    }
}
