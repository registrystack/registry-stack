//! The closed set of checks a request can fail, and the recorder that counts
//! and logs a refusal by its check.
//!
//! The check is operator-side only. It is never written to a response body.

/// Declares [`FailedCheck`], [`FailedCheck::ALL`] and [`FailedCheck::as_str`]
/// from one list, so a member cannot exist without its label and its place in
/// `ALL`.
macro_rules! failed_checks {
    ($($(#[$doc:meta])* $member:ident => $label:literal,)+) => {
        /// The check a request failed. Closed. Operator-side only: never written to a
        /// response.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum FailedCheck {
            $($(#[$doc])* $member,)+
        }

        impl FailedCheck {
            /// Every member, in declaration order.
            pub const ALL: [Self; [$($label),+].len()] = [$(Self::$member),+];

            /// The number of members.
            pub const COUNT: usize = Self::ALL.len();

            /// Stable kebab-case label for the counter and the log line.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$member => $label,)+
                }
            }
        }
    };
}

failed_checks! {
    /// No credential, or not the scheme the route takes.
    CredentialMissing => "credential-missing",
    /// Credential header repeated or unreadable, or the credential is not in the expected shape.
    CredentialMalformed => "credential-malformed",
    /// Signing algorithm not allowed.
    TokenAlgorithm => "token-algorithm",
    /// Token type not allowed.
    TokenType => "token-type",
    /// Key id missing, too long or unknown.
    TokenKey => "token-key",
    /// Signature does not verify.
    TokenSignature => "token-signature",
    /// Issuer is not the configured one.
    TokenIssuer => "token-issuer",
    /// Audience does not include this service.
    TokenAudience => "token-audience",
    /// Expired, not yet valid, or time claims unusable.
    TokenTime => "token-time",
    /// Client not on the verifier's allow list, or the matched client is unusable.
    TokenClient => "token-client",
    /// An exchanged token whose assertion issuer is not allowed or not declared.
    TokenAssertionIssuer => "token-assertion-issuer",
    /// A required identity claim is missing or malformed (principal, subject, issuer, expiry).
    TokenClaims => "token-claims",
    /// Actor kind claim missing, malformed, or not the kind the route or profile takes.
    ActorKind => "actor-kind",
    /// A delegated actor is present where none is allowed, or is not the trusted one.
    Delegation => "delegation",
    /// The token is sender-constrained and the service does not accept that.
    SenderConstraint => "sender-constraint",
    /// The verifier could not reach or use its key source.
    KeySourceUnavailable => "key-source-unavailable",
    /// A static secret, API key, Basic pair or path token does not match.
    SharedSecret => "shared-secret",
    /// A single-use code or token is unknown, expired, already used or locked out.
    OneTimeCredential => "one-time-credential",
    /// A signed delivery or provider callback has a missing, malformed, unsupported or wrong signature.
    DeliverySignature => "delivery-signature",
    /// A signed delivery time is outside the receiver's window.
    DeliveryFreshness => "delivery-freshness",
    /// A signed delivery's source, type, schema, route or target is not what the receiver expects.
    DeliveryBinding => "delivery-binding",
    /// The request's host or origin is not accepted.
    HostOrigin => "host-origin",
    /// A required scope is missing.
    Scope => "scope",
    /// No access profile, policy or authority entry admits this caller on this surface.
    AccessProfile => "access-profile",
    /// The profile or resource does not admit this requester client.
    RequesterClient => "requester-client",
    /// The declared purpose is missing or not admitted.
    Purpose => "purpose",
    /// The caller's profile or policy does not allow this operation, action, workflow, template or record type.
    Operation => "operation",
    /// The request asks for fields or a response format beyond what the caller's profile discloses.
    Disclosure => "disclosure",
    /// The subject selector is not one the caller's grant or authority covers.
    SubjectSelector => "subject-selector",
    /// The caller pinned a configuration revision that is not the deployed one.
    RevisionPin => "revision-pin",
    /// The acquisition channel is not open to the resolved profile.
    AcquisitionChannel => "acquisition-channel",
    /// The source or target authority refused the access.
    SourceAuthority => "source-authority",
    /// The caller already acted in a role that excludes this one.
    SeparationOfDuties => "separation-of-duties",
    /// The operation needs a task grant and none was presented.
    TaskGrantMissing => "task-grant-missing",
    /// The task grant is partial or malformed.
    TaskGrantClaims => "task-grant-claims",
    /// The task grant has expired.
    TaskGrantExpired => "task-grant-expired",
    /// The task grant is bound to another client, audience, principal, issuer or task.
    TaskGrantBinding => "task-grant-binding",
    /// The task grant does not cover this service, location, action or operation.
    TaskGrantScope => "task-grant-scope",
    /// The task grant has more lifetime, or more lifetime left, than the receiver accepts.
    TaskGrantLifetime => "task-grant-lifetime",
    /// The status authority says the grant is inactive, or its source is not listed.
    TaskGrantStatus => "task-grant-status",
    /// The target row is outside the caller's row boundary.
    RowBoundary => "row-boundary",
    /// The target exists and belongs to another caller.
    Ownership => "ownership",
    /// The target is absent or not visible to the caller, and the product does not tell which.
    Visibility => "visibility",
    /// A BReg Action guard refused. Operator-side only, so an answer never tells a guard from a boundary.
    ActionGuard => "action-guard",
    /// An identity-keyed or route-keyed request budget is spent.
    RateLimit => "rate-limit",
}

/// A trace id that `record_refusal!` may write on a refusal line.
///
/// `registry_platform_httpsec::TraceId` implements it when httpsec's `server`
/// feature is on. That type holds only a validated W3C trace id, 32 lowercase
/// hexadecimal digits, so no other request value (a header, client id or
/// subject) can reach the line through this field. The trait is sealed by
/// convention: its supertrait is a hidden item, and that `TraceId`, with a
/// reference to one, is its only implementation outside this crate's tests.
pub trait RefusalTraceId: core::fmt::Display + __refusal_trace_id_seal::Sealed {}

impl<T: RefusalTraceId + ?Sized> __refusal_trace_id_seal::Sealed for &T {}
impl<T: RefusalTraceId + ?Sized> RefusalTraceId for &T {}

/// The hidden supertrait of [`RefusalTraceId`]. Implemented only beside a
/// `RefusalTraceId` implementation.
#[doc(hidden)]
pub mod __refusal_trace_id_seal {
    pub trait Sealed {}
}

#[cfg(feature = "refusal-recorder")]
pub use recorder::{
    RefusalLine, RefusalNote, RefusalRecorder, REFUSAL_LOG_LINES_PER_WINDOW, REFUSAL_LOG_WINDOW,
};

#[cfg(feature = "refusal-recorder")]
mod recorder {
    use std::sync::{Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use registry_platform_metrics::{CounterVec, LabelSpace, MetricsError};

    use super::FailedCheck;

    /// The length of one log window for one check.
    pub const REFUSAL_LOG_WINDOW: Duration = Duration::from_secs(60);
    /// The most lines one check may write in one window.
    pub const REFUSAL_LOG_LINES_PER_WINDOW: u32 = 5;

    /// What the refusal answer carries to the recording layer, in the response
    /// extensions.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefusalNote {
        pub check: FailedCheck,
        pub remedy: Option<&'static str>,
    }

    impl RefusalNote {
        pub const fn new(check: FailedCheck) -> Self {
            Self {
                check,
                remedy: None,
            }
        }

        /// Attach a fixed operator hint. It is code-defined text, never a
        /// caller value.
        #[must_use]
        pub const fn with_remedy(self, remedy: &'static str) -> Self {
            Self {
                remedy: Some(remedy),
                ..self
            }
        }
    }

    /// One admitted log line.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefusalLine {
        pub failed_check: &'static str,
        /// Refusals of this check counted but not logged since the last line.
        pub suppressed: u64,
    }

    #[derive(Clone, Copy, Default)]
    pub(super) struct Slot {
        window_start: Option<Instant>,
        written: u32,
        suppressed: u64,
    }

    /// Counts refusals by check and admits a bounded number of log lines.
    ///
    /// State is one counter family and a fixed array of slots, one per
    /// [`FailedCheck`]. Nothing is keyed by a value a caller sends.
    ///
    /// The counter, not the log line, is the alert and diagnosis signal. Every
    /// refusal is counted. The log admits at most
    /// [`REFUSAL_LOG_LINES_PER_WINDOW`] lines per check per
    /// [`REFUSAL_LOG_WINDOW`], process-wide, so unauthenticated traffic can
    /// spend a check's lines before an honest client's refusal arrives. The
    /// `suppressed` field on the first line of the next window shows how many
    /// refusals of that check the window counted but did not log.
    pub struct RefusalRecorder {
        counter: CounterVec,
        pub(super) slots: Mutex<[Slot; FailedCheck::COUNT]>,
    }

    impl RefusalRecorder {
        /// `product` is the metric prefix, for example "breg" or
        /// "evidence_oid4vci".
        pub fn new(product: &'static str) -> Result<Self, MetricsError> {
            let labels: Vec<[&str; 1]> = FailedCheck::ALL
                .iter()
                .map(|check| [check.as_str()])
                .collect();
            let declared: Vec<&[&str]> = labels.iter().map(<[&str; 1]>::as_slice).collect();
            Ok(Self {
                counter: CounterVec::new(
                    format!("{product}_request_refusals_total"),
                    "Requests refused, by the check that failed.",
                    LabelSpace::closed_zero_filled(&["check"], &declared)?,
                )?,
                slots: Mutex::new([Slot::default(); FailedCheck::COUNT]),
            })
        }

        /// Count the refusal. Returns the line to write when the limiter
        /// admits one.
        #[must_use]
        pub fn record(&self, check: FailedCheck) -> Option<RefusalLine> {
            self.record_at(check, Instant::now())
        }

        pub(super) fn record_at(&self, check: FailedCheck, now: Instant) -> Option<RefusalLine> {
            let label = check.as_str();
            let counted = self.counter.inc(&[label]);
            // The slot state is plain counters, so a poisoned lock is safe to reuse.
            let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            let slot = &mut slots[check as usize];
            if counted.is_err() {
                // Labels come from the closed enum, so this is a defect. It is
                // reported once per window, not swallowed.
                if slot
                    .window_start
                    .is_none_or(|start| now.saturating_duration_since(start) >= REFUSAL_LOG_WINDOW)
                {
                    tracing::error!(
                        failed_check = label,
                        "a refusal was rejected by its closed label space"
                    );
                }
            }
            let expired = slot
                .window_start
                .is_none_or(|start| now.saturating_duration_since(start) >= REFUSAL_LOG_WINDOW);
            if expired {
                let suppressed = slot.suppressed;
                *slot = Slot {
                    window_start: Some(now),
                    written: 1,
                    suppressed: 0,
                };
                return Some(RefusalLine {
                    failed_check: label,
                    suppressed,
                });
            }
            if slot.written < REFUSAL_LOG_LINES_PER_WINDOW {
                slot.written += 1;
                return Some(RefusalLine {
                    failed_check: label,
                    suppressed: 0,
                });
            }
            slot.suppressed = slot.suppressed.saturating_add(1);
            None
        }

        /// For the product's exposition.
        pub fn counter(&self) -> &CounterVec {
            &self.counter
        }
    }

    /// Count a refusal and write the admitted line at the call site's own
    /// tracing target.
    ///
    /// The line carries `decision`, `failed_check`, `suppressed`, the note's
    /// code-defined `remedy` when it has one, and `trace_id` when one is
    /// given. The macro takes no other value. `trace_id` must be a
    /// [`RefusalTraceId`](crate::RefusalTraceId) or a reference to one, in
    /// practice the request's `registry_platform_httpsec::TraceId`, as in
    /// `record_refusal!(recorder, note, trace_id = &trace.trace_id)`. A raw
    /// header, client id or subject does not compile:
    ///
    /// ```compile_fail
    /// # use registry_platform_authcommon::{record_refusal, FailedCheck, RefusalNote, RefusalRecorder};
    /// let recorder = RefusalRecorder::new("doc").unwrap();
    /// let client_id = String::from("a value the caller sent");
    /// record_refusal!(recorder, RefusalNote::new(FailedCheck::Scope), trace_id = client_id);
    /// ```
    ///
    /// The caller's obligation: tracing formatters also print the fields of
    /// every span that encloses the event. Do not call this macro inside a
    /// span that records request values (a URI, query, header, client id or
    /// subject), or those values reach the refusal line through the span.
    #[macro_export]
    macro_rules! record_refusal {
        (@write $recorder:expr, $note:expr, $trace_id:expr) => {{
            let note: $crate::RefusalNote = $note;
            let trace_id: ::core::option::Option<&dyn $crate::RefusalTraceId> = $trace_id;
            if let Some(line) = $recorder.record(note.check) {
                let trace_id = trace_id.map($crate::__tracing::field::display);
                match note.remedy {
                    Some(remedy) => $crate::__tracing::info!(
                        decision = "refused",
                        failed_check = line.failed_check,
                        suppressed = line.suppressed,
                        remedy,
                        trace_id,
                        "request refused"
                    ),
                    None => $crate::__tracing::info!(
                        decision = "refused",
                        failed_check = line.failed_check,
                        suppressed = line.suppressed,
                        trace_id,
                        "request refused"
                    ),
                }
            }
        }};
        ($recorder:expr, $note:expr) => {
            $crate::record_refusal!(@write $recorder, $note, ::core::option::Option::None)
        };
        ($recorder:expr, $note:expr, trace_id = $trace_id:expr) => {{
            let typed: &dyn $crate::RefusalTraceId = &$trace_id;
            $crate::record_refusal!(@write $recorder, $note, ::core::option::Option::Some(typed))
        }};
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_set_is_closed_unique_and_in_declaration_order() {
        assert_eq!(FailedCheck::ALL.len(), 45);
        assert_eq!(FailedCheck::COUNT, 45);
        let mut seen = std::collections::HashSet::new();
        for (index, check) in FailedCheck::ALL.iter().enumerate() {
            assert_eq!(*check as usize, index);
            let label = check.as_str();
            assert!(seen.insert(label), "duplicate label {label}");
            assert!(
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && !label.contains("--")
                    && label.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "label {label} is not kebab-case"
            );
        }
    }

    #[test]
    fn the_members_labels_and_order_are_the_published_ones() {
        let published = [
            ("CredentialMissing", "credential-missing"),
            ("CredentialMalformed", "credential-malformed"),
            ("TokenAlgorithm", "token-algorithm"),
            ("TokenType", "token-type"),
            ("TokenKey", "token-key"),
            ("TokenSignature", "token-signature"),
            ("TokenIssuer", "token-issuer"),
            ("TokenAudience", "token-audience"),
            ("TokenTime", "token-time"),
            ("TokenClient", "token-client"),
            ("TokenAssertionIssuer", "token-assertion-issuer"),
            ("TokenClaims", "token-claims"),
            ("ActorKind", "actor-kind"),
            ("Delegation", "delegation"),
            ("SenderConstraint", "sender-constraint"),
            ("KeySourceUnavailable", "key-source-unavailable"),
            ("SharedSecret", "shared-secret"),
            ("OneTimeCredential", "one-time-credential"),
            ("DeliverySignature", "delivery-signature"),
            ("DeliveryFreshness", "delivery-freshness"),
            ("DeliveryBinding", "delivery-binding"),
            ("HostOrigin", "host-origin"),
            ("Scope", "scope"),
            ("AccessProfile", "access-profile"),
            ("RequesterClient", "requester-client"),
            ("Purpose", "purpose"),
            ("Operation", "operation"),
            ("Disclosure", "disclosure"),
            ("SubjectSelector", "subject-selector"),
            ("RevisionPin", "revision-pin"),
            ("AcquisitionChannel", "acquisition-channel"),
            ("SourceAuthority", "source-authority"),
            ("SeparationOfDuties", "separation-of-duties"),
            ("TaskGrantMissing", "task-grant-missing"),
            ("TaskGrantClaims", "task-grant-claims"),
            ("TaskGrantExpired", "task-grant-expired"),
            ("TaskGrantBinding", "task-grant-binding"),
            ("TaskGrantScope", "task-grant-scope"),
            ("TaskGrantLifetime", "task-grant-lifetime"),
            ("TaskGrantStatus", "task-grant-status"),
            ("RowBoundary", "row-boundary"),
            ("Ownership", "ownership"),
            ("Visibility", "visibility"),
            ("ActionGuard", "action-guard"),
            ("RateLimit", "rate-limit"),
        ];
        let actual: Vec<(String, &str)> = FailedCheck::ALL
            .iter()
            .map(|check| (format!("{check:?}"), check.as_str()))
            .collect();
        let expected: Vec<(String, &str)> = published
            .iter()
            .map(|(member, label)| ((*member).to_string(), *label))
            .collect();
        assert_eq!(actual, expected);
    }
}

#[cfg(all(test, feature = "refusal-recorder"))]
mod recorder_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use crate::record_refusal;
    use registry_platform_metrics::Exposition;

    /// A stand-in for `registry_platform_httpsec::TraceId`, which this crate
    /// does not depend on. httpsec's own tests pass its `TraceId` to the macro.
    struct ServerTraceId(&'static str);

    impl std::fmt::Display for ServerTraceId {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl crate::__refusal_trace_id_seal::Sealed for ServerTraceId {}
    impl crate::RefusalTraceId for ServerTraceId {}

    #[test]
    fn a_new_recorder_exposes_every_check_at_zero() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let mut out = Exposition::new();
        recorder.counter().write(&mut out).unwrap();
        let text = out.finish();
        assert!(text.contains("# TYPE breg_request_refusals_total counter"));
        for check in FailedCheck::ALL {
            let line = format!(
                "breg_request_refusals_total{{check=\"{}\"}} 0",
                check.as_str()
            );
            assert!(text.contains(&line), "missing {line}");
        }
        assert_eq!(
            text.lines().filter(|l| l.starts_with("breg_")).count(),
            FailedCheck::COUNT
        );
    }

    #[test]
    fn record_counts_the_right_series() {
        let recorder = RefusalRecorder::new("scheduling").unwrap();
        let _ = recorder.record(FailedCheck::Scope);
        let _ = recorder.record(FailedCheck::Scope);
        let _ = recorder.record(FailedCheck::TokenSignature);
        assert_eq!(recorder.counter().get(&["scope"]), Some(2));
        assert_eq!(recorder.counter().get(&["token-signature"]), Some(1));
        assert_eq!(recorder.counter().get(&["purpose"]), Some(0));
        assert_eq!(recorder.counter().refused(), 0);
    }

    #[test]
    fn a_flood_writes_five_lines_then_reports_the_rest() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let start = Instant::now();
        let mut lines = Vec::new();
        for _ in 0..10_000 {
            if let Some(line) = recorder.record_at(FailedCheck::TokenSignature, start) {
                lines.push(line);
            }
        }
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().all(|l| l.suppressed == 0));
        assert_eq!(lines[0].failed_check, "token-signature");
        assert_eq!(recorder.counter().get(&["token-signature"]), Some(10_000));
        let next = recorder
            .record_at(FailedCheck::TokenSignature, start + REFUSAL_LOG_WINDOW)
            .expect("the next window admits a line");
        assert_eq!(next.suppressed, 9_995);
        let after = recorder
            .record_at(FailedCheck::TokenSignature, start + REFUSAL_LOG_WINDOW)
            .expect("the new window admits more lines");
        assert_eq!(after.suppressed, 0);
    }

    #[test]
    fn members_do_not_share_a_budget() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let now = Instant::now();
        for _ in 0..1_000 {
            let _ = recorder.record_at(FailedCheck::TokenSignature, now);
        }
        for _ in 0..5 {
            assert!(recorder.record_at(FailedCheck::Scope, now).is_some());
        }
        assert!(recorder.record_at(FailedCheck::Scope, now).is_none());
    }

    #[test]
    fn a_poisoned_lock_still_counts_and_logs() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = recorder.slots.lock().unwrap();
            panic!("poison the lock");
        }));
        assert!(poisoned.is_err());
        assert!(recorder.record(FailedCheck::Scope).is_some());
        assert_eq!(recorder.counter().get(&["scope"]), Some(1));
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured(run: impl FnOnce()) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn every_member_is_counted_and_logged_under_its_own_label() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        for check in FailedCheck::ALL {
            let label = check.as_str();
            let output = captured(|| {
                record_refusal!(recorder, RefusalNote::new(check));
            });
            assert_eq!(output.lines().count(), 1, "{label}: {output}");
            assert!(
                output.contains(&format!("failed_check=\"{label}\"")),
                "{label}: {output}"
            );
            assert!(!output.contains("ERROR"), "{label}: {output}");
            assert_eq!(recorder.counter().get(&[label]), Some(1), "{label}");
        }
        assert_eq!(recorder.counter().refused(), 0);
    }

    #[test]
    fn a_caller_value_reaches_the_line_only_through_an_enclosing_span() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let canary = "canary-request-value-7f3a";

        // Outside a request span the line holds the fixed fields only.
        let output = captured(|| {
            record_refusal!(recorder, RefusalNote::new(FailedCheck::TokenAudience));
        });
        assert_eq!(output.lines().count(), 1, "{output}");
        assert!(output.contains("request refused"));
        assert!(output.contains("decision=\"refused\""));
        assert!(output.contains("failed_check=\"token-audience\""));
        assert!(output.contains("suppressed=0"));
        assert!(!output.contains("remedy"));
        assert!(!output.contains("trace_id"));
        assert!(!output.contains("canary"), "{output}");

        // The trace id is the only value the macro takes from a request. It
        // must be a `RefusalTraceId`, so a `&str` or `String` does not compile
        // (see the macro's `compile_fail` example). httpsec's tests show that
        // caller text cannot become its `TraceId`.
        let from_traceparent = ServerTraceId("4bf92f3577b34da6a3ce929d0e0e4736");
        let output = captured(|| {
            record_refusal!(
                recorder,
                RefusalNote::new(FailedCheck::TokenAudience),
                trace_id = from_traceparent
            );
        });
        assert!(output.contains("trace_id=4bf92f3577b34da6a3ce929d0e0e4736"));
        assert!(!output.contains("canary"), "{output}");

        // The documented rule: a span that records a request value prints it
        // on every event inside it, the refusal line included. The macro
        // cannot prevent this, so call sites must not record refusals there.
        let output = captured(|| {
            let span = tracing::info_span!("request", uri = canary);
            let _entered = span.enter();
            record_refusal!(recorder, RefusalNote::new(FailedCheck::TokenAudience));
        });
        assert_eq!(output.lines().count(), 1, "{output}");
        assert!(output.contains(canary), "{output}");
    }

    #[test]
    fn the_macro_carries_a_remedy_and_a_trace_id_when_given() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let trace_id = ServerTraceId("4bf92f3577b34da6a3ce929d0e0e4736");
        let output = captured(|| {
            let note = RefusalNote::new(FailedCheck::Scope).with_remedy("check readsScope");
            record_refusal!(recorder, note, trace_id = trace_id);
        });
        assert!(output.contains("remedy=\"check readsScope\""), "{output}");
        assert!(
            output.contains("trace_id=4bf92f3577b34da6a3ce929d0e0e4736"),
            "{output}"
        );

        let output = captured(|| {
            record_refusal!(
                recorder,
                RefusalNote::new(FailedCheck::Scope),
                trace_id = &trace_id
            );
            record_refusal!(
                recorder,
                RefusalNote::new(FailedCheck::Scope),
                trace_id = ServerTraceId("0af7651916cd43dd8448eb211c80319c")
            );
        });
        assert_eq!(output.lines().count(), 2, "{output}");
        assert!(!output.contains("remedy"), "{output}");
        assert!(output.contains("trace_id=0af7651916cd43dd8448eb211c80319c"));
    }

    #[test]
    fn the_macro_is_bounded() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let output = captured(|| {
            for _ in 0..100 {
                record_refusal!(recorder, RefusalNote::new(FailedCheck::Scope));
            }
        });
        assert_eq!(output.lines().count(), 5);
        let _ = Duration::ZERO;
    }
}
