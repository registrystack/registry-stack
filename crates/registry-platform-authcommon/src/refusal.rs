//! The closed set of checks a request can fail, and the recorder that counts
//! and logs a refusal by its check.
//!
//! The check is operator-side only. It is never written to a response body.

/// The check a request failed. Closed. Operator-side only: never written to a
/// response.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailedCheck {
    /// No credential, or not the scheme the route takes.
    CredentialMissing,
    /// Credential header repeated or unreadable, or the credential is not in the expected shape.
    CredentialMalformed,
    /// Signing algorithm not allowed.
    TokenAlgorithm,
    /// Token type not allowed.
    TokenType,
    /// Key id missing, too long or unknown.
    TokenKey,
    /// Signature does not verify.
    TokenSignature,
    /// Issuer is not the configured one.
    TokenIssuer,
    /// Audience does not include this service.
    TokenAudience,
    /// Expired, not yet valid, or time claims unusable.
    TokenTime,
    /// Client not on the verifier's allow list, or the matched client is unusable.
    TokenClient,
    /// An exchanged token whose assertion issuer is not allowed or not declared.
    TokenAssertionIssuer,
    /// A required identity claim is missing or malformed (principal, subject, issuer, expiry).
    TokenClaims,
    /// Actor kind claim missing, malformed, or not the kind the route or profile takes.
    ActorKind,
    /// A delegated actor is present where none is allowed, or is not the trusted one.
    Delegation,
    /// The token is sender-constrained and the service does not accept that.
    SenderConstraint,
    /// The verifier could not reach or use its key source.
    KeySourceUnavailable,
    /// A static secret, API key, Basic pair or path token does not match.
    SharedSecret,
    /// A single-use code or token is unknown, expired, already used or locked out.
    OneTimeCredential,
    /// A signed delivery or provider callback has a missing, malformed, unsupported or wrong signature.
    DeliverySignature,
    /// A signed delivery time is outside the receiver's window.
    DeliveryFreshness,
    /// A signed delivery's source, type, schema, route or target is not what the receiver expects.
    DeliveryBinding,
    /// The request's host or origin is not accepted.
    HostOrigin,
    /// A required scope is missing.
    Scope,
    /// No access profile, policy or authority entry admits this caller on this surface.
    AccessProfile,
    /// The profile or resource does not admit this requester client.
    RequesterClient,
    /// The declared purpose is missing or not admitted.
    Purpose,
    /// The caller's profile or policy does not allow this operation, action, workflow, template or record type.
    Operation,
    /// The request asks for fields or a response format beyond what the caller's profile discloses.
    Disclosure,
    /// The subject selector is not one the caller's grant or authority covers.
    SubjectSelector,
    /// The caller pinned a configuration revision that is not the deployed one.
    RevisionPin,
    /// The acquisition channel is not open to the resolved profile.
    AcquisitionChannel,
    /// The source or target authority refused the access.
    SourceAuthority,
    /// The caller already acted in a role that excludes this one.
    SeparationOfDuties,
    /// The operation needs a task grant and none was presented.
    TaskGrantMissing,
    /// The task grant is partial or malformed.
    TaskGrantClaims,
    /// The task grant has expired.
    TaskGrantExpired,
    /// The task grant is bound to another client, audience, principal, issuer or task.
    TaskGrantBinding,
    /// The task grant does not cover this service, location, action or operation.
    TaskGrantScope,
    /// The task grant has more lifetime, or more lifetime left, than the receiver accepts.
    TaskGrantLifetime,
    /// The status authority says the grant is inactive, or its source is not listed.
    TaskGrantStatus,
    /// The target row is outside the caller's row boundary.
    RowBoundary,
    /// The target exists and belongs to another caller.
    Ownership,
    /// The target is absent or not visible to the caller, and the product does not tell which.
    Visibility,
    /// A BReg Action guard refused. Operator-side only, so an answer never tells a guard from a boundary.
    ActionGuard,
    /// An identity-keyed or route-keyed request budget is spent.
    RateLimit,
}

impl FailedCheck {
    /// Every member, in declaration order.
    pub const ALL: [Self; 45] = [
        Self::CredentialMissing,
        Self::CredentialMalformed,
        Self::TokenAlgorithm,
        Self::TokenType,
        Self::TokenKey,
        Self::TokenSignature,
        Self::TokenIssuer,
        Self::TokenAudience,
        Self::TokenTime,
        Self::TokenClient,
        Self::TokenAssertionIssuer,
        Self::TokenClaims,
        Self::ActorKind,
        Self::Delegation,
        Self::SenderConstraint,
        Self::KeySourceUnavailable,
        Self::SharedSecret,
        Self::OneTimeCredential,
        Self::DeliverySignature,
        Self::DeliveryFreshness,
        Self::DeliveryBinding,
        Self::HostOrigin,
        Self::Scope,
        Self::AccessProfile,
        Self::RequesterClient,
        Self::Purpose,
        Self::Operation,
        Self::Disclosure,
        Self::SubjectSelector,
        Self::RevisionPin,
        Self::AcquisitionChannel,
        Self::SourceAuthority,
        Self::SeparationOfDuties,
        Self::TaskGrantMissing,
        Self::TaskGrantClaims,
        Self::TaskGrantExpired,
        Self::TaskGrantBinding,
        Self::TaskGrantScope,
        Self::TaskGrantLifetime,
        Self::TaskGrantStatus,
        Self::RowBoundary,
        Self::Ownership,
        Self::Visibility,
        Self::ActionGuard,
        Self::RateLimit,
    ];

    /// The number of members.
    pub const COUNT: usize = Self::ALL.len();

    /// Stable kebab-case label for the counter and the log line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialMissing => "credential-missing",
            Self::CredentialMalformed => "credential-malformed",
            Self::TokenAlgorithm => "token-algorithm",
            Self::TokenType => "token-type",
            Self::TokenKey => "token-key",
            Self::TokenSignature => "token-signature",
            Self::TokenIssuer => "token-issuer",
            Self::TokenAudience => "token-audience",
            Self::TokenTime => "token-time",
            Self::TokenClient => "token-client",
            Self::TokenAssertionIssuer => "token-assertion-issuer",
            Self::TokenClaims => "token-claims",
            Self::ActorKind => "actor-kind",
            Self::Delegation => "delegation",
            Self::SenderConstraint => "sender-constraint",
            Self::KeySourceUnavailable => "key-source-unavailable",
            Self::SharedSecret => "shared-secret",
            Self::OneTimeCredential => "one-time-credential",
            Self::DeliverySignature => "delivery-signature",
            Self::DeliveryFreshness => "delivery-freshness",
            Self::DeliveryBinding => "delivery-binding",
            Self::HostOrigin => "host-origin",
            Self::Scope => "scope",
            Self::AccessProfile => "access-profile",
            Self::RequesterClient => "requester-client",
            Self::Purpose => "purpose",
            Self::Operation => "operation",
            Self::Disclosure => "disclosure",
            Self::SubjectSelector => "subject-selector",
            Self::RevisionPin => "revision-pin",
            Self::AcquisitionChannel => "acquisition-channel",
            Self::SourceAuthority => "source-authority",
            Self::SeparationOfDuties => "separation-of-duties",
            Self::TaskGrantMissing => "task-grant-missing",
            Self::TaskGrantClaims => "task-grant-claims",
            Self::TaskGrantExpired => "task-grant-expired",
            Self::TaskGrantBinding => "task-grant-binding",
            Self::TaskGrantScope => "task-grant-scope",
            Self::TaskGrantLifetime => "task-grant-lifetime",
            Self::TaskGrantStatus => "task-grant-status",
            Self::RowBoundary => "row-boundary",
            Self::Ownership => "ownership",
            Self::Visibility => "visibility",
            Self::ActionGuard => "action-guard",
            Self::RateLimit => "rate-limit",
        }
    }
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
    /// tracing target. The line names the check and nothing a caller sent.
    #[macro_export]
    macro_rules! record_refusal {
        ($recorder:expr, $note:expr $(, trace_id = $trace_id:expr)?) => {{
            let note: $crate::RefusalNote = $note;
            if let Some(line) = $recorder.record(note.check) {
                match note.remedy {
                    Some(remedy) => $crate::__tracing::info!(
                        decision = "refused",
                        failed_check = line.failed_check,
                        suppressed = line.suppressed,
                        remedy
                        $(, trace_id = %$trace_id)?,
                        "request refused"
                    ),
                    None => $crate::__tracing::info!(
                        decision = "refused",
                        failed_check = line.failed_check,
                        suppressed = line.suppressed
                        $(, trace_id = %$trace_id)?,
                        "request refused"
                    ),
                }
            }
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
}

#[cfg(all(test, feature = "refusal-recorder"))]
mod recorder_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use crate::record_refusal;
    use registry_platform_metrics::Exposition;

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
    fn the_macro_writes_one_fixed_line_with_the_member_only() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let canary = String::from("canary-token-value-7f3a");
        let output = captured(|| {
            // The caller-supplied string is in scope but is not an argument.
            let note = RefusalNote::new(FailedCheck::TokenAudience);
            let _unused = &canary;
            record_refusal!(recorder, note);
        });
        assert_eq!(output.lines().count(), 1, "{output}");
        assert!(output.contains("request refused"));
        assert!(output.contains("decision=\"refused\""));
        assert!(output.contains("failed_check=\"token-audience\""));
        assert!(output.contains("suppressed=0"));
        assert!(!output.contains("remedy"));
        assert!(!output.contains("canary"));
    }

    #[test]
    fn the_macro_carries_a_remedy_and_a_trace_id_when_given() {
        let recorder = RefusalRecorder::new("breg").unwrap();
        let output = captured(|| {
            let note = RefusalNote::new(FailedCheck::Scope).with_remedy("check readsScope");
            record_refusal!(recorder, note, trace_id = "01TRACE");
        });
        assert!(output.contains("remedy=\"check readsScope\""), "{output}");
        assert!(output.contains("trace_id=01TRACE"), "{output}");
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
