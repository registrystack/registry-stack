//! Bounded diagnostic categories, independent of credential and configuration values.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use registry_platform_authcommon::FailedCheck;

use crate::OidcError;

/// Fixed verification stages suitable for operational logs.
#[derive(Clone, Copy, Debug)]
pub enum AuthenticationStage {
    Header,
    Algorithm,
    TokenType,
    Key,
    Signature,
    Issuer,
    Audience,
    Time,
    Client,
    Scope,
    Profile,
    Unavailable,
}

impl AuthenticationStage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Algorithm => "algorithm",
            Self::TokenType => "token-type",
            Self::Key => "key",
            Self::Signature => "signature",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Time => "time",
            Self::Client => "client",
            Self::Scope => "scope",
            Self::Profile => "profile",
            Self::Unavailable => "unavailable",
        }
    }
}

impl OidcError {
    /// Never format the underlying error to diagnose a public authentication failure.
    pub fn authentication_stage(&self) -> AuthenticationStage {
        match self {
            Self::MalformedToken | Self::InvalidToken => AuthenticationStage::Header,
            Self::AlgorithmNotAllowed => AuthenticationStage::Algorithm,
            Self::TokenTypeNotAllowed => AuthenticationStage::TokenType,
            Self::MissingKid | Self::KidTooLong | Self::UnknownKid => AuthenticationStage::Key,
            Self::SignatureInvalid => AuthenticationStage::Signature,
            Self::IssuerMismatch { .. } => AuthenticationStage::Issuer,
            Self::AudienceMismatch => AuthenticationStage::Audience,
            Self::TokenExpired | Self::TokenNotYetValid | Self::InvalidTimeClaims => {
                AuthenticationStage::Time
            }
            Self::ClientNotAllowed | Self::AssertionIssuerNotAllowed => AuthenticationStage::Client,
            Self::Transport(_)
            | Self::BoundedRead(_)
            | Self::FetchUrl(_)
            | Self::HttpStatus(_)
            | Self::InvalidUrl
            | Self::Parse
            | Self::InvalidJwk
            | Self::EmptyKeySet
            | Self::StaticKeySet(_)
            | Self::MissingIssuer
            | Self::ConflictingEndpointConfiguration
            | Self::InsecureHttpRequiresOptIn
            | Self::EndpointRefused { .. } => AuthenticationStage::Unavailable,
        }
    }
}

impl OidcError {
    /// The check a verification failure maps to. Never format the underlying
    /// error to diagnose a public authentication failure.
    pub fn failed_check(&self) -> FailedCheck {
        match self {
            Self::MalformedToken | Self::InvalidToken => FailedCheck::CredentialMalformed,
            Self::AlgorithmNotAllowed => FailedCheck::TokenAlgorithm,
            Self::TokenTypeNotAllowed => FailedCheck::TokenType,
            Self::MissingKid | Self::KidTooLong | Self::UnknownKid => FailedCheck::TokenKey,
            Self::SignatureInvalid => FailedCheck::TokenSignature,
            Self::IssuerMismatch { .. } => FailedCheck::TokenIssuer,
            Self::AudienceMismatch => FailedCheck::TokenAudience,
            Self::TokenExpired | Self::TokenNotYetValid | Self::InvalidTimeClaims => {
                FailedCheck::TokenTime
            }
            Self::ClientNotAllowed => FailedCheck::TokenClient,
            Self::AssertionIssuerNotAllowed => FailedCheck::TokenAssertionIssuer,
            Self::Transport(_)
            | Self::BoundedRead(_)
            | Self::FetchUrl(_)
            | Self::HttpStatus(_)
            | Self::InvalidUrl
            | Self::Parse
            | Self::InvalidJwk
            | Self::EmptyKeySet
            | Self::StaticKeySet(_)
            | Self::MissingIssuer
            | Self::ConflictingEndpointConfiguration
            | Self::InsecureHttpRequiresOptIn
            | Self::EndpointRefused { .. } => FailedCheck::KeySourceUnavailable,
        }
    }

    /// True when the verifier could not reach or use its key source.
    pub fn is_key_source_unavailable(&self) -> bool {
        self.failed_check() == FailedCheck::KeySourceUnavailable
    }
}

/// Log one value-free refusal at the call site's own tracing target, at most
/// once per stage per minute per verifier. `$message` is a literal naming the
/// product; the optional `remedy` is a fixed operator hint.
#[macro_export]
macro_rules! log_authentication_refusal {
    ($verifier:expr, $stage:expr, $message:literal $(, remedy = $remedy:expr)?) => {
        if let Some(stage) = $verifier.authentication_diagnostic($stage) {
            $crate::__tracing::info!(stage, $(remedy = $remedy,)? $message);
        }
    };
}

/// At most one diagnostic per fixed stage per minute, per verifier.
/// The fixed array cannot grow with attacker-controlled inputs.
#[derive(Debug, Default)]
pub struct AuthenticationDiagnostics {
    last: Mutex<[Option<Instant>; 12]>,
}

impl AuthenticationDiagnostics {
    pub fn admit(&self, stage: AuthenticationStage) -> bool {
        self.admit_at(stage, Instant::now())
    }

    fn admit_at(&self, stage: AuthenticationStage, now: Instant) -> bool {
        // The guarded state is plain timestamps, so a poisoned lock is safe to reuse.
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = &mut last[stage as usize];
        if slot.is_some_and(|previous| {
            now.saturating_duration_since(previous) < Duration::from_secs(60)
        }) {
            return false;
        }
        *slot = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_tokens_remain_header_failures() {
        assert_eq!(
            OidcError::MalformedToken.authentication_stage().label(),
            "header"
        );
        assert_eq!(
            OidcError::InvalidToken.authentication_stage().label(),
            "header"
        );
    }

    #[test]
    fn diagnostics_are_value_free_and_bounded_per_stage() {
        let error = OidcError::IssuerMismatch {
            expected: "canary-expected-issuer".into(),
            actual: "canary-actual-issuer".into(),
        };
        let stage = error.authentication_stage();
        assert_eq!(stage.label(), "issuer");
        assert!(!format!("{stage:?}").contains("canary"));
        let diagnostics = AuthenticationDiagnostics::default();
        let now = Instant::now();
        assert!(diagnostics.admit_at(stage, now));
        for _ in 0..1000 {
            assert!(!diagnostics.admit_at(stage, now));
        }
        assert!(diagnostics.admit_at(AuthenticationStage::Audience, now));
        assert!(diagnostics.admit_at(stage, now + Duration::from_secs(60)));
    }

    #[test]
    fn a_poisoned_lock_keeps_admitting_diagnostics() {
        let diagnostics = AuthenticationDiagnostics::default();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = diagnostics.last.lock().unwrap();
            panic!("poison the lock");
        }));
        assert!(poisoned.is_err());
        assert!(diagnostics.admit(AuthenticationStage::Header));
    }
}

#[cfg(test)]
mod failed_check_tests {
    use crate::OidcError;
    use registry_platform_authcommon::FailedCheck;

    #[test]
    fn issuer_mismatch_maps_without_the_issuers() {
        let error = OidcError::IssuerMismatch {
            expected: "canary-expected-issuer".into(),
            actual: "canary-actual-issuer".into(),
        };
        let check = error.failed_check();
        assert_eq!(check, FailedCheck::TokenIssuer);
        assert!(!format!("{check:?}{}", check.as_str()).contains("canary"));
    }

    #[test]
    fn key_source_failures_are_unavailable() {
        assert!(OidcError::EmptyKeySet.is_key_source_unavailable());
        assert!(OidcError::InvalidUrl.is_key_source_unavailable());
        assert!(!OidcError::SignatureInvalid.is_key_source_unavailable());
    }

    #[test]
    fn every_simple_variant_maps_to_its_member() {
        let table = [
            (OidcError::MalformedToken, FailedCheck::CredentialMalformed),
            (OidcError::InvalidToken, FailedCheck::CredentialMalformed),
            (OidcError::AlgorithmNotAllowed, FailedCheck::TokenAlgorithm),
            (OidcError::TokenTypeNotAllowed, FailedCheck::TokenType),
            (OidcError::MissingKid, FailedCheck::TokenKey),
            (OidcError::KidTooLong, FailedCheck::TokenKey),
            (OidcError::UnknownKid, FailedCheck::TokenKey),
            (OidcError::SignatureInvalid, FailedCheck::TokenSignature),
            (OidcError::AudienceMismatch, FailedCheck::TokenAudience),
            (OidcError::TokenExpired, FailedCheck::TokenTime),
            (OidcError::TokenNotYetValid, FailedCheck::TokenTime),
            (OidcError::InvalidTimeClaims, FailedCheck::TokenTime),
            (OidcError::ClientNotAllowed, FailedCheck::TokenClient),
            (
                OidcError::AssertionIssuerNotAllowed,
                FailedCheck::TokenAssertionIssuer,
            ),
            (OidcError::Parse, FailedCheck::KeySourceUnavailable),
            (OidcError::InvalidJwk, FailedCheck::KeySourceUnavailable),
            (OidcError::MissingIssuer, FailedCheck::KeySourceUnavailable),
            (
                OidcError::ConflictingEndpointConfiguration,
                FailedCheck::KeySourceUnavailable,
            ),
            (
                OidcError::InsecureHttpRequiresOptIn,
                FailedCheck::KeySourceUnavailable,
            ),
        ];
        for (error, expected) in table {
            assert_eq!(error.failed_check(), expected, "{error:?}");
        }
    }
}
