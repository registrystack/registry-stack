//! Bounded diagnostic categories, independent of credential and configuration values.

use registry_platform_authcommon::FailedCheck;

use crate::OidcError;

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
            Self::SubjectMismatch => FailedCheck::TokenClaims,
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

#[cfg(test)]
mod failed_check_tests {
    use crate::{OidcEndpoint, OidcError, StaticJwksError};
    use registry_platform_authcommon::FailedCheck;
    use registry_platform_httputil::{BoundedReadError, FetchUrlError};

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

    /// One row per `OidcError` variant: the reviewable spec of the mapping.
    /// A header the named key cannot serve is `AlgorithmNotAllowed`, a token
    /// fault; `InvalidJwk` is reserved for a key the source should not have
    /// published, a key-source fault.
    #[test]
    fn every_variant_maps_to_its_member() {
        let transport = reqwest::Client::new()
            .get("not a url")
            .build()
            .expect_err("an unparsable URL is a client error");
        let table = [
            (
                OidcError::Transport(transport),
                FailedCheck::KeySourceUnavailable,
            ),
            (
                OidcError::BoundedRead(BoundedReadError::LengthOverflow),
                FailedCheck::KeySourceUnavailable,
            ),
            (
                OidcError::FetchUrl(FetchUrlError::MissingHost),
                FailedCheck::KeySourceUnavailable,
            ),
            (
                OidcError::HttpStatus(503),
                FailedCheck::KeySourceUnavailable,
            ),
            (OidcError::InvalidUrl, FailedCheck::KeySourceUnavailable),
            (OidcError::Parse, FailedCheck::KeySourceUnavailable),
            (
                OidcError::IssuerMismatch {
                    expected: String::new(),
                    actual: String::new(),
                },
                FailedCheck::TokenIssuer,
            ),
            (OidcError::MalformedToken, FailedCheck::CredentialMalformed),
            (OidcError::AlgorithmNotAllowed, FailedCheck::TokenAlgorithm),
            (OidcError::TokenTypeNotAllowed, FailedCheck::TokenType),
            (OidcError::MissingKid, FailedCheck::TokenKey),
            (OidcError::KidTooLong, FailedCheck::TokenKey),
            (OidcError::UnknownKid, FailedCheck::TokenKey),
            (OidcError::InvalidJwk, FailedCheck::KeySourceUnavailable),
            (OidcError::EmptyKeySet, FailedCheck::KeySourceUnavailable),
            (
                OidcError::StaticKeySet(StaticJwksError::Empty),
                FailedCheck::KeySourceUnavailable,
            ),
            (OidcError::TokenExpired, FailedCheck::TokenTime),
            (OidcError::TokenNotYetValid, FailedCheck::TokenTime),
            (OidcError::AudienceMismatch, FailedCheck::TokenAudience),
            (OidcError::SubjectMismatch, FailedCheck::TokenClaims),
            (OidcError::SignatureInvalid, FailedCheck::TokenSignature),
            (OidcError::InvalidToken, FailedCheck::CredentialMalformed),
            (OidcError::InvalidTimeClaims, FailedCheck::TokenTime),
            (OidcError::ClientNotAllowed, FailedCheck::TokenClient),
            (
                OidcError::AssertionIssuerNotAllowed,
                FailedCheck::TokenAssertionIssuer,
            ),
            (OidcError::MissingIssuer, FailedCheck::KeySourceUnavailable),
            (
                OidcError::ConflictingEndpointConfiguration,
                FailedCheck::KeySourceUnavailable,
            ),
            (
                OidcError::InsecureHttpRequiresOptIn,
                FailedCheck::KeySourceUnavailable,
            ),
            (
                OidcError::EndpointRefused {
                    endpoint: OidcEndpoint::DeclaredJwks,
                    remedy: "a fixed remedy",
                },
                FailedCheck::KeySourceUnavailable,
            ),
        ];
        for (error, expected) in table {
            assert_eq!(error.failed_check(), expected, "{error:?}");
            assert_eq!(
                error.is_key_source_unavailable(),
                expected == FailedCheck::KeySourceUnavailable,
                "{error:?}"
            );
        }
    }
}
