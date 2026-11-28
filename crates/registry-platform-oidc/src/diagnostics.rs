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
            Self::TokenTypeNotAllowed | Self::IdTokenPresented => FailedCheck::TokenType,
            Self::MissingKid | Self::KidTooLong | Self::UnknownKid => FailedCheck::TokenKey,
            Self::SignatureInvalid => FailedCheck::TokenSignature,
            Self::IssuerMismatch { .. } | Self::IssuerNotConfigured => FailedCheck::TokenIssuer,
            Self::ActorKindConflict | Self::ActorKindMalformed | Self::IdentityOnly => {
                FailedCheck::ActorKind
            }
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

    /// The sentence for the operator's log line that names the issuer entry
    /// setting involved in a caller-contract refusal, or `None` for a refusal
    /// no setting changes. `admits_jwt` says whether the entry that refused
    /// admits access tokens typed `JWT`.
    ///
    /// A remedy names keys, never values. It belongs on the log line beside
    /// the failed check, never in a response body.
    #[must_use]
    pub fn remedy(&self, admits_jwt: bool) -> Option<&'static str> {
        match self {
            Self::TokenTypeNotAllowed if admits_jwt => Some(
                "The token's type is not the one accessTokenType names for this issuer entry. \
                 If the provider types its access tokens as RFC 9068 access tokens, remove \
                 accessTokenType from the entry so the default type applies.",
            ),
            Self::TokenTypeNotAllowed => Some(
                "The token's type is not one this issuer entry admits. If the provider types \
                 its access tokens as plain JWTs, set accessTokenType on the entry.",
            ),
            Self::IdTokenPresented => Some(
                "The token carries an ID token claim. Either the provider put an ID token \
                 claim in an access token, or the client sent an ID token as an access token. \
                 Configure the provider to leave ID token claims out of access tokens, or send \
                 the access token.",
            ),
            Self::IssuerNotConfigured => Some(
                "No issuer entry names the token's issuer. Add an entry under issuers whose \
                 issuer is exactly the token's issuer.",
            ),
            Self::ActorKindConflict => Some(
                "The token's actor kind claim differs from the kind declared in actorKind or \
                 clientActorKinds. Correct the declaration or the provider's claim.",
            ),
            Self::ActorKindMalformed => Some(
                "The token's actor kind claim is not a kind this service reads. Have the \
                 provider write a kind this service reads, or leave the claim out and declare \
                 the kind in clientActorKinds or actorKind.",
            ),
            Self::IdentityOnly => Some(
                "The token grants no scope and its kind is not declared. Declare the client's \
                 kind in clientActorKinds, or the issuer's in actorKind, or have the provider \
                 grant a scope.",
            ),
            _ => None,
        }
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
            (OidcError::IssuerNotConfigured, FailedCheck::TokenIssuer),
            (OidcError::IdTokenPresented, FailedCheck::TokenType),
            (OidcError::ActorKindConflict, FailedCheck::ActorKind),
            (OidcError::ActorKindMalformed, FailedCheck::ActorKind),
            (OidcError::IdentityOnly, FailedCheck::ActorKind),
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

    fn remedies(admits_jwt: bool) -> Vec<(OidcError, &'static str)> {
        [
            OidcError::TokenTypeNotAllowed,
            OidcError::IdTokenPresented,
            OidcError::IssuerNotConfigured,
            OidcError::ActorKindConflict,
            OidcError::ActorKindMalformed,
            OidcError::IdentityOnly,
        ]
        .into_iter()
        .map(|error| {
            let remedy = error
                .remedy(admits_jwt)
                .unwrap_or_else(|| panic!("{error:?} has a remedy"));
            (error, remedy)
        })
        .collect()
    }

    #[test]
    fn each_caller_contract_refusal_names_the_key_that_changes_it() {
        for admits_jwt in [false, true] {
            for (error, remedy) in remedies(admits_jwt) {
                let keys: &[&str] = match error {
                    OidcError::TokenTypeNotAllowed => &["accessTokenType"],
                    OidcError::IssuerNotConfigured => &["issuers", "issuer"],
                    OidcError::ActorKindConflict
                    | OidcError::ActorKindMalformed
                    | OidcError::IdentityOnly => &["actorKind", "clientActorKinds"],
                    _ => &[],
                };
                for key in keys {
                    assert!(remedy.contains(key), "{error:?}: {remedy}");
                }
            }
        }
    }

    #[test]
    fn a_remedy_names_keys_and_never_a_setting_value() {
        for admits_jwt in [false, true] {
            for (error, remedy) in remedies(admits_jwt) {
                for value in [
                    ": ",
                    "at+jwt",
                    "JWT ",
                    "JWT.",
                    "unrestricted",
                    "human",
                    "agent",
                    "\u{2014}",
                ] {
                    assert!(
                        !remedy.contains(value),
                        "{error:?} holds {value:?}: {remedy}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_token_type_remedy_follows_the_entry_s_type() {
        let at_jwt = OidcError::TokenTypeNotAllowed.remedy(false).unwrap();
        let jwt = OidcError::TokenTypeNotAllowed.remedy(true).unwrap();
        assert_ne!(at_jwt, jwt);
        assert!(at_jwt.contains("set accessTokenType"), "{at_jwt}");
        assert!(jwt.contains("remove accessTokenType"), "{jwt}");
    }

    #[test]
    fn the_id_token_remedy_names_both_causes() {
        let remedy = OidcError::IdTokenPresented.remedy(true).unwrap();
        assert!(
            remedy.contains("provider put an ID token claim in an access token"),
            "{remedy}"
        );
        assert!(
            remedy.contains("sent an ID token as an access token"),
            "{remedy}"
        );
    }

    #[test]
    fn a_refusal_no_setting_changes_has_no_remedy() {
        for error in [
            OidcError::MalformedToken,
            OidcError::SignatureInvalid,
            OidcError::TokenExpired,
            OidcError::AudienceMismatch,
            OidcError::ClientNotAllowed,
            OidcError::UnknownKid,
        ] {
            assert_eq!(error.remedy(true), None, "{error:?}");
            assert_eq!(error.remedy(false), None, "{error:?}");
        }
    }
}
