// SPDX-License-Identifier: Apache-2.0
//! A set of issuers a resource server accepts tokens from.
//!
//! Each entry has its own verifier, keys, audience and rules. A token is
//! matched to one entry by its exact `iss` and verified only by that entry, so
//! a token that names one issuer and is signed with another's key fails at the
//! named entry.

use std::collections::BTreeMap;
use std::sync::Arc;

use jsonwebtoken::decode_header;
use registry_platform_authcommon::FailedCheck;
use reqwest::Url;

use crate::caller_kind::{caller_kind, refuse_identity_only, CallerKind, CallerKindError};
use crate::{
    issuer_claim, untrusted_payload, ClaimNames, DeclaredKinds, OidcError, TokenVerifier,
    VerifiedToken,
};

/// One issuer of an [`IssuerSet`].
#[derive(Debug)]
pub struct IssuerEntry {
    /// The issuer id the operator gave the entry.
    pub id: Arc<str>,
    verifier: TokenVerifier,
    declared: DeclaredKinds,
}

impl IssuerEntry {
    #[must_use]
    pub fn new(id: impl Into<Arc<str>>, verifier: TokenVerifier, declared: DeclaredKinds) -> Self {
        Self {
            id: id.into(),
            verifier,
            declared,
        }
    }

    /// The verifier of this entry.
    #[must_use]
    pub fn verifier(&self) -> &TokenVerifier {
        &self.verifier
    }
}

/// Why a set could not be built.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IssuerSetError {
    #[error("an issuer set needs at least one entry")]
    Empty,
    /// Two entries name one issuer. `first` and `second` are the entry ids.
    #[error("two issuer entries name one issuer")]
    DuplicateIss { first: String, second: String },
    /// The claim names the set reads the actor kind with are invalid.
    #[error("contextual authorization claim names are invalid")]
    InvalidClaimNames,
}

/// The issuers a resource server accepts tokens from.
#[derive(Debug)]
pub struct IssuerSet {
    entries: Vec<IssuerEntry>,
    by_iss: BTreeMap<String, usize>,
    names: ClaimNames,
}

/// Why [`IssuerSet::verify`] refused a token.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct CallerRefusal {
    /// The refusal. Its [`OidcError::failed_check`] is the check to count and
    /// log.
    pub error: OidcError,
    /// The sentence for the operator's log line that names the setting
    /// involved, from [`OidcError::remedy`]. It names keys, never values, and
    /// never enters a response body.
    pub remedy: Option<&'static str>,
}

impl CallerRefusal {
    fn new(error: OidcError, entry: Option<&IssuerEntry>) -> Self {
        let admits_jwt = entry.is_some_and(|entry| entry.verifier.admits_jwt_type());
        let remedy = error.remedy(admits_jwt);
        Self { error, remedy }
    }

    /// The check that refused the token.
    #[must_use]
    pub fn failed_check(&self) -> FailedCheck {
        self.error.failed_check()
    }
}

/// A token verified by one entry of an [`IssuerSet`].
#[derive(Clone, Debug)]
pub struct VerifiedCaller {
    /// The id of the entry that verified the token.
    pub issuer_id: Arc<str>,
    pub token: VerifiedToken,
    pub kind: CallerKind,
}

impl IssuerSet {
    /// Build the set. `names` are the claim names the actor kind is read
    /// with, checked here once. Two entries that name one issuer are refused,
    /// comparing the issuer as a parsed URL.
    pub fn new(entries: Vec<IssuerEntry>, names: ClaimNames) -> Result<Self, IssuerSetError> {
        if entries.is_empty() {
            return Err(IssuerSetError::Empty);
        }
        names
            .validate()
            .map_err(|_| IssuerSetError::InvalidClaimNames)?;
        let mut by_iss = BTreeMap::new();
        let mut normalized: BTreeMap<String, usize> = BTreeMap::new();
        for (entry, index) in entries.iter().zip(0_usize..) {
            let issuer = entry.verifier.issuer();
            let key = Url::parse(issuer)
                .map(String::from)
                .unwrap_or_else(|_| issuer.to_owned());
            if let Some(first) = normalized.insert(key, index) {
                return Err(IssuerSetError::DuplicateIss {
                    first: entries[first].id.to_string(),
                    second: entry.id.to_string(),
                });
            }
            by_iss.insert(issuer.to_owned(), index);
        }
        Ok(Self {
            entries,
            by_iss,
            names,
        })
    }

    /// The entries, in the order they were given.
    pub fn entries(&self) -> impl Iterator<Item = &IssuerEntry> {
        self.entries.iter()
    }

    /// Verify `token` with the entry its `iss` names, settle the caller kind,
    /// and refuse an identity-only token.
    ///
    /// A credential that is not three dot-separated segments with a readable
    /// header and a JSON object payload is [`OidcError::MalformedToken`]. An
    /// `iss` no entry names is [`OidcError::IssuerNotConfigured`], refused
    /// before any key is fetched. A kind claim that contradicts the declared
    /// kind is [`OidcError::ActorKindConflict`], and one that cannot be read is
    /// [`OidcError::ActorKindMalformed`]. Only `iss` is read before
    /// verification, so a wrongly typed claim elsewhere is refused by the
    /// entry's own checks.
    pub async fn verify(&self, token: &str) -> Result<VerifiedCaller, CallerRefusal> {
        let issuer = untrusted_issuer(token).map_err(|error| CallerRefusal::new(error, None))?;
        let entry = issuer
            .and_then(|issuer| self.by_iss.get(&issuer))
            .map(|index| &self.entries[*index])
            .ok_or_else(|| CallerRefusal::new(OidcError::IssuerNotConfigured, None))?;
        let refused = |error| CallerRefusal::new(error, Some(entry));
        let verified = entry.verifier.verify(token).await.map_err(refused)?;
        let client = match verified
            .matched_client_id()
            .map_err(|_| refused(OidcError::ClientNotAllowed))?
        {
            Some(client) => Some(client.to_owned()),
            None => verified
                .claims
                .azp
                .clone()
                .or_else(|| verified.claims.client_id.clone()),
        };
        let kind = caller_kind(
            &entry.declared,
            client.as_deref(),
            &verified.claims,
            &self.names,
        )
        .map_err(|error| {
            refused(match error {
                CallerKindError::Conflict => OidcError::ActorKindConflict,
                CallerKindError::Claim(_) => OidcError::ActorKindMalformed,
            })
        })?;
        refuse_identity_only(&kind, &verified.scopes).map_err(refused)?;
        Ok(VerifiedCaller {
            issuer_id: Arc::clone(&entry.id),
            token: verified,
            kind,
        })
    }
}

/// The `iss` of a credential shaped like a signed token, read before any key
/// work. `None` when the payload names no issuer as a non-empty string.
fn untrusted_issuer(token: &str) -> Result<Option<String>, OidcError> {
    if token.split('.').count() != 3 || decode_header(token).is_err() {
        return Err(OidcError::MalformedToken);
    }
    let claims = untrusted_payload(token).ok_or(OidcError::MalformedToken)?;
    Ok(issuer_claim(&claims))
}

#[cfg(test)]
#[path = "issuer_set_tests.rs"]
mod tests;
