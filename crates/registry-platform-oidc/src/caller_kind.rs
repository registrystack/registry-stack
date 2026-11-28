// SPDX-License-Identifier: Apache-2.0
//! The kind of caller a verified token stands for.
//!
//! An operator may declare the kind of an issuer's tokens, or of one client's,
//! and a token may carry the kind as a claim. [`caller_kind`] resolves the two
//! in a fixed order, and [`refuse_identity_only`] refuses a token that grants
//! nothing unless the operator declared its kind.

use std::collections::BTreeMap;

use crate::{actor_kind, ActorKind, ClaimError, ClaimMember, ClaimNames, Claims, OidcError};

/// The OpenID Connect scopes. They ask for claims about the person and grant
/// nothing, so a token that carries only these grants no scope.
pub const OPENID_CONNECT_SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];

/// The actor kind an operator declares for the tokens of one issuer entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeclaredKinds {
    /// No kind is declared.
    None,
    /// Every token from the issuer is this kind.
    Issuer(ActorKind),
    /// Tokens from each named client are that kind, keyed by client
    /// identifier.
    Clients(BTreeMap<String, ActorKind>),
}

/// How a verified token's caller kind was settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerKind {
    /// The operator declared it for the issuer or the client.
    Declared(ActorKind),
    /// The token carried it as a claim and the operator declared none.
    Claimed(ActorKind),
    /// Neither the operator nor the token said. A profile, route or grant that
    /// pins a kind refuses it.
    Unspecified,
}

impl CallerKind {
    /// The kind, or `None` when it is unspecified.
    #[must_use]
    pub const fn kind(&self) -> Option<ActorKind> {
        match self {
            Self::Declared(kind) | Self::Claimed(kind) => Some(*kind),
            Self::Unspecified => None,
        }
    }
}

/// Why a caller kind could not be settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CallerKindError {
    /// The token carries a kind that differs from the declared one.
    #[error("the token's actor kind contradicts the declared kind")]
    Conflict,
    /// The claim names or values are unusable.
    #[error(transparent)]
    Claim(ClaimError),
}

/// Settle the caller kind of a verified token.
///
/// The order is: the kind declared for `client`, else the one declared for the
/// issuer, else the kind claim, else unspecified. A token whose claim differs
/// from the declared kind is refused with [`CallerKindError::Conflict`], and a
/// malformed claim is refused even when a kind is declared, so a declaration
/// never hides a token that says something else. The claim is read as
/// [`actor_kind`] reads it.
pub fn caller_kind(
    declared: &DeclaredKinds,
    client: Option<&str>,
    claims: &Claims,
    names: &ClaimNames,
) -> Result<CallerKind, CallerKindError> {
    let claimed = match actor_kind(claims, names) {
        Ok(kind) => Some(kind),
        Err(ClaimError::Missing(ClaimMember::ActorKind)) => None,
        Err(error) => return Err(CallerKindError::Claim(error)),
    };
    let declared = match declared {
        DeclaredKinds::None => None,
        DeclaredKinds::Issuer(kind) => Some(*kind),
        DeclaredKinds::Clients(kinds) => client.and_then(|client| kinds.get(client)).copied(),
    };
    match (declared, claimed) {
        (Some(declared), Some(claimed)) if declared != claimed => Err(CallerKindError::Conflict),
        (Some(declared), _) => Ok(CallerKind::Declared(declared)),
        (None, Some(claimed)) => Ok(CallerKind::Claimed(claimed)),
        (None, None) => Ok(CallerKind::Unspecified),
    }
}

/// Refuse a token that is identity only: it grants no scope other than the
/// [`OPENID_CONNECT_SCOPES`], and the operator declared no kind for its client
/// or issuer. A kind the token claims does not admit it: the claim is token
/// content, not the operator's declaration.
pub fn refuse_identity_only(kind: &CallerKind, scopes: &[String]) -> Result<(), OidcError> {
    let grants = scopes
        .iter()
        .any(|scope| !OPENID_CONNECT_SCOPES.contains(&scope.as_str()));
    if grants || matches!(kind, CallerKind::Declared(_)) {
        Ok(())
    } else {
        Err(OidcError::IdentityOnly)
    }
}

#[cfg(test)]
#[path = "caller_kind_tests.rs"]
mod tests;
