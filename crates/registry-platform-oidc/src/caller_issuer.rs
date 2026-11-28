// SPDX-License-Identifier: Apache-2.0
//! From a configured issuer entry to the verifier settings and declared kinds
//! of an [`IssuerEntry`](crate::IssuerEntry).
//!
//! A product reads its issuer set into [`CallerIssuerCore`] values. The
//! functions here turn the shared members of one entry into what the verifier
//! needs: the access-token type set, the scope claim, the admitted clients and
//! the declared actor kinds. The product adds its own members, such as its key
//! source, algorithms and token lifetime.

use jsonwebtoken::Algorithm;
use registry_platform_config::{
    AccessTokenType, Admitted, AdmittedClients, CallerIssuerCore, ClientRule, DeclaredActorKind,
};

use crate::{access_token_typ_set, ActorKind, DeclaredKinds, TokenVerifierConfig};

impl From<DeclaredActorKind> for ActorKind {
    fn from(kind: DeclaredActorKind) -> Self {
        match kind {
            DeclaredActorKind::Human => Self::Human,
            DeclaredActorKind::Agent => Self::Agent,
            DeclaredActorKind::Service => Self::Service,
        }
    }
}

/// The `typ` header values an entry's `accessTokenType` admits: both RFC 9068
/// spellings for `at+jwt`, and `JWT` alone for `JWT`.
#[must_use]
pub fn access_token_types(access_token_type: AccessTokenType) -> Vec<String> {
    match access_token_type {
        AccessTokenType::AtJwt => access_token_typ_set("at+jwt"),
        AccessTokenType::Jwt => vec!["JWT".to_owned()],
    }
}

/// An entry declares an actor kind for its issuer and for its clients
/// together. [`CallerIssuers::check`](registry_platform_config::CallerIssuers::check)
/// reports it as `platform.oidc.actor-kind-twice`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("actorKind and clientActorKinds are both written")]
pub struct ActorKindTwice;

/// An entry reads its clients from the package or from the policies, and no
/// resolved list was given.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("allowedClients names no list: pass the clients resolved from the package or the policies")]
pub struct UnresolvedClients;

impl DeclaredKinds {
    /// The kinds an entry declares through `actorKind` or `clientActorKinds`.
    pub fn from_core<C>(core: &CallerIssuerCore<C>) -> Result<Self, ActorKindTwice> {
        match (&core.actor_kind, &core.client_actor_kinds) {
            (Some(_), Some(_)) => Err(ActorKindTwice),
            (Some(kind), None) => Ok(Self::Issuer(kind.get().0.into())),
            (None, Some(kinds)) => Ok(Self::Clients(
                kinds
                    .get()
                    .0
                    .iter()
                    .map(|(client, kind)| (client.as_str().to_owned(), (*kind).into()))
                    .collect(),
            )),
            (None, None) => Ok(Self::None),
        }
    }
}

impl TokenVerifierConfig {
    /// The access-token profile of one issuer entry: its issuer, audience,
    /// token type set, scope claim and admitted clients.
    ///
    /// `resolved_clients` is the list a product resolved for an entry whose
    /// clients come from the package or the policies. When given, it is the
    /// admitted list for any entry. Without it, a listed entry admits its list,
    /// an unrestricted entry admits every client, and an entry that reads its
    /// clients from the package or the policies is refused.
    pub fn for_caller_issuer<C: ClientRule>(
        core: &CallerIssuerCore<C>,
        allowed_algorithms: Vec<Algorithm>,
        resolved_clients: Option<&AdmittedClients>,
    ) -> Result<Self, UnresolvedClients> {
        let clients = match (resolved_clients, core.allowed_clients.admitted()) {
            (Some(resolved), _) => resolved.as_slice().to_vec(),
            (None, Admitted::Listed(listed)) => listed.to_vec(),
            (None, Admitted::Unrestricted) => Vec::new(),
            (None, Admitted::FromPackage | Admitted::FromPolicies) => {
                return Err(UnresolvedClients)
            }
        };
        Ok(Self::access_token_profile(
            core.provider.issuer.as_str(),
            vec![core.provider.audience.clone()],
            allowed_algorithms,
            access_token_types(*core.access_token_type.get()),
        )
        .with_scope_claim(core.scope_claim.get().as_str())
        .with_allowed_clients(clients))
    }
}

#[cfg(test)]
#[path = "caller_issuer_tests.rs"]
mod tests;
