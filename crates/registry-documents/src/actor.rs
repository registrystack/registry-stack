// SPDX-License-Identifier: Apache-2.0

//! The caller a document request acts for.
//!
//! Every document handler reads its caller through one seam, [`ActorSource`],
//! so the provenance a version records and the authority a read checks come
//! from one place. The production listener serves no document route: no
//! source of verified actors is wired into it until token verification is.

use axum::http::HeaderMap;

/// Whether the caller is a registered service or a signed-in person.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKind {
    Service,
    Human,
}

impl ActorKind {
    /// The spelling the version provenance stores.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Human => "human",
        }
    }
}

/// One authenticated caller, as a version's provenance records it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Actor {
    pub issuer: String,
    pub subject: String,
    pub kind: ActorKind,
    pub client_id: String,
    pub access_profile_id: String,
    /// The institution the caller's access profile acts for. It is never
    /// taken from a request body.
    pub issuing_institution: String,
}

impl Actor {
    /// Whether every provenance member is present. A version's provenance
    /// columns refuse an empty value, so an incomplete actor is refused
    /// before any write.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        [
            &self.issuer,
            &self.subject,
            &self.client_id,
            &self.access_profile_id,
            &self.issuing_institution,
        ]
        .iter()
        .all(|value| !value.is_empty())
    }
}

/// Where a document handler reads its caller from. `None` refuses the
/// request as not found, so an unauthenticated caller learns nothing about
/// which documents exist.
pub trait ActorSource: Send + Sync + 'static {
    fn actor(&self, headers: &HeaderMap) -> Option<Actor>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> Actor {
        Actor {
            issuer: "https://identity.example.test".to_owned(),
            subject: "custodian-app".to_owned(),
            kind: ActorKind::Service,
            client_id: "civil-registry-app".to_owned(),
            access_profile_id: "custodian-app".to_owned(),
            issuing_institution: "civil-registry".to_owned(),
        }
    }

    #[test]
    fn an_actor_with_an_empty_member_is_incomplete() {
        assert!(actor().is_complete());
        let mut missing = actor();
        missing.issuing_institution.clear();
        assert!(!missing.is_complete());
    }

    #[test]
    fn actor_kinds_are_spelled_as_stored() {
        assert_eq!(ActorKind::Service.as_str(), "service");
        assert_eq!(ActorKind::Human.as_str(), "human");
    }
}
