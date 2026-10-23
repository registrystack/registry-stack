// SPDX-License-Identifier: Apache-2.0

//! Access: who a verified token is, and what that caller may do to one
//! document.
//!
//! Every decision here is pure. The runtime verifies the token's signature,
//! issuer, audience, lifetime, and client, then hands the verified facts to
//! [`AccessProfiles::resolve`], which names exactly one access profile and
//! one principal or refuses. What the resolved caller may do to a document
//! is then decided against the document's frozen custody and policy, never
//! against raw claims or a request body.

use std::collections::{BTreeMap, BTreeSet};

use registry_platform_yaml::{ExternalId, LocalId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::custody::DocumentStatus;
use crate::problem::ProblemCode;
use crate::project::{
    AccessProfile, AccessRole, ActorKind, CustodianRule, DocumentPolicy, DocumentsProject,
    RepresentedPrincipalGrants,
};

/// The access profiles of a project, indexed by requester client.
///
/// The project reader already refuses a client listed by two profiles, so a
/// token never has to choose between two authorities.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessProfiles {
    profiles: BTreeMap<LocalId, AccessProfile>,
    by_client: BTreeMap<String, LocalId>,
}

impl AccessProfiles {
    #[must_use]
    pub fn new(project: &DocumentsProject) -> Self {
        let mut by_client = BTreeMap::new();
        for (id, profile) in &project.access_profiles {
            for client in profile.requester_clients.as_slice() {
                by_client
                    .entry(client.as_str().to_owned())
                    .or_insert_with(|| id.clone());
            }
        }
        Self {
            profiles: project.access_profiles.clone(),
            by_client,
        }
    }

    fn profile_for(&self, client_id: Option<&str>) -> Option<(&LocalId, &AccessProfile)> {
        let id = self.by_client.get(client_id?)?;
        self.profiles.get_key_value(id)
    }

    /// Resolve verified token facts to exactly one profile and principal.
    pub fn resolve(&self, token: &VerifiedTokenFacts<'_>) -> Result<Caller, AccessRefusal> {
        let (profile_id, profile) = self
            .profile_for(token.client_id)
            .ok_or(AccessRefusal::Profile)?;
        if first_missing_scope(profile, token).is_some() {
            return Err(AccessRefusal::Profile);
        }
        // A malformed actor-kind claim is a malformed credential whatever the
        // profile demands. Every profile names a kind, so an absent claim, or
        // a kind no profile admits, is a profile refusal.
        let kind = match token.actor_kind {
            ActorKindClaim::Malformed => return Err(AccessRefusal::Claims),
            ActorKindClaim::Absent | ActorKindClaim::Unadmitted => {
                return Err(AccessRefusal::Profile)
            }
            ActorKindClaim::Present(kind) => kind,
        };
        if kind != profile.actor_kind {
            return Err(AccessRefusal::Profile);
        }
        let principal = if profile.principal_claim.as_str() == "sub" {
            token.subject
        } else {
            token
                .claims
                .get(profile.principal_claim.as_str())
                .and_then(Value::as_str)
        }
        .filter(|value| !value.is_empty())
        .ok_or(AccessRefusal::Claims)?;
        let issuer = token
            .issuer
            .filter(|issuer| !issuer.is_empty())
            .ok_or(AccessRefusal::Claims)?;
        let client_id = token.client_id.ok_or(AccessRefusal::Profile)?;
        Ok(Caller {
            issuer: issuer.to_owned(),
            subject: principal.to_owned(),
            kind,
            client_id: client_id.to_owned(),
            profile_id: profile_id.clone(),
            role: profile.role,
            institution: profile.institution.clone(),
        })
    }

    /// The first scope the token's client profile requires and the token
    /// does not carry. Both values come from the deployment's configuration,
    /// never from the token, so a refusal log may name them.
    #[must_use]
    pub fn missing_scope(&self, token: &VerifiedTokenFacts<'_>) -> Option<MissingScope<'_>> {
        let (id, profile) = self.profile_for(token.client_id)?;
        first_missing_scope(profile, token).map(|scope| MissingScope {
            profile: id.as_str(),
            scope,
        })
    }
}

/// A scope an access profile requires that a verified token lacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissingScope<'a> {
    pub profile: &'a str,
    pub scope: &'a str,
}

fn first_missing_scope<'a>(
    profile: &'a AccessProfile,
    token: &VerifiedTokenFacts<'_>,
) -> Option<&'a str> {
    let scopes: BTreeSet<&str> = token.scopes.iter().map(String::as_str).collect();
    profile
        .required_scopes
        .as_slice()
        .iter()
        .map(ExternalId::as_str)
        .find(|scope| !scopes.contains(scope))
}

/// The actor-kind claim as the verified token carries it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKindClaim {
    Absent,
    Malformed,
    /// A well-formed kind no Document Store profile admits.
    Unadmitted,
    Present(ActorKind),
}

/// The facts of a token whose signature, issuer, audience, lifetime, and
/// client the runtime has already verified.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedTokenFacts<'a> {
    pub issuer: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub scopes: &'a [String],
    pub actor_kind: ActorKindClaim,
    /// Every claim beyond the registered ones, for a non-`sub` principal.
    pub claims: &'a Map<String, Value>,
}

/// A caller resolved to one access profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Caller {
    pub issuer: String,
    pub subject: String,
    pub kind: ActorKind,
    pub client_id: String,
    pub profile_id: LocalId,
    pub role: AccessRole,
    /// The institution the caller's profile acts for, never a request value.
    pub institution: Option<ExternalId>,
}

/// Why a verified token resolved to no profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRefusal {
    /// No profile authorizes this client, scope set, or actor kind.
    Profile,
    /// The token's identity claims are missing or malformed.
    Claims,
}

impl AccessRefusal {
    #[must_use]
    pub const fn problem(self) -> ProblemCode {
        match self {
            Self::Profile => ProblemCode::ProfileNotAuthorized,
            Self::Claims => ProblemCode::AuthenticationRefused,
        }
    }
}

/// Whom a document is held for: a principal at the token issuer, with its
/// actor kind, and the represented principal when custody is held on a
/// person's behalf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Custody {
    pub issuer: String,
    pub subject: String,
    pub kind: ActorKind,
    pub represented_principal: Option<String>,
}

/// What a reservation asks about custody.
#[derive(Clone, Copy, Debug)]
pub struct CustodyAsk<'a> {
    /// The custodian subject the body names.
    pub subject: &'a str,
    /// The issuing institution the body names, if any. It may only repeat
    /// the caller's profile institution.
    pub issuing_institution: Option<&'a str>,
}

/// Decide the custody a reservation places a document in.
///
/// The caller's profile must be one of the policy's custody profiles. A
/// human may place a document only in its own custody; a service may name
/// any subject at its own issuer, and a subject other than its own is the
/// person the document is held for. Under [`CustodianRule::Institution`]
/// custody stays with the service and that person is recorded only as the
/// represented principal; under [`CustodianRule::RepresentedPrincipal`]
/// that person is the custodian. A body that
/// names an issuing institution other than the profile's is refused: the
/// institution is the profile's, never the request's.
pub fn place_custody(
    policy: &DocumentPolicy,
    caller: &Caller,
    ask: CustodyAsk<'_>,
) -> Result<Custody, ProblemCode> {
    if !policy.custody_profiles.contains(&caller.profile_id) {
        return Err(ProblemCode::CustodyNotPermitted);
    }
    if let Some(named) = ask.issuing_institution {
        if caller.institution.as_ref().map(ExternalId::as_str) != Some(named) {
            return Err(ProblemCode::CustodyNotPermitted);
        }
    }
    let own = ask.subject == caller.subject;
    let represented =
        (caller.role == AccessRole::RepresentedPrincipal).then(|| caller.subject.clone());
    match (caller.kind, own) {
        (ActorKind::Human, false) => Err(ProblemCode::CustodyNotPermitted),
        (_, true) => Ok(Custody {
            issuer: caller.issuer.clone(),
            subject: caller.subject.clone(),
            kind: caller.kind,
            represented_principal: represented,
        }),
        (ActorKind::Service, false) => Ok(match policy.custodian {
            CustodianRule::Institution => Custody {
                issuer: caller.issuer.clone(),
                subject: caller.subject.clone(),
                kind: caller.kind,
                represented_principal: Some(ask.subject.to_owned()),
            },
            CustodianRule::RepresentedPrincipal => Custody {
                issuer: caller.issuer.clone(),
                subject: ask.subject.to_owned(),
                kind: ActorKind::Human,
                represented_principal: Some(ask.subject.to_owned()),
            },
        }),
    }
}

/// The principal that reserved a document version.
#[derive(Clone, Copy, Debug)]
pub struct Reserver<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub kind: ActorKind,
}

/// What one caller is to one document.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Standing {
    /// The caller holds the document in custody.
    pub custodian: bool,
    /// The caller reserved the document under a custody profile for another
    /// custodian. It reads metadata and status, but neither grants nor is
    /// released content.
    pub owner: bool,
    /// The caller may issue and revoke document grants.
    pub may_grant: bool,
}

impl Standing {
    /// Whether the caller may know the document exists at all.
    #[must_use]
    pub const fn sees(self) -> bool {
        self.custodian || self.owner
    }
}

/// Decide what `caller` is to a document held in `custody` under `policy`,
/// reserved by `reserver`.
#[must_use]
pub fn standing(
    policy: &DocumentPolicy,
    custody: &Custody,
    reserver: Reserver<'_>,
    caller: &Caller,
) -> Standing {
    let profile = &caller.profile_id;
    let in_custody = policy.custody_profiles.contains(profile);
    let represented = *profile == policy.represented_principal_profile;
    let custodian = caller.issuer == custody.issuer
        && caller.subject == custody.subject
        && caller.kind == custody.kind
        && (in_custody || represented);
    let owner = caller.issuer == reserver.issuer
        && caller.subject == reserver.subject
        && caller.kind == reserver.kind
        && in_custody
        && !custodian;
    let granting = policy.granting_profiles.contains(profile);
    let represented_grants =
        represented && policy.represented_principal_grants == RepresentedPrincipalGrants::Permitted;
    // Only the holder grants. A reserving system that is not the custodian
    // keeps metadata and status visibility but no grant authority.
    let may_grant = custodian && (granting || represented_grants);
    Standing {
        custodian,
        owner,
        may_grant,
    }
}

/// Whether `caller`'s profile may be named the recipient of a grant under
/// `policy`, so a grant's holder must still resolve to a recipient profile
/// at release.
#[must_use]
pub fn is_recipient(policy: &DocumentPolicy, caller: &Caller) -> bool {
    policy.recipient_profiles.contains(&caller.profile_id)
}

/// The expiry, in hours, a grant is issued with: the policy default when
/// none is asked for, otherwise the asked value when it is between one hour
/// and the policy maximum.
pub fn grant_expiry_hours(
    policy: &DocumentPolicy,
    requested: Option<u32>,
) -> Result<u32, ProblemCode> {
    let restrictions = &policy.mandatory_restrictions;
    match requested {
        None => Ok(restrictions.grant_expiry_hours.get()),
        Some(hours) if hours >= 1 && hours <= restrictions.maximum_grant_expiry_hours.get() => {
            Ok(hours)
        }
        Some(_) => Err(ProblemCode::DocumentGrantExpiryOutOfRange),
    }
}

/// An action a caller may take on a document, from a closed vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum DocumentAction {
    Download,
    Share,
    RevokeShare,
    ListShares,
    RequestErasure,
}

/// Whether a caller with `standing` may ask for the document's removal from
/// custody. Custody belongs to the custodian, so only the custodian may end
/// it. The removal route and the actions a document offers both ask this.
#[must_use]
pub const fn may_request_erasure(standing: Standing) -> bool {
    standing.custodian
}

/// The actions `standing` allows on a document whose current version has
/// `status`, in vocabulary order. `granted` is whether the caller holds an
/// active grant on that version. A document whose removal was requested
/// offers nothing but its share history: every grant on it is revoked.
#[must_use]
pub fn allowed_actions(
    standing: Standing,
    status: DocumentStatus,
    granted: bool,
) -> Vec<DocumentAction> {
    if status.is_erasing() {
        return if standing.sees() {
            vec![DocumentAction::ListShares]
        } else {
            Vec::new()
        };
    }
    let ready = status.is_releasable();
    let mut actions = Vec::new();
    if ready && (standing.custodian || granted) {
        actions.push(DocumentAction::Download);
    }
    if standing.may_grant && ready {
        actions.push(DocumentAction::Share);
    }
    if standing.may_grant {
        actions.push(DocumentAction::RevokeShare);
    }
    if standing.sees() {
        actions.push(DocumentAction::ListShares);
    }
    if may_request_erasure(standing) {
        actions.push(DocumentAction::RequestErasure);
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    const STARTER: &str =
        include_str!("../../../products/documents/examples/starter/documents.yaml");
    const ISSUER: &str = "https://identity.example.test/realms/registry";

    fn project() -> DocumentsProject {
        DocumentsProject::decode("documents.yaml", STARTER.as_bytes())
            .unwrap_or_else(|report| panic!("the starter project is refused: {report:?}"))
            .value
    }

    fn policy(id: &str) -> DocumentPolicy {
        project()
            .document_policies
            .into_iter()
            .find(|(key, _)| key.as_str() == id)
            .map(|(_, policy)| policy)
            .unwrap()
    }

    fn facts<'a>(
        client: &'a str,
        subject: &'a str,
        scopes: &'a [String],
        kind: ActorKindClaim,
        claims: &'a Map<String, Value>,
    ) -> VerifiedTokenFacts<'a> {
        VerifiedTokenFacts {
            issuer: Some(ISSUER),
            subject: Some(subject),
            client_id: Some(client),
            scopes,
            actor_kind: kind,
            claims,
        }
    }

    fn caller(client: &str, subject: &str, scope: &str, kind: ActorKind) -> Caller {
        let claims = Map::new();
        let scopes = vec![scope.to_owned()];
        AccessProfiles::new(&project())
            .resolve(&facts(
                client,
                subject,
                &scopes,
                ActorKindClaim::Present(kind),
                &claims,
            ))
            .unwrap()
    }

    fn app() -> Caller {
        caller(
            "civil-registry-app",
            "registry-app",
            "documents:custody",
            ActorKind::Service,
        )
    }

    fn citizen(subject: &str) -> Caller {
        caller("citizen-portal", subject, "documents:own", ActorKind::Human)
    }

    fn reader(subject: &str) -> Caller {
        caller(
            "partner-portal",
            subject,
            "documents:read",
            ActorKind::Human,
        )
    }

    fn ask(subject: &str) -> CustodyAsk<'_> {
        CustodyAsk {
            subject,
            issuing_institution: None,
        }
    }

    #[test]
    fn a_verified_token_resolves_to_its_client_profile_and_institution() {
        let resolved = app();
        assert_eq!(resolved.profile_id.as_str(), "custodian-app");
        assert_eq!(resolved.role, AccessRole::Custodian);
        assert_eq!(resolved.subject, "registry-app");
        assert_eq!(resolved.issuer, ISSUER);
        assert_eq!(
            resolved.institution.as_ref().map(ExternalId::as_str),
            Some("civil-registry")
        );
        assert_eq!(citizen("citizen-1").institution, None);
    }

    #[test]
    fn a_token_outside_its_profile_is_refused_as_a_profile_refusal() {
        let profiles = AccessProfiles::new(&project());
        let claims = Map::new();
        let custody = vec!["documents:custody".to_owned()];
        let none: Vec<String> = Vec::new();
        let present = ActorKindClaim::Present(ActorKind::Service);
        for refused in [
            facts("unknown-client", "s", &custody, present, &claims),
            facts("civil-registry-app", "s", &none, present, &claims),
            facts(
                "civil-registry-app",
                "s",
                &custody,
                ActorKindClaim::Present(ActorKind::Human),
                &claims,
            ),
            facts(
                "civil-registry-app",
                "s",
                &custody,
                ActorKindClaim::Absent,
                &claims,
            ),
            facts(
                "civil-registry-app",
                "s",
                &custody,
                ActorKindClaim::Unadmitted,
                &claims,
            ),
        ] {
            assert_eq!(profiles.resolve(&refused), Err(AccessRefusal::Profile));
        }
        let missing = profiles
            .missing_scope(&facts("civil-registry-app", "s", &none, present, &claims))
            .unwrap();
        assert_eq!(missing.scope, "documents:custody");
        assert_eq!(missing.profile, "custodian-app");
    }

    #[test]
    fn malformed_identity_claims_are_refused_as_claims() {
        let profiles = AccessProfiles::new(&project());
        let claims = Map::new();
        let custody = vec!["documents:custody".to_owned()];
        let present = ActorKindClaim::Present(ActorKind::Service);
        let malformed = facts(
            "civil-registry-app",
            "s",
            &custody,
            ActorKindClaim::Malformed,
            &claims,
        );
        assert_eq!(profiles.resolve(&malformed), Err(AccessRefusal::Claims));
        let empty_subject = facts("civil-registry-app", "", &custody, present, &claims);
        assert_eq!(profiles.resolve(&empty_subject), Err(AccessRefusal::Claims));
        let mut no_issuer = facts("civil-registry-app", "s", &custody, present, &claims);
        no_issuer.issuer = None;
        assert_eq!(profiles.resolve(&no_issuer), Err(AccessRefusal::Claims));
        assert_eq!(AccessRefusal::Claims.problem().http_status(), 401);
        assert_eq!(AccessRefusal::Profile.problem().http_status(), 403);
    }

    #[test]
    fn a_service_may_name_any_custodian_and_holds_for_a_person() {
        let policy = policy("citizen-delivery");
        let custody = place_custody(&policy, &app(), ask("citizen-1")).unwrap();
        assert_eq!(custody.subject, "citizen-1");
        assert_eq!(custody.kind, ActorKind::Human);
        assert_eq!(custody.represented_principal.as_deref(), Some("citizen-1"));
        let own = place_custody(
            &self::policy("institutional-custody"),
            &app(),
            ask("registry-app"),
        )
        .unwrap();
        assert_eq!(own.kind, ActorKind::Service);
        assert_eq!(own.represented_principal, None);
    }

    #[test]
    fn under_institutional_custody_the_reserving_system_stays_the_custodian() {
        let policy = policy("institutional-custody");
        let custody = place_custody(&policy, &app(), ask("citizen-1")).unwrap();
        assert_eq!(custody.subject, "registry-app");
        assert_eq!(custody.kind, ActorKind::Service);
        assert_eq!(custody.represented_principal.as_deref(), Some("citizen-1"));
        let named = standing(&policy, &custody, BY_APP, &citizen("citizen-1"));
        assert!(!named.sees() && !named.may_grant);
        let institution = standing(&policy, &custody, BY_APP, &app());
        assert!(institution.custodian && institution.may_grant && !institution.owner);
    }

    #[test]
    fn a_human_may_place_a_document_only_in_its_own_custody() {
        let policy = policy("named-share");
        let own = place_custody(&policy, &citizen("citizen-1"), ask("citizen-1")).unwrap();
        assert_eq!(own.kind, ActorKind::Human);
        assert_eq!(own.represented_principal.as_deref(), Some("citizen-1"));
        assert_eq!(
            place_custody(&policy, &citizen("citizen-1"), ask("citizen-2")),
            Err(ProblemCode::CustodyNotPermitted)
        );
    }

    #[test]
    fn a_profile_outside_the_custody_profiles_is_refused() {
        assert_eq!(
            place_custody(
                &policy("citizen-delivery"),
                &citizen("citizen-1"),
                ask("citizen-1")
            ),
            Err(ProblemCode::CustodyNotPermitted)
        );
        assert_eq!(
            place_custody(&policy("named-share"), &reader("reader-1"), ask("reader-1")),
            Err(ProblemCode::CustodyNotPermitted)
        );
    }

    #[test]
    fn the_issuing_institution_is_the_profile_s_never_the_body_s() {
        let policy = policy("citizen-delivery");
        let same = CustodyAsk {
            subject: "citizen-1",
            issuing_institution: Some("civil-registry"),
        };
        assert!(place_custody(&policy, &app(), same).is_ok());
        let other = CustodyAsk {
            subject: "citizen-1",
            issuing_institution: Some("someone-else"),
        };
        assert_eq!(
            place_custody(&policy, &app(), other),
            Err(ProblemCode::CustodyNotPermitted)
        );
        let named_by_a_profile_without_one = CustodyAsk {
            subject: "citizen-1",
            issuing_institution: Some("civil-registry"),
        };
        assert_eq!(
            place_custody(
                &self::policy("named-share"),
                &citizen("citizen-1"),
                named_by_a_profile_without_one
            ),
            Err(ProblemCode::CustodyNotPermitted)
        );
    }

    fn held_for(subject: &str) -> Custody {
        Custody {
            issuer: ISSUER.to_owned(),
            subject: subject.to_owned(),
            kind: ActorKind::Human,
            represented_principal: Some(subject.to_owned()),
        }
    }

    const BY_APP: Reserver<'static> = Reserver {
        issuer: ISSUER,
        subject: "registry-app",
        kind: ActorKind::Service,
    };

    #[test]
    fn the_custodian_matches_issuer_subject_and_kind() {
        let policy = policy("citizen-delivery");
        let custody = held_for("citizen-1");
        assert!(standing(&policy, &custody, BY_APP, &citizen("citizen-1")).custodian);
        assert!(!standing(&policy, &custody, BY_APP, &citizen("citizen-2")).sees());
        let mut elsewhere = citizen("citizen-1");
        elsewhere.issuer = "https://other.example.test".to_owned();
        assert!(!standing(&policy, &custody, BY_APP, &elsewhere).sees());
        // A service whose subject happens to equal the person's is not them.
        let impostor = caller(
            "civil-registry-app",
            "citizen-1",
            "documents:custody",
            ActorKind::Service,
        );
        let standing = standing(&policy, &custody, BY_APP, &impostor);
        assert!(!standing.custodian);
    }

    #[test]
    fn the_owner_matches_the_reserver_s_kind_as_well_as_its_subject() {
        let policy = policy("named-share");
        // A person whose subject happens to equal the reserving service's.
        let lookalike = citizen("registry-app");
        let standing = standing(&policy, &held_for("citizen-2"), BY_APP, &lookalike);
        assert!(!standing.owner && !standing.sees());
    }

    #[test]
    fn the_reserving_system_sees_a_delivered_document_but_may_neither_grant_nor_read_it() {
        let policy = policy("citizen-delivery");
        let owner = standing(&policy, &held_for("citizen-1"), BY_APP, &app());
        assert!(owner.owner && owner.sees() && !owner.custodian && !owner.may_grant);
        assert_eq!(
            allowed_actions(owner, DocumentStatus::Ready, false),
            vec![DocumentAction::ListShares]
        );
    }

    #[test]
    fn the_reserving_system_never_grants_even_when_the_policy_lists_its_profile() {
        let mut policy = policy("citizen-delivery");
        policy.granting_profiles =
            registry_platform_yaml::UniqueList::new(vec![LocalId::new("custodian-app").unwrap()])
                .unwrap();
        let owner = standing(&policy, &held_for("citizen-1"), BY_APP, &app());
        assert!(owner.owner && !owner.may_grant);
    }

    #[test]
    fn under_citizen_delivery_the_citizen_holds_the_document_and_issues_grants() {
        let policy = policy("citizen-delivery");
        let custodian = standing(
            &policy,
            &held_for("citizen-1"),
            BY_APP,
            &citizen("citizen-1"),
        );
        assert!(custodian.custodian && !custodian.owner && custodian.may_grant);
        assert_eq!(
            allowed_actions(custodian, DocumentStatus::Ready, false),
            vec![
                DocumentAction::Download,
                DocumentAction::Share,
                DocumentAction::RevokeShare,
                DocumentAction::ListShares,
                DocumentAction::RequestErasure
            ]
        );
    }

    #[test]
    fn a_represented_principal_grants_only_where_the_policy_permits() {
        let citizen = citizen("citizen-1");
        let mut refusing = policy("citizen-delivery");
        refusing.represented_principal_grants = RepresentedPrincipalGrants::Refused;
        let refused = standing(&refusing, &held_for("citizen-1"), BY_APP, &citizen);
        assert!(refused.custodian && !refused.may_grant);
        assert_eq!(
            allowed_actions(refused, DocumentStatus::Ready, false),
            vec![
                DocumentAction::Download,
                DocumentAction::ListShares,
                DocumentAction::RequestErasure
            ]
        );
        let permitted = standing(
            &policy("named-share"),
            &held_for("citizen-1"),
            BY_APP,
            &citizen,
        );
        assert!(permitted.custodian && permitted.may_grant);
    }

    #[test]
    fn nothing_is_downloadable_or_shareable_before_the_version_is_ready() {
        let custodian = Standing {
            custodian: true,
            owner: false,
            may_grant: true,
        };
        for status in [
            DocumentStatus::AwaitingContent,
            DocumentStatus::Pending,
            DocumentStatus::Suspended,
            DocumentStatus::Rejected,
        ] {
            assert_eq!(
                allowed_actions(custodian, status, true),
                vec![
                    DocumentAction::RevokeShare,
                    DocumentAction::ListShares,
                    DocumentAction::RequestErasure
                ]
            );
        }
        assert_eq!(
            allowed_actions(Standing::default(), DocumentStatus::Ready, true),
            vec![DocumentAction::Download]
        );
    }

    #[test]
    fn only_the_custodian_may_request_erasure_and_an_erasing_document_offers_its_shares_only() {
        let custodian = Standing {
            custodian: true,
            owner: false,
            may_grant: true,
        };
        let owner = Standing {
            custodian: false,
            owner: true,
            may_grant: true,
        };
        assert!(may_request_erasure(custodian));
        assert!(!may_request_erasure(owner));
        assert!(!may_request_erasure(Standing::default()));
        assert!(allowed_actions(custodian, DocumentStatus::Ready, false)
            .contains(&DocumentAction::RequestErasure));
        assert!(!allowed_actions(owner, DocumentStatus::Ready, false)
            .contains(&DocumentAction::RequestErasure));
        for status in [DocumentStatus::ErasurePending, DocumentStatus::Erased] {
            for standing in [custodian, owner] {
                assert_eq!(
                    allowed_actions(standing, status, true),
                    vec![DocumentAction::ListShares]
                );
            }
            assert_eq!(
                allowed_actions(Standing::default(), status, true),
                Vec::new()
            );
        }
        assert_eq!(
            serde_json::to_value(DocumentAction::RequestErasure).unwrap(),
            "request-erasure"
        );
    }

    #[test]
    fn a_grant_expiry_is_the_default_or_within_the_maximum() {
        let policy = policy("named-share");
        assert_eq!(grant_expiry_hours(&policy, None), Ok(24));
        assert_eq!(grant_expiry_hours(&policy, Some(1)), Ok(1));
        assert_eq!(grant_expiry_hours(&policy, Some(168)), Ok(168));
        for refused in [0, 169, u32::MAX] {
            assert_eq!(
                grant_expiry_hours(&policy, Some(refused)),
                Err(ProblemCode::DocumentGrantExpiryOutOfRange)
            );
        }
    }

    #[test]
    fn only_recipient_profiles_may_hold_a_grant() {
        let policy = policy("citizen-delivery");
        assert!(is_recipient(&policy, &reader("reader-1")));
        assert!(!is_recipient(&policy, &citizen("citizen-1")));
        assert!(!is_recipient(&policy, &app()));
    }
}
