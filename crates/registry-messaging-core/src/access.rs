// SPDX-License-Identifier: Apache-2.0

//! Access profiles and the pure decisions over them.
//!
//! A caller is resolved to exactly one access profile from facts a verified
//! access token carries: the client it was issued to, its scopes, the actor
//! kind it claims, and the claim naming the principal. Signature, issuer,
//! audience, lifetime, and the allowed-client list are checked by the runtime
//! before these functions run; nothing here trusts a token by itself.
//!
//! Messaging inherits no authorization from a caller product. A profile names
//! the sender profiles and templates it may use, whether it may submit direct
//! content, and its rate limits, so a reviewer reads who may send what next to
//! the templates themselves.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::problem::ProblemCode;
use crate::visibility::CallerIdentity;

/// The closed actor-kind vocabulary, spelled exactly as the Registry Stack
/// contextual-claim profile spells it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorKind {
    Human,
    Agent,
    Service,
}

impl ActorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }
}

/// What a profile is for. A sender submits and reads its own messages; an
/// operator reads and acts on every message but submits none.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessRole {
    Sender,
    Operator,
}

/// One declared caller profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    pub id: String,
    /// `sub`, or the name of another string claim identifying the principal.
    pub principal_claim: String,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// The OAuth clients whose tokens resolve to this profile.
    pub requester_clients: Vec<String>,
    /// The actor kind the token must claim. Absent means any kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<ActorKind>,
    pub role: AccessRole,
    #[serde(default)]
    pub sender_profiles: Vec<String>,
    #[serde(default)]
    pub templates: Vec<String>,
    #[serde(default)]
    pub allow_direct_content: bool,
    pub requests_per_minute: u32,
    pub burst: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_limit: Option<u32>,
}

/// The longest profile identifier accepted.
pub const MAXIMUM_PROFILE_IDENTIFIER_BYTES: usize = 64;

/// Whether `value` is a lowercase kebab identifier of bounded length.
#[must_use]
pub fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_PROFILE_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// Why a set of access profiles cannot be used. Profile identifiers and
/// client identifiers are deployment configuration, not secrets, so they are
/// named to point the operator at the entry.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AccessProfileError {
    #[error(
        "access profile identifier `{0}` is not a lowercase kebab identifier of at most 64 bytes"
    )]
    InvalidIdentifier(String),
    #[error("access profile `{0}` is declared more than once")]
    DuplicateIdentifier(String),
    #[error("access profile `{0}` names no principal claim")]
    MissingPrincipalClaim(String),
    #[error("access profile `{0}` names no requester client")]
    MissingRequesterClient(String),
    #[error("client `{client}` is a requester client of both `{first}` and `{second}`")]
    SharedRequesterClient {
        client: String,
        first: String,
        second: String,
    },
    #[error("access profile `{0}` declares an empty scope, client, sender profile, or template")]
    EmptyEntry(String),
    #[error("access profile `{0}` is a sender with no sender profile or no template")]
    SenderWithoutTargets(String),
    #[error("access profile `{0}` is an operator but declares sending permissions")]
    OperatorWithSendingPermissions(String),
    #[error("access profile `{0}` declares a zero rate, burst, or daily limit")]
    ZeroLimit(String),
}

/// A validated set of access profiles, indexed by requester client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessProfiles {
    profiles: BTreeMap<String, AccessProfile>,
    by_client: BTreeMap<String, String>,
}

impl AccessProfiles {
    /// Validate `profiles`. Every requester client resolves to at most one
    /// profile, so a token never has to choose between two authorities.
    pub fn new(profiles: Vec<AccessProfile>) -> Result<Self, AccessProfileError> {
        let mut indexed = BTreeMap::new();
        let mut by_client: BTreeMap<String, String> = BTreeMap::new();
        for profile in profiles {
            check_profile(&profile)?;
            for client in &profile.requester_clients {
                if let Some(first) = by_client.get(client) {
                    return Err(AccessProfileError::SharedRequesterClient {
                        client: client.clone(),
                        first: first.clone(),
                        second: profile.id.clone(),
                    });
                }
                by_client.insert(client.clone(), profile.id.clone());
            }
            if indexed.contains_key(&profile.id) {
                return Err(AccessProfileError::DuplicateIdentifier(profile.id));
            }
            indexed.insert(profile.id.clone(), profile);
        }
        Ok(Self {
            profiles: indexed,
            by_client,
        })
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&AccessProfile> {
        self.profiles.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AccessProfile> {
        self.profiles.values()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Resolve verified token facts to exactly one profile and principal.
    pub fn resolve(&self, token: &VerifiedTokenFacts<'_>) -> Result<Caller, AccessRefusal> {
        let profile = token
            .client_id
            .and_then(|client| self.by_client.get(client))
            .and_then(|id| self.profiles.get(id))
            .ok_or(AccessRefusal::Profile)?;
        let scopes: BTreeSet<&str> = token.scopes.iter().map(String::as_str).collect();
        if !profile
            .required_scopes
            .iter()
            .all(|scope| scopes.contains(scope.as_str()))
        {
            return Err(AccessRefusal::Profile);
        }
        // A malformed actor-kind claim is a malformed credential whatever the
        // profile demands; an absent one only matters to a profile that names
        // a kind.
        let claimed = match token.actor_kind {
            ActorKindClaim::Malformed => return Err(AccessRefusal::Claims),
            ActorKindClaim::Absent => None,
            ActorKindClaim::Present(kind) => Some(kind),
        };
        if let Some(required) = profile.actor_kind {
            if claimed != Some(required) {
                return Err(AccessRefusal::Profile);
            }
        }
        let principal = if profile.principal_claim == "sub" {
            token.subject
        } else {
            token
                .claims
                .get(&profile.principal_claim)
                .and_then(Value::as_str)
        }
        .filter(|value| !value.is_empty())
        .ok_or(AccessRefusal::Claims)?;
        let issuer = token
            .issuer
            .filter(|issuer| !issuer.is_empty())
            .ok_or(AccessRefusal::Claims)?;
        Ok(Caller {
            identity: CallerIdentity {
                issuer: issuer.to_owned(),
                subject: principal.to_owned(),
            },
            actor_kind: claimed,
            profile: profile.clone(),
        })
    }
}

fn check_profile(profile: &AccessProfile) -> Result<(), AccessProfileError> {
    let id = || profile.id.clone();
    if !valid_identifier(&profile.id) {
        return Err(AccessProfileError::InvalidIdentifier(id()));
    }
    if profile.principal_claim.is_empty() {
        return Err(AccessProfileError::MissingPrincipalClaim(id()));
    }
    if profile.requester_clients.is_empty() {
        return Err(AccessProfileError::MissingRequesterClient(id()));
    }
    let has_empty = profile
        .required_scopes
        .iter()
        .chain(&profile.requester_clients)
        .chain(&profile.sender_profiles)
        .chain(&profile.templates)
        .any(String::is_empty);
    if has_empty {
        return Err(AccessProfileError::EmptyEntry(id()));
    }
    match profile.role {
        AccessRole::Sender => {
            if profile.sender_profiles.is_empty() || profile.templates.is_empty() {
                return Err(AccessProfileError::SenderWithoutTargets(id()));
            }
        }
        AccessRole::Operator => {
            if !profile.sender_profiles.is_empty()
                || !profile.templates.is_empty()
                || profile.allow_direct_content
            {
                return Err(AccessProfileError::OperatorWithSendingPermissions(id()));
            }
        }
    }
    if profile.requests_per_minute == 0 || profile.burst == 0 || profile.daily_limit == Some(0) {
        return Err(AccessProfileError::ZeroLimit(id()));
    }
    Ok(())
}

/// The actor-kind claim as the verified token carries it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKindClaim {
    Absent,
    Malformed,
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

/// A caller resolved to one profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Caller {
    pub identity: CallerIdentity,
    pub actor_kind: Option<ActorKind>,
    pub profile: AccessProfile,
}

impl Caller {
    #[must_use]
    pub fn role(&self) -> AccessRole {
        self.profile.role
    }
}

/// Why a verified token resolved to no profile.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AccessRefusal {
    /// No profile authorizes this client, scope set, or actor kind.
    #[error("no access profile authorizes this caller")]
    Profile,
    /// The token's identity claims are missing or malformed.
    #[error("the verified identity claims are invalid")]
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

/// What one submission asks to use.
#[derive(Clone, Copy, Debug)]
pub struct SubmissionScope<'a> {
    pub sender_profile: &'a str,
    pub template: Option<&'a str>,
    pub direct_content: bool,
}

/// Why a resolved caller may not make one submission.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SubmissionRefusal {
    #[error("the caller's role does not submit messages")]
    Role,
    #[error("the caller's profile does not allow this sender profile")]
    SenderProfile,
    #[error("the caller's profile does not allow this template")]
    Template,
    #[error("the caller's profile does not allow direct content")]
    DirectContent,
}

impl SubmissionRefusal {
    #[must_use]
    pub const fn problem(self) -> ProblemCode {
        match self {
            Self::Role => ProblemCode::OperationNotAuthorized,
            Self::SenderProfile | Self::Template | Self::DirectContent => {
                ProblemCode::ProfileNotAuthorized
            }
        }
    }
}

/// Decide whether `caller` may submit through `scope`. A submission names a
/// template or carries direct content, never both; the runtime's request
/// validation refuses the combination before this runs.
pub fn authorize_submission(
    caller: &Caller,
    scope: &SubmissionScope<'_>,
) -> Result<(), SubmissionRefusal> {
    let profile = &caller.profile;
    if profile.role != AccessRole::Sender {
        return Err(SubmissionRefusal::Role);
    }
    if !profile
        .sender_profiles
        .iter()
        .any(|allowed| allowed == scope.sender_profile)
    {
        return Err(SubmissionRefusal::SenderProfile);
    }
    if let Some(template) = scope.template {
        if !profile.templates.iter().any(|allowed| allowed == template) {
            return Err(SubmissionRefusal::Template);
        }
    }
    if scope.direct_content && !profile.allow_direct_content {
        return Err(SubmissionRefusal::DirectContent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://issuer.test";

    fn sender(id: &str, client: &str) -> AccessProfile {
        AccessProfile {
            id: id.to_owned(),
            principal_claim: "sub".to_owned(),
            required_scopes: vec!["messaging-send".to_owned()],
            requester_clients: vec![client.to_owned()],
            actor_kind: None,
            role: AccessRole::Sender,
            sender_profiles: vec!["notices-sms".to_owned()],
            templates: vec!["appointment-reminder".to_owned()],
            allow_direct_content: false,
            requests_per_minute: 60,
            burst: 10,
            daily_limit: None,
        }
    }

    fn operator(id: &str, client: &str) -> AccessProfile {
        AccessProfile {
            role: AccessRole::Operator,
            sender_profiles: Vec::new(),
            templates: Vec::new(),
            required_scopes: vec!["messaging-operate".to_owned()],
            ..sender(id, client)
        }
    }

    struct Token {
        issuer: Option<String>,
        subject: Option<String>,
        client: Option<String>,
        scopes: Vec<String>,
        actor_kind: ActorKindClaim,
        claims: Map<String, Value>,
    }

    impl Token {
        fn standing(client: &str, scopes: &[&str]) -> Self {
            Self {
                issuer: Some(ISSUER.to_owned()),
                subject: Some("principal-1".to_owned()),
                client: Some(client.to_owned()),
                scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                actor_kind: ActorKindClaim::Present(ActorKind::Service),
                claims: Map::new(),
            }
        }

        fn facts(&self) -> VerifiedTokenFacts<'_> {
            VerifiedTokenFacts {
                issuer: self.issuer.as_deref(),
                subject: self.subject.as_deref(),
                client_id: self.client.as_deref(),
                scopes: &self.scopes,
                actor_kind: self.actor_kind,
                claims: &self.claims,
            }
        }
    }

    fn profiles() -> AccessProfiles {
        AccessProfiles::new(vec![
            sender("clinic-reminders", "clinic-backend"),
            operator("messaging-operators", "operator-console"),
        ])
        .expect("the fixture profiles are valid")
    }

    #[test]
    fn a_token_resolves_to_the_profile_its_client_is_listed_in() {
        let caller = profiles()
            .resolve(&Token::standing("clinic-backend", &["messaging-send"]).facts())
            .expect("the listed client with the required scope resolves");
        assert_eq!(caller.profile.id, "clinic-reminders");
        assert_eq!(caller.role(), AccessRole::Sender);
        assert_eq!(caller.identity.issuer, ISSUER);
        assert_eq!(caller.identity.subject, "principal-1");
        assert_eq!(caller.actor_kind, Some(ActorKind::Service));
    }

    #[test]
    fn a_client_listed_in_no_profile_is_refused() {
        assert_eq!(
            profiles().resolve(&Token::standing("unlisted-client", &["messaging-send"]).facts()),
            Err(AccessRefusal::Profile)
        );
        let mut clientless = Token::standing("clinic-backend", &["messaging-send"]);
        clientless.client = None;
        assert_eq!(
            profiles().resolve(&clientless.facts()),
            Err(AccessRefusal::Profile)
        );
    }

    #[test]
    fn a_missing_required_scope_is_refused() {
        assert_eq!(
            profiles().resolve(&Token::standing("clinic-backend", &["messaging-read"]).facts()),
            Err(AccessRefusal::Profile)
        );
        assert_eq!(
            profiles().resolve(&Token::standing("clinic-backend", &[]).facts()),
            Err(AccessRefusal::Profile)
        );
    }

    #[test]
    fn an_actor_kind_the_profile_does_not_accept_is_refused() {
        let mut agents_only = sender("agent-sender", "agent-client");
        agents_only.actor_kind = Some(ActorKind::Agent);
        let profiles = AccessProfiles::new(vec![agents_only]).unwrap();
        let mut token = Token::standing("agent-client", &["messaging-send"]);
        assert_eq!(
            profiles.resolve(&token.facts()),
            Err(AccessRefusal::Profile)
        );
        token.actor_kind = ActorKindClaim::Absent;
        assert_eq!(
            profiles.resolve(&token.facts()),
            Err(AccessRefusal::Profile)
        );
        token.actor_kind = ActorKindClaim::Present(ActorKind::Agent);
        assert!(profiles.resolve(&token.facts()).is_ok());
    }

    #[test]
    fn an_absent_actor_kind_is_accepted_by_a_profile_that_names_none() {
        let mut token = Token::standing("clinic-backend", &["messaging-send"]);
        token.actor_kind = ActorKindClaim::Absent;
        let caller = profiles().resolve(&token.facts()).unwrap();
        assert_eq!(caller.actor_kind, None);
    }

    #[test]
    fn a_malformed_actor_kind_is_an_invalid_claim_for_every_profile() {
        let mut token = Token::standing("clinic-backend", &["messaging-send"]);
        token.actor_kind = ActorKindClaim::Malformed;
        assert_eq!(
            profiles().resolve(&token.facts()),
            Err(AccessRefusal::Claims)
        );
    }

    #[test]
    fn the_principal_comes_from_the_declared_claim() {
        let mut by_claim = sender("by-claim", "claim-client");
        by_claim.principal_claim = "registry_principal".to_owned();
        let profiles = AccessProfiles::new(vec![by_claim]).unwrap();
        let mut token = Token::standing("claim-client", &["messaging-send"]);
        assert_eq!(profiles.resolve(&token.facts()), Err(AccessRefusal::Claims));
        token
            .claims
            .insert("registry_principal".to_owned(), json!("worker-7"));
        assert_eq!(
            profiles.resolve(&token.facts()).unwrap().identity.subject,
            "worker-7"
        );
        token
            .claims
            .insert("registry_principal".to_owned(), json!(""));
        assert_eq!(profiles.resolve(&token.facts()), Err(AccessRefusal::Claims));
        token
            .claims
            .insert("registry_principal".to_owned(), json!(7));
        assert_eq!(profiles.resolve(&token.facts()), Err(AccessRefusal::Claims));
    }

    #[test]
    fn a_missing_subject_or_issuer_is_an_invalid_claim() {
        let mut token = Token::standing("clinic-backend", &["messaging-send"]);
        token.subject = None;
        assert_eq!(
            profiles().resolve(&token.facts()),
            Err(AccessRefusal::Claims)
        );
        let mut token = Token::standing("clinic-backend", &["messaging-send"]);
        token.issuer = Some(String::new());
        assert_eq!(
            profiles().resolve(&token.facts()),
            Err(AccessRefusal::Claims)
        );
    }

    #[test]
    fn refusals_map_to_their_problems() {
        assert_eq!(
            AccessRefusal::Profile.problem(),
            ProblemCode::ProfileNotAuthorized
        );
        assert_eq!(
            AccessRefusal::Claims.problem(),
            ProblemCode::AuthenticationRefused
        );
    }

    #[test]
    fn a_client_in_two_profiles_is_refused() {
        assert_eq!(
            AccessProfiles::new(vec![
                sender("first", "shared-client"),
                operator("second", "shared-client"),
            ]),
            Err(AccessProfileError::SharedRequesterClient {
                client: "shared-client".to_owned(),
                first: "first".to_owned(),
                second: "second".to_owned(),
            })
        );
    }

    #[test]
    fn malformed_profiles_are_refused() {
        let cases: Vec<(AccessProfile, AccessProfileError)> = vec![
            (
                sender("Upper", "c"),
                AccessProfileError::InvalidIdentifier("Upper".to_owned()),
            ),
            (
                AccessProfile {
                    principal_claim: String::new(),
                    ..sender("p", "c")
                },
                AccessProfileError::MissingPrincipalClaim("p".to_owned()),
            ),
            (
                AccessProfile {
                    requester_clients: Vec::new(),
                    ..sender("p", "c")
                },
                AccessProfileError::MissingRequesterClient("p".to_owned()),
            ),
            (
                AccessProfile {
                    required_scopes: vec![String::new()],
                    ..sender("p", "c")
                },
                AccessProfileError::EmptyEntry("p".to_owned()),
            ),
            (
                AccessProfile {
                    templates: Vec::new(),
                    ..sender("p", "c")
                },
                AccessProfileError::SenderWithoutTargets("p".to_owned()),
            ),
            (
                AccessProfile {
                    allow_direct_content: true,
                    ..operator("p", "c")
                },
                AccessProfileError::OperatorWithSendingPermissions("p".to_owned()),
            ),
            (
                AccessProfile {
                    burst: 0,
                    ..sender("p", "c")
                },
                AccessProfileError::ZeroLimit("p".to_owned()),
            ),
            (
                AccessProfile {
                    daily_limit: Some(0),
                    ..sender("p", "c")
                },
                AccessProfileError::ZeroLimit("p".to_owned()),
            ),
        ];
        for (profile, expected) in cases {
            assert_eq!(AccessProfiles::new(vec![profile]), Err(expected));
        }
        assert_eq!(
            AccessProfiles::new(vec![sender("p", "a"), sender("p", "b")]),
            Err(AccessProfileError::DuplicateIdentifier("p".to_owned()))
        );
    }

    #[test]
    fn a_profile_document_refuses_unknown_keys() {
        let error = serde_json::from_value::<AccessProfile>(json!({
            "id": "p",
            "principalClaim": "sub",
            "requesterClients": ["c"],
            "role": "sender",
            "requestsPerMinute": 1,
            "burst": 1,
            "endpoint": "https://elsewhere.test"
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"), "{error}");
        let parsed: AccessProfile = serde_json::from_value(json!({
            "id": "p",
            "principalClaim": "sub",
            "requesterClients": ["c"],
            "actorKind": "agent",
            "role": "operator",
            "requestsPerMinute": 1,
            "burst": 1
        }))
        .unwrap();
        assert_eq!(parsed.actor_kind, Some(ActorKind::Agent));
        assert_eq!(parsed.role, AccessRole::Operator);
    }

    fn caller(profile: AccessProfile) -> Caller {
        Caller {
            identity: CallerIdentity {
                issuer: ISSUER.to_owned(),
                subject: "principal-1".to_owned(),
            },
            actor_kind: Some(ActorKind::Service),
            profile,
        }
    }

    /// Security invariant 1: a caller sends only through the sender profiles
    /// and templates its access profile lists.
    #[test]
    fn a_submission_outside_the_callers_sender_profiles_or_templates_is_refused() {
        let sender = caller(sender("clinic-reminders", "clinic-backend"));
        let allowed = SubmissionScope {
            sender_profile: "notices-sms",
            template: Some("appointment-reminder"),
            direct_content: false,
        };
        assert_eq!(authorize_submission(&sender, &allowed), Ok(()));
        assert_eq!(
            authorize_submission(
                &sender,
                &SubmissionScope {
                    sender_profile: "payments-email",
                    ..allowed
                }
            ),
            Err(SubmissionRefusal::SenderProfile)
        );
        assert_eq!(
            authorize_submission(
                &sender,
                &SubmissionScope {
                    template: Some("payment-notice"),
                    ..allowed
                }
            ),
            Err(SubmissionRefusal::Template)
        );
        assert_eq!(
            authorize_submission(
                &sender,
                &SubmissionScope {
                    template: None,
                    direct_content: true,
                    ..allowed
                }
            ),
            Err(SubmissionRefusal::DirectContent)
        );
        let operator = caller(operator("messaging-operators", "operator-console"));
        assert_eq!(
            authorize_submission(&operator, &allowed),
            Err(SubmissionRefusal::Role)
        );
        assert_eq!(
            SubmissionRefusal::Role.problem(),
            ProblemCode::OperationNotAuthorized
        );
        assert_eq!(
            SubmissionRefusal::Template.problem(),
            ProblemCode::ProfileNotAuthorized
        );
    }

    #[test]
    fn direct_content_is_accepted_only_where_the_profile_allows_it() {
        let mut profile = sender("direct", "direct-client");
        profile.allow_direct_content = true;
        let direct = caller(profile);
        assert_eq!(
            authorize_submission(
                &direct,
                &SubmissionScope {
                    sender_profile: "notices-sms",
                    template: None,
                    direct_content: true,
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn actor_kind_spellings_match_the_contextual_claim_profile() {
        for (kind, spelling) in [
            (ActorKind::Human, "human"),
            (ActorKind::Agent, "agent"),
            (ActorKind::Service, "service"),
        ] {
            assert_eq!(kind.as_str(), spelling);
            assert_eq!(serde_json::to_value(kind).unwrap(), json!(spelling));
        }
    }
}
