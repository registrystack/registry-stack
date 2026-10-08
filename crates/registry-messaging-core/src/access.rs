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

use registry_platform_yaml::{shape_union, ExternalId, Identified, Invalid, LocalId, UniqueList};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::problem::ProblemCode;
use crate::visibility::CallerIdentity;

/// The closed actor-kind vocabulary, spelled exactly as the Registry Stack
/// contextual-claim profile spells it.
// Not `registry_platform_oidc::ActorKind`: that crate links reqwest and tokio,
// which this I/O-free core and the client built on it must not carry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AccessRole {
    Sender,
    Operator,
}

/// One declared caller profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    /// `sub`, or the name of another string claim identifying the principal.
    #[serde(deserialize_with = "crate::typed::external_id")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::ExternalId")
    )]
    pub principal_claim: String,
    /// The scopes a token must carry: `unrestricted`, or a list of at least
    /// one scope. Held as the listed scopes, so `unrestricted` is the empty
    /// list.
    #[serde(deserialize_with = "required_scopes")]
    #[cfg_attr(feature = "schema", schemars(with = "RequiredScopes"))]
    pub required_scopes: Vec<String>,
    /// The OAuth clients whose tokens resolve to this profile, at least one.
    #[serde(deserialize_with = "requester_clients")]
    #[cfg_attr(feature = "schema", schemars(with = "ListedNames"))]
    pub requester_clients: Vec<String>,
    /// The actor kind the token must claim. Absent means any kind.
    #[serde(default)]
    pub actor_kind: Option<ActorKind>,
    pub role: AccessRole,
    /// The sender profiles a sender may select; an operator lists none.
    #[serde(default, deserialize_with = "crate::typed::local_ids")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>")
    )]
    pub sender_profiles: Vec<String>,
    /// The templates a sender may use, by id, every declared version; an
    /// operator lists none.
    #[serde(default, deserialize_with = "crate::typed::local_ids")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>")
    )]
    pub templates: Vec<String>,
    #[serde(default)]
    pub allow_direct_content: bool,
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_REQUESTS_PER_MINUTE>")]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = MAXIMUM_REQUESTS_PER_MINUTE))
    )]
    pub requests_per_minute: u32,
    #[serde(deserialize_with = "crate::typed::bounded_u32::<_, 1, MAXIMUM_BURST>")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAXIMUM_BURST)))]
    pub burst: u32,
    /// The most messages the profile may submit in any 24 hours. Absent
    /// means no daily bound beyond the rate.
    #[serde(
        default,
        deserialize_with = "crate::typed::optional_bounded_u32::<_, 1, MAXIMUM_MESSAGES_PER_DAY>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = MAXIMUM_MESSAGES_PER_DAY))
    )]
    pub maximum_messages_per_day: Option<u32>,
}

impl Identified for AccessProfile {
    fn id(&self) -> &str {
        &self.id
    }
}

impl AccessProfile {
    /// Whether a sender profile names no sender profile or no template, so
    /// it could submit nothing.
    #[must_use]
    pub fn sends_nothing(&self) -> bool {
        self.sender_profiles.is_empty() || self.templates.is_empty()
    }

    /// Whether the profile declares anything only a sender may hold.
    #[must_use]
    pub fn declares_sending_permissions(&self) -> bool {
        !self.sender_profiles.is_empty() || !self.templates.is_empty() || self.allow_direct_content
    }
}

/// The most requests per minute one profile may declare.
pub const MAXIMUM_REQUESTS_PER_MINUTE: u32 = 60_000;

/// The largest burst one profile may declare.
pub const MAXIMUM_BURST: u32 = 10_000;

/// The most messages per day one profile may declare.
pub const MAXIMUM_MESSAGES_PER_DAY: u32 = 10_000_000;

const SCOPES_EXPECTED: &str = "unrestricted, or a list of at least one scope";
const SCOPES_ACTION: &str =
    "List the scopes a token must carry, or write unrestricted to require none.";

/// The keyword `unrestricted`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnrestrictedKeyword;

impl<'de> Deserialize<'de> for UnrestrictedKeyword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == "unrestricted" {
            Ok(Self)
        } else {
            Err(Invalid::expected(SCOPES_EXPECTED, SCOPES_ACTION).into_error())
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for UnrestrictedKeyword {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "UnrestrictedKeyword".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Require no scope.",
            "type": "string",
            "const": "unrestricted",
        })
    }
}

/// A list of at least one distinct name.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ListedNames(Vec<String>);

impl ListedNames {
    fn read<'de, D: Deserializer<'de>>(
        deserializer: D,
        expected: &'static str,
        action: &'static str,
    ) -> Result<Self, D::Error> {
        let items = UniqueList::<ExternalId>::deserialize(deserializer)?.into_vec();
        if items.is_empty() {
            return Err(Invalid::expected(expected, action).into_error());
        }
        Ok(Self(
            items.into_iter().map(ExternalId::into_string).collect(),
        ))
    }
}

impl<'de> Deserialize<'de> for ListedNames {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::read(deserializer, SCOPES_EXPECTED, SCOPES_ACTION)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ListedNames {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ListedNames".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<UniqueList<ExternalId>>();
        schema.insert("minItems".to_owned(), 1.into());
        schema
    }
}

/// The scopes a token must carry: the keyword `unrestricted`, or a list of
/// at least one scope. An empty list is refused, because it reads as both
/// "none" and "any" (CFG-EMPTY-2).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum RequiredScopes {
    Unrestricted(UnrestrictedKeyword),
    Listed(ListedNames),
}

shape_union!(RequiredScopes { scalar => Unrestricted, list => Listed });

fn required_scopes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    Ok(match RequiredScopes::deserialize(deserializer)? {
        RequiredScopes::Unrestricted(_) => Vec::new(),
        RequiredScopes::Listed(ListedNames(scopes)) => scopes,
    })
}

fn requester_clients<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    ListedNames::read(
        deserializer,
        "a list of at least one OAuth client",
        "List the OAuth clients whose tokens resolve to this profile.",
    )
    .map(|ListedNames(clients)| clients)
}

/// The longest profile identifier accepted.
pub const MAXIMUM_PROFILE_IDENTIFIER_BYTES: usize = 64;

/// Whether `value` is a local identifier: a lowercase letter, then up to 63
/// lowercase letters, digits, underscores, or hyphens.
#[must_use]
pub fn valid_identifier(value: &str) -> bool {
    LocalId::new(value).is_ok()
}

/// Why a set of access profiles cannot be used. Profile identifiers and
/// client identifiers are deployment configuration, not secrets, so they are
/// named to point the operator at the entry.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AccessProfileError {
    #[error(
        "access profile identifier `{0}` is not a lowercase letter followed by at most 63 lowercase letters, digits, underscores, or hyphens"
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
        AccessRole::Sender if profile.sends_nothing() => {
            return Err(AccessProfileError::SenderWithoutTargets(id()));
        }
        AccessRole::Operator if profile.declares_sending_permissions() => {
            return Err(AccessProfileError::OperatorWithSendingPermissions(id()));
        }
        _ => {}
    }
    if profile.requests_per_minute == 0
        || profile.burst == 0
        || profile.maximum_messages_per_day == Some(0)
    {
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

/// Decide whether `caller` may preview `template`. Preview is a sender's
/// authoring aid: it answers only for a template the caller's profile could
/// submit, and an operator, who submits nothing, previews nothing.
pub fn authorize_preview(caller: &Caller, template: &str) -> Result<(), SubmissionRefusal> {
    let profile = &caller.profile;
    if profile.role != AccessRole::Sender {
        return Err(SubmissionRefusal::Role);
    }
    if !profile.templates.iter().any(|allowed| allowed == template) {
        return Err(SubmissionRefusal::Template);
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
            maximum_messages_per_day: None,
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
                    maximum_messages_per_day: Some(0),
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

    const PROFILE_FORMAT: registry_platform_yaml::FormatSpec<'static> =
        registry_platform_yaml::FormatSpec {
            kind: "AccessProfile",
            envelope: registry_platform_yaml::EnvelopeRule::Exempt { reason: "test" },
            removed_keys: &[],
        };

    fn read(value: serde_json::Value) -> Result<AccessProfile, Vec<(String, String)>> {
        let bytes = serde_json::to_vec(&value).unwrap();
        let document = registry_platform_yaml::read_document(
            "messaging.yaml",
            &bytes,
            &registry_platform_yaml::Expect::one(&PROFILE_FORMAT),
        )
        .unwrap();
        document.decode::<AccessProfile>().map_err(|report| {
            report
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
                .collect()
        })
    }

    fn document(extra: serde_json::Value) -> serde_json::Value {
        let mut value = json!({
            "id": "p",
            "principalClaim": "sub",
            "requiredScopes": ["messaging:send"],
            "requesterClients": ["c"],
            "role": "sender",
            "senderProfiles": ["transactional"],
            "templates": ["appointment-reminder"],
            "requestsPerMinute": 1,
            "burst": 1
        });
        for (key, member) in extra.as_object().unwrap() {
            if member.is_null() {
                value.as_object_mut().unwrap().remove(key);
            } else {
                value[key] = member.clone();
            }
        }
        value
    }

    #[test]
    fn a_profile_document_refuses_unknown_keys() {
        assert_eq!(
            read(document(json!({"endpoint": "https://elsewhere.test"}))).unwrap_err(),
            vec![("config.unknown-key".to_owned(), "/endpoint".to_owned())]
        );
        let parsed = read(document(json!({
            "actorKind": "agent",
            "role": "operator",
            "senderProfiles": null,
            "templates": null
        })))
        .unwrap();
        assert_eq!(parsed.actor_kind, Some(ActorKind::Agent));
        assert_eq!(parsed.role, AccessRole::Operator);
    }

    #[test]
    fn required_scopes_are_unrestricted_or_listed_never_empty() {
        let parsed = read(document(json!({"requiredScopes": "unrestricted"}))).unwrap();
        assert!(parsed.required_scopes.is_empty());
        let parsed = read(document(json!({"requiredScopes": ["a", "b"]}))).unwrap();
        assert_eq!(parsed.required_scopes, ["a", "b"]);
        for scopes in [json!([]), json!("any"), json!(null)] {
            let refused = read(document(json!({"requiredScopes": scopes.clone()}))).unwrap_err();
            assert_eq!(refused.len(), 1, "{scopes}");
        }
        let refused = read(document(json!({"requiredScopes": ["a", "a"]}))).unwrap_err();
        assert_eq!(refused[0].0, "config.duplicate-item");
        let refused = read(document(json!({"requesterClients": []}))).unwrap_err();
        assert_eq!(refused[0].1, "/requesterClients");
    }

    #[test]
    fn profile_members_are_typed_and_bounded() {
        for (member, value) in [
            ("id", json!("Upper")),
            ("principalClaim", json!("")),
            ("senderProfiles", json!(["Transactional"])),
            ("requestsPerMinute", json!(0)),
            ("requestsPerMinute", json!(MAXIMUM_REQUESTS_PER_MINUTE + 1)),
            ("burst", json!(MAXIMUM_BURST + 1)),
            ("maximumMessagesPerDay", json!(0)),
            ("maximumMessagesPerDay", json!(MAXIMUM_MESSAGES_PER_DAY + 1)),
        ] {
            let refused = read(document(json!({member: value.clone()}))).unwrap_err();
            assert!(
                refused[0].1.starts_with(&format!("/{member}")),
                "{member} {value}: {refused:?}"
            );
        }
        let parsed = read(document(json!({"maximumMessagesPerDay": 100}))).unwrap();
        assert_eq!(parsed.maximum_messages_per_day, Some(100));
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

    /// A preview answers only for a template the caller's profile could
    /// submit, so it is no wider than security invariant 1.
    #[test]
    fn a_preview_outside_the_callers_templates_is_refused() {
        let sender = caller(sender("clinic-reminders", "clinic-backend"));
        assert_eq!(authorize_preview(&sender, "appointment-reminder"), Ok(()));
        assert_eq!(
            authorize_preview(&sender, "payment-notice"),
            Err(SubmissionRefusal::Template)
        );
        let operator = caller(operator("messaging-operators", "operator-console"));
        assert_eq!(
            authorize_preview(&operator, "appointment-reminder"),
            Err(SubmissionRefusal::Role)
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
