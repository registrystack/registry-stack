// SPDX-License-Identifier: Apache-2.0
//! The issuer set a runtime accepts access tokens from, and the rules every
//! entry of it follows.
//!
//! A runtime's `authentication.oidc.issuers` is a map from an issuer id to one
//! entry. Each entry holds the shared [`CallerIssuerCore`]: the issuer, its
//! audience and key source, the access-token type, the scope claim, the client
//! rule, and an optional declared actor kind. A product embeds the core in its
//! own entry type beside its own members and implements
//! [`CallerIssuerEntry`], so [`CallerIssuers::check`] can check the set.
//!
//! The members that relax something are [`Stated`] values. They never refuse:
//! they reach the posture report, which the startup log and `check` print.

use std::collections::BTreeMap;

use registry_platform_yaml::{escape_pointer_segment, Diagnostic, ExternalId, LocalId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::blocks::{ListedClients, OidcAllowedClients, OidcIssuerConfig, UnrestrictedClients};
use crate::{ExplicitClass, ExplicitProductionSetting, PackageClients, RuntimeFileCheck, Stated};

static JWT_ACCESS_TOKEN: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "platform.posture.jwt-access-token",
    key: "accessTokenType",
    summary: "admits access tokens typed JWT. ID tokens stay refused",
};

static SCOPE_CLAIM: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "platform.posture.scope-claim",
    key: "scopeClaim",
    summary: "reads scopes from a claim other than scope",
};

static UNRESTRICTED_CLIENTS: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "platform.posture.unrestricted-clients",
    key: "allowedClients",
    summary: "admits a token from every client this issuer signs for",
};

static ISSUER_ACTOR_KIND: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "platform.posture.issuer-actor-kind",
    key: "actorKind",
    summary: "every token from this issuer is treated as the declared kind",
};

static CLIENT_ACTOR_KINDS: ExplicitProductionSetting = ExplicitProductionSetting {
    code: "platform.posture.client-actor-kinds",
    key: "clientActorKinds",
    summary: "tokens from the named clients are treated as the declared kinds",
};

/// The claim names a scope claim may not take: they identify the caller, so
/// reading scopes from one would grant by identity.
const RESERVED_SCOPE_CLAIMS: [&str; 4] = ["sub", "client_id", "azp", "aud"];

/// The default scope claim.
const DEFAULT_SCOPE_CLAIM: &str = "scope";

/// The access-token type an issuer entry admits.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AccessTokenType {
    /// RFC 9068 access tokens, typed `at+jwt` or `application/at+jwt`.
    #[serde(rename = "at+jwt")]
    AtJwt,
    /// Access tokens typed `JWT`, from a provider that does not type them
    /// `at+jwt`. An ID token stays refused.
    #[serde(rename = "JWT")]
    Jwt,
}

impl ExplicitClass for AccessTokenType {
    const SETTINGS: &'static [&'static ExplicitProductionSetting] = &[&JWT_ACCESS_TOKEN];

    fn explicit_setting(&self) -> Option<&'static ExplicitProductionSetting> {
        match self {
            Self::AtJwt => None,
            Self::Jwt => Some(&JWT_ACCESS_TOKEN),
        }
    }
}

/// The name of the claim that carries scopes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ScopeClaimName(ExternalId);

impl ScopeClaimName {
    /// The claim name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl ExplicitClass for ScopeClaimName {
    const SETTINGS: &'static [&'static ExplicitProductionSetting] = &[&SCOPE_CLAIM];

    fn explicit_setting(&self) -> Option<&'static ExplicitProductionSetting> {
        (self.as_str() != DEFAULT_SCOPE_CLAIM).then_some(&SCOPE_CLAIM)
    }
}

/// An actor kind an operator declares for a caller.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclaredActorKind {
    Human,
    Agent,
    Service,
}

/// The kind every token from one issuer is treated as.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct IssuerActorKind(pub DeclaredActorKind);

impl ExplicitClass for IssuerActorKind {
    const SETTINGS: &'static [&'static ExplicitProductionSetting] = &[&ISSUER_ACTOR_KIND];

    fn explicit_setting(&self) -> Option<&'static ExplicitProductionSetting> {
        Some(&ISSUER_ACTOR_KIND)
    }
}

/// The kind tokens from each named client are treated as, keyed by client
/// identifier. At least one client.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ClientActorKinds(pub BTreeMap<ExternalId, DeclaredActorKind>);

impl<'de> Deserialize<'de> for ClientActorKinds {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let kinds = BTreeMap::<ExternalId, DeclaredActorKind>::deserialize(deserializer)?;
        if kinds.is_empty() {
            return Err(registry_platform_yaml::Invalid::expected(
                "at least one client",
                "List at least one client with its kind, or omit clientActorKinds.",
            )
            .into_error());
        }
        Ok(Self(kinds))
    }
}

impl ExplicitClass for ClientActorKinds {
    const SETTINGS: &'static [&'static ExplicitProductionSetting] = &[&CLIENT_ACTOR_KINDS];

    fn explicit_setting(&self) -> Option<&'static ExplicitProductionSetting> {
        Some(&CLIENT_ACTOR_KINDS)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ClientActorKinds {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ClientActorKinds".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let client = generator.subschema_for::<ExternalId>();
        let kind = generator.subschema_for::<DeclaredActorKind>();
        schemars::json_schema!({
            "type": "object",
            "minProperties": 1,
            "propertyNames": client,
            "additionalProperties": kind,
        })
    }
}

/// What a client rule admits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admitted<'a> {
    /// Exactly the listed clients.
    Listed(&'a [String]),
    /// Every client the issuer verifies.
    Unrestricted,
    /// The clients the governed package names.
    FromPackage,
    /// The clients the runtime's policies name.
    FromPolicies,
}

/// The type of an entry's `allowedClients`. A product picks the one whose
/// forms it offers.
pub trait ClientRule {
    fn admitted(&self) -> Admitted<'_>;
}

/// `allowedClients` where a list or `unrestricted` is written. `unrestricted`
/// is an explicit production setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowedClients {
    Listed(Vec<String>),
    Unrestricted,
}

impl ExplicitClass for OidcAllowedClients {
    const SETTINGS: &'static [&'static ExplicitProductionSetting] = &[&UNRESTRICTED_CLIENTS];

    fn explicit_setting(&self) -> Option<&'static ExplicitProductionSetting> {
        match self {
            Self::Unrestricted(UnrestrictedClients) => Some(&UNRESTRICTED_CLIENTS),
            Self::Listed(ListedClients(_)) => None,
        }
    }
}

impl<'de> Deserialize<'de> for AllowedClients {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(
            match Stated::<OidcAllowedClients>::deserialize(deserializer)?.into_inner() {
                OidcAllowedClients::Unrestricted(UnrestrictedClients) => Self::Unrestricted,
                OidcAllowedClients::Listed(ListedClients(clients)) => Self::Listed(clients),
            },
        )
    }
}

impl Serialize for AllowedClients {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unrestricted => serializer.serialize_str("unrestricted"),
            Self::Listed(clients) => clients.serialize(serializer),
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for AllowedClients {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "OidcAllowedClients".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = <OidcAllowedClients as schemars::JsonSchema>::json_schema(generator);
        schema.insert(
            "x-registry-explicit-production".to_owned(),
            vec![UNRESTRICTED_CLIENTS.code].into(),
        );
        schema
    }
}

impl ClientRule for AllowedClients {
    fn admitted(&self) -> Admitted<'_> {
        match self {
            Self::Listed(clients) => Admitted::Listed(clients),
            Self::Unrestricted => Admitted::Unrestricted,
        }
    }
}

/// `allowedClients` where only a list is offered: at least one client.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ClientList(Vec<String>);

impl<'de> Deserialize<'de> for ClientList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ListedClients::deserialize(deserializer).map(|clients| Self(clients.0))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ClientList {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ListedClients".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <ListedClients as schemars::JsonSchema>::json_schema(generator)
    }
}

impl ClientRule for ClientList {
    fn admitted(&self) -> Admitted<'_> {
        Admitted::Listed(&self.0)
    }
}

const FROM_POLICIES: &str = "from-policies";

/// `allowedClients` where the runtime's policies name the clients: the keyword
/// `from-policies` or a list of at least one client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyClients {
    FromPolicies,
    Listed(Vec<String>),
}

/// The keyword `from-policies`.
struct FromPoliciesKeyword;

impl<'de> Deserialize<'de> for FromPoliciesKeyword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == FROM_POLICIES {
            Ok(Self)
        } else {
            Err(registry_platform_yaml::Invalid::expected(
                "from-policies, or a list of at least one OAuth client",
                "Write from-policies to admit the clients the policies name, or list the OAuth clients whose access tokens are admitted.",
            )
            .into_error())
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for FromPoliciesKeyword {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "FromPoliciesKeyword".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "string", "const": FROM_POLICIES})
    }
}

/// The authored shape of [`PolicyClients`].
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
enum PolicyAllowedClients {
    Keyword(FromPoliciesKeyword),
    Listed(ListedClients),
}

registry_platform_yaml::shape_union!(PolicyAllowedClients { scalar => Keyword, list => Listed });

impl<'de> Deserialize<'de> for PolicyClients {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match PolicyAllowedClients::deserialize(deserializer)? {
            PolicyAllowedClients::Keyword(FromPoliciesKeyword) => Self::FromPolicies,
            PolicyAllowedClients::Listed(ListedClients(clients)) => Self::Listed(clients),
        })
    }
}

impl Serialize for PolicyClients {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::FromPolicies => serializer.serialize_str(FROM_POLICIES),
            Self::Listed(clients) => clients.serialize(serializer),
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for PolicyClients {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PolicyAllowedClients".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <PolicyAllowedClients as schemars::JsonSchema>::json_schema(generator)
    }
}

impl ClientRule for PolicyClients {
    fn admitted(&self) -> Admitted<'_> {
        match self {
            Self::FromPolicies => Admitted::FromPolicies,
            Self::Listed(clients) => Admitted::Listed(clients),
        }
    }
}

impl ClientRule for PackageClients {
    fn admitted(&self) -> Admitted<'_> {
        match self {
            Self::FromPackage => Admitted::FromPackage,
            Self::Unrestricted => Admitted::Unrestricted,
            Self::Listed(clients) => Admitted::Listed(clients),
        }
    }
}

fn default_access_token_type() -> Stated<AccessTokenType> {
    Stated::wrap(AccessTokenType::AtJwt)
}

fn default_scope_claim() -> Stated<ScopeClaimName> {
    Stated::wrap(ScopeClaimName(
        ExternalId::new(DEFAULT_SCOPE_CLAIM).expect("scope is an external identifier"),
    ))
}

/// The members every issuer entry shares. A product's entry holds it through
/// the shared-block marker `registry-platform-yaml/shared-block/oidc-issuer-core`
/// and keeps its own members beside it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "schema",
    schemars(deny_unknown_fields, rename = "CallerIssuerCore_{C}")
)]
pub struct CallerIssuerCore<C> {
    /// The issuer, its audience and where its signing keys come from.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub provider: OidcIssuerConfig,
    /// The access-token type the entry admits. Absent reads `at+jwt`.
    #[serde(default = "default_access_token_type")]
    pub access_token_type: Stated<AccessTokenType>,
    /// The claim that carries scopes. Absent reads `scope`.
    #[serde(default = "default_scope_claim")]
    pub scope_claim: Stated<ScopeClaimName>,
    /// The clients whose tokens the entry admits.
    pub allowed_clients: C,
    /// The kind every token from this issuer is treated as. Absent declares
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Stated<IssuerActorKind>"))]
    pub actor_kind: Option<Stated<IssuerActorKind>>,
    /// The kind tokens from each named client are treated as. Absent declares
    /// none. Not combined with `actorKind`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(with = "Stated<ClientActorKinds>"))]
    pub client_actor_kinds: Option<Stated<ClientActorKinds>>,
}

/// An issuer entry of a product: the shared core and the product's own
/// members.
pub trait CallerIssuerEntry {
    type Clients: ClientRule;

    fn core(&self) -> &CallerIssuerCore<Self::Clients>;
}

/// The shared block `oidc-issuers`: the `issuers` map from an issuer id to an
/// entry. A product holds it through the shared-block marker
/// `registry-platform-yaml/shared-block/oidc-issuers`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "schema",
    schemars(deny_unknown_fields, rename = "CallerIssuers_{E}")
)]
pub struct CallerIssuers<E> {
    /// The issuers a token may come from, by issuer id.
    #[cfg_attr(feature = "schema", schemars(extend("minProperties" = 1)))]
    issuers: BTreeMap<LocalId, E>,
}

impl<E> CallerIssuers<E> {
    /// The entries in issuer id order.
    pub fn iter(&self) -> impl Iterator<Item = (&LocalId, &E)> {
        self.issuers.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.issuers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty()
    }
}

/// One problem the set's check found.
struct Finding {
    code: &'static str,
    pointer: String,
    message: String,
    action: &'static str,
    /// The other location the problem involves, with its note.
    related: Option<(String, String)>,
    /// The members whose values the finding compares. An offline check that
    /// did not fill an expression at, above or below one of them skips it.
    compares: Vec<String>,
}

impl Finding {
    fn new(
        code: &'static str,
        pointer: String,
        message: impl Into<String>,
        action: &'static str,
    ) -> Self {
        Self {
            code,
            compares: vec![pointer.clone()],
            pointer,
            message: message.into(),
            action,
            related: None,
        }
    }

    fn related(mut self, pointer: String, note: String) -> Self {
        self.compares.push(pointer.clone());
        self.related = Some((pointer, note));
        self
    }

    fn compares(mut self, pointer: String) -> Self {
        self.compares.push(pointer);
        self
    }
}

impl<E: CallerIssuerEntry> CallerIssuers<E> {
    /// Check the set and report every problem found. `field` is the JSON
    /// pointer of the `issuers` member, such as `/authentication/oidc/issuers`.
    /// A diagnostic points at the member that holds the problem and has no
    /// position. Entries are read in issuer id order, so "second" below means
    /// the later id, and a message names the first entry's id. An offline
    /// `check` uses [`Self::check_file`] instead.
    ///
    /// Each diagnostic is an error: no issuer, two entries naming one issuer,
    /// a client admitted by two entries, an actor kind declared for the issuer
    /// and for clients together, a client kind for a client the entry does not
    /// admit, an audience that is one of the entry's clients under
    /// `accessTokenType: JWT`, and a scope claim that names an identity claim.
    ///
    /// The client kind rule and the audience rule read the entry's listed
    /// clients. Where `allowedClients` is `from-package` or `from-policies`,
    /// the product runs both again once it has resolved the clients: an
    /// audience that is one of the resolved clients under
    /// `accessTokenType: JWT` is refused as
    /// `platform.oidc.audience-is-a-client`, and a client kind for a client
    /// outside the resolved list as
    /// `platform.oidc.actor-kind-for-unadmitted-client`.
    #[must_use]
    pub fn check(&self, field: &str) -> Vec<Diagnostic> {
        self.findings(field)
            .into_iter()
            .map(|finding| {
                Diagnostic::error(
                    finding.code,
                    finding.pointer,
                    finding.message,
                    finding.action,
                )
            })
            .collect()
    }

    /// [`Self::check`] for an offline check of `file`, whose document kind
    /// is `artifact`. Each diagnostic is positioned at the value it points at,
    /// and a problem that involves another entry lists it in `related`. A
    /// rule that compares a member holding an expression the check did not
    /// fill is skipped, so two stand-ins are never read as a repeat.
    #[must_use]
    pub fn check_file<T>(
        &self,
        field: &str,
        file: &RuntimeFileCheck<T>,
        artifact: &str,
    ) -> Vec<Diagnostic> {
        self.findings(field)
            .into_iter()
            .filter(|finding| {
                !finding
                    .compares
                    .iter()
                    .any(|pointer| file.defers_within(pointer))
            })
            .map(|finding| {
                let mut diagnostic = file.error_at(
                    artifact,
                    finding.code,
                    &finding.pointer,
                    finding.message,
                    finding.action,
                );
                if let Some((pointer, note)) = finding.related {
                    file.add_related_at(&mut diagnostic, &pointer, note);
                }
                diagnostic
            })
            .collect()
    }

    fn findings(&self, field: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        if self.issuers.is_empty() {
            findings.push(Finding::new(
                "platform.oidc.no-issuer",
                field.to_owned(),
                "issuers lists no issuer",
                "List at least one issuer a token may come from.",
            ));
            return findings;
        }
        let base_of = |id: &LocalId| format!("{field}/{}", escape_pointer_segment(id.as_str()));
        let mut issuer_owner: BTreeMap<String, &LocalId> = BTreeMap::new();
        let mut client_owner: BTreeMap<&str, (&LocalId, String)> = BTreeMap::new();
        let mut package_owner: Option<&LocalId> = None;
        let mut policies_owner: Option<&LocalId> = None;
        for (id, entry) in &self.issuers {
            let core = entry.core();
            let base = base_of(id);
            let issuer = core.provider.issuer.to_url().as_str().to_owned();
            match issuer_owner.get(&issuer) {
                Some(first) => findings.push(
                    Finding::new(
                        "platform.oidc.duplicate-issuer",
                        format!("{base}/issuer"),
                        format!("the issuer is already named by the entry {first}"),
                        "Give each entry its own issuer. A token is matched to one entry by its exact issuer.",
                    )
                    .related(
                        format!("{}/issuer", base_of(first)),
                        format!("the entry {first} names this issuer"),
                    ),
                ),
                None => {
                    issuer_owner.insert(issuer, id);
                }
            }
            let admitted = core.allowed_clients.admitted();
            let clients = format!("{base}/allowedClients");
            match admitted {
                Admitted::Listed(listed) => {
                    for (index, client) in listed.iter().enumerate() {
                        let pointer = format!("{clients}/{index}");
                        match client_owner.get(client.as_str()) {
                            Some((first, _)) if *first == id => {}
                            Some((first, listing)) => findings.push(
                                Finding::new(
                                    "platform.oidc.client-in-two-issuers",
                                    pointer,
                                    format!("the client is already admitted by the entry {first}"),
                                    CLIENT_IN_TWO_ISSUERS_ACTION,
                                )
                                .related(
                                    listing.clone(),
                                    format!("the entry {first} admits this client"),
                                ),
                            ),
                            None => {
                                client_owner.insert(client.as_str(), (id, pointer));
                            }
                        }
                    }
                }
                Admitted::FromPackage | Admitted::FromPolicies => {
                    let (owner, source) = match admitted {
                        Admitted::FromPackage => (&mut package_owner, "the package"),
                        _ => (&mut policies_owner, "the policies"),
                    };
                    let taken: Option<&LocalId> = *owner;
                    match taken {
                        Some(first) => findings.push(
                            Finding::new(
                                "platform.oidc.client-in-two-issuers",
                                clients.clone(),
                                format!(
                                    "the entry {first} already reads its clients from {source}"
                                ),
                                CLIENT_IN_TWO_ISSUERS_ACTION,
                            )
                            .related(
                                format!("{}/allowedClients", base_of(first)),
                                format!("the entry {first} reads its clients from {source}"),
                            ),
                        ),
                        None => *owner = Some(id),
                    }
                }
                Admitted::Unrestricted => {}
            }
            if core.actor_kind.is_some() && core.client_actor_kinds.is_some() {
                findings.push(Finding::new(
                    "platform.oidc.actor-kind-twice",
                    format!("{base}/clientActorKinds"),
                    "actorKind and clientActorKinds are both written",
                    "Declare one kind for the whole issuer with actorKind, or one per client with clientActorKinds.",
                ));
            }
            if let (Some(kinds), Admitted::Listed(listed)) = (&core.client_actor_kinds, admitted) {
                for client in kinds
                    .get()
                    .0
                    .keys()
                    .filter(|client| !listed.iter().any(|listed| listed == client.as_str()))
                {
                    findings.push(
                        Finding::new(
                            "platform.oidc.actor-kind-for-unadmitted-client",
                            format!(
                                "{base}/clientActorKinds/{}",
                                escape_pointer_segment(client.as_str())
                            ),
                            "clientActorKinds names a client this entry does not admit",
                            "Name only clients listed in allowedClients, or add the client to allowedClients.",
                        )
                        .compares(clients.clone()),
                    );
                }
            }
            if core.access_token_type.get() == &AccessTokenType::Jwt {
                if let Admitted::Listed(listed) = admitted {
                    if listed.contains(&core.provider.audience) {
                        findings.push(
                            Finding::new(
                                "platform.oidc.audience-is-a-client",
                                format!("{base}/audience"),
                                "with accessTokenType JWT the audience is also one of the entry's clients",
                                "Use an audience that names this service and no client, so an ID token issued to a client is not read as an access token.",
                            )
                            .compares(clients.clone()),
                        );
                    }
                }
            }
            if RESERVED_SCOPE_CLAIMS.contains(&core.scope_claim.get().as_str()) {
                findings.push(Finding::new(
                    "platform.oidc.scope-claim-reserved",
                    format!("{base}/scopeClaim"),
                    "scopeClaim names a claim that identifies the caller",
                    "Name the claim that carries scopes, such as scope or scp.",
                ));
            }
        }
        findings
    }
}

const CLIENT_IN_TWO_ISSUERS_ACTION: &str =
    "Admit each client through one issuer entry, so a client rule binds to one issuer.";

#[cfg(test)]
#[path = "caller_issuers_tests.rs"]
mod tests;
