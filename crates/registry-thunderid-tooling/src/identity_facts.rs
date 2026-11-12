//! The per-product identity facts document (`PlatformIdentityFacts`).
//!
//! Each product that admits OIDC tokens states, once and from its own
//! configuration, what it expects of the issuer: the issuer and audience it
//! trusts, the clients it admits, the claims it reads, the access profiles
//! with their scopes and purposes, and the assertion authorities it accepts.
//! The identity generator merges the documents of every product in a
//! deployment and derives the ThunderID configuration from the result, so a
//! fact is written in one place and never copied by hand.
//!
//! A facts document is a tool-written, read-back format. It names no secret,
//! no path, and no key.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use registry_platform_yaml::{
    ApiVersion, Decoded, Diagnostic, Document, EnvelopeRule, Expect, ExternalId, FormatSpec,
    LocalId, Reader, Report, Severity, UniqueList, Url,
};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::description::protected_attribute;
use crate::ToolingError;

pub const API_VERSION: &str = "id.registrystack.org/formats/platform/identity-facts/v1";
pub const KIND: &str = "PlatformIdentityFacts";

/// The sentinel that states an open admission choice in place of a list.
pub const UNRESTRICTED: &str = "unrestricted";

/// The most clients one admission list names.
pub const MAXIMUM_CLIENTS: usize = 256;
/// The most claims one document declares.
pub const MAXIMUM_CLAIMS: usize = 64;
/// The most access profiles one document declares.
pub const MAXIMUM_PROFILES: usize = 64;
/// The most scopes one access profile carries.
pub const MAXIMUM_SCOPES: usize = 32;
/// The most purposes one access profile carries.
pub const MAXIMUM_PURPOSES: usize = 16;
/// The most values one profile's selector requires of a string-array claim.
/// It matches the largest list a product states (scopes, requester tags).
pub const MAXIMUM_SELECTOR_VALUES: usize = 32;
/// The most assertion issuers one document declares.
pub const MAXIMUM_ASSERTION_ISSUERS: usize = 8;

/// The claim that says what kind of principal a token represents.
pub const ACTOR_KIND_CLAIM: &str = "registry_actor_kind";

/// The longest claim name, scope, purpose or client id, in bytes.
pub const MAXIMUM_NAME_BYTES: usize = 128;

pub const FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// Which clients a product admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Every client the issuer authenticates (`unrestricted`).
    Unrestricted,
    /// Exactly these client ids.
    Clients(Vec<String>),
}

impl Admission {
    pub fn admits(&self, client: &str) -> bool {
        match self {
            Self::Unrestricted => true,
            Self::Clients(clients) => clients.iter().any(|admitted| admitted == client),
        }
    }
}

impl Serialize for Admission {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unrestricted => serializer.serialize_str(UNRESTRICTED),
            Self::Clients(clients) => clients.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Admission {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AdmissionVisitor;
        impl<'de> Visitor<'de> for AdmissionVisitor {
            type Value = Admission;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("`unrestricted` or a list of client ids")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Admission, E> {
                if value == UNRESTRICTED {
                    Ok(Admission::Unrestricted)
                } else {
                    Err(E::custom("write `unrestricted` or a list of client ids"))
                }
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Admission, A::Error> {
                let mut clients = Vec::new();
                while let Some(client) = seq.next_element::<String>()? {
                    clients.push(client);
                }
                UniqueList::new(clients)
                    .map(|clients| Admission::Clients(clients.into_vec()))
                    .map_err(<A::Error as de::Error>::custom)
            }
        }
        deserializer.deserialize_any(AdmissionVisitor)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Admission {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Admission".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let client = generator.subschema_for::<ExternalId>();
        schemars::json_schema!({
            "description": "`unrestricted`, or the exact client ids the product admits.",
            "anyOf": [
                {"const": UNRESTRICTED},
                {"type": "array", "items": client, "uniqueItems": true}
            ]
        })
    }
}

/// The type of a claim's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ClaimType {
    String,
    StringArray,
}

/// The kind of principal a token represents, as `registry_actor_kind`
/// carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    Human,
    Agent,
    Service,
}

impl ActorKind {
    /// The claim value for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }

    /// The kind a claim value names. The products' runtimes parse only
    /// these three lowercase values and refuse a token with any other.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::Human, Self::Agent, Self::Service]
            .into_iter()
            .find(|kind| kind.as_str() == value)
    }
}

/// How an assertion authority's signed claims become token claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AssertionMapping {
    /// An institutional grant: the issuer derives grant provenance.
    InstitutionalGrant,
    /// A first-party signer: only `projectedClaims` are copied.
    FirstParty,
}

/// One external authority whose signed assertions a product accepts for
/// token exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssertionIssuer {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub issuer: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub jwks_url: String,
    pub mapping: AssertionMapping,
    /// The signed claims a first-party signer projects, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub projected_claims: BTreeMap<String, ClaimType>,
}

/// A profile that is reached by exchanging an assertion, not by presenting
/// its scopes directly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExchangeBinding {
    /// The `id` of an entry of `assertionIssuers`.
    pub assertion_issuer_id: String,
    /// The audience of the resource that accepts the assertion.
    pub bootstrap_audience: String,
    /// The one scope a client holds to present an assertion.
    pub bootstrap_scope: String,
}

/// One access profile: the scopes (and, where it is bound to them, the
/// purposes) a client receives by being granted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AccessProfile {
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "set")]
    pub scopes: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "set"
    )]
    pub purposes: Vec<String>,
    /// Narrows `allowedClients` for this profile; omitted narrows nothing.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_set"
    )]
    pub requester_clients: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange: Option<ExchangeBinding>,
    /// The claim values by which the product selects this profile: for each
    /// claim name, the values a principal's claim must carry. A `string`
    /// claim names exactly one value; a `string-array` claim names at least
    /// one, all of which the principal must carry. Omitted: the product
    /// does not select this profile by claim values, so no claim check
    /// applies to it.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "sets_by_name"
    )]
    pub selected_by: BTreeMap<String, Vec<String>>,
    /// The `registry_actor_kind` the product requires of every principal
    /// that holds this profile, when it requires one without selecting the
    /// profile by it. A product that selects by the claim states it in
    /// `selectedBy` instead. On an exchange profile it is the kind the
    /// product requires of the client's own bootstrap token, which the
    /// product checks before it issues the assertion. Omitted: the profile
    /// admits any kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<ActorKind>,
    /// Declared claims the product refuses a token for this profile without.
    /// The token subject (`sub`) is always present and is never listed. A
    /// claim the generator derives (`registry_actor_kind`,
    /// `registry_purpose`) counts as carried. Omitted: the profile requires
    /// no claim beyond those the other members state.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "set"
    )]
    pub required_claims: Vec<String>,
    /// The `registry_actor_kind` values the product admits for this profile
    /// without selecting it by them, when it admits only some kinds. A
    /// profile that selects by the claim, or requires one kind, states that
    /// in `selectedBy` or `actorKind` instead. Omitted: the profile admits
    /// any kind.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "set"
    )]
    pub admitted_actor_kinds: Vec<ActorKind>,
    /// Declared claims the product refuses a token for this profile with:
    /// it never selects the profile for a principal that carries any of
    /// them. On an exchange profile the product applies it to the exchanged
    /// token, not to the client's own. Omitted: no claim refuses the
    /// profile.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "set"
    )]
    pub refused_claims: Vec<String>,
}

/// What one product expects of the issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IdentityFacts {
    pub api_version: String,
    pub kind: String,
    /// The product that wrote these facts, as a local identifier.
    pub product: String,
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub issuer: String,
    pub audience: String,
    pub allowed_clients: Admission,
    /// The claims the product reads from a token, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, ClaimType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access_profiles: Vec<AccessProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_issuers: Vec<AssertionIssuer>,
}

impl IdentityFacts {
    /// A document with the envelope filled in and nothing else stated.
    pub fn new(product: &str, issuer: &str, audience: &str, allowed_clients: Admission) -> Self {
        Self {
            api_version: API_VERSION.to_owned(),
            kind: KIND.to_owned(),
            product: product.to_owned(),
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            allowed_clients,
            claims: BTreeMap::new(),
            access_profiles: Vec::new(),
            assertion_issuers: Vec::new(),
        }
    }

    /// The document as YAML, with `apiVersion` and `kind` first (CFG-ENV-5).
    pub fn to_yaml(&self) -> Result<String, ToolingError> {
        serde_norway::to_string(self).map_err(|_| ToolingError::InvalidRender {
            reason: "an identity facts document did not serialize as YAML",
        })
    }
}

/// Whether `text` could open or close a template expression. Deployment
/// output carries `{{.NAME}}` placeholders the generator writes itself, so
/// no input string may contain either delimiter.
pub(crate) fn has_template_syntax(text: &str) -> bool {
    text.contains("{{") || text.contains("}}")
}

/// Findings for every string or member name of `document` that holds template
/// syntax. One validator for every copied string: it reads the parsed
/// document, so a delimiter spelled with a YAML escape is found too.
pub(crate) fn template_findings(document: &Document) -> Vec<Diagnostic> {
    fn walk(value: &serde_json::Value, pointer: &str, found: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) if has_template_syntax(text) => {
                found.push(pointer.to_owned());
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, &format!("{pointer}/{index}"), found);
                }
            }
            serde_json::Value::Object(members) => {
                for (name, member) in members {
                    let at = format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1"));
                    if has_template_syntax(name) {
                        found.push(at.clone());
                    }
                    walk(member, &at, found);
                }
            }
            _ => {}
        }
    }
    let mut pointers = Vec::new();
    walk(&document.to_json_value(), "", &mut pointers);
    pointers
        .iter()
        .map(|pointer| {
            document.diagnostic_at_value(
                Severity::Error,
                "identity.input.template-syntax",
                pointer,
                "a value contains `{{` or `}}`, which the generated files reserve for secret placeholders",
                "Remove the braces; secrets are written only as secret:env/NAME references.",
            )
        })
        .collect()
}

/// Names owned by JWT, token exchange, JWT access tokens and OpenID Connect
/// (RFC 7519, RFC 8693, RFC 9068, OIDC Core), or by the native ThunderID user
/// schema. A custom claim must not shadow a protocol claim or a native field.
const RESERVED_CLAIM_NAMES: [&str; 36] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "scope",
    "scp",
    "client_id",
    "azp",
    "act",
    "may_act",
    "cnf",
    "nonce",
    "auth_time",
    "acr",
    "amr",
    "at_hash",
    "c_hash",
    "sid",
    "sub_jwk",
    "roles",
    "groups",
    "entitlements",
    "authorization_details",
    "email",
    "email_verified",
    "name",
    "preferred_username",
    "given_name",
    "family_name",
    "phone_number",
    "address",
    "username",
    "password",
];

pub(crate) fn valid_claim_name(name: &str) -> bool {
    !RESERVED_CLAIM_NAMES.contains(&name)
        && !name.is_empty()
        && name.len() <= MAXIMUM_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn valid_scope(scope: &str) -> bool {
    scope.len() <= MAXIMUM_NAME_BYTES
        && !scope.contains('*')
        && crate::validate::valid_scope_token(scope)
}

pub(crate) fn valid_client_id(client: &str) -> bool {
    client.len() <= MAXIMUM_NAME_BYTES
        && client != "*"
        && client != UNRESTRICTED
        && ExternalId::new(client).is_ok()
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_NAME_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// An `https` URL without user information, query or fragment.
pub(crate) fn https_url(value: &str) -> bool {
    Url::new(value).is_ok()
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

/// An `https` URL, or `http` to 127.0.0.1, without user information, query
/// or fragment. A facts document may describe a development issuer.
fn issuer_url(value: &str) -> bool {
    https_url(value)
        || (Url::new(value).is_ok()
            && url::Url::parse(value).is_ok_and(|url| {
                url.scheme() == "http"
                    && url.host_str() == Some("127.0.0.1")
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            }))
}

fn unique(items: &[String]) -> bool {
    items.iter().collect::<BTreeSet<_>>().len() == items.len()
}

/// Read a list the schema declares a set, so the shared reader refuses a
/// repeat at the repeat with `config.duplicate-item` (CFG-ID-6).
pub(crate) fn set<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + std::hash::Hash,
{
    UniqueList::<T>::deserialize(deserializer).map(UniqueList::into_vec)
}

/// [`set`] for a member that may be omitted.
fn optional_set<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    Option::<UniqueList<String>>::deserialize(deserializer)
        .map(|list| list.map(UniqueList::into_vec))
}

/// [`set`] for each value of a mapping.
fn sets_by_name<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error> {
    BTreeMap::<String, UniqueList<String>>::deserialize(deserializer).map(|sets| {
        sets.into_iter()
            .map(|(name, values)| (name, values.into_vec()))
            .collect()
    })
}

/// Read one facts document through the shared reader and check it.
/// `file` is the name every diagnostic carries.
pub fn read(file: &str, bytes: &[u8]) -> Result<IdentityFacts, ToolingError> {
    let refused = |report: Report| ToolingError::FileRefused {
        what: "an identity facts document",
        fix: "Regenerate it with the product's `generate identity-facts` command.",
        report: Box::new(report),
    };
    let mut hook = registry_platform_config::AuthoredExpressions;
    let Decoded { value, document } = Reader::new(file)
        .with_hook(&mut hook)
        .decode::<IdentityFacts>(bytes, &Expect::one(&FORMAT))
        .map_err(refused)?;
    let mut found = check(&document, &value);
    found.extend(template_findings(&document));
    if found.is_empty() {
        return Ok(value);
    }
    let mut report = document.warnings();
    for diagnostic in found {
        report.push(diagnostic);
    }
    Err(refused(report))
}

/// What the types do not check. Repeats no value (CFG-SEC-3).
fn check(document: &Document, facts: &IdentityFacts) -> Vec<Diagnostic> {
    let mut found = Vec::new();
    let mut error = |pointer: &str, code: &str, message: &str, action: &str| {
        found.push(document.diagnostic_at_value(Severity::Error, code, pointer, message, action));
    };
    if LocalId::new(facts.product.clone()).is_err() {
        error(
            "/product",
            "identity.facts.invalid-product",
            "the product is not a local identifier",
            "Write the product as 1 to 64 lowercase letters, digits, `-` or `_`.",
        );
    }
    if !issuer_url(&facts.issuer) {
        error(
            "/issuer",
            "identity.facts.invalid-issuer",
            "the issuer is neither https nor http to 127.0.0.1, or carries user information, a query or a fragment",
            "Write the issuer URL the product trusts.",
        );
    }
    if !crate::validate::valid_resource_uri(&facts.audience) {
        error(
            "/audience",
            "identity.facts.invalid-audience",
            "the audience is not an absolute URI without a fragment or user information",
            "Write the audience tokens for this product carry.",
        );
    }
    if let Admission::Clients(clients) = &facts.allowed_clients {
        if clients.is_empty() {
            error(
                "/allowedClients",
                "identity.facts.empty-admission",
                "an empty list admits no client",
                "List the admitted clients, or write `unrestricted` to admit every client.",
            );
        }
        if clients.len() > MAXIMUM_CLIENTS
            || !unique(clients)
            || clients.iter().any(|client| !valid_client_id(client))
        {
            error(
                "/allowedClients",
                "identity.facts.invalid-clients",
                "the admitted clients are more than 256, repeated, or not client ids",
                "List each admitted client id once; `unrestricted` replaces the list.",
            );
        }
    }
    if facts.claims.len() > MAXIMUM_CLAIMS {
        error(
            "/claims",
            "identity.facts.too-many-claims",
            "more than 64 claims are declared",
            "Declare at most 64 claims.",
        );
    }
    for name in facts.claims.keys() {
        if !valid_claim_name(name) || protected_attribute(name) {
            error(
                "/claims",
                "identity.facts.invalid-claim",
                "a claim name is not a bounded token attribute name, or names the protected grant namespace",
                "Use letters, digits and `_`, and not a registry_grant_ name.",
            );
        }
    }
    let issuer_ids: BTreeSet<&str> = facts
        .assertion_issuers
        .iter()
        .map(|issuer| issuer.id.as_str())
        .collect();
    if facts.assertion_issuers.len() > MAXIMUM_ASSERTION_ISSUERS
        || issuer_ids.len() != facts.assertion_issuers.len()
    {
        error(
            "/assertionIssuers",
            "identity.facts.invalid-assertion-issuers",
            "more than eight assertion issuers are declared, or an id is repeated",
            "Declare each assertion issuer once, at most eight.",
        );
    }
    for (index, issuer) in facts.assertion_issuers.iter().enumerate() {
        let pointer = |member: &str| format!("/assertionIssuers/{index}/{member}");
        if LocalId::new(issuer.id.clone()).is_err() {
            error(
                &pointer("id"),
                "identity.facts.invalid-id",
                "the id is not a local identifier",
                "Write the id as 1 to 64 lowercase letters, digits, `-` or `_`.",
            );
        }
        for member in ["issuer", "jwksUrl"] {
            let value = if member == "issuer" {
                &issuer.issuer
            } else {
                &issuer.jwks_url
            };
            if !https_url(value) {
                error(
                    &pointer(member),
                    "identity.facts.invalid-assertion-url",
                    "an assertion issuer URL must be https without user information, a query or a fragment",
                    "Write the authority's https URL.",
                );
            }
        }
        if issuer.mapping == AssertionMapping::InstitutionalGrant
            && !issuer.projected_claims.is_empty()
        {
            error(
                &pointer("projectedClaims"),
                "identity.facts.unexpected-projection",
                "an institutional grant mapping projects no first-party claims",
                "Remove projectedClaims, or use the first-party mapping.",
            );
        }
        if issuer.projected_claims.len() > crate::description::MAX_FIRST_PARTY_TOKEN_ATTRIBUTES
            || issuer
                .projected_claims
                .keys()
                .any(|name| !valid_claim_name(name) || protected_attribute(name))
        {
            error(
                &pointer("projectedClaims"),
                "identity.facts.invalid-claim",
                "a projected claim name is invalid, protected, or more than 16 are declared",
                "Project at most 16 claims with letters, digits and `_`.",
            );
        }
    }
    if facts.access_profiles.len() > MAXIMUM_PROFILES {
        error(
            "/accessProfiles",
            "identity.facts.too-many-profiles",
            "more than 64 access profiles are declared",
            "Declare at most 64 access profiles.",
        );
    }
    let mut profile_ids = BTreeSet::new();
    for (index, profile) in facts.access_profiles.iter().enumerate() {
        let pointer = |member: &str| format!("/accessProfiles/{index}/{member}");
        if LocalId::new(profile.id.clone()).is_err() || !profile_ids.insert(profile.id.as_str()) {
            error(
                &pointer("id"),
                "identity.facts.invalid-id",
                "the id is not a local identifier, or repeats an earlier profile",
                "Write each profile id once, as 1 to 64 lowercase letters, digits, `-` or `_`.",
            );
        }
        if profile.scopes.is_empty()
            || profile.scopes.len() > MAXIMUM_SCOPES
            || !unique(&profile.scopes)
            || profile.scopes.iter().any(|scope| !valid_scope(scope))
        {
            error(
                &pointer("scopes"),
                "identity.facts.invalid-scopes",
                "the scopes are empty, more than 32, repeated, or not exact scope tokens",
                "List 1 to 32 distinct exact scopes without `*`.",
            );
        }
        if profile.purposes.len() > MAXIMUM_PURPOSES
            || !unique(&profile.purposes)
            || profile.purposes.iter().any(|purpose| !valid_text(purpose))
        {
            error(
                &pointer("purposes"),
                "identity.facts.invalid-purposes",
                "the purposes are more than 16, repeated, or not bounded printable text",
                "List at most 16 distinct purposes.",
            );
        }
        if profile.selected_by.len() > MAXIMUM_CLAIMS
            || profile.selected_by.iter().any(|(name, values)| {
                let fits = match facts.claims.get(name) {
                    Some(ClaimType::String) => values.len() == 1,
                    Some(ClaimType::StringArray) => {
                        !values.is_empty() && values.len() <= MAXIMUM_SELECTOR_VALUES
                    }
                    None => false,
                };
                !fits || !unique(values) || values.iter().any(|value| !valid_text(value))
            })
        {
            error(
                &pointer("selectedBy"),
                "identity.facts.invalid-selector",
                "a selector names an undeclared claim, or its values do not fit the claim's type, repeat, or are not bounded printable text",
                "Name declared claims only: one value for a string claim, 1 to 32 distinct values for a string-array claim.",
            );
        }
        if profile
            .selected_by
            .get(ACTOR_KIND_CLAIM)
            .is_some_and(|kinds| kinds.iter().any(|kind| ActorKind::parse(kind).is_none()))
        {
            error(
                &pointer("selectedBy"),
                "identity.facts.unknown-actor-kind",
                "the profile is selected by a registry_actor_kind value the runtime does not parse",
                "Select by human, agent or service.",
            );
        }
        if profile.actor_kind.is_some()
            && facts.claims.get(ACTOR_KIND_CLAIM) != Some(&ClaimType::String)
        {
            error(
                &pointer("actorKind"),
                "identity.facts.undeclared-actor-kind",
                "the profile requires an actor kind, and registry_actor_kind is not declared as a string claim",
                "Declare registry_actor_kind: string under claims, or remove actorKind.",
            );
        }
        if !profile.admitted_actor_kinds.is_empty() {
            if profile.actor_kind.is_some() || profile.selected_by.contains_key(ACTOR_KIND_CLAIM) {
                error(
                    &pointer("admittedActorKinds"),
                    "identity.facts.conflicting-actor-kinds",
                    "the profile states the kinds it admits and also requires or selects by a kind",
                    "State admittedActorKinds, actorKind, or a registry_actor_kind selector, not more than one.",
                );
            }
            if facts.claims.get(ACTOR_KIND_CLAIM) != Some(&ClaimType::String) {
                error(
                    &pointer("admittedActorKinds"),
                    "identity.facts.undeclared-actor-kind",
                    "the profile admits only some actor kinds, and registry_actor_kind is not declared as a string claim",
                    "Declare registry_actor_kind: string under claims, or remove admittedActorKinds.",
                );
            }
        }
        if profile.refused_claims.len() > MAXIMUM_CLAIMS
            || !unique(&profile.refused_claims)
            || profile.refused_claims.iter().any(|name| {
                !facts.claims.contains_key(name) || profile.required_claims.contains(name)
            })
        {
            error(
                &pointer("refusedClaims"),
                "identity.facts.invalid-refused-claims",
                "a refused claim is not declared under claims, is repeated, or is also required",
                "List each refused claim once, declare it under claims, and do not also require it.",
            );
        }
        if profile.required_claims.len() > MAXIMUM_CLAIMS
            || !unique(&profile.required_claims)
            || profile
                .required_claims
                .iter()
                .any(|name| !facts.claims.contains_key(name))
        {
            error(
                &pointer("requiredClaims"),
                "identity.facts.invalid-required-claims",
                "a required claim is not declared under claims, or is repeated",
                "List each required claim once, and declare it under claims with its type.",
            );
        }
        if let Some(clients) = &profile.requester_clients {
            if clients.is_empty()
                || clients.len() > MAXIMUM_CLIENTS
                || !unique(clients)
                || clients.iter().any(|client| !valid_client_id(client))
            {
                error(
                    &pointer("requesterClients"),
                    "identity.facts.invalid-clients",
                    "the requester clients are empty, repeated, or not client ids",
                    "List each requester client once, or omit the member to narrow nothing.",
                );
            }
        }
        if let Some(exchange) = &profile.exchange {
            if !issuer_ids.contains(exchange.assertion_issuer_id.as_str()) {
                error(
                    &pointer("exchange/assertionIssuerId"),
                    "identity.facts.unknown-assertion-issuer",
                    "the exchange names no declared assertion issuer",
                    "Name the id of an entry of assertionIssuers.",
                );
            }
            if !crate::validate::valid_resource_uri(&exchange.bootstrap_audience)
                || !valid_scope(&exchange.bootstrap_scope)
            {
                error(
                    &pointer("exchange"),
                    "identity.facts.invalid-exchange",
                    "the bootstrap audience is not an absolute URI, or the bootstrap scope is not an exact scope",
                    "Write the audience and the one scope that present an assertion.",
                );
            }
        }
    }
    found
}

/// One product's facts after merging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductFacts {
    pub audience: String,
    pub allowed_clients: Admission,
    pub access_profiles: BTreeMap<String, AccessProfile>,
    /// The claims this product reads, with their types.
    pub claims: BTreeMap<String, ClaimType>,
}

/// The facts of every product in one deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedFacts {
    /// The one issuer every product trusts.
    pub issuer: String,
    pub products: BTreeMap<String, ProductFacts>,
    /// Every claim any product reads, with its one type.
    pub claims: BTreeMap<String, ClaimType>,
    pub assertion_issuers: BTreeMap<String, AssertionIssuer>,
}

fn refuse(code: &'static str, message: &'static str, location: String) -> ToolingError {
    ToolingError::IdentityRefused {
        code,
        message,
        location,
    }
}

/// Merge the facts documents of several products. Refuses when the products
/// trust different issuers, when one claim is declared with two types, when
/// a product or an audience is stated twice, or when an assertion issuer is
/// stated two different ways. `facts[n]` in a refusal is the n-th document.
pub fn merge(documents: Vec<IdentityFacts>) -> Result<MergedFacts, ToolingError> {
    let Some(first) = documents.first() else {
        return Err(refuse(
            "identity.facts.none",
            "no identity facts were supplied",
            "facts".to_owned(),
        ));
    };
    let issuer = first.issuer.clone();
    let mut merged = MergedFacts {
        issuer,
        products: BTreeMap::new(),
        claims: BTreeMap::new(),
        assertion_issuers: BTreeMap::new(),
    };
    let mut audiences = BTreeSet::new();
    let mut issuer_urls: BTreeMap<String, String> = BTreeMap::new();
    for (index, facts) in documents.into_iter().enumerate() {
        let location = format!("facts[{index}]");
        if facts.issuer != merged.issuer {
            return Err(refuse(
                "identity.facts.issuer-mismatch",
                "the products trust different issuers",
                format!("{location}/issuer"),
            ));
        }
        if merged.products.contains_key(&facts.product) {
            return Err(refuse(
                "identity.facts.duplicate-product",
                "a product states its facts twice",
                format!("{location}/product"),
            ));
        }
        if !audiences.insert(facts.audience.clone()) {
            return Err(refuse(
                "identity.facts.duplicate-audience",
                "two products share one audience",
                format!("{location}/audience"),
            ));
        }
        for (name, kind) in &facts.claims {
            if merged
                .claims
                .insert(name.clone(), *kind)
                .is_some_and(|prior| prior != *kind)
            {
                return Err(refuse(
                    "identity.facts.claim-conflict",
                    "one claim is declared with two types",
                    format!("{location}/claims"),
                ));
            }
        }
        for (position, issuer) in facts.assertion_issuers.iter().enumerate() {
            let at = format!("{location}/assertionIssuers/{position}");
            match merged.assertion_issuers.get(&issuer.id) {
                Some(existing) if existing != issuer => {
                    return Err(refuse(
                        "identity.facts.assertion-issuer-conflict",
                        "one assertion issuer id is stated two different ways",
                        at,
                    ));
                }
                Some(_) => {}
                None => {
                    if issuer_urls
                        .insert(issuer.issuer.clone(), issuer.id.clone())
                        .is_some()
                    {
                        return Err(refuse(
                            "identity.facts.assertion-issuer-conflict",
                            "one assertion issuer URL is declared under two ids",
                            at,
                        ));
                    }
                    merged
                        .assertion_issuers
                        .insert(issuer.id.clone(), issuer.clone());
                }
            }
        }
        merged.products.insert(
            facts.product,
            ProductFacts {
                audience: facts.audience,
                allowed_clients: facts.allowed_clients,
                access_profiles: facts
                    .access_profiles
                    .into_iter()
                    .map(|profile| (profile.id.clone(), profile))
                    .collect(),
                claims: facts.claims,
            },
        );
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    include!("identity_facts_tests.rs");
}
