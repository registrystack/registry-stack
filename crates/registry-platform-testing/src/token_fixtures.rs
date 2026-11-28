// SPDX-License-Identifier: Apache-2.0
//! The token fixture corpus, a test-time signer and a closure-driven driver.
//!
//! The corpus lives in `products/platform/conformance/tokens`: one decoded token
//! shape per file under `fixtures/`, and `expected.yaml` with the expected result
//! for every fixture, product and configuration. A fixture holds no signature and
//! no key. [`TokenSigner`] makes a fresh key per algorithm when it is built, keeps
//! it in memory only, and signs a fixture's header and claims with the algorithm
//! the fixture declares. [`TokenCorpus::run_product`] takes a product's
//! authentication as a closure, runs every applicable fixture through it, and
//! compares the results with `expected.yaml` for that product.
//!
//! A product's test depends on this crate and passes its own authenticator in, so
//! no product depends on another.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use futures::FutureExt as _;
use jsonwebtoken::{crypto, Algorithm, DecodingKey, EncodingKey};
use rand::Rng as _;
use registry_platform_crypto::jws::sign_compact_jws;
use registry_platform_crypto::{
    generate_private_jwk, verify as verify_with_public_jwk, GeneratedKeyAlgorithm, LocalJwkSigner,
    PrivateJwk, PublicJwk,
};
use registry_platform_oidc::{ActorKind, OidcError, OPENID_CONNECT_SCOPES};
use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec, Reader};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

const FIXTURE_SCHEMA: &str = "registry.token-fixture/v1";
const EXPECTATIONS_SCHEMA: &str = "registry.token-fixture-expectations/v1";
/// `expected.yaml` is test data with a `schema` member and no `apiVersion` or `kind` envelope.
const EXPECTATIONS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "TokenFixtureExpectations",
    envelope: EnvelopeRule::Exempt {
        reason: "test data checked by the token fixture corpus tests, not a configuration file",
    },
    removed_keys: &[],
};
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];
const SIGNING_ALGORITHMS: [&str; 5] = ["RS256", "ES256", "EdDSA", "HS256", "HS512"];

/// Why a corpus file did not load, validate, sign or run.
#[derive(Debug, Error)]
pub enum TokenFixtureError {
    #[error("token fixture corpus: cannot read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("token fixture `{fixture}`: {reason}")]
    Invalid { fixture: String, reason: String },
    #[error("token fixture expectations: {0}")]
    Expectations(String),
    #[error("token fixture `{fixture}`: cannot sign: {reason}")]
    Signing { fixture: String, reason: String },
    #[error("token fixture signature: {0}")]
    Verification(String),
    #[error("token fixture driver: product `{0}` is not a column of expected.yaml")]
    UnknownProduct(String),
}

fn invalid(fixture: &str, reason: impl Into<String>) -> TokenFixtureError {
    TokenFixtureError::Invalid {
        fixture: fixture.to_owned(),
        reason: reason.into(),
    }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// The check at which a product refused a token: the shared verifier's labels,
/// `claims` for a product's own claim extraction, and `actor-kind` for the
/// caller's actor kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stage {
    Header,
    Algorithm,
    TokenType,
    Key,
    Signature,
    Issuer,
    Audience,
    Time,
    Client,
    Scope,
    Profile,
    Unavailable,
    Claims,
    ActorKind,
}

const STAGES: [(Stage, &str); 14] = [
    (Stage::Header, "header"),
    (Stage::Algorithm, "algorithm"),
    (Stage::TokenType, "token-type"),
    (Stage::Key, "key"),
    (Stage::Signature, "signature"),
    (Stage::Issuer, "issuer"),
    (Stage::Audience, "audience"),
    (Stage::Time, "time"),
    (Stage::Client, "client"),
    (Stage::Scope, "scope"),
    (Stage::Profile, "profile"),
    (Stage::Unavailable, "unavailable"),
    (Stage::Claims, "claims"),
    (Stage::ActorKind, "actor-kind"),
];

impl Stage {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        STAGES
            .iter()
            .find(|(stage, _)| *stage == self)
            .map_or("unknown-stage", |(_, name)| name)
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of running one token through one product. The text forms are the
/// values `expected.yaml` uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `admitted` (no actor kind) or `admitted/<actor kind>`, where the kind
    /// may be `unspecified`.
    Admitted(Option<String>),
    /// `refused/<stage>`.
    Refused(Stage),
    /// `none`: the configuration needs a setting the product does not have.
    None,
    /// `n-a`: the product has no such concept.
    NotApplicable,
    /// `unknown`: not determined.
    Unknown,
}

impl Outcome {
    /// The characterisation result value for a verifier error, `refused/<stage>`.
    /// It names the stage a corpus row records, so the expected table stays
    /// comparable across products. Runtimes log and count the same refusal by
    /// `FailedCheck`, not by this value.
    ///
    /// # Panics
    ///
    /// On an `OidcError` variant added without a stage here.
    #[must_use]
    pub fn refused_by(error: &OidcError) -> Self {
        use OidcError as E;
        let stage = match error {
            E::MalformedToken | E::InvalidToken | E::SubjectMismatch => Stage::Header,
            E::AlgorithmNotAllowed => Stage::Algorithm,
            E::TokenTypeNotAllowed | E::IdTokenPresented => Stage::TokenType,
            E::MissingKid | E::KidTooLong | E::UnknownKid => Stage::Key,
            E::SignatureInvalid => Stage::Signature,
            E::IssuerMismatch { .. } | E::IssuerNotConfigured => Stage::Issuer,
            E::AudienceMismatch => Stage::Audience,
            E::TokenExpired | E::TokenNotYetValid | E::InvalidTimeClaims => Stage::Time,
            E::ClientNotAllowed | E::AssertionIssuerNotAllowed => Stage::Client,
            E::ActorKindConflict | E::ActorKindMalformed | E::IdentityOnly => Stage::ActorKind,
            E::Transport(_)
            | E::BoundedRead(_)
            | E::FetchUrl(_)
            | E::HttpStatus(_)
            | E::InvalidUrl
            | E::Parse
            | E::InvalidJwk
            | E::EmptyKeySet
            | E::StaticKeySet(_)
            | E::MissingIssuer
            | E::ConflictingEndpointConfiguration
            | E::InsecureHttpRequiresOptIn
            | E::EndpointRefused { .. } => Stage::Unavailable,
            other => panic!("no characterisation stage is recorded for {other:?}"),
        };
        Self::Refused(stage)
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admitted(None) => f.write_str("admitted"),
            Self::Admitted(Some(kind)) => write!(f, "admitted/{kind}"),
            Self::Refused(stage) => write!(f, "refused/{stage}"),
            Self::None => f.write_str("none"),
            Self::NotApplicable => f.write_str("n-a"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

impl FromStr for Outcome {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "admitted" => return Ok(Self::Admitted(None)),
            "none" => return Ok(Self::None),
            "n-a" => return Ok(Self::NotApplicable),
            "unknown" => return Ok(Self::Unknown),
            _ => {}
        }
        if let Some(kind) = text.strip_prefix("admitted/") {
            let well_formed = !kind.is_empty()
                && kind
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            return if well_formed {
                Ok(Self::Admitted(Some(kind.to_owned())))
            } else {
                Err(format!("`{text}` names no actor kind"))
            };
        }
        if let Some(stage) = text.strip_prefix("refused/") {
            return STAGES
                .iter()
                .find(|(_, name)| *name == stage)
                .map(|(stage, _)| Self::Refused(*stage))
                .ok_or_else(|| format!("`{text}` names no known stage"));
        }
        Err(format!("`{text}` is not a result value"))
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureClass {
    Positive,
    Negative,
}

/// The issuer or audience a claim takes from the product under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindTarget {
    Issuer,
    Audience,
}

/// A claim value: plain JSON, or one of three directives.
#[derive(Debug, Clone, PartialEq)]
pub enum ClaimValue {
    Literal(Value),
    Bind(BindTarget),
    /// Seconds after the moment of signing.
    OffsetSeconds(i64),
    /// A random value made at signing time.
    Generated,
}

/// The JOSE header a fixture declares. `kid` is always generated at signing time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureHeader {
    pub alg: String,
    pub typ: Option<String>,
}

/// One decoded token shape.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenFixture {
    pub id: String,
    pub class: FixtureClass,
    pub provider: String,
    pub kind: String,
    pub token_use: String,
    pub subject_kind: String,
    /// The `source` object, kept as written.
    pub source: Value,
    pub header: Option<FixtureHeader>,
    pub claims: BTreeMap<String, ClaimValue>,
    /// A credential that is not a JWT, as a synthetic string.
    pub opaque: Option<String>,
    pub omits: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawFixture {
    schema: String,
    id: String,
    class: FixtureClass,
    provider: String,
    kind: String,
    token_use: String,
    subject_kind: String,
    source: Value,
    header: Option<RawHeader>,
    claims: Option<Map<String, Value>>,
    opaque: Option<String>,
    omits: Option<Vec<String>>,
    notes: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeader {
    alg: String,
    typ: Option<String>,
    kid: Value,
}

impl TokenFixture {
    /// The first value of the claim `claim` that is not an OpenID Connect
    /// scope: a space-separated string, or the first string of an array. `None`
    /// when the claim is absent or holds only OpenID Connect scopes.
    #[must_use]
    pub fn read_scope(&self, claim: &str) -> Option<String> {
        match self.claims.get(claim) {
            Some(ClaimValue::Literal(Value::String(text))) => text
                .split_whitespace()
                .find(|scope| !OPENID_CONNECT_SCOPES.contains(scope))
                .map(str::to_owned),
            Some(ClaimValue::Literal(Value::Array(items))) => items
                .iter()
                .filter_map(Value::as_str)
                .find(|scope| !OPENID_CONNECT_SCOPES.contains(scope))
                .map(str::to_owned),
            _ => None,
        }
    }

    /// Parse and validate one fixture file. `file_stem` is the file name without
    /// its extension and must equal the fixture's `id`.
    pub fn parse(file_stem: &str, text: &str) -> Result<Self, TokenFixtureError> {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| invalid(file_stem, format!("not valid JSON: {error}")))?;
        reject_key_material(file_stem, &value)?;
        let raw: RawFixture =
            serde_json::from_value(value).map_err(|error| invalid(file_stem, error.to_string()))?;
        if raw.schema != FIXTURE_SCHEMA {
            return Err(invalid(
                file_stem,
                format!("schema must be `{FIXTURE_SCHEMA}`"),
            ));
        }
        if raw.id != file_stem {
            return Err(invalid(
                file_stem,
                format!("id `{}` differs from the file name", raw.id),
            ));
        }
        if raw.source.get("basis").and_then(Value::as_str).is_none() {
            return Err(invalid(file_stem, "source.basis is required"));
        }
        let omits = raw.omits.clone().unwrap_or_default();
        let fixture = match (raw.opaque, raw.header, raw.claims) {
            (Some(opaque), None, None) if omits.is_empty() && !opaque.is_empty() => {
                (Some(opaque), None, BTreeMap::new())
            }
            (Some(_), ..) => return Err(invalid(
                file_stem,
                "an opaque fixture holds no header, claims or omits, and a JWT fixture no opaque",
            )),
            (None, Some(header), Some(claims)) => {
                let header = parse_header(file_stem, header)?;
                let claims = parse_claims(file_stem, &claims)?;
                (None, Some(header), claims)
            }
            (None, ..) => {
                return Err(invalid(
                    file_stem,
                    "a fixture holds opaque, or both header and claims",
                ))
            }
        };
        let (opaque, header, claims) = fixture;
        for omitted in &omits {
            if claims.contains_key(omitted) {
                return Err(invalid(
                    file_stem,
                    format!("omits names claim `{omitted}`, which the fixture sets"),
                ));
            }
        }
        Ok(Self {
            id: raw.id,
            class: raw.class,
            provider: raw.provider,
            kind: raw.kind,
            token_use: raw.token_use,
            subject_kind: raw.subject_kind,
            source: raw.source,
            header,
            claims,
            opaque,
            omits,
            notes: raw.notes,
        })
    }
}

fn parse_header(fixture: &str, raw: RawHeader) -> Result<FixtureHeader, TokenFixtureError> {
    if !SIGNING_ALGORITHMS.contains(&raw.alg.as_str()) {
        return Err(invalid(
            fixture,
            format!(
                "header alg `{}` is not one of {SIGNING_ALGORITHMS:?}",
                raw.alg
            ),
        ));
    }
    if raw.kid != json!({ "generated": true }) {
        return Err(invalid(fixture, "header kid must be {\"generated\": true}"));
    }
    Ok(FixtureHeader {
        alg: raw.alg,
        typ: raw.typ,
    })
}

fn parse_claims(
    fixture: &str,
    raw: &Map<String, Value>,
) -> Result<BTreeMap<String, ClaimValue>, TokenFixtureError> {
    let mut claims = BTreeMap::new();
    for (name, value) in raw {
        let claim = parse_claim(value)
            .map_err(|reason| invalid(fixture, format!("claim `{name}`: {reason}")))?;
        if matches!(name.as_str(), "exp" | "iat" | "nbf")
            && !matches!(claim, ClaimValue::OffsetSeconds(_))
        {
            return Err(invalid(
                fixture,
                format!("claim `{name}` must be an offsetSeconds directive"),
            ));
        }
        claims.insert(name.clone(), claim);
    }
    if !claims.contains_key("exp") {
        return Err(invalid(fixture, "claims must carry exp"));
    }
    Ok(claims)
}

fn parse_claim(value: &Value) -> Result<ClaimValue, String> {
    let Some(map) = value.as_object() else {
        return Ok(ClaimValue::Literal(value.clone()));
    };
    let is_directive = ["bind", "offsetSeconds", "generated"]
        .iter()
        .any(|key| map.contains_key(*key));
    if !is_directive {
        return Ok(ClaimValue::Literal(value.clone()));
    }
    if map.len() != 1 {
        return Err("a directive holds exactly one member".to_owned());
    }
    if let Some(bind) = map.get("bind") {
        return match bind.as_str() {
            Some("issuer") => Ok(ClaimValue::Bind(BindTarget::Issuer)),
            Some("audience") => Ok(ClaimValue::Bind(BindTarget::Audience)),
            _ => Err("bind is `issuer` or `audience`".to_owned()),
        };
    }
    if let Some(offset) = map.get("offsetSeconds") {
        return match offset.as_i64() {
            Some(seconds) if seconds >= 0 => Ok(ClaimValue::OffsetSeconds(seconds)),
            _ => Err("offsetSeconds is a non-negative integer".to_owned()),
        };
    }
    if map.get("generated") == Some(&Value::Bool(true)) {
        return Ok(ClaimValue::Generated);
    }
    Err("generated is `true`".to_owned())
}

/// A fixture is never a key and never a live token: refuse a private JWK member
/// name anywhere, and any string shaped like a compact JWT.
fn reject_key_material(fixture: &str, value: &Value) -> Result<(), TokenFixtureError> {
    match value {
        Value::Object(map) => {
            for (name, member) in map {
                if PRIVATE_JWK_MEMBERS.contains(&name.as_str()) {
                    return Err(invalid(
                        fixture,
                        format!("holds the private JWK member name `{name}`"),
                    ));
                }
                reject_key_material(fixture, member)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_key_material(fixture, item)?;
            }
        }
        Value::String(text) => {
            if text.starts_with("eyJ") && text.matches('.').count() == 2 {
                return Err(invalid(fixture, "holds a string shaped like a compact JWT"));
            }
            if text.contains("PRIVATE KEY") {
                return Err(invalid(fixture, "holds PEM key material"));
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Expectations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Against {
    PlainRead,
    HumanOnlyProfile,
}

/// The issuer block a product is configured with for a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Configuration {
    Default,
    Recipe,
    JwtAccepted,
}

/// The configuration a row of `expected.yaml` names: an issuer block, and for
/// `recipe-declared-kind` an actor kind the operator declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RowConfiguration {
    Default,
    Recipe,
    JwtAccepted,
    /// The `recipe` block plus an actor kind the operator declares for the
    /// fixture's client, or for the whole issuer where the token names no
    /// client.
    RecipeDeclaredKind,
}

impl RowConfiguration {
    /// The issuer block the product is configured with.
    #[must_use]
    pub fn block(self) -> Configuration {
        match self {
            Self::Default => Configuration::Default,
            Self::Recipe | Self::RecipeDeclaredKind => Configuration::Recipe,
            Self::JwtAccepted => Configuration::JwtAccepted,
        }
    }

    /// The actor kind the operator declares for `fixture` under this
    /// configuration: none outside `recipe-declared-kind`, and there the
    /// fixture's subject kind, human for a user and service for a service.
    /// `None` too for a fixture whose subject kind is unspecified.
    #[must_use]
    pub fn declared_kind(self, fixture: &TokenFixture) -> Option<ActorKind> {
        if self != Self::RecipeDeclaredKind {
            return None;
        }
        match fixture.subject_kind.as_str() {
            "user" => Some(ActorKind::Human),
            "service" => Some(ActorKind::Service),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Basis {
    Inferred,
    Observed,
}

/// One product's cell in a row.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExpectedCell {
    pub main: Outcome,
    pub target: Outcome,
    #[serde(deserialize_with = "change_or_none")]
    pub changed_by: Option<String>,
    pub landed: Option<bool>,
    pub basis: Basis,
    pub reason: Option<String>,
    pub target_reason: Option<String>,
}

impl ExpectedCell {
    /// What a test asserts: `target` where the change has landed, `main`
    /// everywhere else.
    #[must_use]
    pub fn expected(&self) -> &Outcome {
        if self.landed == Some(true) {
            &self.target
        } else {
            &self.main
        }
    }
}

/// A change name is lowercase kebab-case: `caller-contract`.
fn is_change_name(text: &str) -> bool {
    let mut words = text.split('-');
    let word_ok = |word: &str| {
        !word.is_empty()
            && word
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    };
    words
        .next()
        .is_some_and(|first| word_ok(first) && first.starts_with(|c: char| c.is_ascii_lowercase()))
        && words.all(word_ok)
}

fn change_or_none<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let text = String::deserialize(deserializer)?;
    if text == "none" {
        return Ok(None);
    }
    if is_change_name(&text) {
        Ok(Some(text))
    } else {
        Err(serde::de::Error::custom(format!(
            "changedBy `{text}` is neither `none` nor a lowercase kebab-case change name like `caller-contract`"
        )))
    }
}

/// One fixture, `against` value and configuration, with a cell per product.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedRow {
    pub fixture: String,
    pub against: Against,
    pub configuration: RowConfiguration,
    pub products: BTreeMap<String, ExpectedCell>,
}

/// `expected.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectations {
    pub schema: String,
    pub products: Vec<String>,
    pub configurations: BTreeMap<String, String>,
    pub rows: Vec<ExpectedRow>,
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

/// The issuer and audience of the product under test, which `bind` claims take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub issuer: String,
    pub audience: String,
}

/// A signed token, or a synthetic opaque credential. Its `Debug` form shows no
/// token text.
#[derive(Clone)]
pub struct SignedToken {
    text: String,
    opaque: bool,
}

impl SignedToken {
    /// The credential as a product receives it in an `Authorization` header.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn is_opaque(&self) -> bool {
        self.opaque
    }

    /// The same kind of credential with other text, for tampering tests.
    #[must_use]
    pub fn with_text(&self, text: String) -> Self {
        Self {
            text,
            opaque: self.opaque,
        }
    }
}

impl fmt::Debug for SignedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedToken")
            .field("opaque", &self.opaque)
            .field("length", &self.text.len())
            .finish()
    }
}

/// Keys made when the signer is built, one per algorithm, held in memory only.
/// A product that verifies tokens is given [`TokenSigner::public_key_set`].
pub struct TokenSigner {
    rs256: PrivateJwk,
    es256: PrivateJwk,
    eddsa: PrivateJwk,
    hs256: Vec<u8>,
    hs512: Vec<u8>,
}

impl fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSigner").finish_non_exhaustive()
    }
}

impl Default for TokenSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSigner {
    /// Make a fresh key for every algorithm.
    ///
    /// # Panics
    ///
    /// Panics if a key cannot be generated.
    #[must_use]
    pub fn new() -> Self {
        let mut rs256 = generate_private_jwk(GeneratedKeyAlgorithm::Rs384)
            .expect("ephemeral RSA test key generates");
        rs256.alg = Some("RS256".to_owned());
        let es256 = generate_private_jwk(GeneratedKeyAlgorithm::Es256)
            .expect("ephemeral ES256 test key generates");
        let eddsa = generate_private_jwk(GeneratedKeyAlgorithm::Ed25519)
            .expect("ephemeral EdDSA test key generates");
        let mut hs256 = vec![0_u8; 32];
        let mut hs512 = vec![0_u8; 64];
        rand::rng().fill(hs256.as_mut_slice());
        rand::rng().fill(hs512.as_mut_slice());
        Self {
            rs256,
            es256,
            eddsa,
            hs256,
            hs512,
        }
    }

    /// The public halves of the asymmetric keys as a key set. HMAC keys have no
    /// public half and are never in it, so a product cannot verify an HS256 or
    /// HS512 token from a key set.
    ///
    /// # Panics
    ///
    /// Panics if a public key cannot be serialised.
    #[must_use]
    pub fn public_key_set(&self) -> Value {
        let keys: Vec<Value> = [&self.rs256, &self.es256, &self.eddsa]
            .into_iter()
            .map(|key| serde_json::to_value(key.public()).expect("public JWK serialises"))
            .collect();
        json!({ "keys": keys })
    }

    fn asymmetric_key(&self, alg: &str) -> Option<&PrivateJwk> {
        match alg {
            "RS256" => Some(&self.rs256),
            "ES256" => Some(&self.es256),
            "EdDSA" => Some(&self.eddsa),
            _ => None,
        }
    }

    fn hmac_key(&self, alg: &str) -> Option<(&[u8], Algorithm)> {
        match alg {
            "HS256" => Some((&self.hs256, Algorithm::HS256)),
            "HS512" => Some((&self.hs512, Algorithm::HS512)),
            _ => None,
        }
    }

    /// Sign a fixture now. Times are offsets from this moment, `bind` claims take
    /// `binding`, and an opaque fixture yields its synthetic string.
    pub fn sign(
        &self,
        fixture: &TokenFixture,
        binding: &Binding,
    ) -> Result<SignedToken, TokenFixtureError> {
        let signing = |reason: String| TokenFixtureError::Signing {
            fixture: fixture.id.clone(),
            reason,
        };
        if let Some(opaque) = &fixture.opaque {
            return Ok(SignedToken {
                text: opaque.clone(),
                opaque: true,
            });
        }
        let header = fixture
            .header
            .as_ref()
            .ok_or_else(|| signing("no header".to_owned()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| signing(error.to_string()))?
            .as_secs();
        let now = i64::try_from(now).map_err(|error| signing(error.to_string()))?;
        let mut claims = Map::new();
        for (name, claim) in &fixture.claims {
            let value = match claim {
                ClaimValue::Literal(value) => value.clone(),
                ClaimValue::Bind(BindTarget::Issuer) => Value::String(binding.issuer.clone()),
                ClaimValue::Bind(BindTarget::Audience) => Value::String(binding.audience.clone()),
                ClaimValue::OffsetSeconds(seconds) => json!(now + seconds),
                ClaimValue::Generated => Value::String(random_hex()),
            };
            claims.insert(name.clone(), value);
        }
        let payload = serde_json::to_vec(&Value::Object(claims))
            .map_err(|error| signing(error.to_string()))?;
        let mut extra_header = Map::new();
        if let Some(typ) = &header.typ {
            extra_header.insert("typ".to_owned(), Value::String(typ.clone()));
        }
        let text = if let Some(key) = self.asymmetric_key(&header.alg) {
            let signer =
                LocalJwkSigner::new(key.clone()).map_err(|error| signing(error.to_string()))?;
            // The signer is local, so its future is ready on the first poll. Polling it
            // directly keeps signing usable from inside any executor.
            sign_compact_jws(extra_header, &payload, &signer)
                .now_or_never()
                .ok_or_else(|| signing("the local signer did not complete at once".to_owned()))?
                .map_err(|error| signing(error.to_string()))?
        } else if let Some((secret, algorithm)) = self.hmac_key(&header.alg) {
            extra_header.insert("alg".to_owned(), Value::String(header.alg.clone()));
            extra_header.insert(
                "kid".to_owned(),
                Value::String(format!("test-hmac-{}", header.alg.to_lowercase())),
            );
            let header_bytes = serde_json::to_vec(&Value::Object(extra_header))
                .map_err(|error| signing(error.to_string()))?;
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header_bytes),
                URL_SAFE_NO_PAD.encode(&payload)
            );
            let signature = crypto::sign(
                input.as_bytes(),
                &EncodingKey::from_secret(secret),
                algorithm,
            )
            .map_err(|error| signing(error.to_string()))?;
            format!("{input}.{signature}")
        } else {
            return Err(signing(format!("no key for algorithm `{}`", header.alg)));
        };
        Ok(SignedToken {
            text,
            opaque: false,
        })
    }

    /// Check a signed token's signature with this signer's keys. An opaque
    /// credential has no signature and passes.
    pub fn verify_signature(&self, token: &SignedToken) -> Result<(), TokenFixtureError> {
        let fail = |reason: &str| TokenFixtureError::Verification(reason.to_owned());
        if token.opaque {
            return Ok(());
        }
        let mut parts = token.text.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(fail("not three segments"));
        };
        let input = format!("{header}.{payload}");
        let header: Value = URL_SAFE_NO_PAD
            .decode(header)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or_else(|| fail("header is not base64url JSON"))?;
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("header has no alg"))?;
        if let Some(key) = self.asymmetric_key(alg) {
            if header.get("kid").and_then(Value::as_str) != key.kid.as_deref() {
                return Err(fail("kid names no key of this signer"));
            }
            let signature = URL_SAFE_NO_PAD
                .decode(signature)
                .map_err(|_| fail("signature is not base64url"))?;
            let public: PublicJwk = key.public();
            verify_with_public_jwk(input.as_bytes(), &signature, &public)
                .map_err(|_| fail("signature does not verify"))
        } else if let Some((secret, algorithm)) = self.hmac_key(alg) {
            let expected_kid = format!("test-hmac-{}", alg.to_lowercase());
            if header.get("kid").and_then(Value::as_str) != Some(expected_kid.as_str()) {
                return Err(fail("kid names no key of this signer"));
            }
            match crypto::verify(
                signature,
                input.as_bytes(),
                &DecodingKey::from_secret(secret),
                algorithm,
            ) {
                Ok(true) => Ok(()),
                Ok(false) | Err(_) => Err(fail("signature does not verify")),
            }
        } else {
            Err(fail("alg is not one this signer holds"))
        }
    }
}

fn random_hex() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Corpus and driver
// ---------------------------------------------------------------------------

/// What the product under test is given for one row.
#[derive(Debug, Clone)]
pub struct FixtureCase {
    pub fixture: TokenFixture,
    pub against: Against,
    /// The issuer block. A `recipe-declared-kind` row is the `recipe` block
    /// with [`Self::declared_kind`] set.
    pub configuration: Configuration,
    /// The actor kind the operator declares for the fixture's client, or for
    /// the whole issuer where the token names no client. Set only for a
    /// `recipe-declared-kind` row.
    pub declared_kind: Option<ActorKind>,
    /// The product's issuer.
    pub issuer: String,
    /// The audience the product is configured with for this row. It is the
    /// audience the driver was given, except for a positive fixture in the
    /// `recipe` configuration that states a literal `aud`: the documented
    /// recipe names that audience.
    pub audience: String,
    /// The credential to present.
    pub token: SignedToken,
    /// The public key set the product verifies against.
    pub jwks: Value,
}

/// Whether a product's result matched `expected.yaml` for a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Match,
    Mismatch,
    /// The expected value is `none` or `n-a`: nothing was run.
    NotApplicable,
    /// The expected value is `unknown`: the result was observed and not judged.
    Unresolved,
}

/// The outcome of one row for one product. It holds no token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowReport {
    pub fixture: String,
    pub against: Against,
    pub configuration: RowConfiguration,
    pub expected: Outcome,
    pub observed: Option<Outcome>,
    pub comparison: Comparison,
}

/// Every row of `expected.yaml` for one product column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductReport {
    pub product: String,
    pub rows: Vec<RowReport>,
}

impl ProductReport {
    #[must_use]
    pub fn mismatches(&self) -> Vec<&RowReport> {
        self.rows
            .iter()
            .filter(|row| row.comparison == Comparison::Mismatch)
            .collect()
    }

    /// # Panics
    ///
    /// Panics, listing each differing row, if any row mismatched.
    pub fn assert_matches(&self) {
        let mismatches = self.mismatches();
        for row in self
            .rows
            .iter()
            .filter(|row| row.comparison == Comparison::Unresolved)
        {
            if let Some(observed) = &row.observed {
                eprintln!(
                    "unresolved {} / {} / {:?} / {:?}: observed {observed}",
                    self.product, row.fixture, row.against, row.configuration
                );
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} rows of `{}` differ from expected.yaml:\n{}",
            mismatches.len(),
            self.product,
            mismatches
                .iter()
                .map(|row| format!(
                    "  {} / {:?} / {:?}: expected {}, observed {}",
                    row.fixture,
                    row.against,
                    row.configuration,
                    row.expected,
                    row.observed
                        .as_ref()
                        .map_or_else(|| "nothing".to_owned(), ToString::to_string),
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// The fixtures and `expected.yaml`, loaded and cross-checked.
#[derive(Debug, Clone)]
pub struct TokenCorpus {
    fixtures: Vec<TokenFixture>,
    expectations: Expectations,
}

struct PlannedRow {
    report: RowReport,
    case: Option<FixtureCase>,
}

impl TokenCorpus {
    /// The corpus directory, resolved from this crate's manifest directory.
    #[must_use]
    pub fn directory() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/platform/conformance/tokens")
    }

    /// Load every fixture and `expected.yaml`, and check them against each other.
    pub fn load() -> Result<Self, TokenFixtureError> {
        let root = Self::directory();
        let fixtures_dir = root.join("fixtures");
        let read_error = |path: &Path| {
            let path = path.display().to_string();
            move |source| TokenFixtureError::Io { path, source }
        };
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&fixtures_dir).map_err(read_error(&fixtures_dir))? {
            let path = entry.map_err(read_error(&fixtures_dir))?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                paths.push(path);
            }
        }
        paths.sort();
        let mut fixtures = Vec::new();
        for path in &paths {
            let text = std::fs::read_to_string(path).map_err(read_error(path))?;
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid(&path.display().to_string(), "file name is not UTF-8"))?;
            fixtures.push(TokenFixture::parse(stem, &text)?);
        }
        let expected_path = root.join("expected.yaml");
        let text = std::fs::read_to_string(&expected_path).map_err(read_error(&expected_path))?;
        let expectations: Expectations = Reader::new("expected.yaml")
            .decode::<Expectations>(text.as_bytes(), &Expect::one(&EXPECTATIONS_FORMAT))
            .map_err(|report| {
                TokenFixtureError::Expectations(
                    report
                        .diagnostics()
                        .iter()
                        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            })?
            .value;
        let corpus = Self {
            fixtures,
            expectations,
        };
        corpus.check_expectations()?;
        Ok(corpus)
    }

    fn check_expectations(&self) -> Result<(), TokenFixtureError> {
        let fail = |reason: String| Err(TokenFixtureError::Expectations(reason));
        let expectations = &self.expectations;
        if expectations.schema != EXPECTATIONS_SCHEMA {
            return fail(format!("schema must be `{EXPECTATIONS_SCHEMA}`"));
        }
        let products: BTreeSet<&str> = expectations.products.iter().map(String::as_str).collect();
        if products.len() != expectations.products.len() || products.is_empty() {
            return fail("products must be a non-empty list without repeats".to_owned());
        }
        let mut seen = BTreeSet::new();
        for row in &expectations.rows {
            let Some(fixture) = self.fixture(&row.fixture) else {
                return fail(format!("row names unknown fixture `{}`", row.fixture));
            };
            if !seen.insert((row.fixture.as_str(), row.against, row.configuration)) {
                return fail(format!(
                    "row `{}` / {:?} / {:?} repeats",
                    row.fixture, row.against, row.configuration
                ));
            }
            let row_products: BTreeSet<&str> = row.products.keys().map(String::as_str).collect();
            if row_products != products {
                return fail(format!(
                    "row `{}` does not have exactly the product columns",
                    row.fixture
                ));
            }
            for (product, cell) in &row.products {
                if cell.landed.is_some() != cell.changed_by.is_some() {
                    return fail(format!(
                        "`{}` / `{product}`: landed appears exactly when changedBy is a change name",
                        row.fixture
                    ));
                }
                let admitted = |outcome: &Outcome| matches!(outcome, Outcome::Admitted(_));
                if fixture.class == FixtureClass::Negative
                    && (admitted(&cell.main) || admitted(&cell.target))
                {
                    return fail(format!(
                        "negative fixture `{}` is admitted by `{product}`",
                        row.fixture
                    ));
                }
            }
        }
        for fixture in &self.fixtures {
            if !expectations
                .rows
                .iter()
                .any(|row| row.fixture == fixture.id)
            {
                return fail(format!("fixture `{}` has no row", fixture.id));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn fixtures(&self) -> &[TokenFixture] {
        &self.fixtures
    }

    #[must_use]
    pub fn fixture(&self, id: &str) -> Option<&TokenFixture> {
        self.fixtures.iter().find(|fixture| fixture.id == id)
    }

    #[must_use]
    pub fn expectations(&self) -> &Expectations {
        &self.expectations
    }

    fn plan(
        &self,
        product: &str,
        signer: &TokenSigner,
        issuer: &str,
        audience: &str,
    ) -> Result<Vec<PlannedRow>, TokenFixtureError> {
        if !self
            .expectations
            .products
            .iter()
            .any(|name| name == product)
        {
            return Err(TokenFixtureError::UnknownProduct(product.to_owned()));
        }
        let jwks = signer.public_key_set();
        let mut planned = Vec::new();
        for row in &self.expectations.rows {
            let cell = row
                .products
                .get(product)
                .ok_or_else(|| TokenFixtureError::UnknownProduct(product.to_owned()))?;
            let expected = cell.expected().clone();
            let mut report = RowReport {
                fixture: row.fixture.clone(),
                against: row.against,
                configuration: row.configuration,
                expected: expected.clone(),
                observed: None,
                comparison: Comparison::NotApplicable,
            };
            if matches!(expected, Outcome::None | Outcome::NotApplicable) {
                planned.push(PlannedRow { report, case: None });
                continue;
            }
            let fixture = self
                .fixture(&row.fixture)
                .ok_or_else(|| invalid(&row.fixture, "no such fixture"))?;
            let declared_kind = row.configuration.declared_kind(fixture);
            if row.configuration == RowConfiguration::RecipeDeclaredKind && declared_kind.is_none()
            {
                return Err(invalid(
                    &row.fixture,
                    "a recipe-declared-kind row needs a fixture whose subject kind is user or service",
                ));
            }
            let audience = configured_audience(fixture, row.configuration.block(), audience);
            let token = signer.sign(
                fixture,
                &Binding {
                    issuer: issuer.to_owned(),
                    audience: audience.clone(),
                },
            )?;
            report.comparison = Comparison::Unresolved;
            planned.push(PlannedRow {
                report,
                case: Some(FixtureCase {
                    fixture: fixture.clone(),
                    against: row.against,
                    configuration: row.configuration.block(),
                    declared_kind,
                    issuer: issuer.to_owned(),
                    audience,
                    token,
                    jwks: jwks.clone(),
                }),
            });
        }
        Ok(planned)
    }

    /// Run every applicable row through `authenticate` and compare the results
    /// with `expected.yaml` for `product`. Rows whose expected value is `none`
    /// or `n-a` are not run. `issuer` and `audience` are the product's own.
    pub fn run_product<F>(
        &self,
        product: &str,
        signer: &TokenSigner,
        issuer: &str,
        audience: &str,
        mut authenticate: F,
    ) -> Result<ProductReport, TokenFixtureError>
    where
        F: FnMut(&FixtureCase) -> Outcome,
    {
        let mut rows = Vec::new();
        for planned in self.plan(product, signer, issuer, audience)? {
            let observed = planned.case.as_ref().map(&mut authenticate);
            rows.push(finish(planned.report, observed));
        }
        Ok(ProductReport {
            product: product.to_owned(),
            rows,
        })
    }

    /// [`Self::run_product`] for an authenticator that is asynchronous.
    pub async fn run_product_async<F, Fut>(
        &self,
        product: &str,
        signer: &TokenSigner,
        issuer: &str,
        audience: &str,
        mut authenticate: F,
    ) -> Result<ProductReport, TokenFixtureError>
    where
        F: FnMut(FixtureCase) -> Fut,
        Fut: Future<Output = Outcome>,
    {
        let mut rows = Vec::new();
        for planned in self.plan(product, signer, issuer, audience)? {
            let observed = match planned.case {
                Some(case) => Some(authenticate(case).await),
                None => None,
            };
            rows.push(finish(planned.report, observed));
        }
        Ok(ProductReport {
            product: product.to_owned(),
            rows,
        })
    }
}

fn configured_audience(
    fixture: &TokenFixture,
    configuration: Configuration,
    product_audience: &str,
) -> String {
    if fixture.class == FixtureClass::Positive && configuration == Configuration::Recipe {
        if let Some(ClaimValue::Literal(Value::String(literal))) = fixture.claims.get("aud") {
            return literal.clone();
        }
    }
    product_audience.to_owned()
}

fn finish(mut report: RowReport, observed: Option<Outcome>) -> RowReport {
    if let Some(observed) = observed {
        report.comparison = match report.expected {
            Outcome::Unknown => Comparison::Unresolved,
            ref expected if *expected == observed => Comparison::Match,
            _ => Comparison::Mismatch,
        };
        report.observed = Some(observed);
    }
    report
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[test]
    fn the_private_member_list_is_the_platform_list() {
        assert_eq!(
            super::PRIVATE_JWK_MEMBERS
                .into_iter()
                .collect::<BTreeSet<_>>(),
            registry_platform_crypto::PRIVATE_JWK_MEMBERS
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }
}
