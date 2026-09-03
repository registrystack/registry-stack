//! The client registry: the server-side binding from keys to authority.
//!
//! This module is the reason Mint exists. A JWKS answers only "was this signed
//! by a trusted key?" The registry answers the question that actually matters:
//! "*this specific client* holds *these specific keys*, and is permitted to act
//! as *this principal* with *this server-governed authority*."
//!
//! Two rules keep that binding meaningful:
//!
//! 1. A client's assertion is verified against that client's keys only, never
//!    against a pooled key set. See [`crate::assertion`].
//! 2. Authority is read from here, never from the assertion payload.
//!
//! The registry is reloadable so that onboarding, offboarding, and caller key
//! rotation never require restarting a resource server.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
    sync::Arc,
};

use jsonwebtoken::{jwk::JwkSet, DecodingKey};
use registry_platform_authcommon::{parse_fingerprint, verify_api_key};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

/// Evidence rejects principals longer than this, so a longer one could never
/// be used.
const MAX_PRINCIPAL_BYTES: usize = 512;
/// Evidence accepts at most this many requester tags.
const MAX_TAGS: usize = 32;
const MAX_KEYS_PER_CLIENT: usize = 8;
const MAX_CLIENT_FILE_BYTES: u64 = 256 * 1024;
const MAX_CLIENTS: usize = 4_096;
/// Evidence permits at most this many fields in one selector profile, so a
/// larger subject could never satisfy one.
const MAX_SUBJECT_FIELDS: usize = 16;
const MAX_DELEGATED_ACTORS: usize = 64;
/// The longest claim path Evidence will resolve.
const MAX_CLAIM_PATH_BYTES: usize = 512;
/// A registration stays substantially below the compact access-token ceiling.
const MAX_AUTHORIZATION_SCOPES: usize = 64;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_AUTHORIZATION_CLAIMS: usize = 32;
const MAX_AUTHORIZATION_CLAIM_NAME_BYTES: usize = 128;
/// Relay accepts direct authority values only through this byte ceiling.
const MAX_AUTHORIZATION_CLAIM_VALUE_BYTES: usize = 512;
/// A resource server reads at most this many values from one multi-valued
/// authority claim, so a longer list could never be used in full.
const MAX_AUTHORIZATION_CLAIM_VALUES: usize = 64;
/// One active credential plus one planned rotation credential.
const MAX_CLIENT_SECRET_FINGERPRINTS: usize = 2;

const RESERVED_ACCESS_TOKEN_CLAIMS: [&str; 9] = [
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "sub",
    "scope",
];

/// JWK members that only ever appear in private keys. `oth` carries the
/// remaining prime factors of a multi-prime RSA private key (RFC 7518 section
/// 6.3.2.7); a whole private key also carries `d`, but the guard must not depend
/// on which private member happens to be present.
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ClientRegistryError {
    #[error("the client registry directory is unavailable")]
    DirectoryUnavailable,
    #[error("a client registration file is unreadable")]
    Unreadable,
    #[error("client registration {0} is invalid: {1}")]
    Invalid(String, &'static str),
    #[error("client registration document {0} is malformed: {1}")]
    Document(String, String),
    #[error("client id {0} is registered more than once")]
    Duplicate(String),
    #[error("the client registry holds more than {MAX_CLIENTS} clients")]
    TooManyClients,
}

/// A grant reference minted into tokens for callers acting under a recorded
/// authority. Evidence requires the id and authority together or not at all.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub authority: String,
}

/// Permission for a client to obtain tokens bound to one delegated actor acting
/// for one subject.
///
/// This is what makes a delegated token narrower than an ordinary one rather
/// than merely differently labelled. The subject's selector values are minted
/// into the token at [`Delegation::subject_claims`], which must mirror the
/// `valueClaims` of the matching `authenticated-context` entitlement in the
/// resource server's bundle. The resource server then reads the subject from
/// the token and refuses any request that carries its own selector values, so a
/// token issued for one subject cannot reach another.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Delegation {
    /// A closed set of actor identities this client may act as. Omitted means
    /// the client names its own actor, bounded only by length.
    #[serde(default)]
    pub actors: Option<Vec<String>>,
    /// Selector field name to the claim path its value is minted at.
    pub subject_claims: BTreeMap<String, String>,
}

/// One server-governed authority value written into a standard access token.
///
/// A single string is the ordinary shape. A list is what a resource server's
/// multi-valued row boundary requires: it reads an array-valued claim and
/// refuses a scalar, so a registration that must satisfy one names every
/// permitted value here.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum AuthorizationClaimValue {
    Text(String),
    List(Vec<String>),
}

impl AuthorizationClaimValue {
    /// The JSON this value is minted as.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::Text(value) => Value::String(value.clone()),
            Self::List(values) => Value::Array(values.iter().cloned().map(Value::String).collect()),
        }
    }
}

/// Product-neutral authority written into a standard OAuth access token.
///
/// The client assertion never supplies these values. They are fixed in the
/// reloadable server-side registration and emitted as one space-delimited
/// `scope` claim plus bounded direct string or string-list claims.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorization {
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, AuthorizationClaimValue>,
}

/// The client authentication method selected by one registration.
///
/// Existing registrations omit `clientAuthentication` and remain
/// `private_key_jwt` clients. Client-secret authentication is an explicit
/// compatibility profile and cannot silently become the default.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(
    tag = "method",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ClientAuthenticationDocument {
    PrivateKeyJwt,
    ClientSecret { secret_fingerprints: Vec<String> },
}

#[derive(Clone, Eq, PartialEq)]
pub enum ClientAuthentication {
    PrivateKeyJwt,
    ClientSecret { secret_fingerprints: Vec<String> },
}

impl fmt::Debug for ClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateKeyJwt => formatter.write_str("PrivateKeyJwt"),
            Self::ClientSecret {
                secret_fingerprints,
            } => formatter
                .debug_struct("ClientSecret")
                .field(
                    "secret_fingerprints",
                    &format_args!("[{} redacted]", secret_fingerprints.len()),
                )
                .finish(),
        }
    }
}

impl fmt::Debug for Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authorization")
            .field("scopes", &format_args!("[{} redacted]", self.scopes.len()))
            .field("claims", &format_args!("[{} redacted]", self.claims.len()))
            .finish()
    }
}

impl Delegation {
    /// Whether `actor` is one this client may act as.
    #[must_use]
    pub fn permits_actor(&self, actor: &str) -> bool {
        match &self.actors {
            Some(actors) => actors.iter().any(|permitted| permitted == actor),
            None => true,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientDocument {
    client_id: String,
    principal: String,
    #[serde(default)]
    evidence_audience: Option<String>,
    #[serde(default)]
    requester_tags: Option<Vec<String>>,
    #[serde(default)]
    grant: Option<Grant>,
    #[serde(default)]
    delegation: Option<Delegation>,
    #[serde(default)]
    authorization: Option<Authorization>,
    #[serde(default)]
    client_authentication: Option<ClientAuthenticationDocument>,
    #[serde(default)]
    keys: Vec<Value>,
}

/// One registered client: its public keys, and the authority Mint will assert
/// on its behalf.
#[derive(Clone)]
pub struct RegisteredClient {
    client_id: String,
    principal: String,
    evidence_audience: Option<String>,
    requester_tags: Option<Vec<String>>,
    grant: Option<Grant>,
    delegation: Option<Delegation>,
    authorization: Option<Authorization>,
    authentication: ClientAuthentication,
    jwks: JwkSet,
}

impl RegisteredClient {
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    #[must_use]
    pub fn evidence_audience(&self) -> Option<&str> {
        self.evidence_audience.as_deref()
    }

    #[must_use]
    pub fn requester_tags(&self) -> Option<&[String]> {
        self.requester_tags.as_deref()
    }

    #[must_use]
    pub fn grant(&self) -> Option<&Grant> {
        self.grant.as_ref()
    }

    /// The delegation this client is registered for, if any. A client with no
    /// delegation may never obtain a token carrying an actor or a bound
    /// subject.
    #[must_use]
    pub fn delegation(&self) -> Option<&Delegation> {
        self.delegation.as_ref()
    }

    /// The standard scoped authority this client is registered for, if any.
    /// Evidence registrations instead expose the Evidence-specific accessors
    /// above. Loading guarantees the two profiles never coexist.
    #[must_use]
    pub fn authorization(&self) -> Option<&Authorization> {
        self.authorization.as_ref()
    }

    /// The one client-authentication method this registration accepts.
    #[must_use]
    pub fn authentication(&self) -> &ClientAuthentication {
        &self.authentication
    }

    #[must_use]
    pub fn accepts_private_key_jwt(&self) -> bool {
        matches!(self.authentication, ClientAuthentication::PrivateKeyJwt)
    }

    /// Verify a presented client secret against every active rotation
    /// fingerprint without returning early on the matching slot.
    #[must_use]
    pub fn verifies_client_secret(&self, secret: &str) -> bool {
        let ClientAuthentication::ClientSecret {
            secret_fingerprints,
        } = &self.authentication
        else {
            return false;
        };
        let mut accepted = false;
        for fingerprint in secret_fingerprints {
            // Loading parsed every fingerprint already. Treat disagreement as
            // non-acceptance rather than converting configuration trouble into
            // a credential oracle.
            accepted |= verify_api_key(secret, fingerprint).unwrap_or(false);
        }
        accepted
    }

    /// The public keys registered for this client, and nothing else. This is
    /// the set an assertion from this client is verified against.
    #[must_use]
    pub fn jwks(&self) -> &JwkSet {
        &self.jwks
    }
}

/// Authority data identifies real callers, so it is kept out of logs for the
/// same reason Evidence redacts its authenticated context.
impl fmt::Debug for RegisteredClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredClient")
            .field("client_id", &"[redacted]")
            .field("principal", &"[redacted]")
            .field(
                "evidence_audience",
                &self.evidence_audience.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "requester_tags",
                &self
                    .requester_tags
                    .as_ref()
                    .map(|tags| format!("[{} redacted]", tags.len())),
            )
            .field("grant", &self.grant.as_ref().map(|_| "[redacted]"))
            .field(
                "delegation",
                &self.delegation.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[redacted]"),
            )
            .field("authentication", &self.authentication)
            .field("keys", &self.jwks.keys.len())
            .finish()
    }
}

/// An immutable snapshot of the registered clients.
#[derive(Debug, Default)]
pub struct ClientRegistry {
    clients: BTreeMap<String, Arc<RegisteredClient>>,
}

impl ClientRegistry {
    /// Load every `*.yaml` registration in `directory`.
    ///
    /// The load is all-or-nothing: one malformed registration fails the whole
    /// load, so a partially applied registry can never serve.
    pub fn load(directory: &Path) -> Result<Self, ClientRegistryError> {
        let entries =
            fs::read_dir(directory).map_err(|_| ClientRegistryError::DirectoryUnavailable)?;
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| ClientRegistryError::Unreadable)?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("yaml") {
                paths.push(path);
            }
        }
        paths.sort();

        let mut clients = BTreeMap::new();
        for path in paths {
            let client = load_client_file(&path)?;
            if clients.contains_key(client.client_id()) {
                return Err(ClientRegistryError::Duplicate(
                    client.client_id().to_owned(),
                ));
            }
            clients.insert(client.client_id().to_owned(), Arc::new(client));
        }
        if clients.len() > MAX_CLIENTS {
            return Err(ClientRegistryError::TooManyClients);
        }
        Ok(Self { clients })
    }

    #[must_use]
    pub fn get(&self, client_id: &str) -> Option<&Arc<RegisteredClient>> {
        self.clients.get(client_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    #[must_use]
    pub fn client_ids(&self) -> Vec<&str> {
        self.clients.keys().map(String::as_str).collect()
    }
}

fn load_client_file(path: &Path) -> Result<RegisteredClient, ClientRegistryError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<unnamed>")
        .to_owned();

    let metadata = fs::symlink_metadata(path).map_err(|_| ClientRegistryError::Unreadable)?;
    if !metadata.is_file() {
        return Err(ClientRegistryError::Invalid(
            name,
            "registrations must be regular files",
        ));
    }
    if metadata.len() > MAX_CLIENT_FILE_BYTES {
        return Err(ClientRegistryError::Invalid(
            name,
            "registration is too large",
        ));
    }

    let text = fs::read_to_string(path).map_err(|_| ClientRegistryError::Unreadable)?;
    let document: ClientDocument = serde_norway::from_str(&text)
        .map_err(|error| ClientRegistryError::Document(name.clone(), error.to_string()))?;
    build_client(&name, document)
}

fn build_client(
    name: &str,
    document: ClientDocument,
) -> Result<RegisteredClient, ClientRegistryError> {
    let invalid = |reason: &'static str| ClientRegistryError::Invalid(name.to_owned(), reason);

    if document.client_id.trim().is_empty() || document.client_id.len() > 256 {
        return Err(invalid("client id must be 1..=256 bytes"));
    }
    if document.principal.trim().is_empty() || document.principal.len() > MAX_PRINCIPAL_BYTES {
        return Err(invalid("principal must be 1..=512 bytes"));
    }
    validate_authority_profile(&document, &invalid)?;
    let authentication = validate_client_authentication(&document, &invalid)?;
    let jwks = match &authentication {
        ClientAuthentication::PrivateKeyJwt => build_public_jwks(document.keys, &invalid)?,
        ClientAuthentication::ClientSecret { .. } => JwkSet { keys: Vec::new() },
    };

    Ok(RegisteredClient {
        client_id: document.client_id,
        principal: document.principal,
        evidence_audience: document.evidence_audience,
        requester_tags: document.requester_tags,
        grant: document.grant,
        delegation: document.delegation,
        authorization: document.authorization,
        authentication,
        jwks,
    })
}

fn validate_client_authentication(
    document: &ClientDocument,
    invalid: &impl Fn(&'static str) -> ClientRegistryError,
) -> Result<ClientAuthentication, ClientRegistryError> {
    match document.client_authentication.as_ref() {
        None | Some(ClientAuthenticationDocument::PrivateKeyJwt) => {
            if document.keys.is_empty() {
                return Err(invalid(
                    "private-key-jwt authentication requires client keys",
                ));
            }
            Ok(ClientAuthentication::PrivateKeyJwt)
        }
        Some(ClientAuthenticationDocument::ClientSecret {
            secret_fingerprints,
        }) => {
            if !document.keys.is_empty() {
                return Err(invalid(
                    "client-secret and private-key-jwt authentication are mutually exclusive",
                ));
            }
            if document.authorization.is_none()
                || document.evidence_audience.is_some()
                || document.requester_tags.is_some()
                || document.grant.is_some()
                || document.delegation.is_some()
            {
                return Err(invalid(
                    "client-secret authentication requires standard authorization",
                ));
            }
            if secret_fingerprints.is_empty()
                || secret_fingerprints.len() > MAX_CLIENT_SECRET_FINGERPRINTS
            {
                return Err(invalid(
                    "between 1 and 2 client-secret fingerprints are required",
                ));
            }
            for fingerprint in secret_fingerprints {
                parse_fingerprint(fingerprint).map_err(|_| {
                    invalid("client-secret fingerprints must be canonical SHA-256 values")
                })?;
            }
            if secret_fingerprints.iter().collect::<BTreeSet<_>>().len()
                != secret_fingerprints.len()
            {
                return Err(invalid("client-secret fingerprints must be unique"));
            }
            Ok(ClientAuthentication::ClientSecret {
                secret_fingerprints: secret_fingerprints.clone(),
            })
        }
    }
}

fn validate_authority_profile(
    document: &ClientDocument,
    invalid: &impl Fn(&'static str) -> ClientRegistryError,
) -> Result<(), ClientRegistryError> {
    let has_evidence = document.evidence_audience.is_some()
        || document.requester_tags.is_some()
        || document.grant.is_some()
        || document.delegation.is_some();
    match (has_evidence, document.authorization.as_ref()) {
        (true, Some(_)) => {
            return Err(invalid(
                "Evidence authority and standard authorization are mutually exclusive",
            ))
        }
        (false, None) => {
            return Err(invalid(
                "an Evidence authority or standard authorization is required",
            ))
        }
        (false, Some(authorization)) => return validate_authorization(authorization, invalid),
        (true, None) => {}
    }

    let evidence_audience = document
        .evidence_audience
        .as_deref()
        .ok_or_else(|| invalid("Evidence authority requires evidenceAudience and requesterTags"))?;
    let requester_tags = document
        .requester_tags
        .as_deref()
        .ok_or_else(|| invalid("Evidence authority requires evidenceAudience and requesterTags"))?;

    if evidence_audience.len() > MAX_PRINCIPAL_BYTES {
        return Err(invalid("evidence audience must be at most 512 bytes"));
    }
    // Evidence parses this claim as a URL and mixes it into the subject-binding
    // MAC, so a value that fails to parse there must fail here.
    Url::parse(evidence_audience).map_err(|_| invalid("evidence audience must be a URL"))?;

    if requester_tags.is_empty() || requester_tags.len() > MAX_TAGS {
        return Err(invalid("between 1 and 32 requester tags are required"));
    }
    for tag in requester_tags {
        if tag.trim().is_empty() || tag.len() > 256 {
            return Err(invalid("requester tags must be 1..=256 bytes"));
        }
    }
    let unique_tags = requester_tags.iter().collect::<BTreeSet<_>>();
    if unique_tags.len() != requester_tags.len() {
        return Err(invalid("requester tags must be unique"));
    }

    if let Some(grant) = &document.grant {
        if grant.id.trim().is_empty() || grant.id.len() > MAX_PRINCIPAL_BYTES {
            return Err(invalid("grant id must be 1..=512 bytes"));
        }
        if grant.authority.trim().is_empty() || grant.authority.len() > MAX_PRINCIPAL_BYTES {
            return Err(invalid("grant authority must be 1..=512 bytes"));
        }
    }

    if let Some(delegation) = &document.delegation {
        validate_delegation(delegation, invalid)?;
    }
    Ok(())
}

fn validate_authorization(
    authorization: &Authorization,
    invalid: &impl Fn(&'static str) -> ClientRegistryError,
) -> Result<(), ClientRegistryError> {
    if authorization.scopes.is_empty() || authorization.scopes.len() > MAX_AUTHORIZATION_SCOPES {
        return Err(invalid(
            "between 1 and 64 authorization scopes are required",
        ));
    }
    for scope in &authorization.scopes {
        if scope.len() > MAX_SCOPE_BYTES || !valid_scope_token(scope) {
            return Err(invalid(
                "authorization scopes must be 1..=256 byte RFC 6749 scope-tokens",
            ));
        }
    }
    if authorization.scopes.iter().collect::<BTreeSet<_>>().len() != authorization.scopes.len() {
        return Err(invalid("authorization scopes must be unique"));
    }

    if authorization.claims.len() > MAX_AUTHORIZATION_CLAIMS {
        return Err(invalid("at most 32 authorization claims are permitted"));
    }
    for (name, value) in &authorization.claims {
        if !valid_authorization_claim_name(name) {
            return Err(invalid("authorization claim names are invalid"));
        }
        if RESERVED_ACCESS_TOKEN_CLAIMS.contains(&name.as_str()) {
            return Err(invalid(
                "authorization claims must not shadow registered access-token claims",
            ));
        }
        let values = match value {
            AuthorizationClaimValue::Text(value) => std::slice::from_ref(value),
            AuthorizationClaimValue::List(values) => {
                // An empty list names a claim while asserting nothing, so it is
                // refused rather than minted as an empty array.
                if values.is_empty() || values.len() > MAX_AUTHORIZATION_CLAIM_VALUES {
                    return Err(invalid(
                        "authorization claim value lists must hold between 1 and 64 values",
                    ));
                }
                if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
                    return Err(invalid("authorization claim values must be unique"));
                }
                values.as_slice()
            }
        };
        for value in values {
            if value.is_empty() || value.len() > MAX_AUTHORIZATION_CLAIM_VALUE_BYTES {
                return Err(invalid(
                    "authorization claim values must be 1..=512 byte direct strings",
                ));
            }
        }
    }
    Ok(())
}

fn valid_scope_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
        })
}

fn valid_authorization_claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUTHORIZATION_CLAIM_NAME_BYTES
        && valid_scope_token(value)
}

fn validate_delegation(
    delegation: &Delegation,
    invalid: &impl Fn(&'static str) -> ClientRegistryError,
) -> Result<(), ClientRegistryError> {
    if let Some(actors) = &delegation.actors {
        // An empty list reads as "no restriction" but means "nothing may be
        // requested", so it is refused rather than silently interpreted.
        if actors.is_empty() || actors.len() > MAX_DELEGATED_ACTORS {
            return Err(invalid("between 1 and 64 delegated actors are required"));
        }
        for actor in actors {
            if actor.trim().is_empty() || actor.len() > MAX_PRINCIPAL_BYTES {
                return Err(invalid("delegated actors must be 1..=512 bytes"));
            }
        }
        if actors.iter().collect::<BTreeSet<_>>().len() != actors.len() {
            return Err(invalid("delegated actors must be unique"));
        }
    }

    if delegation.subject_claims.is_empty() || delegation.subject_claims.len() > MAX_SUBJECT_FIELDS
    {
        return Err(invalid("between 1 and 16 subject claims are required"));
    }
    for (field, path) in &delegation.subject_claims {
        if !valid_selector_field(field) {
            return Err(invalid("subject claim field names are invalid"));
        }
        if !valid_claim_path(path) {
            return Err(invalid("subject claim paths are invalid"));
        }
    }

    // Two fields minted at one path would leave whichever came last in place,
    // so the resource server would read one field's value for both.
    let paths = delegation.subject_claims.values().collect::<BTreeSet<_>>();
    if paths.len() != delegation.subject_claims.len() {
        return Err(invalid("subject claim paths must be unique"));
    }

    // Minting builds nested objects, so `identity` and `identity.given_name`
    // cannot both hold a value. Sorting groups any prefix with what it
    // prefixes, so comparing neighbours is enough.
    let mut segmented = paths
        .iter()
        .map(|path| path.split('.').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    segmented.sort_unstable();
    if segmented
        .windows(2)
        .any(|pair| pair[1].starts_with(&pair[0]))
    {
        return Err(invalid(
            "subject claim paths must not nest inside one another",
        ));
    }
    Ok(())
}

/// The selector field name grammar Evidence enforces on bundle selector
/// profiles. A field Mint accepts but Evidence rejects could never resolve.
fn valid_selector_field(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// The claim path grammar Evidence resolves tokens against.
fn valid_claim_path(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_CLAIM_PATH_BYTES {
        return false;
    }
    value.split('.').all(|segment| {
        let bytes = segment.as_bytes();
        !bytes.is_empty()
            && matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            && bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn build_public_jwks(
    keys: Vec<Value>,
    invalid: &impl Fn(&'static str) -> ClientRegistryError,
) -> Result<JwkSet, ClientRegistryError> {
    if keys.is_empty() || keys.len() > MAX_KEYS_PER_CLIENT {
        return Err(invalid("between 1 and 8 keys are required"));
    }

    let mut kids = BTreeSet::new();
    for key in &keys {
        let object = key
            .as_object()
            .ok_or_else(|| invalid("keys must be objects"))?;
        reject_private_material(object, invalid)?;
        let kid = object
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("every key must carry a kid"))?;
        if kid.trim().is_empty() || kid.len() > 256 {
            return Err(invalid("key ids must be 1..=256 bytes"));
        }
        if !kids.insert(kid.to_owned()) {
            return Err(invalid("key ids must be unique within a client"));
        }
    }

    let jwks: JwkSet = serde_json::from_value(Value::Object(
        [("keys".to_owned(), Value::Array(keys))]
            .into_iter()
            .collect::<Map<_, _>>(),
    ))
    .map_err(|_| invalid("keys are not a valid JWK set"))?;

    // Prove at load time that every key is actually usable, so a broken
    // registration fails at startup rather than at the first token request.
    for jwk in &jwks.keys {
        DecodingKey::from_jwk(jwk).map_err(|_| invalid("a key is not a usable public key"))?;
    }
    Ok(jwks)
}

/// Reject anything carrying private key material. A client registration is
/// public data; a private member here would mean an operator pasted a signing
/// key into the registry.
fn reject_private_material(
    object: &Map<String, Value>,
    invalid: &impl Fn(&'static str) -> ClientRegistryError,
) -> Result<(), ClientRegistryError> {
    if contains_private_material(object) {
        return Err(invalid("client keys must not contain private key material"));
    }
    Ok(())
}

/// Whether a JWK object carries any member that only exists in a private key.
///
/// Shared with the published JWKS so neither the registry nor the public key
/// set can ever carry private material.
#[must_use]
pub fn contains_private_material(object: &Map<String, Value>) -> bool {
    PRIVATE_JWK_MEMBERS
        .iter()
        .any(|member| object.contains_key(*member))
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_authcommon::fingerprint_api_key;

    const CLIENT_SECRET: &str = "M7vEwCZZ5R2UjUVn5tQJ8w23F4w7T6s8d9P0yK1mN2o";

    const CLIENT_A: &str = r#"
clientId: client-a
principal: urn:example:client-a
evidenceAudience: https://client-a.example.org
requesterTags: [ministry-of-health]
keys:
  - {kty: OKP, crv: Ed25519, kid: client-a-2026-01, alg: EdDSA, x: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo}
"#;

    const SCOPED_CLIENT: &str = r#"
clientId: relay-consumer
principal: urn:example:relay-consumer
authorization:
  scopes: [registry:business:read, registry:business:lookup]
  claims:
    purpose: statutory-consultation
    authority: district-17
keys:
  - {kty: OKP, crv: Ed25519, kid: relay-consumer-2026-01, alg: EdDSA, x: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo}
"#;

    fn secret_client(fingerprints: &[String]) -> String {
        let fingerprints = if fingerprints.is_empty() {
            "  secretFingerprints: []".to_owned()
        } else {
            format!(
                "  secretFingerprints:\n{}",
                fingerprints
                    .iter()
                    .map(|fingerprint| format!("    - {fingerprint}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        format!(
            "clientId: qgis-installation\nprincipal: urn:example:qgis-installation\nauthorization:\n  scopes: [registry:qgis:read]\nclientAuthentication:\n  method: client-secret\n{fingerprints}\n"
        )
    }

    fn registry_from(files: &[(&str, &str)]) -> Result<ClientRegistry, ClientRegistryError> {
        let directory = tempfile::tempdir().expect("temp dir");
        for (name, contents) in files {
            fs::write(directory.path().join(name), contents).expect("write client");
        }
        ClientRegistry::load(directory.path())
    }

    fn load_one(contents: &str) -> Result<ClientRegistry, ClientRegistryError> {
        registry_from(&[("client.yaml", contents)])
    }

    fn registry_error(files: &[(&str, &str)]) -> ClientRegistryError {
        registry_from(files).expect_err("the registration must be rejected")
    }

    fn load_error(contents: &str) -> ClientRegistryError {
        registry_error(&[("client.yaml", contents)])
    }

    fn invalid(reason: &'static str) -> ClientRegistryError {
        ClientRegistryError::Invalid("client.yaml".to_owned(), reason)
    }

    #[test]
    fn a_valid_registration_binds_keys_to_authority() {
        let registry = load_one(CLIENT_A).expect("registry loads");
        let client = registry.get("client-a").expect("client-a is registered");

        assert_eq!(client.principal(), "urn:example:client-a");
        assert_eq!(
            client.evidence_audience(),
            Some("https://client-a.example.org")
        );
        assert_eq!(
            client
                .requester_tags()
                .expect("the Evidence authority carries requester tags"),
            ["ministry-of-health"]
        );
        assert_eq!(client.grant(), None);
        assert_eq!(client.authorization(), None);
        assert_eq!(client.jwks().keys.len(), 1);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn a_scoped_registration_binds_standard_authority_without_evidence_fields() {
        let registry = load_one(SCOPED_CLIENT).expect("registry loads");
        let client = registry
            .get("relay-consumer")
            .expect("the scoped client is registered");
        let authorization = client
            .authorization()
            .expect("the scoped authority is present");

        assert_eq!(client.principal(), "urn:example:relay-consumer");
        assert_eq!(client.evidence_audience(), None);
        assert_eq!(client.requester_tags(), None);
        assert_eq!(client.grant(), None);
        assert_eq!(client.delegation(), None);
        assert_eq!(
            authorization.scopes,
            ["registry:business:read", "registry:business:lookup"]
        );
        assert_eq!(
            authorization.claims,
            BTreeMap::from([
                (
                    "authority".to_owned(),
                    AuthorizationClaimValue::Text("district-17".to_owned())
                ),
                (
                    "purpose".to_owned(),
                    AuthorizationClaimValue::Text("statutory-consultation".to_owned())
                ),
            ])
        );
    }

    #[test]
    fn a_standard_authority_claim_may_carry_a_list_of_values() {
        let text = SCOPED_CLIENT.replace(
            "authority: district-17",
            "authority: [district-17, district-18]",
        );
        let registry = load_one(&text).expect("registry loads");
        let authorization = registry
            .get("relay-consumer")
            .expect("the scoped client is registered")
            .authorization()
            .expect("the scoped authority is present");

        assert_eq!(
            authorization.claims,
            BTreeMap::from([
                (
                    "authority".to_owned(),
                    AuthorizationClaimValue::List(vec![
                        "district-17".to_owned(),
                        "district-18".to_owned(),
                    ])
                ),
                (
                    "purpose".to_owned(),
                    AuthorizationClaimValue::Text("statutory-consultation".to_owned())
                ),
            ])
        );
    }

    #[test]
    fn a_listed_authority_claim_is_bounded_non_empty_and_free_of_repeats() {
        let with_authority = |value: &str| {
            SCOPED_CLIENT.replace("authority: district-17", &format!("authority: {value}"))
        };

        let too_many = (0..=MAX_AUTHORIZATION_CLAIM_VALUES)
            .map(|index| format!("district-{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        for values in ["[]", &format!("[{too_many}]")] {
            assert_eq!(
                load_error(&with_authority(values)),
                invalid("authorization claim value lists must hold between 1 and 64 values"),
                "value list {values} must be refused"
            );
        }

        assert_eq!(
            load_error(&with_authority("[district-17, district-17]")),
            invalid("authorization claim values must be unique")
        );

        for value in [
            "''".to_owned(),
            format!("'{}'", "a".repeat(MAX_AUTHORIZATION_CLAIM_VALUE_BYTES + 1)),
        ] {
            assert_eq!(
                load_error(&with_authority(&format!("[{value}]"))),
                invalid("authorization claim values must be 1..=512 byte direct strings")
            );
        }

        for value in ["17", "true", "{district: 17}", "[17]", "[[district-17]]"] {
            assert!(
                load_one(&with_authority(value)).is_err(),
                "claim value {value} is neither a string nor a string list and must be refused"
            );
        }
    }

    #[test]
    fn a_client_secret_registration_is_explicit_bounded_and_verifiable() {
        let fingerprint = fingerprint_api_key(CLIENT_SECRET);
        let registry = load_one(&secret_client(std::slice::from_ref(&fingerprint)))
            .expect("client-secret registration loads");
        let client = registry
            .get("qgis-installation")
            .expect("client is registered");

        assert!(matches!(
            client.authentication(),
            ClientAuthentication::ClientSecret { secret_fingerprints }
                if secret_fingerprints == std::slice::from_ref(&fingerprint)
        ));
        assert!(!client.accepts_private_key_jwt());
        assert!(client.verifies_client_secret(CLIENT_SECRET));
        assert!(!client.verifies_client_secret("wrong-client-secret"));
        assert!(client.jwks().keys.is_empty());
    }

    #[test]
    fn client_secret_authentication_is_opt_in_and_mutually_exclusive_with_keys() {
        let registry = load_one(SCOPED_CLIENT).expect("legacy registration loads");
        assert!(registry
            .get("relay-consumer")
            .expect("client is registered")
            .accepts_private_key_jwt());

        let fingerprint = fingerprint_api_key(CLIENT_SECRET);
        let with_key = secret_client(std::slice::from_ref(&fingerprint)).replace(
            "clientAuthentication:",
            "keys:\n  - {kty: OKP, crv: Ed25519, kid: client-key, alg: EdDSA, x: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo}\nclientAuthentication:",
        );
        assert_eq!(
            load_error(&with_key),
            invalid("client-secret and private-key-jwt authentication are mutually exclusive")
        );

        let missing_keys = SCOPED_CLIENT
            .lines()
            .take_while(|line| *line != "keys:")
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            load_error(&missing_keys),
            invalid("private-key-jwt authentication requires client keys")
        );
    }

    #[test]
    fn client_secret_fingerprints_are_canonical_unique_and_rotation_bounded() {
        let first = fingerprint_api_key(CLIENT_SECRET);
        let second = fingerprint_api_key("another-high-entropy-client-secret-value");
        load_one(&secret_client(&[first.clone(), second.clone()]))
            .expect("two rotation fingerprints load");

        for (fingerprints, reason) in [
            (
                Vec::<String>::new(),
                "between 1 and 2 client-secret fingerprints are required",
            ),
            (
                vec![first.clone(), second.clone(), fingerprint_api_key("third")],
                "between 1 and 2 client-secret fingerprints are required",
            ),
            (
                vec![first.clone(), first.clone()],
                "client-secret fingerprints must be unique",
            ),
            (
                vec!["sha256:not-canonical".to_owned()],
                "client-secret fingerprints must be canonical SHA-256 values",
            ),
        ] {
            assert_eq!(load_error(&secret_client(&fingerprints)), invalid(reason));
        }
    }

    #[test]
    fn client_secret_authentication_cannot_enter_the_evidence_authority_profile() {
        let fingerprint = fingerprint_api_key(CLIENT_SECRET);
        let evidence = CLIENT_A
            .lines()
            .take_while(|line| *line != "keys:")
            .chain([
                "clientAuthentication:",
                "  method: client-secret",
                "  secretFingerprints:",
                &format!("    - {fingerprint}"),
            ])
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            load_error(&evidence),
            invalid("client-secret authentication requires standard authorization")
        );
    }

    #[test]
    fn authority_profiles_are_required_complete_and_mutually_exclusive() {
        let no_authority = SCOPED_CLIENT.replace(
            "authorization:\n  scopes: [registry:business:read, registry:business:lookup]\n  claims:\n    purpose: statutory-consultation\n    authority: district-17\n",
            "",
        );
        assert_eq!(
            load_error(&no_authority),
            invalid("an Evidence authority or standard authorization is required")
        );

        let incomplete = CLIENT_A.replace("evidenceAudience: https://client-a.example.org\n", "");
        assert_eq!(
            load_error(&incomplete),
            invalid("Evidence authority requires evidenceAudience and requesterTags")
        );

        let combined = CLIENT_A.replace(
            "requesterTags: [ministry-of-health]\n",
            "requesterTags: [ministry-of-health]\nauthorization: {scopes: [registry:read]}\n",
        );
        assert_eq!(
            load_error(&combined),
            invalid("Evidence authority and standard authorization are mutually exclusive")
        );
    }

    #[test]
    fn standard_authority_is_closed_bounded_and_cannot_shadow_token_claims() {
        let empty = SCOPED_CLIENT.replace(
            "scopes: [registry:business:read, registry:business:lookup]",
            "scopes: []",
        );
        assert_eq!(
            load_error(&empty),
            invalid("between 1 and 64 authorization scopes are required")
        );

        for scopes in [
            "[registry:read, registry:read]",
            "['registry:read records']",
            "['registry:read\\records']",
        ] {
            let text =
                SCOPED_CLIENT.replace("[registry:business:read, registry:business:lookup]", scopes);
            assert!(
                load_one(&text).is_err(),
                "invalid scopes {scopes} must be refused"
            );
        }

        for reserved in RESERVED_ACCESS_TOKEN_CLAIMS {
            let text = SCOPED_CLIENT.replace("purpose:", &format!("{reserved}:"));
            assert_eq!(
                load_error(&text),
                invalid("authorization claims must not shadow registered access-token claims"),
                "claim {reserved} must be refused"
            );
        }

        let empty_value = SCOPED_CLIENT.replace("purpose: statutory-consultation", "purpose: ''");
        assert_eq!(
            load_error(&empty_value),
            invalid("authorization claim values must be 1..=512 byte direct strings")
        );
    }

    #[test]
    fn standard_authority_size_limits_are_enforced_before_minting() {
        let replace_authorization = |authorization: &str| {
            SCOPED_CLIENT.replace(
                "authorization:\n  scopes: [registry:business:read, registry:business:lookup]\n  claims:\n    purpose: statutory-consultation\n    authority: district-17",
                authorization,
            )
        };

        let too_many_scopes = (0..=MAX_AUTHORIZATION_SCOPES)
            .map(|index| format!("scope:{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            load_error(&replace_authorization(&format!(
                "authorization:\n  scopes: [{too_many_scopes}]"
            ))),
            invalid("between 1 and 64 authorization scopes are required")
        );

        assert_eq!(
            load_error(&replace_authorization(&format!(
                "authorization:\n  scopes: ['{}']",
                "a".repeat(MAX_SCOPE_BYTES + 1)
            ))),
            invalid("authorization scopes must be 1..=256 byte RFC 6749 scope-tokens")
        );

        let too_many_claims = (0..=MAX_AUTHORIZATION_CLAIMS)
            .map(|index| format!("    claim{index}: value"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            load_error(&replace_authorization(&format!(
                "authorization:\n  scopes: [registry:read]\n  claims:\n{too_many_claims}"
            ))),
            invalid("at most 32 authorization claims are permitted")
        );

        for name in [
            "claim with space".to_owned(),
            "a".repeat(MAX_AUTHORIZATION_CLAIM_NAME_BYTES + 1),
        ] {
            assert_eq!(
                load_error(&replace_authorization(&format!(
                    "authorization:\n  scopes: [registry:read]\n  claims:\n    '{name}': value"
                ))),
                invalid("authorization claim names are invalid")
            );
        }

        assert_eq!(
            load_error(&replace_authorization(&format!(
                "authorization:\n  scopes: [registry:read]\n  claims:\n    purpose: '{}'",
                "a".repeat(MAX_AUTHORIZATION_CLAIM_VALUE_BYTES + 1)
            ))),
            invalid("authorization claim values must be 1..=512 byte direct strings")
        );
    }

    #[test]
    fn private_key_material_is_rejected() {
        for member in PRIVATE_JWK_MEMBERS {
            let text = CLIENT_A.replace(
                "alg: EdDSA,",
                &format!("alg: EdDSA, {member}: nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A,"),
            );
            assert_eq!(
                load_error(&text),
                invalid("client keys must not contain private key material"),
                "member {member} must be rejected"
            );
        }
    }

    #[test]
    fn keys_require_unique_non_empty_kids() {
        let text = CLIENT_A.replace("kid: client-a-2026-01, ", "");
        assert_eq!(load_error(&text), invalid("every key must carry a kid"));

        let duplicated = format!(
            "{CLIENT_A}  - {{kty: OKP, crv: Ed25519, kid: client-a-2026-01, alg: EdDSA, x: 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo}}\n"
        );
        assert_eq!(
            load_error(&duplicated),
            invalid("key ids must be unique within a client")
        );
    }

    #[test]
    fn evidence_audience_must_parse_as_a_url() {
        let text = CLIENT_A.replace("https://client-a.example.org", "not-a-url");
        assert_eq!(
            load_error(&text),
            invalid("evidence audience must be a URL")
        );
    }

    #[test]
    fn requester_tags_are_required_bounded_and_unique() {
        let text = CLIENT_A.replace("[ministry-of-health]", "[]");
        assert_eq!(
            load_error(&text),
            invalid("between 1 and 32 requester tags are required")
        );

        let text = CLIENT_A.replace("[ministry-of-health]", "[a, a]");
        assert_eq!(load_error(&text), invalid("requester tags must be unique"));
    }

    #[test]
    fn duplicate_client_ids_across_files_fail_the_whole_load() {
        assert_eq!(
            registry_error(&[("a.yaml", CLIENT_A), ("b.yaml", CLIENT_A)]),
            ClientRegistryError::Duplicate("client-a".to_owned())
        );
    }

    #[test]
    fn unknown_registration_fields_are_rejected() {
        let text = CLIENT_A.replace("clientId: client-a", "clientId: client-a\nunexpected: true");
        assert!(matches!(
            load_one(&text),
            Err(ClientRegistryError::Document(_, _))
        ));
    }

    #[test]
    fn a_grant_requires_both_an_id_and_an_authority() {
        let text = format!("{CLIENT_A}grant: {{id: grant-1, authority: statute-7}}\n");
        let registry = load_one(&text).expect("registry loads");
        let client = registry.get("client-a").expect("client-a is registered");
        assert_eq!(
            client.grant(),
            Some(&Grant {
                id: "grant-1".to_owned(),
                authority: "statute-7".to_owned()
            })
        );

        let text = format!("{CLIENT_A}grant: {{id: grant-1}}\n");
        assert!(matches!(
            load_one(&text),
            Err(ClientRegistryError::Document(_, _))
        ));
    }

    /// A registration with a `delegation` block, whose subject claims mirror
    /// the `valueClaims` of an `authenticated-context` entitlement.
    fn delegated(body: &str) -> String {
        format!("{CLIENT_A}delegation:\n{body}")
    }

    const SUBJECT_CLAIMS: &str =
        "  subjectClaims:\n    given_name: identity.given_name\n    birth_date: identity.birth_date\n";

    #[test]
    fn a_delegated_registration_declares_its_actors_and_subject_claims() {
        let text = delegated(&format!(
            "  actors: [urn:example:agent:scheduling]\n{SUBJECT_CLAIMS}"
        ));
        let registry = load_one(&text).expect("registry loads");
        let client = registry.get("client-a").expect("client-a is registered");
        let delegation = client.delegation().expect("client-a may delegate");

        assert_eq!(
            delegation.subject_claims,
            BTreeMap::from([
                ("given_name".to_owned(), "identity.given_name".to_owned()),
                ("birth_date".to_owned(), "identity.birth_date".to_owned()),
            ])
        );
        assert!(delegation.permits_actor("urn:example:agent:scheduling"));
        assert!(!delegation.permits_actor("urn:example:agent:other"));

        // Ordinary registrations stay undelegated, which is what makes an
        // assertion asking to delegate refusable.
        assert_eq!(
            load_one(CLIENT_A)
                .expect("registry loads")
                .get("client-a")
                .expect("client-a is registered")
                .delegation(),
            None
        );
    }

    #[test]
    fn an_omitted_actor_list_permits_any_actor_the_client_names() {
        let registry = load_one(&delegated(SUBJECT_CLAIMS)).expect("registry loads");
        let client = registry.get("client-a").expect("client-a is registered");
        let delegation = client.delegation().expect("client-a may delegate");

        assert_eq!(delegation.actors, None);
        assert!(delegation.permits_actor("urn:example:agent:anything"));
    }

    #[test]
    fn an_actor_list_must_be_non_empty_bounded_and_unique() {
        assert_eq!(
            load_error(&delegated(&format!("  actors: []\n{SUBJECT_CLAIMS}"))),
            invalid("between 1 and 64 delegated actors are required")
        );
        assert_eq!(
            load_error(&delegated(&format!("  actors: [a, a]\n{SUBJECT_CLAIMS}"))),
            invalid("delegated actors must be unique")
        );
        assert_eq!(
            load_error(&delegated(&format!("  actors: ['']\n{SUBJECT_CLAIMS}"))),
            invalid("delegated actors must be 1..=512 bytes")
        );
    }

    #[test]
    fn subject_claim_paths_must_use_the_resource_servers_claim_path_grammar() {
        for path in ["identity..given_name", "1identity.given_name", "", "a.b!c"] {
            let text = delegated(&format!("  subjectClaims:\n    given_name: \"{path}\"\n"));
            assert_eq!(
                load_error(&text),
                invalid("subject claim paths are invalid"),
                "path {path:?} must be rejected"
            );
        }
    }

    #[test]
    fn subject_claim_field_names_follow_the_selector_profile_grammar() {
        for field in ["Given_Name", "1given", "given name", ""] {
            let text = delegated(&format!(
                "  subjectClaims:\n    \"{field}\": identity.given_name\n"
            ));
            assert_eq!(
                load_error(&text),
                invalid("subject claim field names are invalid"),
                "field {field:?} must be rejected"
            );
        }
    }

    /// Minting builds nested objects, so a path and a path inside it cannot
    /// both hold a value.
    #[test]
    fn subject_claim_paths_must_be_unique_and_must_not_nest() {
        let text = delegated(
            "  subjectClaims:\n    given_name: identity.name\n    family_name: identity.name\n",
        );
        assert_eq!(
            load_error(&text),
            invalid("subject claim paths must be unique")
        );

        let text = delegated(
            "  subjectClaims:\n    given_name: identity\n    family_name: identity.family_name\n",
        );
        assert_eq!(
            load_error(&text),
            invalid("subject claim paths must not nest inside one another")
        );
    }

    #[test]
    fn a_delegation_must_bind_at_least_one_subject_claim() {
        // Delegation with no subject binding would be an actor label on an
        // otherwise unbounded token.
        let text = delegated("  subjectClaims: {}\n");
        assert_eq!(
            load_error(&text),
            invalid("between 1 and 16 subject claims are required")
        );

        let fields = (0..17)
            .map(|index| format!("    field_{index}: identity.f{index}\n"))
            .collect::<String>();
        assert_eq!(
            load_error(&delegated(&format!("  subjectClaims:\n{fields}"))),
            invalid("between 1 and 16 subject claims are required")
        );
    }

    #[test]
    fn debug_output_redacts_client_authority() {
        let registry = load_one(CLIENT_A).expect("registry loads");
        let client = registry.get("client-a").expect("client-a is registered");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("urn:example:client-a"));
        assert!(!rendered.contains("ministry-of-health"));
        assert!(!rendered.contains("client-a.example.org"));

        let registry = load_one(SCOPED_CLIENT).expect("registry loads");
        let client = registry
            .get("relay-consumer")
            .expect("the scoped client is registered");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("registry:business:read"));
        assert!(!rendered.contains("statutory-consultation"));
        assert!(!rendered.contains("district-17"));
    }

    #[test]
    fn non_yaml_files_are_ignored() {
        let registry = registry_from(&[
            ("client.yaml", CLIENT_A),
            ("notes.txt", "not a registration"),
            ("client.yaml.bak", "also not a registration"),
        ])
        .expect("registry loads");
        assert_eq!(registry.len(), 1);
    }
}
