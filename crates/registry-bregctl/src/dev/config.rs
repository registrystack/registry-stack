// SPDX-License-Identifier: Apache-2.0
//! Authored local teaching identities and generated private service bindings.

use super::{private, State, DATABASE_ID, MAX_BYTES, MIGRATION_ROLE, RUNTIME_ROLE};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::SigningKey;
use registry_breg::literal_text::{
    LiteralText, WRITE_THE_VALUE, WRITE_THE_VALUE_OR_A_SECRET_REFERENCE,
};
use registry_platform_config::{SecretProvidersConfig, SecretReference};
use registry_platform_yaml::{
    ApiVersion, Diagnostic, Document, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey, Report,
    Severity,
};
use registry_platform_yaml::{ExternalId, LocalId, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use zeroize::Zeroizing;

pub(super) const API_VERSION: &str = "id.registrystack.org/formats/breg/dev-clients/v1alpha1";
pub(super) const KIND: &str = "BRegDevClients";

/// The development clients file `bregctl dev start` reads, and the copy a
/// session retains as `.breg/dev/clients.json`.
pub(crate) const DEV_CLIENTS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/version",
            replacement: "Delete `version`; the apiVersion header names the format version.",
        },
        RemovedKey {
            pointer: "/clients/*/clientIdFile",
            replacement: "Delete it; copy a client's credential pair with `bregctl dev export-client` once the session has started.",
        },
        RemovedKey {
            pointer: "/clients/*/assertionKeyFile",
            replacement: "Delete it; copy a client's credential pair with `bregctl dev export-client` once the session has started.",
        },
        RemovedKey {
            pointer: "/clients/*/assertionKeyInputFile",
            replacement: "Use `assertionKeyRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/eventDestinations/*/hmacKeyFile",
            replacement: "Use `hmacSha256KeyRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/evidenceProviders/*/tokenFile",
            replacement: "Use `tokenRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/evidenceProviders/*/trustedJwksFile",
            replacement: "Use `trustedJwksRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/evidenceProviders/*/caBundleFile",
            replacement: "Use `caBundleRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/evidenceProviders/*/privateKeyJwt/privateKeyFile",
            replacement: "Use `privateKeyRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/reviewAuthorities/*/completionTokenFile",
            replacement: "Use `completionTokenRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/issuer/interactiveApplications/*/clientSecretFile",
            replacement: "Use `clientSecretRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/issuer/syntheticUsers/*/passwordFile",
            replacement: "Use `passwordRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
    ],
};

/// The JSON Schema of the development clients members the reader decodes. The
/// header is checked and removed before decoding, so the publisher adds it.
#[cfg(feature = "schema")]
pub(crate) fn clients_schema() -> schemars::Schema {
    schemars::schema_for!(Clients)
}

/// Members that name something by a local identifier, an outside identifier,
/// or an absolute URL decode through the reader's own types, so a refusal
/// carries its code and position.
fn local_id<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    LocalId::deserialize(deserializer).map(LocalId::into_string)
}

fn url<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Url::deserialize(deserializer).map(Url::into_string)
}

fn local_id_keys<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Deserialize<'de>,
{
    let map = BTreeMap::<LocalId, V>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

fn external_id_keys<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Deserialize<'de>,
{
    let map = BTreeMap::<ExternalId, V>::deserialize(deserializer)?;
    Ok(map
        .into_iter()
        .map(|(key, value)| (key.into_string(), value))
        .collect())
}

/// An id-keyed mapping: `propertyNames` and the item schema (CFG-ID-1).
#[cfg(feature = "schema")]
fn keyed_schema<K: schemars::JsonSchema, V: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<K>(),
        "additionalProperties": generator.subschema_for::<V>(),
    })
}

/// Claim values are written into the development token as given.
#[cfg(feature = "schema")]
fn claims_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "propertyNames": generator.subschema_for::<ExternalId>(),
        "additionalProperties": true,
        "x-registry-passthrough": "Claim values are written into the development token as given.",
    })
}

/// The record body is sent to the registry as given; the registry validates it.
#[cfg(feature = "schema")]
fn seed_data_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "additionalProperties": true,
        "x-registry-passthrough": "The record body is sent to the registry as given; the registry validates it.",
    })
}

fn api_version() -> String {
    API_VERSION.to_owned()
}

fn kind() -> String {
    KIND.to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Clients {
    #[serde(skip_deserializing, default = "api_version")]
    pub api_version: String,
    #[serde(skip_deserializing, default = "kind")]
    pub kind: String,
    /// The providers that resolve this file's secret references. Required
    /// once any member names a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_providers: Option<SecretProvidersConfig>,
    pub clients: Vec<Client>,
    #[serde(default)]
    pub seed: Vec<Seed>,
    #[serde(default)]
    pub issuer: IssuerComposition,
    /// Optional exact local webhook bindings. An empty map keeps the inbox.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, LocalEventDestination>")
    )]
    pub event_destinations: BTreeMap<String, LocalEventDestination>,
    /// Exact local Evidence provider bindings for governed action packages.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, LocalEvidenceProvider>")
    )]
    pub evidence_providers: BTreeMap<String, LocalEvidenceProvider>,
    /// Exact local Casework review-authority bindings for governed proposals.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, LocalReviewAuthority>")
    )]
    pub review_authorities: BTreeMap<String, LocalReviewAuthority>,
    /// Exact local service clients that apply approved change requests.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, LocalReviewExecutor>")
    )]
    pub review_executors: BTreeMap<String, LocalReviewExecutor>,
    /// Exact Casework status services for compiled task-grant profiles.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, LocalTaskGrantStatus>")
    )]
    pub task_grant_status: BTreeMap<String, LocalTaskGrantStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalEventDestination {
    pub origin: String,
    pub path: String,
    pub hmac_sha256_key_ref: SecretReference,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalEvidenceProvider {
    #[serde(deserialize_with = "url")]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
    pub base_url: String,
    pub trust_binding_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ref: Option<SecretReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_jwt: Option<LocalEvidencePrivateKeyJwt>,
    pub trusted_jwks_ref: SecretReference,
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_ref: Option<SecretReference>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalEvidencePrivateKeyJwt {
    pub token_endpoint: String,
    pub client_id: String,
    pub private_key_ref: SecretReference,
    pub assertion_audience: String,
    pub resource: String,
    pub scopes: Vec<String>,
}

fn recovery_days<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    registry_platform_yaml::BoundedU32::<1, 90>::deserialize(deserializer)
        .map(registry_platform_yaml::BoundedU32::get)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalReviewAuthority {
    pub endpoint: String,
    /// Casework requester access profile selected on every authority exchange.
    pub profile: String,
    pub producer_id: String,
    #[serde(deserialize_with = "recovery_days")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 90)))]
    pub recovery_days: u32,
    /// Logical client from this same closed file. Its generated key is copied
    /// into the private runtime secret tree and is never written to this file.
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_token_ref: Option<SecretReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_recipient: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalReviewExecutor {
    /// The one service-only apply-request profile selected by the worker.
    pub access_profile: String,
    /// Logical client from this same closed file. Its retained issuer key is
    /// copied into the private runtime secret tree.
    pub client: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalTaskGrantStatus {
    pub source_issuer: ExternalId,
    #[serde(deserialize_with = "url")]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
    pub base_url: String,
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub client: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IssuerComposition {
    #[serde(default)]
    pub resources: Vec<IssuerResource>,
    #[serde(default)]
    pub exchange_issuers: Vec<IssuerConnection>,
    #[serde(default)]
    pub interactive_applications: Vec<BrowserApplication>,
    /// Owner-registered browser app IDs this borrower admits at its BREG resource.
    #[serde(default)]
    pub browser_clients: Vec<String>,
    #[serde(default)]
    pub synthetic_users: Vec<BrowserUser>,
    /// Client IDs mapped to a non-default resource audience.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, String>")
    )]
    pub client_resources: BTreeMap<String, String>,
    /// Clients with one bootstrap scope that may exchange signed assertions.
    #[serde(default)]
    pub exchange_clients: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IssuerResource {
    pub audience: String,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IssuerConnection {
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub id: String,
    #[serde(deserialize_with = "url")]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
    pub issuer: String,
    pub jwks_endpoint: String,
    pub mapping: IssuerConnectionMapping,
    /// The exchange clients paired with this connection's authority. A
    /// resource server refuses every other authority's assertion from them,
    /// and under first-party mapping these are also the clients whose claims
    /// this connection projects.
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default, deserialize_with = "external_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<ExternalId, ExchangeAttributeKindSchema>")
    )]
    pub token_attributes:
        BTreeMap<String, registry_thunderid_tooling::description::ExchangeAttributeKind>,
}

/// The schema of `ExchangeAttributeKind`, which lives in a crate that does not
/// derive schemas.
#[cfg(feature = "schema")]
#[derive(schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[allow(dead_code)]
enum ExchangeAttributeKindSchema {
    String,
    StringArray,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(super) enum IssuerConnectionMapping {
    InstitutionalGrant,
    FirstParty,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserApplication {
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub id: String,
    pub client_secret_ref: SecretReference,
    pub origin: String,
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Explicit permissions granted to this application, per resource audience.
    #[serde(default)]
    pub grants: Vec<LocalPermissionGrant>,
    pub token_attributes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BrowserUser {
    pub username: String,
    pub email: String,
    pub password_ref: SecretReference,
    #[serde(deserialize_with = "external_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<ExternalId, String>")
    )]
    pub attributes: BTreeMap<String, String>,
    /// Explicit permissions granted to this user, per resource audience.
    #[serde(default)]
    pub grants: Vec<LocalPermissionGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalPermissionGrant {
    /// Omit for the owner BREG resource; otherwise use a declared audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Client {
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub id: String,
    /// The access profiles this client is the one local binding for. Empty
    /// means no journey step resolves to it and no seed may reference it.
    pub access_profiles: Vec<String>,
    /// Explicitly admits a profile-free integration client to BReg's
    /// `allowedClients`. The default is false, so a client carrying scopes or
    /// claims for another product cannot call BReg accidentally.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_breg_access: bool,
    /// Explicitly permits this local teaching client to carry the human actor
    /// marker. This does not admit the client to BReg's allowedClients.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_human_fixture: bool,
    pub scopes: Vec<String>,
    #[serde(deserialize_with = "external_id_keys")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "claims_schema"))]
    pub claims: BTreeMap<String, Value>,
    /// Additional explicit permissions on declared resource audiences. These
    /// do not change default token scopes or the exchange bootstrap scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<LocalPermissionGrant>,
    /// Exact schema-test steps that use this claim variant. Runtime requests
    /// still select an authored access profile; this field only disambiguates
    /// credentials for maintained local journeys.
    #[serde(default)]
    pub test_bindings: Vec<TestBinding>,
    /// Existing ES256 assertion key, for a client whose key is already
    /// governed by another local tool such as Evidence access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_key_ref: Option<SecretReference>,
}

/// The purposes one logical local client may request in a schema-test step.
///
/// A scalar `registry_purpose` keeps the original one-purpose form. An array
/// declares a closed set; the first value remains the ordinary dev token's
/// purpose, while rehearsal tokens may select any declared member.
pub(super) fn client_purposes(client: &Client) -> Result<Vec<Option<String>>> {
    let Some(value) = client.claims.get("registry_purpose") else {
        return Ok(vec![None]);
    };
    let values = match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("registry_purpose entries must be strings")
            })
            .collect::<Result<Vec<_>>>()?,
        _ => bail!("registry_purpose must be a string or a list of strings"),
    };
    if values.is_empty()
        || values.len() > 16
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > 256)
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        bail!("registry_purpose needs 1..16 distinct bounded values");
    }
    Ok(values.into_iter().map(Some).collect())
}

/// Return the exact authored client claims with the ordinary machine default
/// made explicit. Direct credentials and exchanged credentials must carry the
/// same actor semantics even when the author omits this optional teaching
/// marker.
pub(super) fn client_token_claims(client: &Client) -> BTreeMap<String, Value> {
    let mut claims = client.claims.clone();
    claims
        .entry("registry_actor_kind".to_owned())
        .or_insert_with(|| json!("service"));
    claims
}

fn is_false(value: &bool) -> bool {
    !value
}

const ASSERTION_KEY_BYTES: usize = 16 * 1024;
const CLIENT_SECRET_BYTES: usize = 1024;
const PASSWORD_BYTES: usize = 1024;
const HMAC_KEY_BYTES: usize = 1024;
const COMPLETION_TOKEN_BYTES: usize = 4096;
const EVIDENCE_TOKEN_BYTES: usize = 16 * 1024;
const EVIDENCE_DOCUMENT_BYTES: usize = 64 * 1024;

/// One secret an Evidence provider references: the member naming it, the
/// reference, its bound, and the private file the session copies it to.
struct EvidenceSecret<'a> {
    member: String,
    reference: &'a SecretReference,
    maximum: usize,
    copy: String,
}

/// Every secret one Evidence provider references.
fn evidence_secrets<'a>(id: &str, provider: &'a LocalEvidenceProvider) -> Vec<EvidenceSecret<'a>> {
    let mut secrets = vec![EvidenceSecret {
        member: format!("evidenceProviders.{id}.trustedJwksRef"),
        reference: &provider.trusted_jwks_ref,
        maximum: EVIDENCE_DOCUMENT_BYTES,
        copy: format!("evidence-jwks-{id}"),
    }];
    if let Some(reference) = &provider.token_ref {
        secrets.push(EvidenceSecret {
            member: format!("evidenceProviders.{id}.tokenRef"),
            reference,
            maximum: EVIDENCE_TOKEN_BYTES,
            copy: format!("evidence-token-{id}"),
        });
    }
    if let Some(credentials) = &provider.private_key_jwt {
        secrets.push(EvidenceSecret {
            member: format!("evidenceProviders.{id}.privateKeyJwt.privateKeyRef"),
            reference: &credentials.private_key_ref,
            maximum: EVIDENCE_DOCUMENT_BYTES,
            copy: format!("evidence-client-key-{id}"),
        });
    }
    if let Some(reference) = &provider.ca_bundle_ref {
        secrets.push(EvidenceSecret {
            member: format!("evidenceProviders.{id}.caBundleRef"),
            reference,
            maximum: EVIDENCE_DOCUMENT_BYTES,
            copy: format!("evidence-ca-{id}"),
        });
    }
    secrets
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TestBinding {
    pub journey_id: String,
    pub step_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Seed {
    #[serde(deserialize_with = "local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "LocalId"))]
    pub id: String,
    pub client: String,
    pub entity: String,
    pub access_profile: String,
    #[serde(default)]
    pub operation: SeedOperation,
    #[cfg_attr(feature = "schema", schemars(schema_with = "seed_data_schema"))]
    pub data: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub(super) enum SeedOperation {
    #[default]
    Create,
    Import,
}

/// The governed identifier grammar of a registry project.
///
/// A name that must equal one the project declares, an Evidence provider or a
/// governed action among them, is held to the project's own grammar rather than
/// this file's narrower one. The two differ by the underscore, and refusing it
/// here would make a declared name a dev session can never bind.
pub(super) fn governed_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

pub(super) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn grant_scopes(clients: &Clients, audience: Option<&str>, scopes: &[String]) -> bool {
    let available: BTreeSet<_> = match audience {
        Some(audience) => clients
            .issuer
            .resources
            .iter()
            .find(|resource| resource.audience == audience)
            .map(|resource| resource.scopes.iter().map(String::as_str).collect())
            .unwrap_or_default(),
        None => clients
            .clients
            .iter()
            .filter(|client| !clients.issuer.client_resources.contains_key(&client.id))
            .flat_map(|client| client.scopes.iter().map(String::as_str))
            .collect(),
    };
    !scopes.is_empty()
        && scopes.len() <= 32
        && scopes.iter().collect::<BTreeSet<_>>().len() == scopes.len()
        && scopes
            .iter()
            .all(|scope| available.contains(scope.as_str()))
}

fn valid_grants(clients: &Clients, grants: &[LocalPermissionGrant]) -> bool {
    !grants.is_empty()
        && grants.len() <= 7
        && grants
            .iter()
            .all(|grant| grant_scopes(clients, grant.audience.as_deref(), &grant.scopes))
        && grants
            .iter()
            .map(|grant| grant.audience.as_deref())
            .collect::<BTreeSet<_>>()
            .len()
            == grants.len()
}

/// A development clients file the shared reader refused. `bregctl dev`
/// prints its diagnostics unchanged (CFG-DIAG-1, CFG-DIAG-2).
#[derive(Debug)]
pub(crate) struct ClientsRefused(pub Report);

impl std::fmt::Display for ClientsRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.render_human())
    }
}

impl std::error::Error for ClientsRefused {}

/// Decode a development clients document through the shared reader, without
/// the semantic checks or secret resolution `clients` adds.
pub(super) fn decode(file: &str, bytes: &[u8]) -> Result<Clients, Report> {
    Reader::new(file)
        .with_hook(&mut LiteralText {
            remedy: WRITE_THE_VALUE_OR_A_SECRET_REFERENCE,
        })
        .decode::<Clients>(bytes, &Expect::one(&DEV_CLIENTS_FORMAT))
        .map(|decoded| decoded.value)
}

/// The clients a session retains in `.breg/dev/clients.json`, written by this
/// `bregctl` when the session started. Secrets are not resolved again.
pub(super) fn retained(bytes: &[u8]) -> Result<Clients, Report> {
    decode(".breg/dev/clients.json", bytes)
}

/// Resolve one secret the clients file references, bounded to `maximum`
/// bytes. A refusal names the member and never the reference or the value
/// (CFG-SEC-3).
fn resolve_secret(
    clients: &Clients,
    member: &str,
    reference: &SecretReference,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let Some(providers) = &clients.secret_providers else {
        bail!(
            "{member} names a secret, but the clients file declares no secretProviders; \
             declare secretProviders.file with an absolute root, secretProviders.environment, or both"
        );
    };
    let resolver = providers.resolver().map_err(|_| {
        anyhow::anyhow!(
            "secretProviders cannot resolve {member}; \
             declare secretProviders.file with an absolute root, secretProviders.environment, or both"
        )
    })?;
    let secret = resolver.resolve_reference(reference).map_err(|error| {
        let fix = match error {
            registry_platform_config::SecretError::ProviderDisabled => {
                "declare the provider the reference names under secretProviders"
            }
            registry_platform_config::SecretError::Unavailable => {
                "create the file under secretProviders.file.root, or set the environment variable the reference names"
            }
            registry_platform_config::SecretError::UnsafeFile => {
                "make it a regular file you own, with mode 0400 or 0600 and a single link"
            }
            registry_platform_config::SecretError::InvalidValue => {
                "store a non-empty value without NUL bytes, at most 64 KiB"
            }
            _ => "check the reference and the provider that resolves it",
        };
        anyhow::anyhow!("{member} could not be resolved: {error}; {fix}")
    })?;
    if secret.len() > maximum {
        bail!("{member} is larger than its {maximum}-byte limit; store the expected secret under this reference");
    }
    Ok(Zeroizing::new(secret.expose_secret().to_vec()))
}

/// How a clients check treats the secrets the file references.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Secrets {
    /// Resolve every secret and check its value, as a session start does.
    Resolve,
    /// Check that every reference names an enabled provider, reading no
    /// secret (CFG-CHECK-1).
    Declared,
}

/// One secret the clients file references: its value when `secrets`
/// resolves, nothing when it only checks the declaration.
fn secret(
    clients: &Clients,
    secrets: Secrets,
    member: &str,
    reference: &SecretReference,
    maximum: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match secrets {
        Secrets::Resolve => resolve_secret(clients, member, reference, maximum).map(Some),
        Secrets::Declared => {
            let Some(providers) = &clients.secret_providers else {
                bail!(
                    "{member} names a secret, but the clients file declares no secretProviders; \
                     declare secretProviders.file with an absolute root, secretProviders.environment, or both"
                );
            };
            providers
                .check_reference(member, reference.as_str())
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            Ok(None)
        }
    }
}

/// Read a development clients file, check it, and resolve every secret it
/// references.
pub(super) fn clients(file: &str, bytes: &[u8]) -> Result<Clients> {
    let clients = decode(file, bytes).map_err(ClientsRefused)?;
    validate(clients, Secrets::Resolve)
}

/// Check a development clients document `bregctl check --file` read,
/// without resolving a secret: a reference only has to name an enabled
/// provider. A refusal is one diagnostic at the document root.
pub(crate) fn check(document: &Document) -> Result<Vec<Diagnostic>, Report> {
    let clients = document.decode::<Clients>()?;
    Ok(match validate(clients, Secrets::Declared) {
        Ok(_) => Vec::new(),
        Err(error) => vec![document.diagnostic_at_value(
            Severity::Error,
            "breg.dev-clients.refused",
            "",
            &error.to_string(),
            "Correct the clients file as the message says, then check it again.",
        )],
    })
}

fn validate(clients: Clients, secrets: Secrets) -> Result<Clients> {
    if let Some(providers) = &clients.secret_providers {
        providers.check().map_err(|error| {
            anyhow::anyhow!("{error}; declare secretProviders.file with an absolute root, secretProviders.environment, or both")
        })?;
    }
    if clients.clients.is_empty() || clients.clients.len() > 32 || clients.seed.len() > 100 {
        bail!("local clients require 1..32 explicit clients and at most 100 seed records");
    }
    let mut ids = BTreeSet::new();
    let mut profile_defaults = BTreeSet::new();
    let mut test_bindings = BTreeSet::new();
    for client in &clients.clients {
        let mut client_profiles = BTreeSet::new();
        if client.id == "issuer"
            || !identifier(&client.id)
            || !ids.insert(&client.id)
            || client.scopes.is_empty()
        {
            bail!("local clients need unique bounded IDs and explicit scopes");
        }
        let carries_human_marker = client
            .claims
            .get("registry_actor_kind")
            .is_some_and(|kind| kind == "human");
        if client.allow_human_fixture != carries_human_marker {
            bail!("allowHumanFixture must be true exactly when registry_actor_kind is human");
        }
        for profile in &client.access_profiles {
            if !identifier(profile) || !client_profiles.insert(profile) {
                bail!(
                    "local access profile bindings must be unique bounded identifiers per client"
                );
            }
            if client.test_bindings.is_empty() && !profile_defaults.insert(profile) {
                bail!("a shared local access profile needs at most one default client; use exact testBindings for claim variants");
            }
        }
        if client.test_bindings.len() > 100 {
            bail!("one local client may bind at most 100 schema-test steps");
        }
        for binding in &client.test_bindings {
            if !identifier(&binding.journey_id)
                || !identifier(&binding.step_id)
                || !test_bindings.insert(binding.clone())
            {
                bail!("testBindings need unique exact bounded journeyId and stepId pairs");
            }
        }
        if client.scopes.len() > 32
            || client.claims.len() > 32
            || client
                .scopes
                .iter()
                .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_whitespace))
        {
            bail!("local client scopes or claims exceed their bounds");
        }
        client_purposes(client)?;
        if let Some(reference) = &client.assertion_key_ref {
            secret(
                &clients,
                secrets,
                &format!("clients.{}.assertionKeyRef", client.id),
                reference,
                ASSERTION_KEY_BYTES,
            )?;
        }
    }
    // Every multi-purpose client shares the one generated first-party purpose
    // connection, which projects the union of their claim names plus the
    // signer-generated claims. The issuer bounds that union, not each client.
    let mut purpose_claims = BTreeSet::new();
    for client in &clients.clients {
        if client_purposes(client)?.len() > 1 {
            purpose_claims.extend(client_token_claims(client).into_keys());
            purpose_claims.extend(
                super::purpose::GENERATED_CLAIMS
                    .iter()
                    .map(|name| (*name).to_owned()),
            );
        }
    }
    let limit = registry_thunderid_tooling::description::MAX_FIRST_PARTY_TOKEN_ATTRIBUTES;
    if purpose_claims.len() > limit {
        bail!(
            "multi-purpose clients may together project at most {limit} distinct token claims, \
             counting registry_actor_kind, registry_purpose, and scope; they project {}",
            purpose_claims.len()
        );
    }
    let generated_purpose_connection = usize::from(clients.clients.iter().any(|client| {
        client
            .claims
            .get("registry_purpose")
            .and_then(Value::as_array)
            .is_some_and(|purposes| purposes.len() > 1)
    }));
    if clients.issuer.resources.len() > 7
        || clients.issuer.exchange_issuers.len() + generated_purpose_connection > 8
        || clients.issuer.interactive_applications.len() > 8
        || clients.issuer.browser_clients.len() > 8
        || clients.issuer.synthetic_users.len() > 32
        || clients.issuer.client_resources.len() > 32
        || clients.issuer.exchange_clients.len() > 32
    {
        bail!("local issuer composition exceeds its bounded inventory");
    }
    if clients.event_destinations.len() > 16 {
        bail!("at most 16 local event destinations may be bound");
    }
    if clients.evidence_providers.len() > 8 {
        bail!("at most 8 local Evidence providers may be bound");
    }
    if clients.review_authorities.len() > 8 {
        bail!("at most 8 local review authorities may be bound");
    }
    if clients.task_grant_status.len() > 8 {
        bail!("at most 8 local task-grant status services may be bound");
    }
    let mut task_sources = BTreeSet::new();
    for (id, status) in &clients.task_grant_status {
        let endpoint = reqwest::Url::parse(&status.base_url)
            .context("local task-grant status baseUrl must be an exact loopback HTTP URL")?;
        let client = clients
            .clients
            .iter()
            .find(|client| client.id == status.client);
        if !governed_identifier(id)
            || !registry_platform_httputil::valid_resource_uri(&status.source_issuer)
            || !task_sources.insert(&status.source_issuer)
            || endpoint.scheme() != "http"
            || endpoint.host_str() != Some("127.0.0.1")
            || endpoint.port().is_none_or(|port| port == 0)
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || registry_platform_httputil::client::ServiceBaseUrl::new(endpoint).is_err()
            || client.is_none_or(|client| {
                client.scopes != ["casework:grants:status"]
                    || !client.access_profiles.is_empty()
                    || client.allow_breg_access
                    || client_token_claims(client).get("registry_actor_kind")
                        != Some(&json!("service"))
            })
        {
            bail!("local task-grant status services need unique source issuers, exact loopback endpoints, and declared service clients scoped only to casework:grants:status without BReg access");
        }
    }
    for (id, authority) in &clients.review_authorities {
        let endpoint = reqwest::Url::parse(&authority.endpoint)
            .context("local review authority endpoint must be an exact loopback HTTP URL")?;
        if !governed_identifier(id)
            || endpoint.scheme() != "http"
            || endpoint.host_str() != Some("127.0.0.1")
            || endpoint.port().is_none_or(|port| port == 0)
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || registry_platform_httputil::client::ServiceBaseUrl::new(endpoint).is_err()
            || authority.profile.is_empty()
            || authority.profile.len() > 128
            || !authority.profile.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || authority.producer_id.trim().is_empty()
            || authority.producer_id.len() > 128
            || authority.producer_id.chars().any(char::is_control)
            || !(1..=90).contains(&authority.recovery_days)
            || !clients
                .clients
                .iter()
                .any(|client| client.id == authority.client)
        {
            bail!("local review authorities need bounded IDs, exact loopback endpoints, producer bindings, recovery windows, and declared clients");
        }
        match (
            &authority.completion_token_ref,
            &authority.completion_recipient,
        ) {
            (None, None) => (),
            (Some(reference), Some(recipient))
                if !recipient.trim().is_empty()
                    && recipient.len() <= 128
                    && !recipient.chars().any(char::is_control) =>
            {
                let token = secret(
                    &clients,
                    secrets,
                    &format!("reviewAuthorities.{id}.completionTokenRef"),
                    reference,
                    COMPLETION_TOKEN_BYTES,
                )?;
                if token.is_some_and(|token| !token.iter().all(|byte| byte.is_ascii_graphic())) {
                    bail!("local review completion tokens must be bounded visible ASCII");
                }
            }
            _ => bail!(
                "local review completionTokenRef and completionRecipient must be declared together"
            ),
        }
    }
    if clients.review_executors.len() > 8 {
        bail!("at most 8 local review executors may be bound");
    }
    for (id, executor) in &clients.review_executors {
        let client = clients
            .clients
            .iter()
            .find(|client| client.id == executor.client);
        if !governed_identifier(id)
            || !identifier(&executor.access_profile)
            || client.is_none_or(|client| {
                !client.access_profiles.contains(&executor.access_profile)
                    || client_token_claims(client).get("registry_actor_kind")
                        != Some(&json!("service"))
            })
        {
            bail!("local review executors need bounded IDs, one declared service client, and its exact access profile");
        }
    }
    for (id, provider) in &clients.evidence_providers {
        let origin = reqwest::Url::parse(&provider.base_url)
            .context("local Evidence provider baseUrl must be an exact loopback HTTP origin")?;
        if !governed_identifier(id)
            || provider.trust_binding_id.is_empty()
            || provider.trust_binding_id.len() > 128
            || registry_evidence_verifier::verifier::revoked_key_ids_are_usable(
                &provider.revoked_key_ids,
            )
            .is_err()
            || origin.scheme() != "http"
            || origin.host_str() != Some("127.0.0.1")
            // The Evidence client refuses a base URL carrying credentials, so
            // it is named here as well rather than left to surface as a failed
            // request once the session is already running.
            || !origin.username().is_empty()
            || origin.password().is_some()
            // Port zero parses and is not the scheme default, so it is named
            // here beside the absent port. A provider bound to it starts a
            // session in which every Evidence request targets an unusable port.
            || origin.port().is_none_or(|port| port == 0)
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            bail!("local Evidence providers need bounded IDs, trust bindings, and exact loopback origins");
        }
        if provider.token_ref.is_some() == provider.private_key_jwt.is_some() {
            bail!("local Evidence providers require exactly one tokenRef or privateKeyJwt");
        }
        for declared in evidence_secrets(id, provider) {
            secret(
                &clients,
                secrets,
                &declared.member,
                declared.reference,
                declared.maximum,
            )?;
        }
        if let Some(credentials) = &provider.private_key_jwt {
            let endpoint = reqwest::Url::parse(&credentials.token_endpoint)
                .context("local Evidence tokenEndpoint must be an exact loopback HTTP URL")?;
            if endpoint.scheme() != "http"
                || endpoint.host_str() != Some("127.0.0.1")
                // Port zero leaves every credential refresh pointed at an
                // unusable port, the same way it does for the provider origin.
                || endpoint.port().is_none_or(|port| port == 0)
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || credentials.client_id.trim().is_empty()
                || credentials.client_id.len() > 128
                || !registry_platform_httputil::valid_resource_uri(&credentials.assertion_audience)
                || !registry_platform_httputil::valid_resource_uri(&credentials.resource)
                || credentials.scopes.is_empty()
                || credentials.scopes.len() > 32
                || credentials.scopes.iter().collect::<BTreeSet<_>>().len()
                    != credentials.scopes.len()
                || credentials.scopes.join(" ").len()
                    > registry_platform_httputil::MAXIMUM_SCOPE_PARAMETER_BYTES
                || credentials.scopes.iter().any(|scope| {
                    scope.len() > 128
                        || scope.contains('*')
                        || !registry_platform_httputil::valid_scope_token(scope)
                })
            {
                bail!("local Evidence privateKeyJwt requires exact loopback token endpoint, client, audience, resource and scopes");
            }
        }
    }
    for (id, destination) in &clients.event_destinations {
        let origin = reqwest::Url::parse(&destination.origin)
            .context("local event destination origin must be an exact loopback HTTP URL")?;
        if !identifier(id)
            || origin.scheme() != "http"
            || origin.host_str() != Some("127.0.0.1")
            // Userinfo in an origin is refused by the runtime's own destination
            // policy, so it is named here as well rather than left to surface
            // as a failed start.
            || !origin.username().is_empty()
            || origin.password().is_some()
            // Port zero parses and is not the scheme default, so it reaches
            // the runtime's own refusal instead of this one unless it is named
            // here beside the absent port.
            || origin.port().is_none_or(|port| port == 0)
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || destination.path.len() > 256
            || !destination.path.starts_with('/')
            // The runtime builds its delivery target through this same
            // validator, which refuses dot segments, percent escapes and
            // non-ASCII bytes. Applying it here keeps preflight and startup
            // agreed on one answer.
            || registry_platform_httputil::destination::validate_fixed_destination_path(
                &destination.path,
            )
                .is_err()
        {
            bail!("local event destinations need bounded IDs, exact loopback origins, and absolute paths");
        }
    }
    let mut resource_ids = BTreeSet::new();
    for resource in &clients.issuer.resources {
        if !registry_platform_httputil::valid_resource_uri(&resource.audience)
            || !resource_ids.insert(&resource.audience)
            || resource.scopes.is_empty()
            || resource.scopes.len() > 32
            || resource
                .scopes
                .iter()
                .any(|scope| !registry_platform_httputil::valid_scope_token(scope))
        {
            bail!("local issuer resources require distinct audiences and exact bounded scopes");
        }
    }
    for (client, resource) in &clients.issuer.client_resources {
        if !ids.contains(client)
            || !resource_ids.contains(resource)
            || !clients
                .clients
                .iter()
                .find(|entry| &entry.id == client)
                .is_some_and(|entry| grant_scopes(&clients, Some(resource), &entry.scopes))
        {
            bail!("issuer client resource bindings need a declared client, audience, and resource scopes");
        }
    }
    for client in &clients.clients {
        if !client.grants.is_empty() && !valid_grants(&clients, &client.grants) {
            bail!("machine client grants require distinct declared audiences and exact bounded resource scopes");
        }
    }
    let mut exchange_clients = BTreeSet::new();
    for id in &clients.issuer.exchange_clients {
        if !exchange_clients.insert(id)
            // A client no connection registers would be exchanged under no
            // recorded authority, and the derived per-client rule would then
            // name nothing at all for it.
            || !clients
                .issuer
                .exchange_issuers
                .iter()
                .any(|connection| connection.clients.contains(id))
            || !clients
                .clients
                .iter()
                .any(|client| &client.id == id && client.scopes.len() == 1)
        {
            bail!("exchange clients need one exact bootstrap scope and a registering exchange connection");
        }
    }
    let mut connection_ids = BTreeSet::new();
    for connection in &clients.issuer.exchange_issuers {
        if !identifier(&connection.id)
            || !connection_ids.insert(&connection.id)
            || connection
                .clients
                .iter()
                .any(|client| !clients.issuer.exchange_clients.contains(client))
        {
            bail!("local exchange connections require distinct bounded IDs and declared exchange clients");
        }
        // The generated purpose connection makes every multi-purpose client a
        // first-party client, and the issuer projects one first-party
        // connection's claims into that client's exchanged tokens. Listed on an
        // authored institutional grant connection, its tokens would lack the
        // registry_grant_* claims the registry requires; listed on an authored
        // first-party connection, they would lack that connection's claims.
        for id in &connection.clients {
            let multi_purpose = clients
                .clients
                .iter()
                .find(|client| &client.id == id)
                .map(client_purposes)
                .transpose()?
                .is_some_and(|purposes| purposes.len() > 1);
            if multi_purpose {
                bail!(
                    "client {id} declares more than one registry_purpose, so its purposes are \
                     signed by the generated purpose connection; it cannot also be listed on \
                     the exchange connection {}",
                    connection.id
                );
            }
        }
    }
    let mut app_ids = BTreeSet::new();
    for app in &clients.issuer.interactive_applications {
        if !identifier(&app.id)
            || !app_ids.insert(&app.id)
            || ids.contains(&app.id)
            || app
                .audience
                .as_ref()
                .is_some_and(|audience| !resource_ids.contains(audience))
            || !valid_grants(&clients, &app.grants)
        {
            bail!("browser applications need distinct IDs and exact declared resource permissions");
        }
        secret(
            &clients,
            secrets,
            &format!("issuer.interactiveApplications.{}.clientSecretRef", app.id),
            &app.client_secret_ref,
            CLIENT_SECRET_BYTES,
        )?;
    }
    for id in &clients.issuer.browser_clients {
        if !identifier(id) || !app_ids.insert(id) || ids.contains(id) {
            bail!("borrowed browser clients need distinct bounded IDs");
        }
    }
    let mut usernames = BTreeSet::new();
    for user in &clients.issuer.synthetic_users {
        if !identifier(&user.username) || !usernames.insert(&user.username) {
            bail!("synthetic users need distinct bounded usernames");
        }
        if !valid_grants(&clients, &user.grants) {
            bail!("synthetic user grants need distinct declared resources and exact permissions");
        }
        secret(
            &clients,
            secrets,
            &format!("issuer.syntheticUsers.{}.passwordRef", user.username),
            &user.password_ref,
            PASSWORD_BYTES,
        )?;
    }
    for (id, destination) in &clients.event_destinations {
        let key = secret(
            &clients,
            secrets,
            &format!("eventDestinations.{id}.hmacSha256KeyRef"),
            &destination.hmac_sha256_key_ref,
            HMAC_KEY_BYTES,
        )?;
        if key.is_some_and(|key| key.len() < 32) {
            bail!("local event destination {id} needs at least 32 HMAC key bytes");
        }
    }
    let mut seeds = BTreeSet::new();
    for seed in &clients.seed {
        if !identifier(&seed.id)
            || !seeds.insert(&seed.id)
            || !identifier(&seed.entity)
            || !clients.clients.iter().any(|client| {
                client.id == seed.client && client.access_profiles.contains(&seed.access_profile)
            })
        {
            bail!("seeds require unique IDs and an explicitly bound client and access profile");
        }
    }
    Ok(clients)
}

pub(super) fn hash(bytes: &[u8]) -> String {
    crate::hex_lower(&Sha256::digest(bytes))
}

pub(super) fn keypair(root: &Path) -> Result<Value> {
    private::directory(root)?;
    let key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().context("generated key lacks x")?);
    let y = URL_SAFE_NO_PAD.encode(point.y().context("generated key lacks y")?);
    let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(
        &json!({"crv":"P-256","kty":"EC","x":x,"y":y}),
    )?));
    let public = json!({"kty":"EC","crv":"P-256","alg":"ES256","kid":kid,"x":x,"y":y});
    let mut private_key = public.clone();
    private_key["d"] = Value::String(URL_SAFE_NO_PAD.encode(key.to_bytes()));
    let bytes = Zeroizing::new(serde_json::to_vec(&private_key)?);
    private::create(&root.join("assertion-key.jwk"), &bytes)?;
    private::create(&root.join("public.jwk"), &serde_json::to_vec(&public)?)?;
    Ok(public)
}

pub(super) fn prepare(root: &Path, state: &State, clients: &Clients) -> Result<()> {
    if state.issuer_project.is_some() {
        validate_borrowed_issuer_composition(&clients.issuer)?;
        if clients
            .clients
            .iter()
            .any(|client| !client.grants.is_empty())
        {
            bail!("a borrowed issuer cannot declare owner-only machine client grants; declare them on the issuer owner");
        }
    }
    for directory in [
        "credentials",
        "secrets",
        "tls",
        "issuer",
        "logs",
        "empty-package",
        "database",
    ] {
        private::directory(&root.join(directory))?;
    }
    let borrowed = super::borrowed_owner(state)?;
    let owner_clients: Option<Clients> = borrowed
        .as_ref()
        .map(|owner| {
            retained(&private::read(
                &owner.root().join("clients.json"),
                MAX_BYTES,
            )?)
            .map_err(|_| anyhow::anyhow!("shared issuer owner has invalid retained clients"))
        })
        .transpose()?;
    if !clients.issuer.browser_clients.is_empty() {
        let (Some(owner), Some(owner_clients)) = (&borrowed, &owner_clients) else {
            bail!("browserClients requires a ready BREG issuer owner");
        };
        check_borrowed_browser_clients(
            owner_clients,
            &clients.issuer.browser_clients,
            &state.audience(),
            &owner.audience(),
        )?;
    }
    for client in &clients.clients {
        let directory = root.join("credentials").join(&client.id);
        if let (Some(owner), Some(owner_clients)) = (&borrowed, &owner_clients) {
            let registered = owner_clients
                .clients
                .iter()
                .find(|entry| entry.id == client.id)
                .with_context(|| {
                    format!("shared issuer owner has no registration for {}", client.id)
                })?;
            if registered.scopes != client.scopes
                || registered.claims != client.claims
                || registered.allow_human_fixture != client.allow_human_fixture
                || owner_clients
                    .issuer
                    .client_resources
                    .contains_key(&client.id)
            {
                bail!("shared issuer registration differs from the local client or BREG audience for {}", client.id);
            }
            private::directory(&directory)?;
            let source = owner.root().join("credentials").join(&client.id);
            let id = Zeroizing::new(private::read(&source.join("client-id"), MAX_BYTES)?);
            let key = Zeroizing::new(private::read(&source.join("assertion-key.jwk"), MAX_BYTES)?);
            super::export_client::validate_pair(&id, &key, &client.id)?;
            private::create(&directory.join("client-id"), &id)?;
            private::create(&directory.join("assertion-key.jwk"), &key)?;
            private::create(
                &directory.join("public.jwk"),
                &private::read(&source.join("public.jwk"), 4096)?,
            )?;
        } else {
            if let Some(reference) = &client.assertion_key_ref {
                let key = resolve_secret(
                    clients,
                    &format!("clients.{}.assertionKeyRef", client.id),
                    reference,
                    ASSERTION_KEY_BYTES,
                )?;
                import_keypair(&directory, &key, &client.id)?;
            } else {
                keypair(&directory)?;
            }
            private::create(&directory.join("client-id"), client.id.as_bytes())?;
        }
    }
    if !clients.issuer.interactive_applications.is_empty()
        || !clients.issuer.synthetic_users.is_empty()
    {
        private::directory(&root.join("issuer/secrets"))?;
    }
    for app in &clients.issuer.interactive_applications {
        let secret = resolve_secret(
            clients,
            &format!("issuer.interactiveApplications.{}.clientSecretRef", app.id),
            &app.client_secret_ref,
            CLIENT_SECRET_BYTES,
        )?;
        private::create(
            &root
                .join("issuer/secrets")
                .join(format!("application-{}", app.id)),
            &secret,
        )?;
    }
    for user in &clients.issuer.synthetic_users {
        let password = resolve_secret(
            clients,
            &format!("issuer.syntheticUsers.{}.passwordRef", user.username),
            &user.password_ref,
            PASSWORD_BYTES,
        )?;
        private::create(
            &root
                .join("issuer/secrets")
                .join(format!("user-{}", user.username)),
            &password,
        )?;
    }
    for (id, destination) in &clients.event_destinations {
        let key = resolve_secret(
            clients,
            &format!("eventDestinations.{id}.hmacSha256KeyRef"),
            &destination.hmac_sha256_key_ref,
            HMAC_KEY_BYTES,
        )?;
        private::create(&root.join("secrets").join(format!("webhook-{id}")), &key)?;
    }
    for (id, provider) in &clients.evidence_providers {
        for secret in evidence_secrets(id, provider) {
            let bytes = resolve_secret(clients, &secret.member, secret.reference, secret.maximum)?;
            private::create(&root.join("secrets").join(&secret.copy), &bytes)?;
        }
    }
    for (id, authority) in &clients.review_authorities {
        let credentials = root.join("credentials").join(&authority.client);
        for (source, name, maximum) in [
            (
                credentials.join("client-id"),
                format!("review-authority-{id}-client-id"),
                1024,
            ),
            (
                credentials.join("assertion-key.jwk"),
                format!("review-authority-{id}-client-assertion-key"),
                64 * 1024,
            ),
        ] {
            let bytes = Zeroizing::new(private::read(&source, maximum)?);
            private::create(&root.join("secrets").join(name), &bytes)?;
        }
        if let Some(reference) = &authority.completion_token_ref {
            let bytes = resolve_secret(
                clients,
                &format!("reviewAuthorities.{id}.completionTokenRef"),
                reference,
                COMPLETION_TOKEN_BYTES,
            )?;
            private::create(
                &root
                    .join("secrets")
                    .join(format!("review-completion-{id}-token")),
                &bytes,
            )?;
        }
    }
    for (id, executor) in &clients.review_executors {
        let credentials = root.join("credentials").join(&executor.client);
        for (source, name, maximum) in [
            (
                credentials.join("client-id"),
                format!("review-executor-{id}-client-id"),
                1024,
            ),
            (
                credentials.join("assertion-key.jwk"),
                format!("review-executor-{id}-client-assertion-key"),
                64 * 1024,
            ),
        ] {
            let bytes = Zeroizing::new(private::read(&source, maximum)?);
            private::create(&root.join("secrets").join(name), &bytes)?;
        }
    }
    for (id, status) in &clients.task_grant_status {
        let source = root
            .join("credentials")
            .join(&status.client)
            .join("assertion-key.jwk");
        let key = Zeroizing::new(private::read(&source, 64 * 1024)?);
        private::create(
            &root
                .join("secrets")
                .join(format!("task-status-{id}-client-assertion-key")),
            &key,
        )?;
    }
    // The dev session's issuer is the pinned upstream ThunderID container,
    // rendered and provisioned through the shared tooling crate from these
    // same authored declarations. BREG keeps its database, seeding, retained
    // state, private outputs, and ownership behavior; only the token issuer
    // changes hands.
    if borrowed.is_none() {
        let description = issuer_description(state, clients, root)?;
        registry_thunderid_tooling::render::render(&description)
            .map_err(|error| anyhow::anyhow!("the dev issuer registration was refused: {error}"))?;
    }
    for filename in ["audit-key", "cursor-key"] {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).context("cannot generate local secret")?;
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
        private::create(&root.join("secrets").join(filename), encoded.as_bytes())?;
    }
    if state.webhook_port.is_some() {
        webhook_secret(root)?;
    }
    let password = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    private::create(
        &root.join("database/postgres.env"),
        format!(
            "POSTGRES_USER=postgres\nPOSTGRES_PASSWORD={}\nPOSTGRES_DB=postgres\n",
            password.as_str()
        )
        .as_bytes(),
    )?;
    let migration_password = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    let runtime_password = Zeroizing::new(uuid::Uuid::new_v4().simple().to_string());
    private::create(
        &root.join("database/migration-password"),
        migration_password.as_bytes(),
    )?;
    private::create(
        &root.join("database/runtime-password"),
        runtime_password.as_bytes(),
    )?;
    for (name, role, database) in [
        ("runtime-database-url", RUNTIME_ROLE, "breg_dev"),
        ("migration-database-url", MIGRATION_ROLE, "breg_dev"),
        ("test-runtime-database-url", RUNTIME_ROLE, "breg_dev_test"),
        (
            "test-migration-database-url",
            MIGRATION_ROLE,
            "breg_dev_test",
        ),
    ] {
        let password = if role == MIGRATION_ROLE {
            &migration_password
        } else {
            &runtime_password
        };
        // The owned container publishes on 127.0.0.1 only. Naming the literal
        // it publishes keeps a host that resolves localhost to ::1 first from
        // failing to connect; the server certificate carries both names.
        let url = Zeroizing::new(format!(
            "postgresql://{role}:{}@127.0.0.1:{}/{database}",
            password.as_str(),
            state.database_port
        ));
        private::create(&root.join("secrets").join(name), url.as_bytes())?;
    }
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "BREG local development CA");
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = rcgen::KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let server_key = rcgen::KeyPair::generate()?;
    let mut server_params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])?;
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "BREG local PostgreSQL");
    server_params.use_authority_key_identifier_extension = true;
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params.signed_by(
        &server_key,
        &rcgen::Issuer::from_params(&ca_params, &ca_key),
    )?;
    private::create(
        &root.join("tls/ca.pem"),
        pem("CERTIFICATE", ca.der()).as_bytes(),
    )?;
    private::create(
        &root.join("tls/server.pem"),
        pem("CERTIFICATE", server.der()).as_bytes(),
    )?;
    private::create(
        &root.join("tls/server.key"),
        Zeroizing::new(pem("PRIVATE KEY", &server_key.serialize_der())).as_bytes(),
    )?;
    private::create(&root.join("database/pg_hba.conf"), b"local all all trust\nhostnossl all all 0.0.0.0/0 reject\nhostnossl all all ::/0 reject\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\n")?;
    runtime(root, state, clients, true)?;
    Ok(())
}

fn validate_borrowed_issuer_composition(issuer: &IssuerComposition) -> Result<()> {
    if !issuer.resources.is_empty()
        || !issuer.exchange_issuers.is_empty()
        || !issuer.interactive_applications.is_empty()
        || !issuer.synthetic_users.is_empty()
        || !issuer.client_resources.is_empty()
        || !issuer.exchange_clients.is_empty()
    {
        bail!("a borrowed issuer cannot declare owner-only resources, exchange connections, applications, users, or client mappings; declare them on the issuer owner");
    }
    Ok(())
}

pub(super) fn check_borrowed_browser_clients(
    owner: &Clients,
    selected: &[String],
    audience: &str,
    owner_default: &str,
) -> Result<()> {
    for id in selected {
        let matched = owner.issuer.interactive_applications.iter().any(|app| {
            &app.id == id && app.audience.as_deref().unwrap_or(owner_default) == audience
        });
        if !matched {
            bail!("shared issuer owner has no browser application for this BREG resource: {id}");
        }
    }
    Ok(())
}

fn import_keypair(directory: &Path, key: &[u8], id: &str) -> Result<()> {
    private::directory(directory)?;
    super::export_client::validate_pair(id.as_bytes(), key, id)?;
    let private: Value = serde_json::from_slice(key)?;
    // Every token this client obtains is a private_key_jwt assertion, whose
    // header needs a usable key identifier. A key without one imports and
    // registers cleanly and then fails at the first token request, so it is
    // refused where the operator named the key.
    if !private["kid"]
        .as_str()
        .is_some_and(|kid| !kid.trim().is_empty() && kid.len() <= 256)
    {
        bail!("imported assertion key for {id} needs a bounded, non-blank kid");
    }
    let public = json!({
        "kty": private["kty"], "crv": private["crv"], "alg": private["alg"],
        "kid": private["kid"], "x": private["x"], "y": private["y"]
    });
    private::create(&directory.join("assertion-key.jwk"), key)?;
    private::create(&directory.join("public.jwk"), &serde_json::to_vec(&public)?)
}

fn role_permissions(
    description: &registry_thunderid_tooling::description::IssuerDescription,
    state: &State,
    grants: &[LocalPermissionGrant],
) -> Result<Vec<(String, Vec<String>)>> {
    grants
        .iter()
        .map(|grant| {
            let audience = grant.audience.clone().unwrap_or_else(|| state.audience());
            let server = description
                .resource_servers
                .iter()
                .find(|server| server.identifier == audience)
                .context("local permission grant resource is missing")?;
            Ok((server.id.clone(), grant.scopes.clone()))
        })
        .collect()
}

/// The dev session's issuer description: one resource server whose
/// identifier is BREG's exact access-token audience, one role per authored
/// client carrying that client's scopes, and one machine agent per client
/// whose static attributes are the authored claims. Derived from the
/// reviewed client declarations only; nothing here reads the registry
/// project's business model.
pub(super) fn issuer_description(
    state: &State,
    clients: &Clients,
    root: &Path,
) -> Result<registry_thunderid_tooling::description::IssuerDescription> {
    use registry_thunderid_tooling::{
        description::{
            ExchangeIssuer, ExchangeMapping, InteractiveApplication, Role, SessionIdentity,
            SyntheticUser, TokenExchangeClient,
        },
        local::{typed_local_description, TypedLocalClient},
    };
    let local_clients = clients
        .clients
        .iter()
        .map(|client| {
            let mut claims = client_token_claims(client);
            let purposes = client_purposes(client)?;
            match purposes.first().and_then(|purpose| purpose.as_deref()) {
                Some(purpose) => {
                    claims.insert("registry_purpose".to_owned(), json!(purpose));
                }
                None => {
                    claims.remove("registry_purpose");
                }
            }
            let directory = root.join("credentials").join(&client.id);
            let public: Value =
                serde_json::from_slice(&private::read(&directory.join("public.jwk"), 4096)?)?;
            Ok(TypedLocalClient {
                client_id: client.id.clone(),
                public_jwks: serde_json::to_string(&json!({"keys":[public]}))?,
                claims,
                scopes: client.scopes.clone(),
                allow_human_fixture: client.allow_human_fixture,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut description = typed_local_description(
        SessionIdentity {
            label: format!("breg-dev-{}", state.instance_id),
            id: state.instance_id.clone(),
        },
        state.issuer_port,
        root.join("issuer"),
        state.audience(),
        local_clients,
    )?;
    for resource in &clients.issuer.resources {
        registry_thunderid_tooling::local::declare_resource(
            &mut description,
            &resource.audience,
            &resource.scopes,
        )?;
    }
    for (client_id, audience) in &clients.issuer.client_resources {
        let server = description
            .resource_servers
            .iter()
            .find(|server| &server.identifier == audience)
            .context("a declared issuer resource is missing")?;
        let agent = registry_thunderid_tooling::local::agent_id(&state.instance_id, client_id);
        let role = description
            .roles
            .iter_mut()
            .find(|role| role.assigned_agents.contains(&agent))
            .context("a declared issuer client role is missing")?;
        role.permissions[0].0 = server.id.clone();
    }
    for client in &clients.clients {
        if client.grants.is_empty() {
            continue;
        }
        let permissions = role_permissions(&description, state, &client.grants)?;
        let agent = registry_thunderid_tooling::local::agent_id(&state.instance_id, &client.id);
        let role = description
            .roles
            .iter_mut()
            .find(|role| role.assigned_agents.contains(&agent))
            .context("a declared issuer client role is missing")?;
        for (resource, scopes) in permissions {
            if let Some((_, existing)) = role.permissions.iter_mut().find(|(id, _)| *id == resource)
            {
                for scope in scopes {
                    if !existing.contains(&scope) {
                        existing.push(scope);
                    }
                }
            } else {
                role.permissions.push((resource, scopes));
            }
        }
    }
    for id in &clients.issuer.exchange_clients {
        let client = clients
            .clients
            .iter()
            .find(|client| &client.id == id)
            .context("an exchange client is missing")?;
        let ordinary_permissions = role_permissions(&description, state, &client.grants)?;
        let machine = description
            .machine_clients
            .iter_mut()
            .find(|machine| machine.client_id == *id)
            .context("an exchange registration is missing")?;
        let role = description
            .roles
            .iter()
            .find(|role| role.assigned_agents.contains(&machine.agent_id))
            .context("an exchange bootstrap role is missing")?;
        machine.token_exchange = Some(TokenExchangeClient {
            assertion_resource_server_id: role.permissions[0].0.clone(),
            assertion_scope: client.scopes[0].clone(),
            ordinary_resource_permissions: ordinary_permissions
                .into_iter()
                .filter(|(resource, _)| resource != &role.permissions[0].0)
                .collect(),
        });
    }
    let mut purpose_clients = Vec::new();
    for client in &clients.clients {
        if client_purposes(client)?.len() > 1 {
            purpose_clients.push(super::purpose::PurposeClient {
                client_id: client.id.clone(),
                subject: registry_thunderid_tooling::local::agent_id(
                    &state.instance_id,
                    &client.id,
                ),
                claims: client_token_claims(client),
            });
        }
    }
    if !purpose_clients.is_empty() {
        let port = state
            .purpose_port
            .context("multi-purpose clients need a retained purpose assertion port")?;
        for purpose_client in &purpose_clients {
            let id = &purpose_client.client_id;
            let client = clients
                .clients
                .iter()
                .find(|client| &client.id == id)
                .context("a multi-purpose client is missing")?;
            let machine = description
                .machine_clients
                .iter_mut()
                .find(|machine| machine.client_id == *id)
                .context("a multi-purpose registration is missing")?;
            let role = description
                .roles
                .iter()
                .find(|role| role.assigned_agents.contains(&machine.agent_id))
                .context("a multi-purpose bootstrap role is missing")?;
            machine.token_exchange = Some(TokenExchangeClient {
                assertion_resource_server_id: role.permissions[0].0.clone(),
                assertion_scope: client.scopes[0].clone(),
                ordinary_resource_permissions: Vec::new(),
            });
        }
        description
            .exchange_issuers
            .push(super::purpose::exchange_issuer(
                &state.instance_id,
                port,
                &purpose_clients,
            )?);
    }
    for issuer in &clients.issuer.exchange_issuers {
        description.exchange_issuers.push(ExchangeIssuer {
            id: registry_thunderid_tooling::local::agent_id(
                &state.instance_id,
                &format!("connection-{}", issuer.id),
            ),
            name: format!("Local {}", issuer.id),
            issuer: issuer.issuer.clone(),
            jwks_endpoint: issuer.jwks_endpoint.clone(),
            mapping: match issuer.mapping {
                IssuerConnectionMapping::InstitutionalGrant => ExchangeMapping::InstitutionalGrant,
                IssuerConnectionMapping::FirstParty => ExchangeMapping::FirstParty,
            },
            // A described connection lists clients to select the first-party
            // claims it projects, and institutional grant mapping projects
            // none. The declared pairing still reaches the runtime, which is
            // where it decides the authority each client may present.
            clients: match issuer.mapping {
                IssuerConnectionMapping::InstitutionalGrant => Vec::new(),
                IssuerConnectionMapping::FirstParty => issuer.clients.clone(),
            },
            token_attributes: issuer.token_attributes.clone(),
        });
    }
    for app in &clients.issuer.interactive_applications {
        let app_id = registry_thunderid_tooling::local::agent_id(
            &state.instance_id,
            &format!("application-{}", app.id),
        );
        let audience = app.audience.clone().unwrap_or_else(|| state.audience());
        let permissions = role_permissions(&description, state, &app.grants)?;
        description
            .interactive_applications
            .push(InteractiveApplication {
                id: app_id.clone(),
                client_id: app.id.clone(),
                client_secret_file: format!("secrets/application-{}", app.id).into(),
                origin: app.origin.clone(),
                redirect_uris: app.redirect_uris.clone(),
                audience,
                token_attributes: app.token_attributes.clone(),
            });
        description.roles.push(Role {
            id: registry_thunderid_tooling::local::agent_id(
                &state.instance_id,
                &format!("application-role-{}", app.id),
            ),
            name: format!("Local browser {}", app.id),
            description: "Explicit local browser application permissions".into(),
            permissions,
            assigned_agents: vec![],
            assigned_users: vec![],
            assigned_applications: vec![app_id],
        });
    }
    for user in &clients.issuer.synthetic_users {
        let user_id = registry_thunderid_tooling::local::agent_id(
            &state.instance_id,
            &format!("user-{}", user.username),
        );
        description.synthetic_users.push(SyntheticUser {
            id: user_id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            password_file: format!("secrets/user-{}", user.username).into(),
            attributes: user.attributes.clone(),
        });
        let permissions = role_permissions(&description, state, &user.grants)?;
        description.roles.push(Role {
            id: registry_thunderid_tooling::local::agent_id(
                &state.instance_id,
                &format!("user-role-{}", user.username),
            ),
            name: format!("Local user {}", user.username),
            description: "Explicit local synthetic user permissions".into(),
            permissions,
            assigned_agents: vec![],
            assigned_users: vec![user_id],
            assigned_applications: vec![],
        });
    }
    description.validate()?;
    Ok(description)
}

/// Re-render an explicitly prepared, stopped-session successor in a separate
/// private tree, then publish only this session's native issuer documents.
/// The owning source-transition journal makes an interrupted publication
/// repeatable. Existing client keys and unrelated issuer database state stay
/// untouched.
pub(super) fn refresh_issuer_registration(state: &State, clients: &Clients) -> Result<()> {
    if state.issuer_project.is_some() {
        return Ok(());
    }
    fn publish_tree(source: &Path, destination: &Path) -> Result<()> {
        private::directory(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let source = entry.path();
            let destination = destination.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                publish_tree(&source, &destination)?;
            } else {
                let bytes = private::read(&source, MAX_BYTES)?;
                private::replace(&destination, &bytes)?;
            }
        }
        Ok(())
    }

    let root = state.root();
    let staging = root.join(format!(".issuer-render-{}", uuid::Uuid::new_v4()));
    private::directory(&staging)?;
    let result: Result<()> = (|| {
        let mut description = issuer_description(state, clients, &root)?;
        description.state_root = staging.clone();
        registry_thunderid_tooling::render::render(&description).map_err(|error| {
            anyhow::anyhow!("the successor issuer registration was refused: {error}")
        })?;
        private::validate_tree(&staging)?;
        for directory in ["resources", "registry-schema"] {
            publish_tree(
                &staging.join(directory),
                &root.join("issuer").join(directory),
            )?;
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&staging);
    result?;
    cleanup.context("cannot remove the private issuer rendering stage")
}

/// Map each exchange client to the assertion authorities it is registered
/// against, so a resource server refuses a token minted from any other
/// authority's assertion even though the issuer itself applies no such rule.
/// Every declared exchange client is registered against at least one
/// connection, so a declared client always reaches the map and an empty map
/// means this deployment exchanges nothing.
///
/// A borrowed session declares no connection of its own and answers on the
/// owner's BREG audience, so a token the owner's runtime refuses is a token
/// this one accepts unless it applies the owner's pairing too. That pairing is
/// read from the owner's retained registration, the same document its issuer
/// was rendered from, rather than from a running owner session: every command
/// that re-renders this runtime reaches the same rule whether or not the owner
/// is currently serving.
pub(super) fn assertion_issuers(
    state: &State,
    clients: &Clients,
) -> Result<BTreeMap<String, Vec<String>>> {
    let owner = state
        .issuer_project
        .as_ref()
        .map(|project| -> Result<Clients> {
            retained(&private::read(
                &project.join(".breg/dev/clients.json"),
                MAX_BYTES,
            )?)
            .map_err(|_| anyhow::anyhow!("shared issuer owner has invalid retained clients"))
        })
        .transpose()?;
    let authority_clients = owner.as_ref().unwrap_or(clients);
    let composition = &authority_clients.issuer;
    let mut authorities: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for connection in &composition.exchange_issuers {
        for client in &connection.clients {
            let registered = authorities.entry(client.clone()).or_default();
            if !registered.contains(&connection.issuer) {
                registered.push(connection.issuer.clone());
            }
        }
    }
    if let Some(port) = state.purpose_port {
        let purpose_issuer = format!("http://127.0.0.1:{port}");
        for client in &authority_clients.clients {
            if client_purposes(client)?.len() > 1 {
                let registered = authorities.entry(client.id.clone()).or_default();
                if !registered.contains(&purpose_issuer) {
                    registered.push(purpose_issuer.clone());
                }
            }
        }
    }
    Ok(authorities)
}

pub(super) fn local_principal_claim(compiled: &registry_breg::CompiledRegistry) -> Result<String> {
    let inventory = registry_breg::authority::authority_inventory(compiled)
        .context("local authority inventory is invalid")?;
    match inventory.principal_claims.len() {
        0 => Ok("registry_principal".to_owned()),
        1 => Ok(inventory.principal_claims.into_iter().next().expect("one principal claim")),
        _ => bail!("local access profiles must use one principal claim; mixed principal claims cannot share a runtime authority mapping"),
    }
}

pub(super) fn runtime(root: &Path, state: &State, clients: &Clients, test: bool) -> Result<()> {
    let final_root = state.root();
    let prefix = if test { "test-" } else { "" };
    let compiled = crate::compile(&root.join("project"), crate::ProfileArg::Production, "dev")
        .map_err(|_| anyhow::anyhow!("captured local project no longer compiles"))?;
    let principal = local_principal_claim(&compiled)?;
    let journeys_path = root.join("project/tests/journeys.yaml");
    if journeys_path.exists() {
        let mut journeys = Reader::new(journeys_path.display().to_string())
            .with_hook(&mut LiteralText {
                remedy: WRITE_THE_VALUE,
            })
            .read(
                &private::read(&journeys_path, MAX_BYTES)?,
                &Expect::one(&registry_breg::fixtures::JOURNEYS_FORMAT),
            )?
            .to_json_value();
        if super::has_local_subject_marker(&journeys) {
            let owner = super::borrowed_owner(state)?;
            let issuer_instance = owner.as_ref().map_or(state.instance_id.as_str(), |owner| {
                owner.instance_id.as_str()
            });
            super::resolve_local_subject_markers(
                &mut journeys,
                clients,
                &compiled,
                issuer_instance,
            )?;
            private::replace(
                &journeys_path,
                serde_norway::to_string(&journeys)?.as_bytes(),
            )?;
        }
    }
    let destinations = if state.webhook_port.is_some() || !clients.event_destinations.is_empty() {
        if let Some(port) = state.webhook_port {
            event_destinations(&compiled, port)
        } else {
            external_event_destinations(&compiled, &clients.event_destinations)?
        }
    } else {
        json!({})
    };
    let review_executors = local_review_executors(state, clients, &compiled)?;
    // A browser application explicitly using this session's default BREG
    // audience is a local OAuth client. Other-resource apps remain outside
    // BREG admission; governed profiles and token scopes still authorize calls.
    let mut allowed_clients = clients
        .clients
        .iter()
        .filter(|client| !client.access_profiles.is_empty() || client.allow_breg_access)
        .map(|client| client.id.clone())
        .collect::<Vec<_>>();
    allowed_clients.extend(
        clients
            .issuer
            .interactive_applications
            .iter()
            .filter(|app| app.audience.is_none())
            .map(|app| app.id.clone()),
    );
    allowed_clients.extend(clients.issuer.browser_clients.iter().cloned());
    // The runtime takes a list of at least one client. A session with no
    // client to name accepts every client of its local issuer.
    let allowed_clients = if allowed_clients.is_empty() {
        json!("unrestricted")
    } else {
        json!(allowed_clients)
    };
    let assertion_issuers = assertion_issuers(state, clients)?;
    // The local registry serves with the migration role, the one-role mode
    // a small deployment runs in. The schema-test rehearsal stays split,
    // because the package fingerprint is defined against a separate runtime
    // role.
    let (runtime_url, runtime_role) = if test {
        ("test-runtime-database-url", RUNTIME_ROLE)
    } else {
        ("migration-database-url", MIGRATION_ROLE)
    };
    let mut runtime = json!({
        "apiVersion":"id.registrystack.org/formats/breg/runtime/v1alpha1","kind":"BRegRuntimeConfig",
        "listener":{"bind":format!("127.0.0.1:{}",state.breg_port),"publicOrigin":state.breg_origin()},
        "identity":{"environment":"local","instanceId":state.instance_id,"databaseId":DATABASE_ID,"databaseInitializationEnvironment":"local"},
        "secretProviders":{"file":{"root":final_root.join("secrets")}},
        "database":{"runtimeUrlRef":format!("secret:file/{runtime_url}"),"migrationUrlRef":format!("secret:file/{prefix}migration-database-url"),"pool":{"maximumConnections":4},"roles":{"migration":MIGRATION_ROLE,"runtime":runtime_role}},
        "package":{"root":final_root.join(if test {"empty-package"}else{"build/package"})},
        "authentication":{"oidc":{"issuer":state.issuer_origin(),"audience":state.audience(),"allowedAlgorithm":"RS256","accessTokenType":"at+jwt","scopeClaim":"scope","scopeSeparator":" ","allowedClients":allowed_clients,"assertionIssuers":&assertion_issuers,"maximumTokenLifetimeSeconds":300,"leewayMilliseconds":30000,"jwksSource":{"type":"static","documentRef":"secret:file/issuer-jwks"}},"authorityClaims":{"principal":principal,"purpose":"registry_purpose"}},
        "audit":{"hashKeyRef":"secret:file/audit-key","destination":"file","path":final_root.join("audit").join(format!("{prefix}audit.jsonl"))},"cursor":{"secretRef":"secret:file/cursor-key"},"eventDestinations":destinations,
        "evidenceProviders":clients.evidence_providers.iter().map(|(id, provider)| (id.clone(), json!({
            "baseUrl":provider.base_url,
            "trustBindingId":provider.trust_binding_id,
            "tokenRef":provider.token_ref.as_ref().map(|_| format!("secret:file/evidence-token-{id}")),
            "privateKeyJwt":provider.private_key_jwt.as_ref().map(|credentials| json!({
                "tokenEndpoint":credentials.token_endpoint,
                "clientId":credentials.client_id,
                "privateKeyRef":format!("secret:file/evidence-client-key-{id}"),
                "assertionAudience":credentials.assertion_audience,
                "resource":credentials.resource,
                "scopes":credentials.scopes
            })),
            "trustedJwksRef":format!("secret:file/evidence-jwks-{id}"),
            "revokedKeyIds":provider.revoked_key_ids,
            "caBundleRef":provider.ca_bundle_ref.as_ref().map(|_| format!("secret:file/evidence-ca-{id}"))
        }))).collect::<BTreeMap<_,_>>(),
        "reviewAuthorities":local_review_authorities(state, clients),
        "reviewExecutors":review_executors,
        "taskGrantStatus":local_task_grant_status(state, clients)
    });
    // runtime.yaml writes an optional member by leaving it out (CFG-EMPTY-1),
    // and an empty assertionIssuers map is refused, so an absent setting is
    // omitted rather than written as null or `{}`.
    omit_null_members(&mut runtime);
    if assertion_issuers.is_empty() {
        runtime["authentication"]["oidc"]
            .as_object_mut()
            .expect("the runtime document carries an oidc object")
            .remove("assertionIssuers");
    }
    write_yaml(
        &root.join(if test {
            "runtime-test.yaml"
        } else {
            "runtime.yaml"
        }),
        &runtime,
    )
}

fn omit_null_members(value: &mut Value) {
    match value {
        Value::Object(members) => {
            members.retain(|_, member| !member.is_null());
            members.values_mut().for_each(omit_null_members);
        }
        Value::Array(items) => items.iter_mut().for_each(omit_null_members),
        _ => {}
    }
}

fn local_review_executors(
    state: &State,
    clients: &Clients,
    compiled: &registry_breg::CompiledRegistry,
) -> Result<BTreeMap<String, Value>> {
    use registry_breg::contract::{ActorKindSource, Operation};
    use registry_breg::model::{CompiledChangeRequestOnApprovedMode, CompiledChangeRequestReview};

    if clients.review_executors.is_empty() {
        return Ok(BTreeMap::new());
    }
    if state.instance_id != compiled.registry_id() {
        bail!("local review executors must target this exact registry");
    }
    clients
        .review_executors
        .iter()
        .map(|(id, executor)| {
            let client = clients
                .clients
                .iter()
                .find(|client| client.id == executor.client)
                .context("a local review executor client is missing")?;
            let claims = client_token_claims(client);
            let purposes = client_purposes(client)?;
            if purposes.len() != 1 {
                bail!("local review executor {id} needs one fixed registry purpose");
            }
            let selected_purpose = purposes.into_iter().next().flatten();
            let request_entities = compiled
                .entities()
                .values()
                .filter(|entity| {
                    entity.change_request.as_ref().is_some_and(|request| {
                        matches!(request.review, CompiledChangeRequestReview::Required(_))
                            && request.on_approved.mode
                                == CompiledChangeRequestOnApprovedMode::Automatic
                            && request.on_approved.executor.as_deref() == Some(id)
                    })
                })
                .collect::<Vec<_>>();
            if request_entities.is_empty() {
                bail!("local review executor {id} is not selected by an automatic request");
            }
            let mut scopes = BTreeSet::new();
            for entity in request_entities {
                let profile = entity
                    .access_profiles
                    .get(&executor.access_profile)
                    .with_context(|| {
                        format!(
                            "local review executor {id} has no apply profile for {}",
                            entity.id
                        )
                    })?;
                if profile.actor_kind != Some(ActorKindSource::Service)
                    || !profile.operations.contains(&Operation::ApplyRequest)
                    || (!profile.requester_clients.is_empty()
                        && !profile.requester_clients.contains(&client.id))
                    || !profile
                        .required_scopes
                        .iter()
                        .all(|scope| client.scopes.contains(scope))
                    || (!profile.required_purposes.is_empty()
                        && selected_purpose
                            .as_ref()
                            .is_none_or(|purpose| !profile.required_purposes.contains(purpose)))
                    || (profile.principal_claim != "sub"
                        && claims
                            .get(&profile.principal_claim)
                            .and_then(Value::as_str)
                            .is_none_or(str::is_empty))
                {
                    bail!("local review executor {id} does not satisfy its service apply profile");
                }
                scopes.extend(profile.required_scopes.iter().cloned());
            }
            // The OAuth provider requires a non-empty scope request. When the
            // profile imposes no narrower scope, keep the explicitly authored
            // client scope set rather than inventing an executor-only scope.
            let scopes = if scopes.is_empty() {
                client.scopes.clone()
            } else {
                scopes.into_iter().collect()
            };
            Ok((
                id.clone(),
                json!({
                    "endpoint": state.breg_origin(),
                    "registryId": compiled.registry_id(),
                    "accessProfile": executor.access_profile,
                    "privateKeyJwt": {
                        "tokenEndpoint": format!("{}/oauth2/token", state.issuer_origin()),
                        "clientIdRef": format!("secret:file/review-executor-{id}-client-id"),
                        "clientAssertionKeyRef": format!("secret:file/review-executor-{id}-client-assertion-key"),
                        "assertionAudience": state.issuer_origin(),
                        "resource": state.audience(),
                        "scopes": scopes,
                    }
                }),
            ))
        })
        .collect()
}

fn local_review_authorities(state: &State, clients: &Clients) -> BTreeMap<String, Value> {
    clients
        .review_authorities
        .iter()
        .map(|(id, authority)| {
            let client = clients
                .clients
                .iter()
                .find(|client| client.id == authority.client)
                .expect("closed local review authority validation resolves its client");
            let resource = client_resource(state, clients, &authority.client);
            let mut binding = json!({
                "endpoint": authority.endpoint,
                "profile": authority.profile,
                "producerId": authority.producer_id,
                "recoveryDays": authority.recovery_days,
                "privateKeyJwt": {
                    "tokenEndpoint": format!("{}/oauth2/token", state.issuer_origin()),
                    "clientIdRef": format!("secret:file/review-authority-{id}-client-id"),
                    "clientAssertionKeyRef": format!("secret:file/review-authority-{id}-client-assertion-key"),
                    "assertionAudience": state.issuer_origin(),
                    "resource": resource,
                    "scopes": client.scopes,
                }
            });
            if let Some(recipient) = &authority.completion_recipient {
                binding["completionTokenRef"] =
                    json!(format!("secret:file/review-completion-{id}-token"));
                binding["completionRecipient"] = json!(recipient);
            }
            (id.clone(), binding)
        })
        .collect()
}

pub(super) fn client_resource(state: &State, clients: &Clients, client: &str) -> String {
    clients
        .issuer
        .client_resources
        .get(client)
        .cloned()
        .unwrap_or_else(|| state.audience())
}

fn local_task_grant_status(state: &State, clients: &Clients) -> Vec<Value> {
    clients
        .task_grant_status
        .iter()
        .map(|(id, status)| {
            json!({
                "sourceIssuer": status.source_issuer,
                "baseUrl": status.base_url,
                "tokenEndpoint": format!("{}/oauth2/token", state.issuer_origin()),
                "clientAssertionAudience": state.issuer_origin(),
                "clientId": status.client,
                "privateKeyRef": format!("secret:file/task-status-{id}-client-assertion-key"),
                "caseworkResource": client_resource(state, clients, &status.client)
            })
        })
        .collect()
}

pub(super) fn external_event_destinations(
    compiled: &registry_breg::CompiledRegistry,
    bindings: &BTreeMap<String, LocalEventDestination>,
) -> Result<Value> {
    // A local handler carries a reviewed program instead of a destination,
    // so only the url deliveries need a binding here.
    let inventory = compiled
        .event_deliveries()
        .deliveries
        .iter()
        .filter_map(|delivery| delivery.destination_id.clone())
        .collect::<BTreeSet<_>>();
    if inventory != bindings.keys().cloned().collect() {
        bail!("local event destinations must bind every compiled destination ID exactly");
    }
    let mut destinations = BTreeMap::new();
    for delivery in &compiled.event_deliveries().deliveries {
        let Some(destination_id) = delivery.destination_id.as_ref() else {
            continue;
        };
        let (classification, timeout, attempts) = destinations.entry(destination_id).or_insert((
            delivery.classification_ceiling,
            delivery.attempt_timeout_ms,
            delivery.maximum_attempts,
        ));
        *classification = (*classification).max(delivery.classification_ceiling);
        *timeout = (*timeout).min(delivery.attempt_timeout_ms);
        *attempts = (*attempts).min(delivery.maximum_attempts);
    }
    Ok(Value::Object(destinations.into_iter().map(|(id, (classification, timeout, attempts))| {
        let binding = &bindings[id];
        (id.clone(), json!({
            "origin":binding.origin,"path":binding.path,
            "networkProfile":"loopback-development-http","dnsFamily":"dual-stack-strict",
            "allowedPrivateCidrs":[],"hmacSha256KeyRef":format!("secret:file/webhook-{id}"),
            "classificationCeiling":classification,
            "deliveryCeilings":{"attemptTimeoutMilliseconds":timeout,"maximumAttempts":attempts}
        }))
    }).collect()))
}

pub(super) fn webhook_secret(root: &Path) -> Result<()> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).context("cannot generate local webhook secret")?;
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
    private::create(&root.join("secrets/webhook-key"), encoded.as_bytes())
}

/// Use the same compiled inventory as `explain events`. Shared destinations
/// use the tightest attempt ceilings and the highest projected classification.
fn event_destinations(compiled: &registry_breg::CompiledRegistry, port: u16) -> Value {
    let mut destinations = BTreeMap::new();
    for delivery in &compiled.event_deliveries().deliveries {
        // A local handler holds a reviewed program instead of a destination
        // and so needs no binding here.
        let Some(destination_id) = delivery.destination_id.as_ref() else {
            continue;
        };
        let (classification, timeout, attempts) = destinations.entry(destination_id).or_insert((
            delivery.classification_ceiling,
            delivery.attempt_timeout_ms,
            delivery.maximum_attempts,
        ));
        *classification = (*classification).max(delivery.classification_ceiling);
        *timeout = (*timeout).min(delivery.attempt_timeout_ms);
        *attempts = (*attempts).min(delivery.maximum_attempts);
    }
    Value::Object(destinations.into_iter().map(|(id, (classification, timeout, attempts))| {
        (id.clone(), json!({
            "origin":format!("http://127.0.0.1:{port}"),"path":"/events",
            "networkProfile":"loopback-development-http","dnsFamily":"dual-stack-strict",
            "allowedPrivateCidrs":[],"hmacSha256KeyRef":"secret:file/webhook-key",
            "classificationCeiling":classification,
            "deliveryCeilings":{"attemptTimeoutMilliseconds":timeout,"maximumAttempts":attempts}
        }))
    }).collect())
}

pub(super) fn write_yaml(path: &Path, value: &Value) -> Result<()> {
    private::create(path, serde_norway::to_string(value)?.as_bytes())
}

fn pem(label: &str, bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut result = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        result.push('\n');
    }
    result.push_str(&format!("-----END {label}-----\n"));
    result
}
