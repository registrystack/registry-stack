// SPDX-License-Identifier: Apache-2.0
//! Offline compatibility checks for authored teaching identities.

use anyhow::{bail, Context, Result};
use registry_platform_config::{SecretProvidersConfig, SecretReference};
use registry_platform_yaml::{
    ApiVersion, Diagnostic, Document, EnvelopeRule, FormatSpec, RemovedKey, Report, Severity,
};
use registry_platform_yaml::{ExternalId, LocalId, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const API_VERSION: &str = "id.registrystack.org/formats/breg/dev-clients/v1alpha1";
pub(super) const KIND: &str = "BRegDevClients";

/// The legacy development clients authoring file, accepted for offline checking.
pub(crate) const DEV_CLIENTS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[
        RemovedKey {
            pointer: "/seed/*/entity",
            replacement: "Rename `entity` to `recordType`, keeping the same Record type reference.",
        },
        RemovedKey {
            pointer: "/version",
            replacement: "Delete `version`; the apiVersion header names the format version.",
        },
        RemovedKey {
            pointer: "/clients/*/clientIdFile",
            replacement: "Delete it; declare test identities in the rstack development plan.",
        },
        RemovedKey {
            pointer: "/clients/*/assertionKeyFile",
            replacement: "Delete it; declare test identities in the rstack development plan.",
        },
        RemovedKey {
            pointer: "/clients/*/assertionKeyInputFile",
            replacement: "Use `assertionKeyRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/eventDestinations",
            replacement: "Move each `eventDestinations` entry under `destinations.hooks`; the entries stay as they are.",
        },
        RemovedKey {
            pointer: "/destinations/hooks/*/hmacKeyFile",
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
            replacement: "Use `completion.hmacSha256KeyRef`: write a secret reference (secret:file/name or secret:env/NAME) and enable its provider under secretProviders.",
        },
        RemovedKey {
            pointer: "/reviewAuthorities/*/completionTokenRef",
            replacement: "Replace completionTokenRef with completion.hmacSha256KeyRef. Casework signs review completions with Standard Webhooks.",
        },
        RemovedKey {
            pointer: "/reviewAuthorities/*/completionRecipient",
            replacement: "Move completionRecipient to completion.recipientBinding.",
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
    /// Optional exact local outbound destination bindings.
    #[serde(default)]
    pub destinations: LocalDestinations,
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
    /// Exact Casework status services for compiled task-grant profiles.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, LocalTaskGrantStatus>")
    )]
    pub task_grant_status: BTreeMap<String, LocalTaskGrantStatus>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalDestinations {
    /// Exact local hook destination bindings. An empty map keeps the inbox.
    #[serde(default, deserialize_with = "local_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "keyed_schema::<LocalId, LocalEventDestination>")
    )]
    pub hooks: BTreeMap<String, LocalEventDestination>,
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
    pub completion: Option<LocalReviewCompletion>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LocalReviewCompletion {
    pub recipient_binding: String,
    pub hmac_sha256_key_ref: SecretReference,
    #[serde(
        default,
        deserialize_with = "present_key_reference",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub previous_hmac_sha256_key_ref: Option<SecretReference>,
}

fn present_key_reference<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SecretReference>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SecretReference::deserialize(deserializer).map(Some)
}

impl LocalReviewCompletion {
    fn references(&self) -> impl Iterator<Item = (&'static str, &'static str, &SecretReference)> {
        std::iter::once(("hmacSha256KeyRef", "key", &self.hmac_sha256_key_ref)).chain(
            self.previous_hmac_sha256_key_ref
                .as_ref()
                .map(|reference| ("previousHmacSha256KeyRef", "previous-key", reference)),
        )
    }
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

fn client_token_claims(client: &Client) -> BTreeMap<String, Value> {
    let mut claims = client.claims.clone();
    claims
        .entry("registry_actor_kind".to_owned())
        .or_insert_with(|| json!("service"));
    claims
}

const GENERATED_CLAIMS: [&str; 2] = ["registry_purpose", "scope"];

fn is_false(value: &bool) -> bool {
    !value
}

/// One secret an Evidence provider references: the member naming it, the
/// reference that must name a declared provider.
struct EvidenceSecret<'a> {
    member: String,
    reference: &'a SecretReference,
}

/// Every secret one Evidence provider references.
fn evidence_secrets<'a>(id: &str, provider: &'a LocalEvidenceProvider) -> Vec<EvidenceSecret<'a>> {
    let mut secrets = vec![EvidenceSecret {
        member: format!("evidenceProviders.{id}.trustedJwksRef"),
        reference: &provider.trusted_jwks_ref,
    }];
    if let Some(reference) = &provider.token_ref {
        secrets.push(EvidenceSecret {
            member: format!("evidenceProviders.{id}.tokenRef"),
            reference,
        });
    }
    if let Some(credentials) = &provider.private_key_jwt {
        secrets.push(EvidenceSecret {
            member: format!("evidenceProviders.{id}.privateKeyJwt.privateKeyRef"),
            reference: &credentials.private_key_ref,
        });
    }
    if let Some(reference) = &provider.ca_bundle_ref {
        secrets.push(EvidenceSecret {
            member: format!("evidenceProviders.{id}.caBundleRef"),
            reference,
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
    pub record_type: String,
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

fn check_reference(clients: &Clients, member: &str, reference: &SecretReference) -> Result<()> {
    let Some(providers) = &clients.secret_providers else {
        bail!(
            "{member} names a secret, but the clients file declares no secretProviders; \
             declare secretProviders.file with an absolute root, secretProviders.environment, or both"
        );
    };
    providers
        .check_reference(member, reference.as_str())
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(())
}

/// Check a development clients document `bregctl check --file` read,
/// without resolving a secret: a reference only has to name an enabled
/// provider. A refusal is one diagnostic at the document root.
pub(crate) fn check(document: &Document) -> Result<Vec<Diagnostic>, Report> {
    let clients = document.decode::<Clients>()?;
    Ok(match validate(clients) {
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

fn validate(clients: Clients) -> Result<()> {
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
                bail!(
                    "a shared local access profile needs at most one default client; use exact testBindings for claim variants"
                );
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
            check_reference(
                &clients,
                &format!("clients.{}.assertionKeyRef", client.id),
                reference,
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
            purpose_claims.extend(GENERATED_CLAIMS.iter().map(|name| (*name).to_owned()));
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
    if clients.destinations.hooks.len() > 16 {
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
            bail!(
                "local task-grant status services need unique source issuers, exact loopback endpoints, and declared service clients scoped only to casework:grants:status without BReg access"
            );
        }
    }

    let mut completion_recipients = BTreeMap::new();
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
            bail!(
                "local review authorities need bounded IDs, exact loopback endpoints, producer bindings, recovery windows, and declared clients"
            );
        }
        if let Some(completion) = &authority.completion {
            let block = format!("reviewAuthorities.{id}.completion");
            if !registry_breg::review_store::valid_completion_recipient(
                &completion.recipient_binding,
            ) {
                bail!("{block}.recipientBinding must contain 1 to 256 visible ASCII characters");
            }
            if let Some(first) = completion_recipients.insert(&completion.recipient_binding, id) {
                bail!("reviewAuthorities.{first}.completion.recipientBinding and {block}.recipientBinding select the same completion recipient");
            }
            for (member, _, reference) in completion.references() {
                check_reference(&clients, &format!("{block}.{member}"), reference)?;
            }
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
            bail!(
                "local Evidence providers need bounded IDs, trust bindings, and exact loopback origins"
            );
        }
        if provider.token_ref.is_some() == provider.private_key_jwt.is_some() {
            bail!("local Evidence providers require exactly one tokenRef or privateKeyJwt");
        }
        for declared in evidence_secrets(id, provider) {
            check_reference(&clients, &declared.member, declared.reference)?;
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
                bail!(
                    "local Evidence privateKeyJwt requires exact loopback token endpoint, client, audience, resource and scopes"
                );
            }
        }
    }
    for (id, destination) in &clients.destinations.hooks {
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
            bail!(
                "local event destinations need bounded IDs, exact loopback origins, and absolute paths"
            );
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
            bail!(
                "issuer client resource bindings need a declared client, audience, and resource scopes"
            );
        }
    }
    for client in &clients.clients {
        if !client.grants.is_empty() && !valid_grants(&clients, &client.grants) {
            bail!(
                "machine client grants require distinct declared audiences and exact bounded resource scopes"
            );
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
            bail!(
                "exchange clients need one exact bootstrap scope and a registering exchange connection"
            );
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
            bail!(
                "local exchange connections require distinct bounded IDs and declared exchange clients"
            );
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
        check_reference(
            &clients,
            &format!("issuer.interactiveApplications.{}.clientSecretRef", app.id),
            &app.client_secret_ref,
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
        check_reference(
            &clients,
            &format!("issuer.syntheticUsers.{}.passwordRef", user.username),
            &user.password_ref,
        )?;
    }
    for (id, destination) in &clients.destinations.hooks {
        let path = format!("destinations.hooks.{id}.hmacSha256KeyRef");
        check_reference(&clients, &path, &destination.hmac_sha256_key_ref)?;
    }
    let mut seeds = BTreeSet::new();
    for seed in &clients.seed {
        if !identifier(&seed.id)
            || !seeds.insert(&seed.id)
            || !identifier(&seed.record_type)
            || !clients.clients.iter().any(|client| {
                client.id == seed.client && client.access_profiles.contains(&seed.access_profile)
            })
        {
            bail!("seeds require unique IDs and an explicitly bound client and access profile");
        }
    }
    Ok(())
}
