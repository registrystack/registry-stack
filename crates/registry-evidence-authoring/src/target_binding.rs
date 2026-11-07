//! Closed deployment bindings carried by an authored [`EvidenceTarget`](super::EvidenceTarget).
//!
//! These are authoring shapes, not a second runtime model. They close the keys
//! an adopter may write and retain scalar deployment values for the runtime to
//! validate against its security and operating invariants.

use registry_platform_yaml::{
    BoundedU32, BoundedU64, Digest, ExternalId, LocalId, SecretReference, UniqueList, Url,
};

pub use crate::target_value::{TargetClaimName, TargetIssuerId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

fn unique_list_is_empty<T>(values: &UniqueList<T>) -> bool {
    values.is_empty()
}

fn serialize_tagged<S: Serializer>(
    external: Result<serde_json::Value, serde_json::Error>,
    tag: &'static str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap as _;

    let external = external.map_err(serde::ser::Error::custom)?;
    let serde_json::Value::Object(entries) = external else {
        return Err(serde::ser::Error::custom(
            "a tagged union serialized as a non-object",
        ));
    };
    let mut entries = entries.into_iter();
    let (Some((variant, members)), None) = (entries.next(), entries.next()) else {
        return Err(serde::ser::Error::custom(
            "a tagged union serialized without exactly one variant",
        ));
    };
    let serde_json::Value::Object(members) = members else {
        return Err(serde::ser::Error::custom(
            "a tagged union variant serialized as a non-object",
        ));
    };
    let mut map = serializer.serialize_map(Some(members.len() + 1))?;
    map.serialize_entry(tag, &variant)?;
    for (key, value) in &members {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

macro_rules! serialize_tagged_union {
    ($type:ty, tag = $tag:literal) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serialize_tagged(
                    <$type>::serialize(self, serde_json::value::Serializer),
                    $tag,
                    serializer,
                )
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetPackage {
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetService {
    pub provider_id: String,
    pub issuer: TargetIssuerId,
    pub public_origin: Url,
    pub trust_domain: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TargetAssuranceProfile {
    Local,
    Production,
    EvidenceGrade,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TargetNetworkExposure {
    PrivateAddress,
    ContainerPrivate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TargetTlsTermination {
    OperatorControlledUpstream,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetListener {
    pub bind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_exposure: Option<TargetNetworkExposure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_termination: Option<TargetTlsTermination>,
    pub trust_proxy_identity_headers: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_request_bytes: Option<BoundedU64<1_024, 1_048_576>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_concurrent_requests: Option<BoundedU32<1, 4_096>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_milliseconds: Option<BoundedU64<1, 30_000>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shutdown_grace_milliseconds: Option<BoundedU64<1, 120_000>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetAuthentication {
    pub oidc: TargetOidcAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetOidcAuthentication {
    pub issuer: Url,
    pub audience: String,
    pub jwks_source: TargetJwksSource,
    pub token_types: UniqueList<TargetAccessTokenType>,
    pub algorithms: UniqueList<TargetAccessTokenAlgorithm>,
    pub principal_claim: String,
    pub requester_tags_claim: String,
    pub evidence_audience_claim: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<TargetClaimNames>,
    pub maximum_token_lifetime_seconds: BoundedU64<1, 86_400>,
    #[serde(default, skip_serializing_if = "unique_list_is_empty")]
    pub revoked_key_ids: UniqueList<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_clients: Option<TargetAdmissionGate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "read_assertion_issuers")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "assertion_issuers_schema"))]
    pub assertion_issuers: Option<BTreeMap<ExternalId, UniqueList<String>>>,
    pub required_scopes: TargetAdmissionGate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust_profile: Option<String>,
}

// The runtime's assertion-issuer gate compares external client and issuer strings
// exactly. Its limits are byte bounds; JSON Schema also exposes character bounds
// while the reader applies the byte limit to non-ASCII identifiers.
fn read_assertion_issuers<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<ExternalId, UniqueList<String>>>, D::Error> {
    let clients = BTreeMap::<ExternalId, UniqueList<String>>::deserialize(deserializer)?;
    if clients.is_empty() || clients.len() > 32 {
        return Err(registry_platform_yaml::Invalid::expected(
            "between one and 32 assertion-issuer clients",
            "List one to 32 clients with their assertion issuers, or omit assertionIssuers.",
        )
        .into_error());
    }
    for (client, issuers) in &clients {
        if client.len() > 128
            || issuers.is_empty()
            || issuers.len() > 8
            || issuers
                .iter()
                .any(|issuer| issuer.is_empty() || issuer.len() > 512 || issuer.contains('\0'))
        {
            return Err(registry_platform_yaml::Invalid::expected(
                "a client identifier of at most 128 bytes and one to eight distinct nonempty issuers of at most 512 bytes",
                "Keep each client within 128 bytes and list one to eight distinct issuer strings within 512 bytes.",
            ).into_error());
        }
    }
    Ok(Some(clients))
}

#[cfg(feature = "schema")]
fn assertion_issuers_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let mut client = generator.subschema_for::<ExternalId>();
    client.insert("maxLength".to_owned(), 128.into());
    schemars::json_schema!({
        "description": "External client identifiers mapped to the exact issuer strings they may assert. Omit to apply no assertion-issuer rule. A present map has one to 32 clients, each within 128 bytes, with one to eight distinct nonempty issuers within 512 bytes.",
        "type": "object",
        "minProperties": 1,
        "maxProperties": 32,
        "propertyNames": client,
        "additionalProperties": {
            "type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true,
            "items": {"type": "string", "minLength": 1, "maxLength": 512}
        }
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum TargetJwksSource {
    Uri { uri: Url },
}

registry_platform_yaml::tagged_union!(TargetJwksSource);
serialize_tagged_union!(TargetJwksSource, tag = "type");

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum TargetAccessTokenType {
    #[serde(rename = "at+jwt")]
    AtJwt,
    #[serde(rename = "application/at+jwt")]
    ApplicationAtJwt,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum TargetAccessTokenAlgorithm {
    EdDSA,
    ES256,
    RS256,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetClaimNames {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_source_issuer: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_client: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_resource: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_exp: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_bounds: Option<TargetClaimName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<TargetClaimName>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetAdmissionKeyword;

impl<'de> Deserialize<'de> for TargetAdmissionKeyword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if String::deserialize(deserializer)? == "unrestricted" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "expected unrestricted or a non-empty list of admitted values",
            ))
        }
    }
}

impl Serialize for TargetAdmissionKeyword {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("unrestricted")
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for TargetAdmissionKeyword {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TargetAdmissionKeyword".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type":"string", "const":"unrestricted"})
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetListedValues(UniqueList<String>);

impl<'de> Deserialize<'de> for TargetListedValues {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = UniqueList::<String>::deserialize(deserializer)?;
        if values.is_empty() {
            Err(serde::de::Error::custom(
                "expected unrestricted or a non-empty list of admitted values",
            ))
        } else {
            Ok(Self(values))
        }
    }
}

impl Serialize for TargetListedValues {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for TargetListedValues {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TargetListedValues".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<UniqueList<String>>();
        schema.insert("minItems".to_owned(), 1.into());
        schema
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
pub enum TargetAdmissionGate {
    Unrestricted(TargetAdmissionKeyword),
    Listed(TargetListedValues),
}

registry_platform_yaml::shape_union!(TargetAdmissionGate {
    scalar => Unrestricted,
    list => Listed,
});

impl Serialize for TargetAdmissionGate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Unrestricted(keyword) => keyword.serialize(serializer),
            Self::Listed(values) => values.serialize(serializer),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetConnection {
    pub endpoints: BTreeMap<LocalId, TargetEndpointBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_private_cidrs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSourceAcquisition {
    pub maximum_data_operations: BoundedU64<1, { u64::MAX }>,
    #[serde(rename = "acquisitionDeadlineMilliseconds")]
    pub deadline_milliseconds: BoundedU64<1, { u64::MAX }>,
    pub maximum_response_bytes: BoundedU64<1, { u64::MAX }>,
}

impl TargetSourceAcquisition {
    pub fn runtime_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetEndpointBinding {
    pub origin: Url,
    pub authentication: TargetConnectionAuthentication,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_identity: Option<TargetMtlsIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_timeout_milliseconds: Option<BoundedU64<1, { u64::MAX }>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_response_bytes: Option<BoundedU64<1, 1_048_576>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetMtlsIdentity {
    pub certificate_ref: SecretReference,
    pub key_ref: SecretReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum TargetConnectionAuthentication {
    None {},
    Basic {
        username_ref: SecretReference,
        password_ref: SecretReference,
    },
    Bearer {
        token_ref: SecretReference,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    StaticAuthorization {
        token_ref: SecretReference,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
    },
    StaticApiKey {
        header_name: String,
        value_ref: SecretReference,
    },
    Oauth2ClientCredentials {
        token_endpoint: String,
        client_id_ref: SecretReference,
        client_secret_ref: SecretReference,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        credential_placement: TargetCredentialPlacement,
        maximum_cache_seconds: BoundedU64<0, 86_400>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assumed_lifetime_seconds: Option<BoundedU64<1, 86_400>>,
    },
    Oauth2PrivateKeyJwt {
        token_endpoint: String,
        client_id_ref: SecretReference,
        client_assertion_key_ref: SecretReference,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_assertion_audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        maximum_cache_seconds: BoundedU64<0, 86_400>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assumed_lifetime_seconds: Option<BoundedU64<1, 86_400>>,
    },
}

registry_platform_yaml::tagged_union!(TargetConnectionAuthentication);
serialize_tagged_union!(TargetConnectionAuthentication, tag = "type");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TargetCredentialPlacement {
    BasicHeader,
    FormBody,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSecretProviders {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<TargetFileSecretProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<TargetEnvironmentSecretProvider>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetFileSecretProvider {
    pub root: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct TargetEnvironmentSecretProvider {}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum TargetSigner {
    LocalJwk {
        algorithm: TargetSigningAlgorithm,
        private_key_ref: SecretReference,
        public_jwk_file: String,
    },
    Transit {
        algorithm: TargetSigningAlgorithm,
        public_jwk_file: String,
        unix_socket_path: String,
        mount: String,
        key_name: String,
        key_version: BoundedU32<1, { u32::MAX }>,
        attempt_timeout_milliseconds: BoundedU64<1, 30_000>,
    },
}

registry_platform_yaml::tagged_union!(TargetSigner);
serialize_tagged_union!(TargetSigner, tag = "type");

impl TargetSigner {
    #[must_use]
    pub fn public_jwk_file(&self) -> &str {
        match self {
            Self::LocalJwk {
                public_jwk_file, ..
            }
            | Self::Transit {
                public_jwk_file, ..
            } => public_jwk_file,
        }
    }

    pub fn runtime_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .expect("a typed target signer serializes as an object");
        object.remove("algorithm");
        object.remove("publicJwkFile");
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum TargetSigningAlgorithm {
    ES256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSubjectBinding {
    pub secret_ref: SecretReference,
    pub key_version: BoundedU32<1, 2_147_483_647>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum TargetAuditDestination {
    File,
    Stdout,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetAudit {
    pub hash_key_ref: SecretReference,
    pub hash_key_version: BoundedU32<1, 2_147_483_647>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<TargetAuditDestination>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_bytes: Option<BoundedU64<1_048_576, { u32::MAX as u64 }>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<BoundedU32<1, 36_500>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetRateLimits {
    pub requests_per_principal_per_minute: BoundedU32<1, 1_000_000>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst_per_principal: Option<BoundedU32<1, 100_000>>,
    pub failed_selector_attempts_per_principal_authority_per_minute: BoundedU32<1, 100_000>,
}

/// What the target may sign, beyond the signer binding. When the target
/// omits this block, it signs for at most 300 seconds.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSigning {
    /// The longest validity, in seconds, any definition on this target may
    /// sign an assertion for.
    pub maximum_assertion_validity_seconds: BoundedU64<1, { crate::project::MAX_VALIDITY_SECONDS }>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetPublication {
    pub service_id: String,
    #[serde(deserialize_with = "registry_platform_yaml::display_text")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::DisplayText")
    )]
    pub title: String,
    #[serde(deserialize_with = "registry_platform_yaml::display_text")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::DisplayText")
    )]
    pub description: String,
    pub endpoint_url: Url,
    pub jurisdictions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TargetResponseFormat {
    SignedJws,
    UnsignedJson,
    SdJwtVc,
    SdJwtVcBatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetOutboundTls {
    pub system_roots: bool,
    pub trust_profiles: BTreeMap<LocalId, TargetTrustProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetTrustProfile {
    pub ca_bundle_file: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetExtractBinding {
    pub path: String,
}

impl TargetService {
    pub fn governed_values(
        &self,
    ) -> Result<(serde_json::Value, serde_json::Value), serde_json::Error> {
        let mut service = serde_json::to_value(self)?;
        service
            .as_object_mut()
            .expect("a typed target service serializes as an object")
            .remove("issuer");
        Ok((service, serde_json::json!({"uri": self.issuer})))
    }
}

impl TargetAuthentication {
    pub fn governed_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        let oidc = value["oidc"]
            .as_object_mut()
            .expect("a typed target OIDC binding serializes as an object");
        oidc.entry("allowedClients")
            .or_insert(serde_json::json!("unrestricted"));
        oidc.entry("revokedKeyIds").or_insert(serde_json::json!([]));
        Ok(value)
    }
}

impl TargetListener {
    pub fn runtime_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .expect("a typed target listener serializes as an object");
        for (key, default) in [
            (
                "tlsTermination",
                serde_json::json!("operator-controlled-upstream"),
            ),
            ("maximumRequestBytes", serde_json::json!(65_536)),
            ("maximumConcurrentRequests", serde_json::json!(64)),
            ("requestTimeoutMilliseconds", serde_json::json!(10_000)),
            ("shutdownGraceMilliseconds", serde_json::json!(30_000)),
        ] {
            object.entry(key).or_insert(default);
        }
        Ok(value)
    }
}

impl TargetConnection {
    pub fn governed_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let endpoints = self
            .endpoints
            .iter()
            .map(|(id, binding)| binding.governed_value(id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(serde_json::json!({"endpoints":endpoints}))
    }

    pub fn runtime_value(
        &self,
        connection: &LocalId,
        outbound_tls: Option<&TargetOutboundTls>,
    ) -> Result<serde_json::Value, serde_json::Error> {
        let endpoints = self
            .endpoints
            .iter()
            .map(|(id, binding)| binding.runtime_value(id))
            .collect::<Result<Vec<_>, _>>()?;
        let mut value = serde_json::json!({
            "id":connection,
            "endpoints":endpoints,
            "allowedPrivateCidrs":self.allowed_private_cidrs
        });
        if let Some(outbound_tls) = outbound_tls {
            value["outboundTls"] = serde_json::json!({
                "trustProfiles":outbound_tls.trust_profiles
            });
        }
        Ok(value)
    }
}

impl TargetEndpointBinding {
    fn governed_value(&self, endpoint: &LocalId) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::json!({
            "endpoint": endpoint,
            "baseUrl": self.origin,
            "authentication": self.authentication.governed_value()?,
            "clientIdentity": if self.mtls_identity.is_some() { "required" } else { "forbidden" }
        });
        if let Some(profile) = &self.tls_trust_profile {
            value["tlsTrustProfile"] = serde_json::json!(profile);
        }
        Ok(value)
    }

    fn runtime_value(&self, endpoint: &LocalId) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::json!({
            "endpoint": endpoint,
            "baseUrl": self.origin,
            "credential": self.authentication.runtime_value()?
        });
        if let Some(profile) = &self.tls_trust_profile {
            value["tlsTrustProfile"] = serde_json::json!(profile);
        }
        if let Some(identity) = &self.mtls_identity {
            value["mtlsIdentity"] = serde_json::to_value(identity)?;
        }
        if let Some(timeout) = self.attempt_timeout_milliseconds {
            value["attemptTimeoutMilliseconds"] = serde_json::json!(timeout);
        }
        if let Some(maximum) = self.maximum_response_bytes {
            value["maximumResponseBytes"] = serde_json::json!(maximum);
        }
        Ok(value)
    }
}

impl TargetConnectionAuthentication {
    fn governed_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .expect("a target connection authentication serializes as an object");
        if object.get("type").and_then(serde_json::Value::as_str) == Some("bearer") {
            object.insert("type".to_owned(), serde_json::json!("static-authorization"));
        }
        for field in [
            "usernameRef",
            "passwordRef",
            "tokenRef",
            "scheme",
            "headerName",
            "valueRef",
            "clientIdRef",
            "clientSecretRef",
            "clientAssertionKeyRef",
            "maximumCacheSeconds",
            "assumedLifetimeSeconds",
        ] {
            object.remove(field);
        }
        Ok(value)
    }

    fn runtime_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .expect("a target connection authentication serializes as an object");
        if object.get("type").and_then(serde_json::Value::as_str) == Some("bearer") {
            object.insert("type".to_owned(), serde_json::json!("static-authorization"));
        }
        object.remove("scheme");
        object.remove("headerName");
        Ok(value)
    }
}

impl TargetAudit {
    pub fn governed_value(&self) -> serde_json::Value {
        serde_json::json!({
            "hashKeyRef": self.hash_key_ref,
            "hashKeyVersion": self.hash_key_version,
        })
    }

    pub fn runtime_value(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        if let Some(destination) = self.destination {
            object.insert("destination".to_owned(), serde_json::json!(destination));
        }
        if let Some(path) = &self.path {
            object.insert("path".to_owned(), serde_json::json!(path));
        }
        if let Some(rotate_bytes) = self.rotate_bytes {
            object.insert("rotateBytes".to_owned(), serde_json::json!(rotate_bytes));
        }
        if let Some(retention_days) = self.retention_days {
            object.insert(
                "retentionDays".to_owned(),
                serde_json::json!(retention_days),
            );
        }
        serde_json::Value::Object(object)
    }
}

impl TargetRateLimits {
    pub fn governed_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("typed target rate limits serialize as an object")
            .entry("burstPerPrincipal")
            .or_insert(serde_json::json!(16));
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_audit_fields_are_partitioned_by_ownership() {
        let audit: TargetAudit = serde_json::from_str(
            r#"{"hashKeyRef":"secret:file/audit-key","hashKeyVersion":1,"destination":"file","path":"audit.jsonl","rotateBytes":1048576,"retentionDays":30}"#,
        )
        .expect("complete target audit binding");
        let governed = audit.governed_value();
        assert_eq!(governed["hashKeyRef"], "secret:file/audit-key");
        assert!(governed.get("path").is_none());
        assert!(governed.get("destination").is_none());

        let runtime = audit.runtime_value();
        assert_eq!(runtime["path"], "audit.jsonl");
        assert_eq!(runtime["rotateBytes"], 1_048_576);
        assert!(runtime.get("hashKeyRef").is_none());
        assert!(runtime.get("hashKeyVersion").is_none());
    }

    #[test]
    fn connection_projection_separates_reviewed_policy_from_runtime_material() {
        let connection: TargetConnection = serde_json::from_str(
            r#"{"endpoints":{"records":{"origin":"https://source.invalid/api","authentication":{"type":"bearer","tokenRef":"secret:file/token"},"attemptTimeoutMilliseconds":45000,"maximumResponseBytes":1048576}}}"#,
        )
        .expect("authored bearer connection");
        let authored = serde_json::to_value(&connection).expect("connection serializes");
        assert_eq!(
            authored["endpoints"]["records"]["authentication"]["type"],
            "bearer"
        );

        let governed = connection.governed_value().expect("connection projects");
        assert_eq!(governed["endpoints"][0]["endpoint"], "records");
        assert_eq!(
            governed["endpoints"][0]["baseUrl"],
            "https://source.invalid/api"
        );
        assert_eq!(
            governed["endpoints"][0]["authentication"]["type"],
            "static-authorization"
        );
        assert!(governed["endpoints"][0]["authentication"]
            .get("tokenRef")
            .is_none());

        let runtime = connection
            .runtime_value(&LocalId::new("register").unwrap(), None)
            .expect("runtime material projects");
        assert_eq!(runtime["id"], "register");
        assert_eq!(runtime["allowedPrivateCidrs"], serde_json::json!([]));
        assert_eq!(
            runtime["endpoints"][0]["credential"]["tokenRef"],
            "secret:file/token"
        );
        assert_eq!(
            runtime["endpoints"][0]["attemptTimeoutMilliseconds"],
            45_000
        );
        assert_eq!(runtime["endpoints"][0]["maximumResponseBytes"], 1_048_576);
        assert!(runtime["endpoints"][0].get("authentication").is_none());
    }

    #[test]
    fn sqlite_only_connection_projects_no_network_authority() {
        let connection: TargetConnection =
            serde_json::from_str(r#"{"endpoints":{}}"#).expect("empty endpoint owner");
        assert_eq!(
            connection.governed_value().expect("governed policy"),
            serde_json::json!({"endpoints":[]})
        );
        let runtime = connection
            .runtime_value(&LocalId::new("extracts").unwrap(), None)
            .expect("runtime binding");
        assert_eq!(runtime["id"], "extracts");
        assert_eq!(runtime["endpoints"], serde_json::json!([]));
        assert_eq!(runtime["allowedPrivateCidrs"], serde_json::json!([]));
    }

    #[test]
    fn source_acquisition_projection_forwards_only_finite_operational_limits() {
        let limits: TargetSourceAcquisition = serde_json::from_value(serde_json::json!({
            "maximumDataOperations": 9,
            "acquisitionDeadlineMilliseconds": 45_000,
            "maximumResponseBytes": 2_097_152
        }))
        .expect("positive source acquisition limits");
        assert_eq!(
            limits.runtime_value().expect("runtime projection"),
            serde_json::json!({
                "maximumDataOperations": 9,
                "acquisitionDeadlineMilliseconds": 45_000,
                "maximumResponseBytes": 2_097_152
            })
        );
        assert!(
            serde_json::from_value::<TargetSourceAcquisition>(serde_json::json!({
                "maximumDataOperations": 0,
                "acquisitionDeadlineMilliseconds": 45_000,
                "maximumResponseBytes": 2_097_152
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<TargetSourceAcquisition>(serde_json::json!({
                "maximumDataOperations": 9,
                "deadlineMilliseconds": 45_000,
                "maximumResponseBytes": 2_097_152
            }))
            .is_err(),
            "the ambiguous generic deadline spelling is not an authored alias"
        );
    }

    #[test]
    fn transit_projection_keeps_only_process_local_signer_fields() {
        let signer: TargetSigner = serde_json::from_str(
            r#"{"type":"transit","algorithm":"ES256","publicJwkFile":"public-keys/active.jwk.json","unixSocketPath":"/run/evidence/transit.sock","mount":"transit","keyName":"evidence-signing","keyVersion":7,"attemptTimeoutMilliseconds":2000}"#,
        )
        .expect("complete Transit target signer");
        assert_eq!(signer.public_jwk_file(), "public-keys/active.jwk.json");

        let runtime = signer.runtime_value().expect("signer projects");
        assert_eq!(runtime["type"], "transit");
        assert_eq!(runtime["keyVersion"], 7);
        assert!(runtime.get("algorithm").is_none());
        assert!(runtime.get("publicJwkFile").is_none());
    }

    fn oidc_with_algorithm(algorithm: &str) -> Result<TargetOidcAuthentication, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "issuer": "https://identity.invalid",
            "audience": "evidence-fixture",
            "jwksSource": {"type": "uri", "uri": "https://identity.invalid/jwks.json"},
            "tokenTypes": ["at+jwt"],
            "algorithms": [algorithm],
            "principalClaim": "sub",
            "requesterTagsClaim": "evidence_tags",
            "evidenceAudienceClaim": "evidence_audience",
            "maximumTokenLifetimeSeconds": 900,
            "requiredScopes": "unrestricted"
        }))
    }

    #[test]
    fn access_token_algorithms_accept_exactly_eddsa_es256_and_rs256() {
        for accepted in ["EdDSA", "ES256", "RS256"] {
            let oidc = oidc_with_algorithm(accepted)
                .unwrap_or_else(|error| panic!("{accepted} is accepted: {error}"));
            assert_eq!(
                serde_json::to_value(&oidc.algorithms).expect("algorithms serialize"),
                serde_json::json!([accepted])
            );
        }
        for rejected in ["ES384", "RS384", "HS256", "PS256", "none", "es256", "EDDSA"] {
            let error = oidc_with_algorithm(rejected).expect_err("the algorithm is refused");
            assert!(
                error.to_string().contains("unknown variant"),
                "{rejected}: {error}"
            );
        }
    }

    // The authoring form keeps its own enum because the shared roster lives in
    // a crate that may perform input or output, which this library may not
    // link. The shared roster is a test-only dependency here, so a member
    // added, renamed or dropped on either side fails a test instead of
    // drifting.
    #[test]
    fn every_access_token_algorithm_names_a_member_of_the_shared_roster() {
        use registry_platform_oidc::AccessTokenAlgorithm as Shared;
        fn shared(algorithm: TargetAccessTokenAlgorithm) -> Shared {
            match algorithm {
                TargetAccessTokenAlgorithm::EdDSA => Shared::EdDSA,
                TargetAccessTokenAlgorithm::ES256 => Shared::ES256,
                TargetAccessTokenAlgorithm::RS256 => Shared::RS256,
            }
        }
        for algorithm in [
            TargetAccessTokenAlgorithm::EdDSA,
            TargetAccessTokenAlgorithm::ES256,
            TargetAccessTokenAlgorithm::RS256,
        ] {
            let authored = serde_json::to_value(algorithm).expect("the algorithm serializes");
            assert_eq!(authored, serde_json::json!(shared(algorithm).jwa_name()));
            let read: Shared = serde_json::from_value(authored.clone())
                .unwrap_or_else(|error| panic!("{authored} is a shared member: {error}"));
            assert_eq!(read, shared(algorithm));
        }
    }
}
