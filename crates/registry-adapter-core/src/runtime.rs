// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration (`AdapterRuntimeConfig`) and the
//! endpoint bindings (`AdapterEndpointBindings`) every mode shares, the
//! environment bindings of one deployment (`products/adapter/CONCEPT.md`
//! sections 6, 10.2, 12, and 17): endpoint base URLs and TLS, credential
//! secret references, and the private-CIDR allowlist. The facade's
//! configuration carries those bindings beside its own members (listener,
//! database, OIDC issuer, admitted clients, audit, idempotency, cursor
//! custody); a job's runtime document carries the bindings alone.
//! Authored artifacts carry no environment values; substitution and
//! secrets live here and only here.

use crate::auth::{MtlsIdentity, RuntimeCredential};
use registry_platform_config::{DatabaseConfig, ListenerConfig, OidcIssuerConfig, RemovedKey};
use registry_platform_yaml::{
    BoundedU64, ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr;

/// One private network range the egress allowlist admits. A string form
/// `addr/prefix`, parsed once and matched by the platform transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr(ipnet::IpNet);

impl Cidr {
    /// Parse a CIDR range in `addr/prefix` form.
    pub fn new(text: &str) -> Result<Self, registry_platform_yaml::Invalid> {
        ipnet::IpNet::from_str(text).map(Self).map_err(|_| {
            registry_platform_yaml::Invalid::expected(
                "a CIDR range in addr/prefix form",
                "Write the private range as an address and prefix, for example 10.0.0.0/8.",
            )
        })
    }

    /// Whether the address falls inside this range.
    #[must_use]
    pub fn contains(&self, address: std::net::IpAddr) -> bool {
        self.0.contains(&address)
    }

    /// The parsed network, as the platform destination policy takes it.
    #[must_use]
    pub fn network(&self) -> ipnet::IpNet {
        self.0
    }
}

impl serde::Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Cidr {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Cidr")
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^[0-9a-fA-F.:]+/[0-9]{1,3}$",
            "description": "A private network range in `addr/prefix` form, for example 10.0.0.0/8.",
        })
    }
}

/// The environment binding of one pack endpoint: its base URL, its
/// credentials matching the endpoint's declared kind, and the optional TLS
/// additions (`products/adapter/CONCEPT.md` section 10.2).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointBinding {
    /// The pack endpoint this binding configures.
    pub endpoint: ExternalId,
    /// The upstream origin; a fixed destination the engine never derives
    /// from a response.
    pub base_url: Url,
    /// The credential; its kind must match the endpoint's declared kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<RuntimeCredential>,
    /// The operator's explicit acknowledgement that a credential-free
    /// source is intentionally served over verified HTTPS. Omission keeps
    /// the credential-free policy closed outside numeric loopback and mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous_https: Option<AnonymousHttpsAcknowledgement>,
    /// A lower attempt timeout than the pack declares, in milliseconds;
    /// absent, the declared one applies. A value above the declared one is
    /// refused when the deployment loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_timeout_milliseconds: Option<BoundedU64<1, 10_000>>,
    /// A lower response bound than the pack declares, in bytes; absent, the
    /// declared one applies. A value above the declared one is refused when
    /// the deployment loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_response_bytes: Option<BoundedU64<1, 1_048_576>>,
    /// A trust profile under `outboundTls.trustProfiles` whose CA bundle
    /// the endpoint trusts beside the system roots; absent, the endpoint
    /// trusts the system roots alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_trust_profile: Option<LocalId>,
    /// The mTLS client identity, combinable with any authentication kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_identity: Option<MtlsIdentity>,
}

/// The one named acknowledgement that admits a credential-free HTTPS
/// source. This is a security-sensitive operator decision, not a boolean
/// whose meaning can be lost in a rendered configuration.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnonymousHttpsAcknowledgement {
    /// The operator reviewed and approved this fixed anonymous source.
    OperatorApproved,
}

impl<'de> Deserialize<'de> for AnonymousHttpsAcknowledgement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "operator-approved" => Ok(Self::OperatorApproved),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["operator-approved"],
            )),
        }
    }
}

impl registry_platform_yaml::Identified for EndpointBinding {
    fn id(&self) -> &str {
        self.endpoint.as_str()
    }
}

/// The private certificate authorities endpoints may trust beside the
/// system roots (`products/adapter/CONCEPT.md` section 10.2), in the shape
/// Evidence ships: a named profile is a process-local PEM file. A CA
/// bundle is not a secret, so the profile names a file, never a secret
/// reference.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutboundTls {
    /// The named private CA bundles.
    #[serde(default, deserialize_with = "crate::typed::local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "crate::typed::local_id_map_schema::<TrustProfile>")
    )]
    pub trust_profiles: BTreeMap<String, TrustProfile>,
}

/// One named private CA bundle: the absolute path of the process-local PEM
/// file the runtime reads.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustProfile {
    /// The absolute path of the PEM file holding the bundle's certificates.
    pub ca_bundle_file: String,
}

/// The keys the runtime configuration no longer accepts, each with what
/// replaced it (CFG-CHANGE-2).
pub const ADAPTER_REMOVED_KEYS: &[RemovedKey] = &[RemovedKey {
    path: "endpoints.*.caBundleRef",
    replacement: "Write tlsTrustProfile on the endpoint binding, naming a \
                  profile declared under outboundTls.trustProfiles whose \
                  caBundleFile is the absolute path of the bundle file.",
}];

/// The audit journal's retention (`products/adapter/CONCEPT.md` section
/// 11), bounded by the platform access-log window.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRetention {
    /// Days a journal row is retained.
    pub retention_days: registry_platform_yaml::BoundedU32<1, 3_650>,
}

/// Exact write-response custody in the idempotency store
/// (`products/adapter/CONCEPT.md` section 9 and D12).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdempotencyRetention {
    /// Seconds an exact facade response remains available for replay. The
    /// spent-key tombstone remains after its response body is erased.
    pub response_retention_seconds: BoundedU64<1, 31_536_000>,
}

/// The endpoint bindings of one deployment: the runtime members every
/// mode shares (`products/adapter/CONCEPT.md` sections 10.2 and 17).
/// The ingestion job's runtime document states these members alone; the
/// facade's document states them beside the facade-only members
/// (`listener`, `database`, `oidc`, `allowedClients`, `audit`,
/// `idempotency`, and the cursor custody), which
/// [`AdapterRuntimeConfig::endpoint_bindings`] sets aside.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterEndpointBindings {
    /// The deployment this binding configures.
    pub id: LocalId,
    /// One binding per configured endpoint.
    pub endpoints: UniqueIdList<EndpointBinding>,
    /// The private CAs endpoints may trust beside the system roots;
    /// absent, every endpoint trusts the system roots alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_tls: Option<OutboundTls>,
    /// The private ranges egress may reach, at least one and at most the
    /// platform bound (CFG-EMPTY-2).
    #[serde(deserialize_with = "at_least_one_cidr")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "at_least_one_cidr_schema"))]
    pub allowed_private_cidrs: UniqueList<Cidr>,
}

/// The operator runtime configuration artifact (`AdapterRuntimeConfig`).
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterRuntimeConfig {
    /// The deployment this config binds.
    pub id: LocalId,
    /// One binding per configured endpoint.
    pub endpoints: UniqueIdList<EndpointBinding>,
    /// The private CAs endpoints may trust beside the system roots;
    /// absent, every endpoint trusts the system roots alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_tls: Option<OutboundTls>,
    /// The private ranges egress may reach, at least one and at most the
    /// platform bound (CFG-EMPTY-2).
    #[serde(deserialize_with = "at_least_one_cidr")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "at_least_one_cidr_schema"))]
    pub allowed_private_cidrs: UniqueList<Cidr>,
    /// The facade listener, from the platform shared block.
    pub listener: ListenerConfig,
    /// The PostgreSQL connections, from the platform shared block.
    pub database: DatabaseConfig,
    /// The OIDC issuer that authenticates facade callers, from the
    /// platform shared block (`products/adapter/CONCEPT.md` section 6).
    pub oidc: OidcIssuerConfig,
    /// The OAuth clients whose access tokens the facade admits, matched
    /// against the token's client claim. At least one: a list that admits
    /// every client the issuer verifies is an omission, not a policy.
    #[serde(deserialize_with = "at_least_one_client")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "at_least_one_client_schema")
    )]
    pub allowed_clients: UniqueList<ExternalId>,
    /// The journal retention.
    pub audit: AuditRetention,
    /// Exact write-response custody. A read-only deployment may omit this;
    /// startup refuses a served write without an explicit operator choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<IdempotencyRetention>,
    /// The secret that seals pagination cursors: exactly 32 bytes. A
    /// deployment that binds a paginated operation declares it; one
    /// that serves only reads by identifier may omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_key_ref: Option<SecretReference>,
    /// The retiring cursor key, still accepted when opening a cursor so
    /// a key rotation does not strand cursors in flight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_cursor_key_ref: Option<SecretReference>,
    /// How long a cursor stays valid, in seconds (60 to 86400); absent,
    /// 900.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_ttl_seconds: Option<BoundedU64<60, 86_400>>,
}

impl AdapterRuntimeConfig {
    /// The endpoint bindings this facade configuration carries, in the
    /// shape the engine consumes and a job's runtime document states
    /// alone. The facade-only members stay outside it.
    #[must_use]
    pub fn endpoint_bindings(&self) -> AdapterEndpointBindings {
        AdapterEndpointBindings {
            id: self.id.clone(),
            endpoints: self.endpoints.clone(),
            outbound_tls: self.outbound_tls.clone(),
            allowed_private_cidrs: self.allowed_private_cidrs.clone(),
        }
    }
}

/// The allowlist cannot be empty: an egress policy admitting no private
/// range is not a configuration, it is an omission (CFG-EMPTY-2). Public
/// so every document that states the endpoint bindings holds the same
/// rule.
///
/// # Errors
///
/// An empty list, or a member that is not a unique CIDR range.
pub fn at_least_one_cidr<'de, D>(deserializer: D) -> Result<UniqueList<Cidr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let list = UniqueList::<Cidr>::deserialize(deserializer)?;
    if list.is_empty() {
        return Err(serde::de::Error::custom(
            "allowedPrivateCidrs carries at least one range",
        ));
    }
    Ok(list)
}

#[cfg(feature = "schema")]
fn at_least_one_cidr_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "array",
        "minItems": 1,
        "uniqueItems": true,
        "items": generator.subschema_for::<Cidr>(),
    })
}

/// The client list cannot be empty: a deployment that names no client
/// admits none.
fn at_least_one_client<'de, D>(deserializer: D) -> Result<UniqueList<ExternalId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let list = UniqueList::<ExternalId>::deserialize(deserializer)?;
    if list.is_empty() {
        return Err(serde::de::Error::custom(
            "allowedClients carries at least one client identifier",
        ));
    }
    Ok(list)
}

#[cfg(feature = "schema")]
fn at_least_one_client_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "array",
        "minItems": 1,
        "uniqueItems": true,
        "items": generator.subschema_for::<ExternalId>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_yaml::SecretReference;

    fn binding() -> EndpointBinding {
        EndpointBinding {
            endpoint: ExternalId::new("case-api").expect("id"),
            base_url: Url::new("https://cases.example.invalid").expect("url"),
            credential: Some(RuntimeCredential::Oauth2ClientCredentials {
                token_endpoint: Url::new("https://token.example.invalid/token").expect("url"),
                client_id_ref: SecretReference::new("secret:env/CLIENT_ID").expect("secret"),
                client_secret_ref: SecretReference::new("secret:env/CLIENT_SECRET")
                    .expect("secret"),
                scope: None,
                audience: None,
                resource: None,
                credential_placement: crate::auth::CredentialPlacement::BasicHeader,
                maximum_cache_seconds: registry_platform_yaml::BoundedU64::<0, 86_400>::new(3600)
                    .expect("cache"),
                assumed_lifetime_seconds: None,
            }),
            anonymous_https: None,
            tls_trust_profile: Some(LocalId::new("private-ca").expect("id")),
            mtls_identity: None,
            attempt_timeout_milliseconds: None,
            maximum_response_bytes: None,
        }
    }

    /// The anonymous HTTPS relaxation is an exact named acknowledgement:
    /// omission stays closed, the one approved spelling parses, and values
    /// of the wrong type or outside the closed vocabulary are refused.
    #[test]
    fn anonymous_https_acknowledgement_is_closed_and_typed() {
        let omitted = serde_json::to_value(binding()).expect("binding json");
        assert!(omitted.get("anonymousHttps").is_none());

        let mut approved = omitted.clone();
        approved["anonymousHttps"] = serde_json::json!("operator-approved");
        let approved: EndpointBinding = serde_json::from_value(approved).expect("approved value");
        assert_eq!(
            approved.anonymous_https,
            Some(AnonymousHttpsAcknowledgement::OperatorApproved)
        );

        for refused in [serde_json::json!(false), serde_json::json!("approved")] {
            let mut value = omitted.clone();
            value["anonymousHttps"] = refused;
            assert!(
                serde_json::from_value::<EndpointBinding>(value).is_err(),
                "anything except the named acknowledgement refuses"
            );
        }
    }

    /// The runtime config round-trips with shared blocks and endpoint
    /// bindings.
    #[test]
    fn runtime_config_round_trips() {
        let config = AdapterRuntimeConfig {
            id: LocalId::new("case-deployment").expect("id"),
            endpoints: UniqueIdList::new(vec![binding()]).expect("unique"),
            outbound_tls: Some(OutboundTls {
                trust_profiles: BTreeMap::from([(
                    "private-ca".to_owned(),
                    TrustProfile {
                        ca_bundle_file: "/etc/registry-adapter/trust/private-ca.pem".to_owned(),
                    },
                )]),
            }),
            allowed_private_cidrs: UniqueList::new(vec![
                Cidr::new("10.0.0.0/8").expect("cidr"),
                Cidr::new("192.168.1.0/24").expect("cidr"),
            ])
            .expect("unique"),
            listener: serde_json::from_str(r#"{ "bind": "127.0.0.1:8080" }"#).expect("listener"),
            database: serde_json::from_str(
                r#"{
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                }"#,
            )
            .expect("database"),
            oidc: serde_json::from_str(
                r#"{
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                }"#,
            )
            .expect("oidc"),
            allowed_clients: UniqueList::new(vec![ExternalId::new("case-portal").expect("id")])
                .expect("unique"),
            audit: AuditRetention {
                retention_days: registry_platform_yaml::BoundedU32::<1, 3_650>::new(90)
                    .expect("retention"),
            },
            idempotency: Some(IdempotencyRetention {
                response_retention_seconds:
                    registry_platform_yaml::BoundedU64::<1, 31_536_000>::new(86_400)
                        .expect("retention"),
            }),
            cursor_key_ref: None,
            previous_cursor_key_ref: None,
            cursor_ttl_seconds: None,
        };
        // The runtime config is read, never written: the round trip goes
        // through the reader only, matching the house pattern (Casework's
        // `RuntimeConfig`).
        let json = format!(
            r#"{{
                "id": "case-deployment",
                "endpoints": [{}],
                "outboundTls": {{
                    "trustProfiles": {{
                        "private-ca": {{
                            "caBundleFile": "/etc/registry-adapter/trust/private-ca.pem"
                        }}
                    }}
                }},
                "allowedPrivateCidrs": ["10.0.0.0/8", "192.168.1.0/24"],
                "listener": {{ "bind": "127.0.0.1:8080" }},
                "database": {{
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                }},
                "oidc": {{
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                }},
                "allowedClients": ["case-portal"],
                "audit": {{ "retentionDays": 90 }},
                "idempotency": {{ "responseRetentionSeconds": 86400 }}
            }}"#,
            serde_json::to_string(&binding()).expect("binding json"),
        );
        let read = serde_json::from_str::<AdapterRuntimeConfig>(&json).expect("read");
        assert_eq!(read.id, config.id);
        assert_eq!(read.endpoints.into_vec(), vec![binding()]);
        assert_eq!(read.outbound_tls, config.outbound_tls);
        assert_eq!(
            read.allowed_private_cidrs.len(),
            config.allowed_private_cidrs.len()
        );
        assert_eq!(read.audit, config.audit);
        assert_eq!(read.idempotency, config.idempotency);
    }

    #[test]
    fn idempotency_response_retention_is_optional_and_bounded() {
        let base = r#"{
            "id": "case-deployment",
            "endpoints": [],
            "allowedPrivateCidrs": ["10.0.0.0/8"],
            "listener": { "bind": "127.0.0.1:8080" },
            "database": {
                "runtimeUrlRef": "secret:env/DB_RUNTIME",
                "migrationUrlRef": "secret:env/DB_MIGRATION"
            },
            "oidc": {
                "issuer": "https://issuer.example.invalid",
                "audience": "case-api"
            },
            "allowedClients": ["case-portal"],
            "audit": { "retentionDays": 90 }
        }"#;
        let read = serde_json::from_str::<AdapterRuntimeConfig>(base).expect("read-only config");
        assert!(read.idempotency.is_none());

        for seconds in [0_u64, 31_536_001] {
            let with_retention = base.replace(
                r#""audit": { "retentionDays": 90 }"#,
                &format!(
                    r#""audit": {{ "retentionDays": 90 }}, "idempotency": {{ "responseRetentionSeconds": {seconds} }}"#
                ),
            );
            assert!(serde_json::from_str::<AdapterRuntimeConfig>(&with_retention).is_err());
        }
    }

    /// A trust profile is keyed by a local identifier: a key outside the
    /// grammar refuses.
    #[test]
    fn a_trust_profile_map_refuses_a_key_that_is_not_a_local_id() {
        let json = r#"{
                "id": "case-deployment",
                "endpoints": [],
                "outboundTls": {
                    "trustProfiles": {
                        "Private CA": { "caBundleFile": "/etc/trust/ca.pem" }
                    }
                },
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listener": { "bind": "127.0.0.1:8080" },
                "database": {
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                },
                "oidc": {
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                },
                "allowedClients": ["case-portal"],
                "audit": { "retentionDays": 90 }
            }"#;
        assert!(serde_json::from_str::<AdapterRuntimeConfig>(json).is_err());
    }

    /// A malformed CIDR is refused at the reader.
    #[test]
    fn malformed_cidrs_are_refused() {
        assert!(Cidr::new("10.0.0.0").is_err());
        assert!(Cidr::new("not-a-range/8").is_err());
        assert!(Cidr::new("10.0.0.0/8").is_ok());
    }

    /// The egress allowlist is required and cannot be empty: omission and
    /// an explicit empty list are both refused (CFG-EMPTY-2).
    #[test]
    fn the_private_allowlist_carries_at_least_one_range() {
        let head = r#"{
                "id": "case-deployment",
                "endpoints": [],
                "listener": { "bind": "127.0.0.1:8080" },
                "database": {
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                },
                "oidc": {
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                },
                "allowedClients": ["case-portal"],
                "audit": { "retentionDays": 90 }
            }"#;
        let json = |cidrs: &str| {
            head.replace(
                r#""endpoints": [],"#,
                &format!(r#""endpoints": [], "allowedPrivateCidrs": {cidrs},"#),
            )
        };
        assert!(serde_json::from_str::<AdapterRuntimeConfig>(head).is_err());
        assert!(serde_json::from_str::<AdapterRuntimeConfig>(&json("[]")).is_err());
        let read =
            serde_json::from_str::<AdapterRuntimeConfig>(&json(r#"["10.0.0.0/8"]"#)).expect("read");
        assert_eq!(read.allowed_private_cidrs.len(), 1);
    }

    /// The client list is required and cannot be empty: omission and an
    /// explicit empty list are both refused.
    #[test]
    fn the_allowed_clients_carry_at_least_one_client() {
        let head = r#"{
                "id": "case-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listener": { "bind": "127.0.0.1:8080" },
                "database": {
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                },
                "oidc": {
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                },
                "audit": { "retentionDays": 90 }
            }"#;
        let json = |clients: &str| {
            head.replace(
                r#""endpoints": [],"#,
                &format!(r#""endpoints": [], "allowedClients": {clients},"#),
            )
        };
        assert!(serde_json::from_str::<AdapterRuntimeConfig>(head).is_err());
        assert!(serde_json::from_str::<AdapterRuntimeConfig>(&json("[]")).is_err());
        let read = serde_json::from_str::<AdapterRuntimeConfig>(&json(r#"["case-portal"]"#))
            .expect("read");
        assert_eq!(read.allowed_clients.len(), 1);
    }

    /// Duplicate endpoint bindings are refused at the reader (CFG-ID-5).
    #[test]
    fn duplicate_endpoint_bindings_are_refused() {
        assert!(UniqueIdList::new(vec![binding(), binding()]).is_err());
    }

    /// The CIDR membership test answers egress decisions.
    #[test]
    fn cidr_contains_answers_membership() {
        let range = Cidr::new("10.0.0.0/8").expect("cidr");
        assert!(range.contains("10.1.2.3".parse().expect("addr")));
        assert!(!range.contains("203.0.113.5".parse().expect("addr")));
    }

    /// A runtime document with the endpoint bindings alone reads: no
    /// listener, database, OIDC issuer, admitted clients, audit,
    /// idempotency, or cursor custody is stated (`products/adapter/`
    /// `CONCEPT.md` section 17).
    #[test]
    fn endpoint_bindings_read_a_document_without_facade_members() {
        let json = format!(
            r#"{{
                "id": "case-deployment",
                "endpoints": [{}],
                "outboundTls": {{
                    "trustProfiles": {{
                        "private-ca": {{
                            "caBundleFile": "/etc/registry-adapter/trust/private-ca.pem"
                        }}
                    }}
                }},
                "allowedPrivateCidrs": ["10.0.0.0/8"]
            }}"#,
            serde_json::to_string(&binding()).expect("binding json"),
        );
        let read = serde_json::from_str::<AdapterEndpointBindings>(&json).expect("bindings");
        assert_eq!(read.id, LocalId::new("case-deployment").expect("id"));
        assert_eq!(read.endpoints.into_vec(), vec![binding()]);
        assert!(read.outbound_tls.is_some());
        assert_eq!(read.allowed_private_cidrs.len(), 1);
    }

    /// The bindings reader refuses every facade member: a document that
    /// states one of them is a facade document, not a binding.
    #[test]
    fn endpoint_bindings_refuse_the_facade_members() {
        let base = r#"{
                "id": "case-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"]
            }"#;
        let members = [
            r#""listener": { "bind": "127.0.0.1:8080" }"#,
            r#""database": { "runtimeUrlRef": "secret:env/DB_RUNTIME", "migrationUrlRef": "secret:env/DB_MIGRATION" }"#,
            r#""oidc": { "issuer": "https://issuer.example.invalid", "audience": "case-api" }"#,
            r#""allowedClients": ["case-portal"]"#,
            r#""audit": { "retentionDays": 90 }"#,
            r#""idempotency": { "responseRetentionSeconds": 86400 }"#,
            r#""cursorKeyRef": "secret:env/CURSOR_KEY""#,
        ];
        for member in members {
            let with_member = base.replace(
                r#""allowedPrivateCidrs": ["10.0.0.0/8"]"#,
                &format!(r#""allowedPrivateCidrs": ["10.0.0.0/8"], {member}"#),
            );
            assert!(
                serde_json::from_str::<AdapterEndpointBindings>(&with_member).is_err(),
                "the bindings reader accepted a facade member: {member}"
            );
        }
        assert!(serde_json::from_str::<AdapterEndpointBindings>(base).is_ok());
    }

    /// The facade configuration's binding view equals the bindings read
    /// from the same members alone.
    #[test]
    fn endpoint_bindings_view_matches_the_standalone_reader() {
        let facade = r#"{
                "id": "case-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"],
                "listener": { "bind": "127.0.0.1:8080" },
                "database": {
                    "runtimeUrlRef": "secret:env/DB_RUNTIME",
                    "migrationUrlRef": "secret:env/DB_MIGRATION"
                },
                "oidc": {
                    "issuer": "https://issuer.example.invalid",
                    "audience": "case-api"
                },
                "allowedClients": ["case-portal"],
                "audit": { "retentionDays": 90 }
            }"#;
        let alone = r#"{
                "id": "case-deployment",
                "endpoints": [],
                "allowedPrivateCidrs": ["10.0.0.0/8"]
            }"#;
        let facade = serde_json::from_str::<AdapterRuntimeConfig>(facade).expect("facade");
        let alone = serde_json::from_str::<AdapterEndpointBindings>(alone).expect("bindings");
        assert_eq!(facade.endpoint_bindings(), alone);
    }
}
