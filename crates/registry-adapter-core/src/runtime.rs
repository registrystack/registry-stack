// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration (`AdapterRuntimeConfig`), the
//! environment bindings of one deployment (`products/adapter/CONCEPT.md`
//! sections 6, 10.2, and 12): endpoint base URLs and TLS, credential
//! secret references, the private-CIDR allowlist, and the platform shared
//! blocks. Authored artifacts carry no environment values; substitution
//! and secrets live here and only here.

use crate::auth::{MtlsIdentity, RuntimeCredential};
use registry_platform_config::{DatabaseConfig, ListenerConfig, OidcIssuerConfig};
use registry_platform_yaml::{ExternalId, LocalId, SecretReference, UniqueIdList, UniqueList, Url};
use serde::{Deserialize, Serialize};
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
    /// A private root-certificate bundle the upstream's TLS chain is
    /// validated against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_ref: Option<SecretReference>,
    /// The mTLS client identity, combinable with any authentication kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_identity: Option<MtlsIdentity>,
}

impl registry_platform_yaml::Identified for EndpointBinding {
    fn id(&self) -> &str {
        self.endpoint.as_str()
    }
}

/// The audit journal's retention (`products/adapter/CONCEPT.md` section
/// 11), bounded by the platform access-log window.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRetention {
    /// Days a journal row is retained.
    pub retention_days: registry_platform_yaml::BoundedU32<1, 3_650>,
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
    /// The journal retention.
    pub audit: AuditRetention,
}

/// The allowlist cannot be empty: an egress policy admitting no private
/// range is not a configuration, it is an omission (CFG-EMPTY-2).
fn at_least_one_cidr<'de, D>(deserializer: D) -> Result<UniqueList<Cidr>, D::Error>
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

#[cfg(test)]
mod tests {
    use super::*;

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
            ca_bundle_ref: Some(
                SecretReference::new("secret:file/private-ca.pem").expect("secret"),
            ),
            mtls_identity: None,
        }
    }

    /// The runtime config round-trips with shared blocks and endpoint
    /// bindings.
    #[test]
    fn runtime_config_round_trips() {
        let config = AdapterRuntimeConfig {
            id: LocalId::new("case-deployment").expect("id"),
            endpoints: UniqueIdList::new(vec![binding()]).expect("unique"),
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
            audit: AuditRetention {
                retention_days: registry_platform_yaml::BoundedU32::<1, 3_650>::new(90)
                    .expect("retention"),
            },
        };
        // The runtime config is read, never written: the round trip goes
        // through the reader only, matching the house pattern (Casework's
        // `RuntimeConfig`).
        let json = format!(
            r#"{{
                "id": "case-deployment",
                "endpoints": [{}],
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
                "audit": {{ "retentionDays": 90 }}
            }}"#,
            serde_json::to_string(&binding()).expect("binding json"),
        );
        let read = serde_json::from_str::<AdapterRuntimeConfig>(&json).expect("read");
        assert_eq!(read.id, config.id);
        assert_eq!(read.endpoints.into_vec(), vec![binding()]);
        assert_eq!(
            read.allowed_private_cidrs.len(),
            config.allowed_private_cidrs.len()
        );
        assert_eq!(read.audit, config.audit);
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
}
