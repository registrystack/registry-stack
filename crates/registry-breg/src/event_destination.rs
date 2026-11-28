// SPDX-License-Identifier: Apache-2.0
//! Activation of deployment bindings for governed hook destinations.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use ipnet::IpNet;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{ProtectedSecret, SecretError, SecretReference, SecretResolver};
use registry_platform_crypto::delivery_signature::{
    distinct_delivery_keys, DeliveryKey, DeliveryKeyError, DeliveryKeys,
};
use registry_platform_hooks::delivery::{UrlDestination, UrlDestinationParts};
use registry_platform_httputil::destination::{
    DestinationDnsFamily, DestinationProfile, DestinationTlsMaterial, EventDestinationPolicy,
    EventDestinationRequestTemplate, MAX_DESTINATION_PRIVATE_CIDRS,
    MAX_DESTINATION_REQUEST_BODY_BYTES, MAX_DESTINATION_REQUEST_HEADER_BYTES,
    MAX_DESTINATION_TARGET_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contract::Classification;
use crate::{
    compiler::{
        MAX_HOOK_ATTEMPTS, MAX_HOOK_ATTEMPT_TIMEOUT_MS, MAX_HOOK_PAYLOAD_BYTES,
        MIN_HOOK_ATTEMPT_TIMEOUT_MS,
    },
    model::CompiledRegistry,
};

const DESTINATION_BINDING_SCHEMA_VERSION: &str = "breg.event-destinations/v1";
const MAX_EVENT_REQUEST_BYTES: usize = MAX_DESTINATION_TARGET_BYTES
    + MAX_DESTINATION_REQUEST_HEADER_BYTES
    + MAX_DESTINATION_REQUEST_BODY_BYTES;

const _: () = assert!(MAX_HOOK_PAYLOAD_BYTES as usize == MAX_DESTINATION_REQUEST_BODY_BYTES);

/// Value-free refusal while activating deployed event destinations.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EventDestinationActivationError {
    #[error("event destination activation found an invalid deployment binding")]
    InvalidBinding,
    #[error("event destination activation requires an exact compiled binding set")]
    InventoryMismatch,
    #[error("event destination runtime ceilings exceed compiled delivery authority")]
    DeliveryCeilingWidening,
    #[error("event destination secret resolution failed")]
    Secret,
    #[error("{path} could not be resolved: {reason}. {action}")]
    SigningKeyUnavailable {
        path: String,
        reason: String,
        action: &'static str,
    },
    #[error("{path} has {length} bytes (trailing newline: {trailing_newline}). {}", signing_key_action(.reason))]
    InvalidSigningKey {
        path: String,
        length: usize,
        trailing_newline: bool,
        reason: DeliveryKeyError,
    },
    #[error("{first} and {second} resolve to the same key bytes. Give {second} its own key by writing 32 new random bytes to another secret and referencing it there.")]
    RepeatedSigningKey { first: String, second: String },
    #[error("{previous} holds the same bytes as {current}. To rotate, write 32 new random bytes to the secret {current} references and keep the old bytes behind {previous}.")]
    PreviousEqualsCurrent { current: String, previous: String },
    #[error("event destination TLS material is invalid")]
    InvalidTlsMaterial,
}

pub(crate) const CURRENT_KEY_MEMBER: &str = "hmacSha256KeyRef";
pub(crate) const PREVIOUS_KEY_MEMBER: &str = "previousHmacSha256KeyRef";

pub(crate) fn present_hook_key_reference<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SecretReference>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SecretReference::deserialize(deserializer).map(Some)
}

pub(crate) fn signing_key_action(reason: &DeliveryKeyError) -> &'static str {
    match reason {
        DeliveryKeyError::TooShort { .. } | DeliveryKeyError::TooLong { .. } => {
            "Supply 32 to 64 exact key bytes."
        }
        DeliveryKeyError::SecretText => "Supply the exact key bytes without the whsec_ encoding.",
        DeliveryKeyError::PreviousEqualsCurrent => unreachable!("key equality has both paths"),
    }
}

fn resolve_delivery_key(
    secrets: &SecretResolver,
    path: &str,
    reference: &SecretReference,
) -> Result<DeliveryKey> {
    let secret = secrets
        .resolve_binary_reference(reference)
        .map_err(
            |error| EventDestinationActivationError::SigningKeyUnavailable {
                path: path.to_owned(),
                reason: error.to_string(),
                action: error.suggested_action(),
            },
        )?;
    let bytes = secret.expose_secret();
    let length = bytes.len();
    let trailing_newline = bytes.ends_with(b"\n");
    let key = DeliveryKey::new(bytes).map_err(|reason| {
        EventDestinationActivationError::InvalidSigningKey {
            path: path.to_owned(),
            length,
            trailing_newline,
            reason,
        }
    })?;
    Ok(key)
}

pub(crate) fn resolve_delivery_keys(
    secrets: &SecretResolver,
    block: &str,
    current: &SecretReference,
    previous: Option<&SecretReference>,
) -> Result<DeliveryKeys> {
    let current = resolve_delivery_key(secrets, &format!("{block}.{CURRENT_KEY_MEMBER}"), current)?;
    let Some(previous) = previous else {
        return Ok(DeliveryKeys::new(current, None).expect("one validated key"));
    };
    let path = format!("{block}.{PREVIOUS_KEY_MEMBER}");
    let previous = resolve_delivery_key(secrets, &path, previous)?;
    DeliveryKeys::new(current, Some(previous)).map_err(|_| {
        EventDestinationActivationError::PreviousEqualsCurrent {
            current: format!("{block}.{CURRENT_KEY_MEMBER}"),
            previous: path,
        }
    })
}

pub(crate) fn labeled_delivery_keys<'a>(
    block: &str,
    keys: &'a DeliveryKeys,
) -> impl Iterator<Item = (String, &'a DeliveryKey)> + use<'a> {
    std::iter::once((format!("{block}.{CURRENT_KEY_MEMBER}"), keys.current())).chain(
        keys.previous()
            .map(|key| (format!("{block}.{PREVIOUS_KEY_MEMBER}"), key)),
    )
}

impl From<SecretError> for EventDestinationActivationError {
    fn from(_error: SecretError) -> Self {
        Self::Secret
    }
}

pub type Result<T> = std::result::Result<T, EventDestinationActivationError>;

/// The exact activated deployment bindings for one compiled Registry.
///
/// The registry deliberately has no iterator over configured names. A caller
/// must already hold a compiler-issued logical destination id to obtain a
/// binding.
pub struct ActivatedEventDestinationRegistry {
    binding_digest: String,
    bindings: BTreeMap<String, Arc<UrlDestination>>,
    payload_retention: Duration,
}

/// Value-free destination identity supplied to package activation.
///
/// This inventory deliberately contains no URL, path, TLS material, or secret
/// reference. It is sufficient only to prove that retained non-terminal work
/// can still use the exact destination binding under which it was captured.
#[derive(Clone, Default)]
pub struct EventDestinationCompatibilityInventory {
    binding_digests: BTreeMap<String, String>,
}

impl EventDestinationCompatibilityInventory {
    #[must_use]
    pub fn binding_digest(&self, logical_destination_id: &str) -> Option<&str> {
        self.binding_digests
            .get(logical_destination_id)
            .map(String::as_str)
    }

    pub(crate) fn binding_digests(&self) -> impl Iterator<Item = (&str, &str)> {
        self.binding_digests
            .iter()
            .map(|(logical_id, digest)| (logical_id.as_str(), digest.as_str()))
    }
}

impl fmt::Debug for EventDestinationCompatibilityInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventDestinationCompatibilityInventory")
            .field("binding_count", &self.binding_digests.len())
            .finish()
    }
}

impl ActivatedEventDestinationRegistry {
    pub(crate) fn activate(
        compiled: &CompiledRegistry,
        configured: &EventDestinationConfigs,
        secrets: &SecretResolver,
        other_keys: Vec<(String, &DeliveryKey)>,
    ) -> Result<Self> {
        let compiled_ids = compiled
            .event_deliveries()
            .deliveries
            .iter()
            .filter_map(|delivery| delivery.destination_id.as_deref())
            .collect::<BTreeSet<_>>();
        let configured_ids = configured.bindings.keys().map(String::as_str).collect();
        if compiled_ids != configured_ids {
            return Err(EventDestinationActivationError::InventoryMismatch);
        }

        let mut keys = configured
            .bindings
            .iter()
            .map(|(id, config)| {
                let block = format!("destinations.hooks.{id}");
                resolve_delivery_keys(
                    secrets,
                    &block,
                    &config.hmac_sha256_key_ref,
                    config.previous_hmac_sha256_key_ref.as_ref(),
                )
                .map(|keys| (id, keys))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let labeled_keys = keys
            .iter()
            .flat_map(|(id, keys)| labeled_delivery_keys(&format!("destinations.hooks.{id}"), keys))
            .chain(other_keys)
            .collect::<Vec<_>>();
        distinct_delivery_keys(labeled_keys.iter().map(|(path, key)| (path.as_str(), *key)))
            .map_err(
                |error| EventDestinationActivationError::RepeatedSigningKey {
                    first: error.first().to_owned(),
                    second: error.second().to_owned(),
                },
            )?;

        let mut bindings = BTreeMap::new();
        for (logical_id, config) in &configured.bindings {
            let deliveries = compiled
                .event_deliveries()
                .deliveries
                .iter()
                .filter(|delivery| delivery.destination_id.as_deref() == Some(logical_id.as_str()))
                .collect::<Vec<_>>();
            if deliveries.is_empty() {
                return Err(EventDestinationActivationError::InventoryMismatch);
            }
            if deliveries.iter().any(|delivery| {
                config.delivery_ceilings.attempt_timeout_milliseconds > delivery.attempt_timeout_ms
                    || config.delivery_ceilings.maximum_attempts > delivery.maximum_attempts
                    || delivery.classification_ceiling > config.classification_ceiling
            }) {
                return Err(EventDestinationActivationError::DeliveryCeilingWidening);
            }
            let maximum_payload_bytes = deliveries
                .iter()
                .map(|delivery| delivery.maximum_payload_bytes)
                .max()
                .ok_or(EventDestinationActivationError::InventoryMismatch)?;
            let resolved_keys = keys
                .remove(logical_id)
                .expect("one resolved key set per destination");
            let activated =
                config.activate(logical_id, maximum_payload_bytes, secrets, resolved_keys)?;
            if bindings
                .insert(logical_id.clone(), Arc::new(activated))
                .is_some()
            {
                return Err(EventDestinationActivationError::InventoryMismatch);
            }
        }

        Ok(Self {
            binding_digest: configured.binding_digest()?,
            bindings,
            payload_retention: Duration::from_secs(7 * 24 * 60 * 60),
        })
    }

    pub(crate) fn with_payload_retention(mut self, payload_retention: Duration) -> Self {
        self.payload_retention = payload_retention;
        self
    }

    /// Deployment-selected lifetime of a retained pending or dead-letter body.
    #[must_use]
    pub fn payload_retention(&self) -> Duration {
        self.payload_retention
    }

    /// Digest of the exact non-secret deployment binding document.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    /// Look up a binding only by its compiler-issued logical destination id.
    #[must_use]
    pub fn lookup(&self, compiled_logical_id: &str) -> Option<&UrlDestination> {
        self.bindings.get(compiled_logical_id).map(Arc::as_ref)
    }

    /// Owned handle to a binding, for callers that carry it across an await
    /// point. Same lookup discipline as [`Self::lookup`].
    #[must_use]
    pub fn lookup_shared(&self, compiled_logical_id: &str) -> Option<Arc<UrlDestination>> {
        self.bindings.get(compiled_logical_id).cloned()
    }

    /// Build the minimized inventory used to keep queued delivery compatible
    /// across a package activation.
    #[must_use]
    pub fn compatibility_inventory(&self) -> EventDestinationCompatibilityInventory {
        EventDestinationCompatibilityInventory {
            binding_digests: self
                .bindings
                .iter()
                .map(|(logical_id, destination)| {
                    (logical_id.clone(), destination.binding_digest().to_owned())
                })
                .collect(),
        }
    }
}

impl fmt::Debug for ActivatedEventDestinationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedEventDestinationRegistry")
            .field("binding_digest", &self.binding_digest)
            .field("binding_count", &self.bindings.len())
            .field("payload_retention", &self.payload_retention)
            .finish()
    }
}

#[derive(Clone, Default)]
pub(crate) struct EventDestinationConfigs {
    bindings: BTreeMap<String, EventDestinationConfig>,
}

impl EventDestinationConfigs {
    pub(crate) fn from_raw(raw: RawEventDestinationConfigs) -> ConfigResult<Self> {
        if raw.len() > 128 {
            return Err(EventDestinationConfigError);
        }
        let mut bindings = BTreeMap::new();
        for (logical_id, raw_config) in raw {
            if !valid_logical_destination_id(&logical_id) {
                return Err(EventDestinationConfigError);
            }
            let config = EventDestinationConfig::from_raw(&logical_id, raw_config)?;
            if bindings.insert(logical_id, config).is_some() {
                return Err(EventDestinationConfigError);
            }
        }
        Ok(Self { bindings })
    }

    fn binding_digest(&self) -> Result<String> {
        let destinations = self
            .bindings
            .iter()
            .map(|(logical_id, config)| config.digest_value(logical_id))
            .collect::<Vec<_>>();
        let value = json!({
            "schemaVersion": DESTINATION_BINDING_SCHEMA_VERSION,
            "eventDestinations": destinations,
        });
        canonical_binding_digest(&value)
    }
}

impl fmt::Debug for EventDestinationConfigs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventDestinationConfigs")
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

#[derive(Clone)]
struct EventDestinationConfig {
    origin: String,
    path: String,
    network_profile: EventDestinationNetworkProfile,
    dns_family: EventDestinationDnsFamily,
    allowed_private_cidrs: Vec<IpNet>,
    hmac_sha256_key_ref: SecretReference,
    previous_hmac_sha256_key_ref: Option<SecretReference>,
    classification_ceiling: Classification,
    tls: Option<EventDestinationTlsConfig>,
    delivery_ceilings: EventDestinationDeliveryCeilings,
}

impl EventDestinationConfig {
    fn from_raw(logical_id: &str, raw: RawEventDestinationConfig) -> ConfigResult<Self> {
        let hmac_sha256_key_ref = raw.hmac_sha256_key_ref;
        let tls = raw
            .tls
            .map(EventDestinationTlsConfig::from_raw)
            .transpose()?;
        let delivery_ceilings = EventDestinationDeliveryCeilings::from_raw(raw.delivery_ceilings)?;
        let allowed_private_cidrs = parse_private_cidrs(raw.allowed_private_cidrs)?;
        let config = Self {
            origin: raw.origin,
            path: raw.path,
            network_profile: raw.network_profile,
            dns_family: raw.dns_family,
            allowed_private_cidrs,
            hmac_sha256_key_ref,
            previous_hmac_sha256_key_ref: raw.previous_hmac_sha256_key_ref,
            classification_ceiling: raw.classification_ceiling,
            tls,
            delivery_ceilings,
        };
        config.validate_platform_binding(logical_id)?;
        Ok(config)
    }

    fn validate_platform_binding(&self, logical_id: &str) -> ConfigResult<()> {
        EventDestinationPolicy::new_with_dns_family(
            logical_id,
            &self.origin,
            self.network_profile.platform(),
            &self.allowed_private_cidrs,
            self.dns_family.platform(),
        )
        .map_err(|_| EventDestinationConfigError)?;
        EventDestinationRequestTemplate::signed_event_delivery(
            &self.path,
            MAX_DESTINATION_REQUEST_BODY_BYTES,
            MAX_EVENT_REQUEST_BYTES,
        )
        .map_err(|_| EventDestinationConfigError)?;
        Ok(())
    }

    fn activate(
        &self,
        logical_id: &str,
        maximum_payload_bytes: u32,
        secrets: &SecretResolver,
        keys: DeliveryKeys,
    ) -> Result<UrlDestination> {
        let mut policy = EventDestinationPolicy::new_with_dns_family(
            logical_id,
            &self.origin,
            self.network_profile.platform(),
            &self.allowed_private_cidrs,
            self.dns_family.platform(),
        )
        .map_err(|_| EventDestinationActivationError::InvalidBinding)?;
        if let Some(tls) = &self.tls {
            let ca_bundle = tls
                .ca_bundle_ref
                .as_ref()
                .map(|reference| secrets.resolve_reference(reference))
                .transpose()?;
            let client_identity = tls
                .client_identity_ref
                .as_ref()
                .map(|reference| secrets.resolve_reference(reference))
                .transpose()?;
            let material = DestinationTlsMaterial::from_pem(
                ca_bundle.as_ref().map(ProtectedSecret::expose_secret),
                client_identity.as_ref().map(ProtectedSecret::expose_secret),
            )
            .map_err(|_| EventDestinationActivationError::InvalidTlsMaterial)?;
            policy = policy.require_configured_tls();
            policy
                .install_configured_tls(material)
                .map_err(|_| EventDestinationActivationError::InvalidTlsMaterial)?;
        }

        let maximum_payload_bytes = usize::try_from(maximum_payload_bytes)
            .map_err(|_| EventDestinationActivationError::InvalidBinding)?;
        UrlDestination::new(UrlDestinationParts {
            binding_digest: self.binding_digest(logical_id)?,
            request_target: self.path.clone(),
            policy,
            maximum_payload_bytes,
            keys,
            attempt_timeout: Duration::from_millis(u64::from(
                self.delivery_ceilings.attempt_timeout_milliseconds,
            )),
            maximum_attempts: self.delivery_ceilings.maximum_attempts,
        })
        .map_err(|_| EventDestinationActivationError::InvalidBinding)
    }

    fn digest_value(&self, logical_id: &str) -> Value {
        let tls = self.tls.as_ref().map(|tls| {
            json!({
                "caBundleRef": tls.ca_bundle_ref.as_ref().map(SecretReference::as_str),
                "clientIdentityRef": tls.client_identity_ref.as_ref().map(SecretReference::as_str),
            })
        });
        json!({
            "logicalId": logical_id,
            "origin": self.origin,
            "path": self.path,
            "networkProfile": self.network_profile.as_str(),
            "dnsFamily": self.dns_family.as_str(),
            "allowedPrivateCidrs": self.allowed_private_cidrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "hmacSha256KeyRef": self.hmac_sha256_key_ref.as_str(),
            "classificationCeiling": self.classification_ceiling,
            "tls": tls,
            "deliveryCeilings": {
                "attemptTimeoutMilliseconds": self.delivery_ceilings.attempt_timeout_milliseconds,
                "maximumAttempts": self.delivery_ceilings.maximum_attempts,
            },
        })
    }

    fn binding_digest(&self, logical_id: &str) -> Result<String> {
        canonical_binding_digest(&json!({
            "schemaVersion": DESTINATION_BINDING_SCHEMA_VERSION,
            "destination": self.digest_value(logical_id),
        }))
    }
}

#[derive(Clone)]
struct EventDestinationTlsConfig {
    ca_bundle_ref: Option<SecretReference>,
    client_identity_ref: Option<SecretReference>,
}

impl EventDestinationTlsConfig {
    fn from_raw(raw: RawEventDestinationTlsConfig) -> ConfigResult<Self> {
        let ca_bundle_ref = raw.ca_bundle_ref;
        let client_identity_ref = raw.client_identity_ref;
        if ca_bundle_ref.is_none() && client_identity_ref.is_none() {
            return Err(EventDestinationConfigError);
        }
        Ok(Self {
            ca_bundle_ref,
            client_identity_ref,
        })
    }
}

#[derive(Clone, Copy)]
struct EventDestinationDeliveryCeilings {
    attempt_timeout_milliseconds: u32,
    maximum_attempts: u8,
}

impl EventDestinationDeliveryCeilings {
    fn from_raw(raw: RawEventDestinationDeliveryCeilings) -> ConfigResult<Self> {
        Ok(Self {
            attempt_timeout_milliseconds: raw.attempt_timeout_milliseconds,
            maximum_attempts: raw.maximum_attempts,
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EventDestinationNetworkProfile {
    ProductionHttps,
    LoopbackDevelopmentHttp,
    #[cfg(feature = "postgres-test")]
    #[cfg_attr(feature = "schema", schemars(skip))]
    PinnedLoopbackHttpsTest,
}

impl EventDestinationNetworkProfile {
    fn platform(self) -> DestinationProfile {
        match self {
            Self::ProductionHttps => DestinationProfile::ProductionHttps,
            Self::LoopbackDevelopmentHttp => DestinationProfile::LoopbackHttp,
            #[cfg(feature = "postgres-test")]
            Self::PinnedLoopbackHttpsTest => DestinationProfile::PinnedLoopbackHttpsTest,
        }
    }

    /// The word the binding digest is computed over. The digest is stored
    /// with every delivery the binding queued, so this word is independent
    /// of the spelling the runtime file writes.
    fn as_str(self) -> &'static str {
        match self {
            Self::ProductionHttps => "productionHttps",
            Self::LoopbackDevelopmentHttp => "loopbackDevelopmentHttp",
            #[cfg(feature = "postgres-test")]
            Self::PinnedLoopbackHttpsTest => "pinnedLoopbackHttpsTest",
        }
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EventDestinationDnsFamily {
    DualStackStrict,
    Ipv4Only,
}

impl EventDestinationDnsFamily {
    fn platform(self) -> DestinationDnsFamily {
        match self {
            Self::DualStackStrict => DestinationDnsFamily::DualStackStrict,
            Self::Ipv4Only => DestinationDnsFamily::Ipv4Only,
        }
    }

    /// The word the binding digest is computed over. The digest is stored
    /// with every delivery the binding queued, so this word is independent
    /// of the spelling the runtime file writes.
    fn as_str(self) -> &'static str {
        match self {
            Self::DualStackStrict => "dualStackStrict",
            Self::Ipv4Only => "ipv4Only",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventDestinationConfigError;

type ConfigResult<T> = std::result::Result<T, EventDestinationConfigError>;

pub(crate) type RawEventDestinationConfigs = BTreeMap<String, RawEventDestinationConfig>;

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawEventDestinationConfig {
    /// Receiver origin without a path or query, such as `https://receiver.example.com`.
    origin: String,
    /// Absolute request path on the configured origin, such as `/events`.
    path: String,
    /// HTTPS for production, or explicit loopback-only HTTP for local development.
    network_profile: EventDestinationNetworkProfile,
    /// Address families to validate when resolving the destination.
    dns_family: EventDestinationDnsFamily,
    /// Explicitly allowed private network ranges in canonical CIDR notation.
    allowed_private_cidrs: Vec<String>,
    /// Runtime secret reference for the receiver's 32 to 64 exact HMAC-SHA-256 key bytes.
    hmac_sha256_key_ref: SecretReference,
    /// Optional previous signing key during rotation.
    #[serde(
        default,
        deserialize_with = "present_hook_key_reference",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    previous_hmac_sha256_key_ref: Option<SecretReference>,
    /// Highest permitted classification, including fields used only in event conditions.
    classification_ceiling: Classification,
    /// Optional private CA and client identity secret references for HTTPS.
    #[serde(default)]
    tls: Option<RawEventDestinationTlsConfig>,
    /// Per-destination limits that may tighten, but never increase, the compiled delivery limits.
    delivery_ceilings: RawEventDestinationDeliveryCeilings,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEventDestinationTlsConfig {
    /// PEM CA bundle secret reference, when the receiver uses a private
    /// certificate authority. Omitted, the platform's trusted roots verify
    /// the receiver. At least one of `caBundleRef` and `clientIdentityRef`
    /// is written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca_bundle_ref: Option<SecretReference>,
    /// PEM client identity secret reference for mutual TLS. Omitted, the
    /// registry presents no client certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_identity_ref: Option<SecretReference>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEventDestinationDeliveryCeilings {
    /// Maximum time allowed for one attempt, in milliseconds.
    #[serde(
        deserialize_with = "crate::contract::bounded_u32::<_, MIN_HOOK_ATTEMPT_TIMEOUT_MS, MAX_HOOK_ATTEMPT_TIMEOUT_MS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::BoundedU32<MIN_HOOK_ATTEMPT_TIMEOUT_MS, MAX_HOOK_ATTEMPT_TIMEOUT_MS>"
        )
    )]
    attempt_timeout_milliseconds: u32,
    /// Maximum total attempts in one delivery generation, including the first attempt.
    #[serde(
        deserialize_with = "crate::contract::bounded_u8::<_, 1, { MAX_HOOK_ATTEMPTS as u32 }>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, { MAX_HOOK_ATTEMPTS as u32 }>")
    )]
    maximum_attempts: u8,
}

fn parse_private_cidrs(raw: Vec<String>) -> ConfigResult<Vec<IpNet>> {
    if raw.len() > MAX_DESTINATION_PRIVATE_CIDRS {
        return Err(EventDestinationConfigError);
    }
    let mut parsed = Vec::with_capacity(raw.len());
    for value in raw {
        let cidr = value
            .parse::<IpNet>()
            .map_err(|_| EventDestinationConfigError)?;
        if cidr.trunc() != cidr || cidr.to_string() != value {
            return Err(EventDestinationConfigError);
        }
        if parsed.last().is_some_and(|prior| prior >= &cidr) {
            return Err(EventDestinationConfigError);
        }
        parsed.push(cidr);
    }
    Ok(parsed)
}

fn valid_logical_destination_id(value: &str) -> bool {
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

fn canonical_binding_digest(value: &Value) -> Result<String> {
    let canonical =
        canonicalize_json(value).map_err(|_| EventDestinationActivationError::InvalidBinding)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(canonical))))
}
