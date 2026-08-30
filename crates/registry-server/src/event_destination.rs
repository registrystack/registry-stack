// SPDX-License-Identifier: Apache-2.0
//! Activation of deployment bindings for governed webhook destinations.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use ipnet::IpNet;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{
    ProtectedSecret, SecretError, SecretReference, SecretResolver, MAX_SECRET_BYTES,
};
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
        MAX_WEBHOOK_ATTEMPTS, MAX_WEBHOOK_ATTEMPT_TIMEOUT_MS, MAX_WEBHOOK_PAYLOAD_BYTES,
        MIN_WEBHOOK_ATTEMPT_TIMEOUT_MS,
    },
    model::CompiledRegistry,
};

const DESTINATION_BINDING_SCHEMA_VERSION: &str = "registry-server.event-destinations/v1";
const MIN_HMAC_SHA256_KEY_BYTES: usize = 32;
const MAX_EVENT_REQUEST_BYTES: usize = MAX_DESTINATION_TARGET_BYTES
    + MAX_DESTINATION_REQUEST_HEADER_BYTES
    + MAX_DESTINATION_REQUEST_BODY_BYTES;

const _: () = assert!(MAX_WEBHOOK_PAYLOAD_BYTES as usize == MAX_DESTINATION_REQUEST_BODY_BYTES);

/// Value-free refusal while activating deployed event destinations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EventDestinationActivationError {
    #[error("event destination activation found an invalid deployment binding")]
    InvalidBinding,
    #[error("event destination activation requires an exact compiled binding set")]
    InventoryMismatch,
    #[error("event destination runtime ceilings exceed compiled delivery authority")]
    DeliveryCeilingWidening,
    #[error("event destination secret resolution failed")]
    Secret,
    #[error("event destination signing material is invalid")]
    InvalidSigningMaterial,
    #[error("event destination TLS material is invalid")]
    InvalidTlsMaterial,
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
    bindings: BTreeMap<String, ActivatedEventDestination>,
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
    ) -> Result<Self> {
        let compiled_ids = compiled
            .event_deliveries()
            .deliveries
            .iter()
            .map(|delivery| delivery.destination_id.as_str())
            .collect::<BTreeSet<_>>();
        let configured_ids = configured.bindings.keys().map(String::as_str).collect();
        if compiled_ids != configured_ids {
            return Err(EventDestinationActivationError::InventoryMismatch);
        }

        let mut bindings = BTreeMap::new();
        for (logical_id, config) in &configured.bindings {
            let deliveries = compiled
                .event_deliveries()
                .deliveries
                .iter()
                .filter(|delivery| delivery.destination_id == *logical_id)
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
            let activated = config.activate(logical_id, maximum_payload_bytes, secrets)?;
            if bindings.insert(logical_id.clone(), activated).is_some() {
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
    pub fn lookup(&self, compiled_logical_id: &str) -> Option<&ActivatedEventDestination> {
        self.bindings.get(compiled_logical_id)
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
                    (logical_id.clone(), destination.binding_digest.clone())
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

/// One activated logical event destination.
pub struct ActivatedEventDestination {
    binding_digest: String,
    request_target: String,
    policy: Arc<EventDestinationPolicy>,
    request_template: EventDestinationRequestTemplate,
    hmac_sha256_key: ProtectedSecret,
    attempt_timeout: Duration,
    maximum_attempts: u8,
}

impl ActivatedEventDestination {
    /// Digest of this exact logical destination's non-secret deployment binding.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    /// Share the only outbound authority for this logical destination.
    #[must_use]
    pub fn policy(&self) -> Arc<EventDestinationPolicy> {
        Arc::clone(&self.policy)
    }

    /// Borrow the closed event request template for rendering a later delivery.
    #[must_use]
    pub fn request_template(&self) -> &EventDestinationRequestTemplate {
        &self.request_template
    }

    /// Borrow the exact validated request target used by the closed template.
    ///
    /// Registry Server binds these same bytes into its product-owned
    /// signature, so signing and transport cannot disagree about the path.
    #[must_use]
    pub fn request_target(&self) -> &str {
        &self.request_target
    }

    /// Borrow signing bytes only for the duration of the supplied operation.
    pub fn with_hmac_sha256_key<T>(&self, use_key: impl FnOnce(&[u8]) -> T) -> T {
        use_key(self.hmac_sha256_key.expose_secret())
    }

    /// Deployed per-attempt timeout, already proved no wider than every user.
    #[must_use]
    pub fn attempt_timeout(&self) -> Duration {
        self.attempt_timeout
    }

    /// Deployed maximum attempt count, already proved no wider than every user.
    #[must_use]
    pub fn maximum_attempts(&self) -> u8 {
        self.maximum_attempts
    }
}

impl fmt::Debug for ActivatedEventDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedEventDestination")
            .field("binding_digest", &self.binding_digest)
            .field("request_target", &"[REDACTED]")
            .field("policy", &self.policy)
            .field("request_template", &self.request_template)
            .field("hmac_sha256_key", &"[REDACTED]")
            .field("attempt_timeout", &self.attempt_timeout)
            .field("maximum_attempts", &self.maximum_attempts)
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
    classification_ceiling: Classification,
    tls: Option<EventDestinationTlsConfig>,
    delivery_ceilings: EventDestinationDeliveryCeilings,
}

impl EventDestinationConfig {
    fn from_raw(logical_id: &str, raw: RawEventDestinationConfig) -> ConfigResult<Self> {
        let hmac_sha256_key_ref =
            parse_secret_reference(raw.hmac_sha256_key_ref).ok_or(EventDestinationConfigError)?;
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
        EventDestinationRequestTemplate::event_delivery(
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
    ) -> Result<ActivatedEventDestination> {
        let hmac_sha256_key = secrets.resolve_reference(&self.hmac_sha256_key_ref)?;
        if !(MIN_HMAC_SHA256_KEY_BYTES..=MAX_SECRET_BYTES).contains(&hmac_sha256_key.len()) {
            return Err(EventDestinationActivationError::InvalidSigningMaterial);
        }

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
        let request_template = EventDestinationRequestTemplate::event_delivery(
            &self.path,
            maximum_payload_bytes,
            MAX_EVENT_REQUEST_BYTES,
        )
        .map_err(|_| EventDestinationActivationError::InvalidBinding)?;

        Ok(ActivatedEventDestination {
            binding_digest: self.binding_digest(logical_id)?,
            request_target: self.path.clone(),
            policy: Arc::new(policy),
            request_template,
            hmac_sha256_key,
            attempt_timeout: Duration::from_millis(u64::from(
                self.delivery_ceilings.attempt_timeout_milliseconds,
            )),
            maximum_attempts: self.delivery_ceilings.maximum_attempts,
        })
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
        let ca_bundle_ref = raw
            .ca_bundle_ref
            .map(parse_secret_reference)
            .transpose_option()?;
        let client_identity_ref = raw
            .client_identity_ref
            .map(parse_secret_reference)
            .transpose_option()?;
        if ca_bundle_ref.is_none() && client_identity_ref.is_none() {
            return Err(EventDestinationConfigError);
        }
        Ok(Self {
            ca_bundle_ref,
            client_identity_ref,
        })
    }
}

trait TransposeOption<T> {
    fn transpose_option(self) -> ConfigResult<Option<T>>;
}

impl<T> TransposeOption<T> for Option<Option<T>> {
    fn transpose_option(self) -> ConfigResult<Option<T>> {
        match self {
            Some(Some(value)) => Ok(Some(value)),
            Some(None) => Err(EventDestinationConfigError),
            None => Ok(None),
        }
    }
}

#[derive(Clone, Copy)]
struct EventDestinationDeliveryCeilings {
    attempt_timeout_milliseconds: u32,
    maximum_attempts: u8,
}

impl EventDestinationDeliveryCeilings {
    fn from_raw(raw: RawEventDestinationDeliveryCeilings) -> ConfigResult<Self> {
        if !(MIN_WEBHOOK_ATTEMPT_TIMEOUT_MS..=MAX_WEBHOOK_ATTEMPT_TIMEOUT_MS)
            .contains(&raw.attempt_timeout_milliseconds)
            || raw.maximum_attempts == 0
            || raw.maximum_attempts > MAX_WEBHOOK_ATTEMPTS
        {
            return Err(EventDestinationConfigError);
        }
        Ok(Self {
            attempt_timeout_milliseconds: raw.attempt_timeout_milliseconds,
            maximum_attempts: raw.maximum_attempts,
        })
    }
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum EventDestinationNetworkProfile {
    ProductionHttps,
    LoopbackDevelopmentHttp,
    #[cfg(feature = "postgres-test")]
    PinnedLoopbackHttpsTest,
}

impl EventDestinationNetworkProfile {
    fn platform(self) -> DestinationProfile {
        match self {
            Self::ProductionHttps => DestinationProfile::ProductionHttps,
            Self::LoopbackDevelopmentHttp => DestinationProfile::LoopbackDevelopmentHttp,
            #[cfg(feature = "postgres-test")]
            Self::PinnedLoopbackHttpsTest => DestinationProfile::PinnedLoopbackHttpsTest,
        }
    }

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
#[serde(rename_all = "camelCase")]
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
    origin: String,
    path: String,
    network_profile: EventDestinationNetworkProfile,
    dns_family: EventDestinationDnsFamily,
    allowed_private_cidrs: Vec<String>,
    hmac_sha256_key_ref: String,
    classification_ceiling: Classification,
    #[serde(default)]
    tls: Option<RawEventDestinationTlsConfig>,
    delivery_ceilings: RawEventDestinationDeliveryCeilings,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEventDestinationTlsConfig {
    #[serde(default)]
    ca_bundle_ref: Option<String>,
    #[serde(default)]
    client_identity_ref: Option<String>,
}

#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEventDestinationDeliveryCeilings {
    attempt_timeout_milliseconds: u32,
    maximum_attempts: u8,
}

fn parse_secret_reference(value: String) -> Option<SecretReference> {
    SecretReference::parse(value).ok()
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
