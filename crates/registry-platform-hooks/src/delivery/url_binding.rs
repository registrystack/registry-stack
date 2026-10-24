// SPDX-License-Identifier: Apache-2.0

//! Activation of the shared URL hook destination block.
//!
//! [`UrlHookDestinationConfig`] is the simple destination block: a URL, an
//! HMAC-SHA256 key reference, and a delivery budget. Activation turns each
//! configured destination into a [`UrlDestination`] under a fixed outbound
//! policy (the URL's own origin, no private address ranges, no client
//! certificate) and digests the non-secret binding, so a retained delivery
//! row can be refused once its destination changed. The product names the
//! digest's schema version, so two products never share a digest domain.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{SecretResolver, UrlHookDestinationConfig};
use registry_platform_httputil::destination::EventDestinationPolicy;
use registry_platform_yaml::LocalId;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::destination::{
    url_destination_address, UrlDestination, UrlDestinationError, UrlDestinationParts,
};

/// Value-free refusal while activating a URL hook destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UrlHookActivationError {
    /// The logical id is not a local identifier, or the attempt timeout or
    /// attempt count is outside the block's delivery budget.
    #[error("the URL hook destination widens its delivery budget")]
    DeliveryBudgetWidening,
    /// The URL or the policy built from it is refused.
    #[error("the URL hook destination is invalid")]
    InvalidDestination,
    /// The signing key reference does not resolve to usable key material.
    #[error("the URL hook destination signing material is invalid")]
    InvalidSigningMaterial,
}

/// Every configured URL hook destination, activated, with the digest of the
/// whole inventory's non-secret bindings.
#[derive(Clone)]
pub struct ActivatedUrlHookDestinations {
    /// Each activated destination, keyed by its logical id.
    pub bindings: BTreeMap<String, Arc<UrlDestination>>,
    /// The digest over every destination's non-secret binding value.
    pub binding_digest: String,
}

impl fmt::Debug for ActivatedUrlHookDestinations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedUrlHookDestinations")
            .field("destination_count", &self.bindings.len())
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

/// Activate every configured destination. `binding_schema` is the product's
/// schema version for its binding digests; `maximum_payload_bytes` is the
/// largest envelope the product sends.
pub fn activate_url_hook_destinations(
    binding_schema: &str,
    configured: &BTreeMap<String, UrlHookDestinationConfig>,
    secrets: &SecretResolver,
    maximum_payload_bytes: usize,
) -> Result<ActivatedUrlHookDestinations, UrlHookActivationError> {
    let mut bindings = BTreeMap::new();
    let mut digest_values = Vec::with_capacity(configured.len());
    for (logical_id, config) in configured {
        let (destination, digest_value) = activate_url_hook_destination(
            binding_schema,
            logical_id,
            config,
            secrets,
            maximum_payload_bytes,
        )?;
        digest_values.push(digest_value);
        bindings.insert(logical_id.clone(), Arc::new(destination));
    }
    let binding_digest = canonical_digest(&json!({
        "schemaVersion": binding_schema,
        "destinations": digest_values,
    }))?;
    Ok(ActivatedUrlHookDestinations {
        bindings,
        binding_digest,
    })
}

/// Activate one configured destination, returning it with the non-secret
/// value its binding digest and the inventory digest cover.
pub fn activate_url_hook_destination(
    binding_schema: &str,
    logical_id: &str,
    config: &UrlHookDestinationConfig,
    secrets: &SecretResolver,
    maximum_payload_bytes: usize,
) -> Result<(UrlDestination, Value), UrlHookActivationError> {
    if LocalId::new(logical_id).is_err() || !config.within_delivery_budget() {
        return Err(UrlHookActivationError::DeliveryBudgetWidening);
    }
    let address = url_destination_address(config.url.as_str())
        .map_err(|_| UrlHookActivationError::InvalidDestination)?;
    let policy = EventDestinationPolicy::new(logical_id, &address.origin, address.profile, &[])
        .map_err(|_| UrlHookActivationError::InvalidDestination)?;
    let hmac_sha256_key = secrets
        .resolve(config.hmac_sha256_key_ref.as_str())
        .map_err(|_| UrlHookActivationError::InvalidSigningMaterial)?;
    let digest_value = json!({
        "logicalId": logical_id,
        "url": config.url.as_str(),
        "hmacSha256KeyRef": config.hmac_sha256_key_ref.as_str(),
        "attemptTimeoutMilliseconds": config.attempt_timeout_milliseconds,
        "maximumAttempts": config.maximum_attempts,
    });
    let binding_digest = canonical_digest(&json!({
        "schemaVersion": binding_schema,
        "destination": digest_value,
    }))?;
    let destination = UrlDestination::new(UrlDestinationParts {
        binding_digest,
        request_target: address.request_target,
        policy,
        maximum_payload_bytes,
        hmac_sha256_key,
        attempt_timeout: Duration::from_millis(u64::from(config.attempt_timeout_milliseconds)),
        maximum_attempts: config.maximum_attempts,
    })
    .map_err(|error| match error {
        UrlDestinationError::InvalidBinding => UrlHookActivationError::InvalidDestination,
        UrlDestinationError::InvalidSigningMaterial => {
            UrlHookActivationError::InvalidSigningMaterial
        }
    })?;
    Ok((destination, digest_value))
}

fn canonical_digest(value: &Value) -> Result<String, UrlHookActivationError> {
    use std::fmt::Write as _;
    let canonical =
        canonicalize_json(value).map_err(|_| UrlHookActivationError::InvalidDestination)?;
    let hash = Sha256::digest(canonical);
    let mut digest = String::with_capacity(7 + hash.len() * 2);
    digest.push_str("sha256:");
    for byte in hash {
        let _ = write!(digest, "{byte:02x}");
    }
    Ok(digest)
}

#[cfg(test)]
#[path = "url_binding_tests.rs"]
mod tests;
