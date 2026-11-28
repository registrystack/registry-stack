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
use registry_platform_config::{
    SecretError, SecretReference, SecretResolver, UrlHookDestinationConfig,
};
use registry_platform_crypto::delivery_signature::{
    distinct_delivery_keys, DeliveryKey, DeliveryKeyError, DeliveryKeys,
};
use registry_platform_httputil::destination::EventDestinationPolicy;
use registry_platform_yaml::LocalId;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::destination::{url_destination_address, UrlDestination, UrlDestinationParts};

const CURRENT_KEY_MEMBER: &str = "hmacSha256KeyRef";
const PREVIOUS_KEY_MEMBER: &str = "previousHmacSha256KeyRef";

/// Refusal while activating a URL hook destination.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum UrlHookActivationError {
    /// The logical id is not a local identifier, or the attempt timeout or
    /// attempt count is outside the block's delivery budget.
    #[error("the URL hook destination widens its delivery budget")]
    DeliveryBudgetWidening,
    /// The URL or the policy built from it is refused.
    #[error("the URL hook destination is invalid")]
    InvalidDestination,
    /// The key reference could not be resolved.
    #[error("Destination {destination} could not resolve {member}: {reason}. {}", reason.suggested_action())]
    SigningKeyUnavailable {
        destination: String,
        member: &'static str,
        reason: SecretError,
    },
    /// The resolved key bytes violate the signing key policy.
    #[error("{}", invalid_signing_key_message(.destination, .member, *.length, *.trailing_newline, .reason))]
    InvalidSigningKey {
        destination: String,
        member: &'static str,
        length: usize,
        trailing_newline: bool,
        reason: DeliveryKeyError,
    },
    /// Two destination members resolve to the same key bytes.
    #[error(
        "{first} and {second} resolve to the same key bytes. Give {second} its own key by writing \
         32 new random bytes to another secret and referencing it there."
    )]
    RepeatedSigningKey { first: String, second: String },
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
    let labeled_keys = bindings
        .iter()
        .flat_map(|(logical_id, destination)| {
            let keys = destination.keys();
            std::iter::once((format!("{logical_id}.{CURRENT_KEY_MEMBER}"), keys.current())).chain(
                keys.previous()
                    .map(|key| (format!("{logical_id}.{PREVIOUS_KEY_MEMBER}"), key)),
            )
        })
        .collect::<Vec<_>>();
    distinct_delivery_keys(
        labeled_keys
            .iter()
            .map(|(label, key)| (label.as_str(), *key)),
    )
    .map_err(|error| UrlHookActivationError::RepeatedSigningKey {
        first: error.first().to_owned(),
        second: error.second().to_owned(),
    })?;
    let binding_digest = inventory_digest(binding_schema, digest_values)?;
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
    let (current, _, _) = resolve_delivery_key(
        secrets,
        logical_id,
        CURRENT_KEY_MEMBER,
        &config.hmac_sha256_key_ref,
    )?;
    let keys = if let Some(reference) = &config.previous_hmac_sha256_key_ref {
        let (previous, length, trailing_newline) =
            resolve_delivery_key(secrets, logical_id, PREVIOUS_KEY_MEMBER, reference)?;
        DeliveryKeys::new(current, Some(previous)).map_err(|reason| {
            UrlHookActivationError::InvalidSigningKey {
                destination: logical_id.to_owned(),
                member: PREVIOUS_KEY_MEMBER,
                length,
                trailing_newline,
                reason,
            }
        })?
    } else {
        DeliveryKeys::new(current, None).expect("one validated key")
    };
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
        keys,
        attempt_timeout: Duration::from_millis(u64::from(config.attempt_timeout_milliseconds)),
        maximum_attempts: config.maximum_attempts,
    })
    .map_err(|_| UrlHookActivationError::InvalidDestination)?;
    Ok((destination, digest_value))
}

fn resolve_delivery_key(
    secrets: &SecretResolver,
    logical_id: &str,
    member: &'static str,
    reference: &SecretReference,
) -> Result<(DeliveryKey, usize, bool), UrlHookActivationError> {
    let secret = secrets
        .resolve_binary_reference(reference)
        .map_err(|reason| UrlHookActivationError::SigningKeyUnavailable {
            destination: logical_id.to_owned(),
            member,
            reason,
        })?;
    let bytes = secret.expose_secret();
    let length = bytes.len();
    let trailing_newline = bytes.ends_with(b"\n");
    let key =
        DeliveryKey::new(bytes).map_err(|reason| UrlHookActivationError::InvalidSigningKey {
            destination: logical_id.to_owned(),
            member,
            length,
            trailing_newline,
            reason,
        })?;
    Ok((key, length, trailing_newline))
}

fn invalid_signing_key_message(
    destination: &str,
    member: &str,
    length: usize,
    trailing_newline: bool,
    reason: &DeliveryKeyError,
) -> String {
    let action = match reason {
        DeliveryKeyError::TooShort { .. } | DeliveryKeyError::TooLong { .. } => {
            "Supply 32 to 64 exact key bytes."
        }
        DeliveryKeyError::SecretText => "Supply the exact key bytes without the whsec_ encoding.",
        DeliveryKeyError::PreviousEqualsCurrent => {
            let previous = format!("{destination}.{PREVIOUS_KEY_MEMBER}");
            let current = format!("{destination}.{CURRENT_KEY_MEMBER}");
            return format!(
                "{previous} holds the same bytes as {current}. To rotate, write 32 new random \
                 bytes to the secret {current} references and keep the old bytes behind \
                 {previous}."
            );
        }
    };
    format!(
        "Destination {destination} member {member} has {length} bytes (trailing newline: \
         {trailing_newline}). {action}"
    )
}

fn inventory_digest(
    binding_schema: &str,
    destinations: Vec<Value>,
) -> Result<String, UrlHookActivationError> {
    canonical_digest(&json!({
        "schemaVersion": binding_schema,
        "destinations": destinations,
    }))
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
