// SPDX-License-Identifier: Apache-2.0

//! Activation of the shared URL hook destination block.
//!
//! [`UrlHookDestinationConfig`] is the simple destination block: a URL, how
//! it is reached, an HMAC-SHA256 key reference, and a delivery budget.
//! Activation turns each configured destination into a [`UrlDestination`]
//! under a fixed outbound policy (the URL's own origin, the declared
//! transport and private ranges, no client certificate) and digests the
//! non-secret binding, so a retained delivery row can be refused once its
//! destination changed. The product names the
//! digest's schema version, so two products never share a digest domain.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{
    RuntimeFileCheck, SecretError, SecretReference, SecretResolver, UrlHookDestinationConfig,
};
use registry_platform_crypto::delivery_signature::{
    distinct_delivery_keys, DeliveryKey, DeliveryKeyError, DeliveryKeys,
};
use registry_platform_httputil::destination::{DestinationPolicyError, EventDestinationPolicy};
use registry_platform_httputil::select::{DestinationSelectionError, TransportClass};
use registry_platform_yaml::{escape_pointer_segment, Diagnostic, LocalId};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::destination::{
    url_destination_address_selected, UrlDestination, UrlDestinationError, UrlDestinationParts,
};

const CURRENT_KEY_MEMBER: &str = "hmacSha256KeyRef";
const PREVIOUS_KEY_MEMBER: &str = "previousHmacSha256KeyRef";

/// Refusal while activating a URL hook destination.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum UrlHookActivationError {
    /// The logical id is not a local identifier, or the attempt timeout or
    /// attempt count is outside the block's delivery budget.
    #[error("the URL hook destination widens its delivery budget")]
    DeliveryBudgetWidening,
    /// A destination the shared check admits failed to build. The check
    /// and activation refuse the same URLs, so this names an internal
    /// inconsistency rather than a configuration to correct.
    #[error("the URL hook destination is invalid")]
    InvalidDestination,
    /// The URL, the transport or a private range is refused, exactly as
    /// [`check_url_hook_destination`] refuses it: `code` is the check's code
    /// and `member` is the JSON pointer of the refused member below the
    /// destination, such as `url` or `allowedPrivateCidrs/0`. No message
    /// repeats a configured value.
    #[error("{code}: destination {destination} member {member}: {message}. {suggested_action}")]
    DestinationRefused {
        destination: String,
        code: String,
        member: String,
        message: String,
        suggested_action: String,
    },
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

impl UrlHookActivationError {
    /// The check's stable code for a [`Self::DestinationRefused`]
    /// destination, or `None` for every other refusal.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::DestinationRefused { code, .. } => Some(code),
            Self::DeliveryBudgetWidening
            | Self::InvalidDestination
            | Self::SigningKeyUnavailable { .. }
            | Self::InvalidSigningKey { .. }
            | Self::RepeatedSigningKey { .. } => None,
        }
    }

    /// The JSON pointer of the refused member of a
    /// [`Self::DestinationRefused`] destination, under `block`, the pointer
    /// of the map that holds the destinations by id (such as
    /// `/destinations/hooks`). The id is escaped as a pointer segment, so
    /// this is the pointer [`check_url_hook_destination`] reports when it is
    /// given `{block}/{escaped id}`.
    #[must_use]
    pub fn pointer_under(&self, block: &str) -> Option<String> {
        match self {
            Self::DestinationRefused {
                destination,
                member,
                ..
            } => Some(format!(
                "{block}/{}/{member}",
                escape_pointer_segment(destination)
            )),
            _ => None,
        }
    }
}

/// Every refusal activation would make from the destination's URL,
/// transport and private ranges, as diagnostics under `pointer`, the
/// pointer of the destination block (`/hooks/destinations/events`).
///
/// Each refused range is reported at its entry, as
/// [`PrivateRanges::check`](registry_platform_config::PrivateRanges::check)
/// reports it. Once the ranges are valid, a selector refusal is reported
/// with its code at `{pointer}/transport` when the declared transport
/// disagrees with the URL or lacks ranges, and at `{pointer}/url` otherwise.
/// A URL with a query or a fragment, and a URL the selector admits but the
/// fixed destination policy refuses (an https URL naming a name under
/// `localhost` or the absolute name `localhost.`, or port zero), are reported
/// at `{pointer}/url` as `config.invalid-value`. An https URL to a loopback
/// literal or the exact name `localhost` is admitted, pinned to loopback
/// addresses as a loopback http URL is. No message repeats a configured value.
#[must_use]
pub fn check_url_hook_destination(
    config: &UrlHookDestinationConfig,
    pointer: &str,
) -> Vec<Diagnostic> {
    let mut found = config
        .allowed_private_cidrs
        .check(&format!("{pointer}/{RANGES_MEMBER}"));
    if let Some(refusal) = destination_refusal(config, pointer) {
        found.push(Diagnostic::error(
            refusal.code,
            refusal.member,
            refusal.message,
            refusal.suggested_action,
        ));
    }
    found
}

/// [`check_url_hook_destination`] for an offline check of `file`, whose
/// document kind is `artifact`. Each diagnostic is positioned at its member.
/// The selector is not asked when the URL, the transport, or a range holds
/// an expression the check did not fill, since the stand-in decides nothing.
#[must_use]
pub fn check_url_hook_destination_file<T>(
    config: &UrlHookDestinationConfig,
    pointer: &str,
    file: &RuntimeFileCheck<T>,
    artifact: &str,
) -> Vec<Diagnostic> {
    let ranges = format!("{pointer}/{RANGES_MEMBER}");
    let mut found = config
        .allowed_private_cidrs
        .check_file(&ranges, file, artifact);
    let deferred = file.defers(&format!("{pointer}/url"))
        || file.defers(&format!("{pointer}/transport"))
        || file.defers_within(&ranges);
    if !deferred {
        if let Some(refusal) = destination_refusal(config, pointer) {
            found.push(file.error_at(
                artifact,
                refusal.code,
                &refusal.member,
                refusal.message,
                refusal.suggested_action,
            ));
        }
    }
    found
}

const RANGES_MEMBER: &str = "allowedPrivateCidrs";

/// What activation would refuse in a destination's URL and transport.
struct DestinationRefusal {
    code: &'static str,
    member: String,
    message: String,
    suggested_action: &'static str,
}

/// The refusal activation would make from the URL and the transport, once
/// every range is valid: the selector's, then the fixed destination
/// policy's. A refused range is the range check's to report.
fn destination_refusal(
    config: &UrlHookDestinationConfig,
    pointer: &str,
) -> Option<DestinationRefusal> {
    let ranges = config.allowed_private_cidrs.ranges().ok()?;
    match url_destination_address_selected(config.url.as_str(), declared_transport(config), &ranges)
    {
        Ok(address) => EventDestinationPolicy::from_selected(CHECK_ORIGIN_ID, &address.selected)
            .err()
            .map(|error| policy_refusal(&error, pointer)),
        Err(UrlDestinationError::Refused(error)) => {
            let member = match error {
                DestinationSelectionError::TransportSchemeMismatch
                | DestinationSelectionError::TransportHostMismatch
                | DestinationSelectionError::PrivateNetworkRequiresRanges => "transport",
                _ => "url",
            };
            Some(DestinationRefusal {
                code: error.code(),
                member: format!("{pointer}/{member}"),
                message: error.to_string(),
                suggested_action: error.fix(),
            })
        }
        Err(UrlDestinationError::InvalidBinding) => Some(DestinationRefusal {
            code: "config.invalid-value",
            member: format!("{pointer}/url"),
            message: "the hook URL carries a query or a fragment".to_owned(),
            suggested_action: "Remove the query and the fragment from the hook URL.",
        }),
    }
}

/// The origin id the check builds its policy under. Activation uses the
/// destination's logical id, which the product checks on its own, so the
/// check names a valid stand-in.
const CHECK_ORIGIN_ID: &str = "destination";

/// What the fixed destination policy refuses in a URL the selector admits,
/// reported at `{pointer}/url` as activation would refuse it. The message is
/// fixed, so it repeats no configured value.
fn policy_refusal(error: &DestinationPolicyError, pointer: &str) -> DestinationRefusal {
    let (message, suggested_action) = match error {
        DestinationPolicyError::LocalhostNamespaceDenied => (
            "an https hook URL cannot name a local-only host name",
            "Reach a local receiver at the exact name localhost or a loopback address, or name a receiver outside the local namespace.",
        ),
        DestinationPolicyError::OriginPortZero => (
            "the hook URL's port is zero",
            "Give the hook URL a port other than 0.",
        ),
        _ => (
            "the hook URL is not a valid destination",
            "Correct the hook URL.",
        ),
    };
    DestinationRefusal {
        code: "config.invalid-value",
        member: format!("{pointer}/url"),
        message: message.to_owned(),
        suggested_action,
    }
}

fn declared_transport(config: &UrlHookDestinationConfig) -> Option<TransportClass> {
    config
        .transport
        .as_ref()
        .map(|transport| TransportClass::from(*transport.get()))
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
    // Refuse with the check's own first diagnostic, so activation names the
    // code and member `check_url_hook_destination` reports for this input.
    if let Some(refused) = check_url_hook_destination(config, "").into_iter().next() {
        return Err(UrlHookActivationError::DestinationRefused {
            destination: logical_id.to_owned(),
            code: refused.code,
            member: refused
                .path
                .strip_prefix('/')
                .unwrap_or(&refused.path)
                .to_owned(),
            message: refused.message,
            suggested_action: refused.suggested_action,
        });
    }
    let ranges = config
        .allowed_private_cidrs
        .ranges()
        .map_err(|_| UrlHookActivationError::InvalidDestination)?;
    let address =
        url_destination_address_selected(config.url.as_str(), declared_transport(config), &ranges)
            .map_err(|_| UrlHookActivationError::InvalidDestination)?;
    let policy = EventDestinationPolicy::from_selected(logical_id, &address.selected)
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
    let mut digest_value = json!({
        "logicalId": logical_id,
        "url": config.url.as_str(),
        "hmacSha256KeyRef": config.hmac_sha256_key_ref.as_str(),
        "attemptTimeoutMilliseconds": config.attempt_timeout_milliseconds,
        "maximumAttempts": config.maximum_attempts,
    });
    // A transport the URL implies and an empty range list leave the digest
    // of a destination that declares neither as it was.
    if address.selected.is_private_plaintext() {
        digest_value["transport"] = json!(config.transport);
    }
    if !ranges.is_empty() {
        digest_value["allowedPrivateCidrs"] =
            json!(ranges.iter().map(ToString::to_string).collect::<Vec<_>>());
    }
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
