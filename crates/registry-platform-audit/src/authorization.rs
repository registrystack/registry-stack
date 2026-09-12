// SPDX-License-Identifier: Apache-2.0

//! Shared, privacy-safe authorization audit event fields.

use std::fmt;

use serde::Serialize;
use thiserror::Error;

const MAX_CODE_BYTES: usize = 128;

/// The authorization decision represented by an audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationOutcome {
    Allowed,
    Denied,
}

/// Common authorization audit fields filled by each product.
///
/// Identity-bearing values must be pseudonyms produced with the product's
/// existing [`crate::AuditKeyHasher`] profile. Evidence's key-versioned
/// pseudonyms are accepted as well, so consumers do not create a second key
/// system to use this shape.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationAuditEvent {
    actor_kind: String,
    principal_pseudonym: String,
    client_pseudonym: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_pseudonym: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    operation: String,
    outcome: AuthorizationOutcome,
    reason: String,
}

impl AuthorizationAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        actor_kind: impl Into<String>,
        principal_pseudonym: impl Into<String>,
        client_pseudonym: impl Into<String>,
        grant_pseudonym: Option<String>,
        purpose: impl Into<String>,
        operation: impl Into<String>,
        outcome: AuthorizationOutcome,
        reason: impl Into<String>,
    ) -> Result<Self, AuthorizationAuditError> {
        let event = Self {
            actor_kind: actor_kind.into(),
            principal_pseudonym: principal_pseudonym.into(),
            client_pseudonym: client_pseudonym.into(),
            grant_pseudonym,
            purpose: Some(purpose.into()),
            operation: operation.into(),
            outcome,
            reason: reason.into(),
        };
        event.validate()?;
        Ok(event)
    }

    /// Build a denial whose product privacy contract withholds the requested
    /// purpose because no entitlement was resolved.
    #[allow(clippy::too_many_arguments)]
    pub fn denied_without_purpose(
        actor_kind: impl Into<String>,
        principal_pseudonym: impl Into<String>,
        client_pseudonym: impl Into<String>,
        grant_pseudonym: Option<String>,
        operation: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, AuthorizationAuditError> {
        let event = Self {
            actor_kind: actor_kind.into(),
            principal_pseudonym: principal_pseudonym.into(),
            client_pseudonym: client_pseudonym.into(),
            grant_pseudonym,
            purpose: None,
            operation: operation.into(),
            outcome: AuthorizationOutcome::Denied,
            reason: reason.into(),
        };
        event.validate()?;
        Ok(event)
    }

    #[must_use]
    pub fn actor_kind(&self) -> &str {
        &self.actor_kind
    }

    #[must_use]
    pub fn principal_pseudonym(&self) -> &str {
        &self.principal_pseudonym
    }

    #[must_use]
    pub fn client_pseudonym(&self) -> &str {
        &self.client_pseudonym
    }

    #[must_use]
    pub fn grant_pseudonym(&self) -> Option<&str> {
        self.grant_pseudonym.as_deref()
    }

    #[must_use]
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    #[must_use]
    pub const fn outcome(&self) -> AuthorizationOutcome {
        self.outcome
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn validate(&self) -> Result<(), AuthorizationAuditError> {
        if !matches!(self.actor_kind.as_str(), "human" | "agent" | "service") {
            return Err(AuthorizationAuditError::InvalidActorKind);
        }
        if !valid_pseudonym(&self.principal_pseudonym)
            || !valid_pseudonym(&self.client_pseudonym)
            || self
                .grant_pseudonym
                .as_deref()
                .is_some_and(|value| !valid_pseudonym(value))
        {
            return Err(AuthorizationAuditError::InvalidPseudonym);
        }
        if self
            .purpose
            .as_deref()
            .is_some_and(|value| !valid_code(value))
            || !valid_operation(&self.operation)
            || !valid_code(&self.reason)
        {
            return Err(AuthorizationAuditError::InvalidCode);
        }
        Ok(())
    }
}

impl fmt::Debug for AuthorizationAuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationAuditEvent")
            .field("actor_kind", &self.actor_kind)
            .field("principal_pseudonym", &"<redacted>")
            .field("client_pseudonym", &"<redacted>")
            .field(
                "grant_pseudonym",
                &self.grant_pseudonym.as_ref().map(|_| "<redacted>"),
            )
            .field("purpose", &"<redacted>")
            .field("operation", &self.operation)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthorizationAuditError {
    #[error("authorization audit actor kind is invalid")]
    InvalidActorKind,
    #[error("authorization audit identity field is not pseudonymized")]
    InvalidPseudonym,
    #[error("authorization audit code is invalid")]
    InvalidCode,
}

fn valid_code(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= MAX_CODE_BYTES
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn valid_operation(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9'))
        && value.len() <= MAX_CODE_BYTES
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_pseudonym(value: &str) -> bool {
    let Some((prefix, digest)) = value.rsplit_once(':') else {
        return false;
    };
    let accepted_prefix = matches!(prefix, "hmac-sha256" | "sha256")
        || prefix
            .strip_prefix("hmac-sha256:v")
            .is_some_and(valid_key_version);
    accepted_prefix
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_key_version(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    #[test]
    fn event_accepts_platform_and_evidence_pseudonyms() {
        let event = AuthorizationAuditEvent::new(
            "agent",
            format!("hmac-sha256:{}", digest('a')),
            format!("hmac-sha256:v2:{}", digest('b')),
            Some(format!("hmac-sha256:v2:{}", digest('c'))),
            "benefit-review",
            "get",
            AuthorizationOutcome::Allowed,
            "authorization.allowed",
        )
        .expect("valid event");
        assert_eq!(event.actor_kind(), "agent");
        assert_eq!(event.outcome(), AuthorizationOutcome::Allowed);
    }

    #[test]
    fn evidence_operation_identifier_is_preserved() {
        let operation = "urn:ulid:01JBY5K5W7XQTB5JX1Q4D0DM6R";
        let event = AuthorizationAuditEvent::new(
            "service",
            format!("hmac-sha256:v2:{}", digest('a')),
            format!("hmac-sha256:v2:{}", digest('b')),
            None,
            "benefit-review",
            operation,
            AuthorizationOutcome::Allowed,
            "authorization.allowed",
        )
        .expect("Evidence operation identifier is a bounded audit operation");

        assert_eq!(event.operation(), operation);
    }

    #[test]
    fn raw_identity_values_are_rejected() {
        let error = AuthorizationAuditEvent::new(
            "human",
            "raw-principal-canary",
            format!("sha256:{}", digest('b')),
            None,
            "review",
            "get",
            AuthorizationOutcome::Denied,
            "authorization.client",
        )
        .expect_err("raw principal is not accepted");
        assert_eq!(error, AuthorizationAuditError::InvalidPseudonym);
    }

    #[test]
    fn serialized_shape_has_common_fields_and_omits_absent_grant() {
        let event = AuthorizationAuditEvent::new(
            "service",
            format!("sha256:{}", digest('a')),
            format!("sha256:{}", digest('b')),
            None,
            "registry-operations",
            "list",
            AuthorizationOutcome::Denied,
            "authorization.profile",
        )
        .expect("valid event");
        assert_eq!(
            serde_json::to_value(event).expect("serializes"),
            json!({
                "actorKind":"service",
                "principalPseudonym":format!("sha256:{}", digest('a')),
                "clientPseudonym":format!("sha256:{}", digest('b')),
                "purpose":"registry-operations",
                "operation":"list",
                "outcome":"denied",
                "reason":"authorization.profile"
            })
        );
    }

    #[test]
    fn denial_can_withhold_unresolved_purpose() {
        let event = AuthorizationAuditEvent::denied_without_purpose(
            "agent",
            format!("sha256:{}", digest('a')),
            format!("sha256:{}", digest('b')),
            None,
            "evaluate",
            "authorization.profile",
        )
        .expect("valid privacy-minimal denial");
        let value = serde_json::to_value(event).expect("serializes");
        assert!(value.get("purpose").is_none());
    }

    #[test]
    fn debug_redacts_pseudonyms_and_purpose() {
        let event = AuthorizationAuditEvent::new(
            "agent",
            format!("hmac-sha256:{}", digest('a')),
            format!("hmac-sha256:{}", digest('b')),
            Some(format!("hmac-sha256:{}", digest('c'))),
            "sensitive-purpose-canary",
            "patch",
            AuthorizationOutcome::Allowed,
            "authorization.allowed",
        )
        .expect("valid event");
        let rendered = format!("{event:?}");
        for canary in [
            digest('a'),
            digest('b'),
            digest('c'),
            "sensitive-purpose-canary".to_owned(),
        ] {
            assert!(!rendered.contains(&canary));
        }
    }
}
