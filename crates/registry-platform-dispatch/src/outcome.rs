// SPDX-License-Identifier: Apache-2.0

//! What a transport reports about one send, and the value-free errors of the
//! core.

use std::time::Duration;

/// The longest provider reference a transport may report, in bytes.
pub const MAX_PROVIDER_REFERENCE_BYTES: usize = 128;

/// The longest permanent-failure code a transport may report, in bytes.
pub const MAX_FAILURE_CODE_BYTES: usize = 64;

/// The one runtime error the core reports.
///
/// Every refused, stale, absent, or failed operation returns the same
/// value-free error, so no caller learns why from the error alone. Refusals
/// an operator must see are reported through the store's operational event
/// hook, never through the error value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DispatchError {
    #[error("dispatch is unavailable")]
    Unavailable,
}

#[cfg(feature = "postgres")]
impl From<tokio_postgres::Error> for DispatchError {
    fn from(_error: tokio_postgres::Error) -> Self {
        Self::Unavailable
    }
}

/// A refused construction-time value. The variants never carry the refused
/// value, so a configuration error cannot leak it into a log.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    #[error("a dispatch identifier must be a plain lowercase SQL identifier within its bound")]
    Identifier,
    #[error("a dispatch value is outside its bound")]
    OutOfBounds,
    #[error("an attempt-timeout bound must be positive, ordered, and at most sixty seconds")]
    AttemptTimeoutBound,
    #[error("a dispatch SQL fragment must not contain a statement terminator or be empty")]
    SqlFragment,
    #[error("a dispatch state set names a state its transition cannot start from")]
    StateSet,
}

/// The provider's own reference for an accepted send: one to 128 printable
/// ASCII bytes with no space.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProviderReference(String);

impl ProviderReference {
    /// Accept a provider reference within its bound.
    ///
    /// # Errors
    ///
    /// [`ConfigError::OutOfBounds`] when the value is empty, longer than
    /// [`MAX_PROVIDER_REFERENCE_BYTES`], or holds a byte outside `!` to `~`.
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PROVIDER_REFERENCE_BYTES
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(ConfigError::OutOfBounds);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A product-owned permanent-failure code: one to 64 bytes of lowercase
/// ASCII letters, digits, `.`, `_`, or `-`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FailureCode(String);

impl FailureCode {
    /// Accept a failure code within its bound.
    ///
    /// # Errors
    ///
    /// [`ConfigError::OutOfBounds`] when the value is empty, longer than
    /// [`MAX_FAILURE_CODE_BYTES`], or holds a byte outside its alphabet.
    pub fn new(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_FAILURE_CODE_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err(ConfigError::OutOfBounds);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What one send did, as far as the transport can tell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// The receiver accepted the job. A provider that names its copy returns
    /// the reference it assigned.
    Accepted {
        provider_reference: Option<ProviderReference>,
    },
    /// The send did not happen or was refused in a way a later attempt may
    /// overcome. A receiver that asked for a pause returns it; the core
    /// honours it up to the job's maximum backoff and never past its expiry.
    Transient { retry_after: Option<Duration> },
    /// The receiver refused the job in a way no retry can change. The job
    /// stops now, whatever attempts it has left.
    Permanent { code: FailureCode },
    /// The request may have reached the receiver and its fate is unknown.
    /// The job's [`crate::UncertainOutcome`] policy decides whether the core
    /// holds it as unknown or retries it.
    MaybeSent,
}

/// One finished send: the neutral outcome the core acts on, and the
/// product's own detail it hands back to the product's audit and columns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sent<D> {
    pub outcome: SendOutcome,
    pub detail: D,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_reference_is_bounded_printable_ascii() {
        assert!(ProviderReference::new("SM0123abcd").is_ok());
        assert!(ProviderReference::new("a".repeat(MAX_PROVIDER_REFERENCE_BYTES)).is_ok());
        for refused in [
            String::new(),
            "a".repeat(MAX_PROVIDER_REFERENCE_BYTES + 1),
            "with space".to_owned(),
            "line\nbreak".to_owned(),
            "é".to_owned(),
        ] {
            assert_eq!(
                ProviderReference::new(refused),
                Err(ConfigError::OutOfBounds)
            );
        }
    }

    #[test]
    fn a_failure_code_is_a_bounded_lowercase_token() {
        assert_eq!(
            FailureCode::new("recipient.rejected-2_x").map(|code| code.as_str().to_owned()),
            Ok("recipient.rejected-2_x".to_owned())
        );
        assert!(FailureCode::new("a".repeat(MAX_FAILURE_CODE_BYTES)).is_ok());
        for refused in [
            String::new(),
            "a".repeat(MAX_FAILURE_CODE_BYTES + 1),
            "Upper".to_owned(),
            "with space".to_owned(),
            "semi;colon".to_owned(),
        ] {
            assert_eq!(FailureCode::new(refused), Err(ConfigError::OutOfBounds));
        }
    }
}
