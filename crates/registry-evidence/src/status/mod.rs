//! Credential status ledger for status-required requirements.
//!
//! This module is mechanism only. It applies the fixed transition table, keys
//! every selector value and holder key thumbprint before anything is written,
//! and decides nothing about eligibility or policy. It never logs or returns a
//! selector value, a record identifier, a raw holder key thumbprint, or an
//! extract metadata value.

mod inheritance;
mod keys;
mod pseudonym;
mod retention;
mod transition;

pub use inheritance::{inherited_status, ObservedStatus, SourceRead};
pub use keys::{
    validate_key_separation, HolderDigestKeyRing, KeyError, KeyRing, KeyRole, KeySeparationError,
    KeyVersion, PseudonymKeyRing, StatusKey, MINIMUM_STATUS_KEY_BYTES,
};
pub use pseudonym::{
    HolderKeyDigest, HolderKeyThumbprint, PseudonymError, StatusPseudonym, StatusSubject,
};
pub use retention::{check_observation_retention, retention_floor, RetentionBelowFloor};
pub use transition::{transition, EntryStatus, Refusal, Transition, TransitionCause};

use std::time::Duration;

/// Default clock-skew allowance between Evidence and its sources.
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(10 * 60);

/// Default deadline across every member of one signing transaction.
pub const DEFAULT_SIGNING_TRANSACTION_DEADLINE: Duration = Duration::from_secs(20);
