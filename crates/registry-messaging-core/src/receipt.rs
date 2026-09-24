// SPDX-License-Identifier: Apache-2.0

//! Provider delivery receipts and the ordered report they carry (spec 6.2).
//!
//! A callback tells the runtime what a provider now believes about one
//! message it accepted for delivery. [`advance_report`] is the only rule for
//! deciding whether that belief may overwrite what is stored: a report only
//! ever moves forward through the ordered states below, a duplicate report
//! is a no-op, and a terminal state is never replaced, even by another
//! terminal state. This module makes that decision in the abstract; applying
//! it to a stored message is a runtime concern that lands with the callback
//! route in a later change.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The longest provider reference or receipt code this module accepts.
pub const MAXIMUM_PROVIDER_REFERENCE_BYTES: usize = 256;
pub const MAXIMUM_RECEIPT_CODE_BYTES: usize = 64;

/// A provider's delivery report for one message, ordered per spec 6.2.
/// `Delivered` and `Undelivered` are both terminal and are siblings, not
/// ranked against each other: once either is stored, no later report of any
/// kind changes it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryReport {
    Sent,
    Delivered,
    Undelivered,
}

impl DeliveryReport {
    /// This report's position in the forward-progression order. Two reports
    /// with the same rank do not advance one another; [`Self::is_terminal`]
    /// additionally stops a terminal report from ever being displaced.
    const fn rank(self) -> u8 {
        match self {
            Self::Sent => 1,
            Self::Delivered | Self::Undelivered => 2,
        }
    }

    /// Whether this report is a final word: once stored, it is never
    /// replaced by another report, including another terminal one.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Undelivered)
    }
}

/// The result of offering an incoming report against what is currently
/// stored for a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportAdvance {
    /// The incoming report is new information and should be stored.
    Advance(DeliveryReport),
    /// The incoming report is a duplicate or out of order; storage does not
    /// change.
    NoChange,
}

/// Decide whether `incoming` advances a message currently at `current`.
/// `current` is `None` before any callback has been received.
#[must_use]
pub fn advance_report(current: Option<DeliveryReport>, incoming: DeliveryReport) -> ReportAdvance {
    match current {
        None => ReportAdvance::Advance(incoming),
        Some(current) if current.is_terminal() => ReportAdvance::NoChange,
        Some(current) if incoming.rank() > current.rank() => ReportAdvance::Advance(incoming),
        Some(_) => ReportAdvance::NoChange,
    }
}

/// One callback's delivery receipt: the provider's own reference for the
/// message, the report it now carries, and an optional provider-specific
/// code (an error code on `undelivered`, for example).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub provider_reference: String,
    pub report: DeliveryReport,
    pub code: Option<String>,
}

/// Why a [`Receipt`] is malformed.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReceiptError {
    #[error("providerReference must be 1 to {MAXIMUM_PROVIDER_REFERENCE_BYTES} bytes")]
    InvalidProviderReference,
    #[error("code must be 1 to {MAXIMUM_RECEIPT_CODE_BYTES} bytes when present")]
    InvalidCode,
}

impl Receipt {
    /// Check this receipt's shape. This does not decide whether the receipt
    /// advances a stored message; call [`advance_report`] for that.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.provider_reference.is_empty()
            || self.provider_reference.len() > MAXIMUM_PROVIDER_REFERENCE_BYTES
        {
            return Err(ReceiptError::InvalidProviderReference);
        }
        if let Some(code) = &self.code {
            if code.is_empty() || code.len() > MAXIMUM_RECEIPT_CODE_BYTES {
                return Err(ReceiptError::InvalidCode);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_report_for_a_message_always_advances() {
        assert_eq!(
            advance_report(None, DeliveryReport::Sent),
            ReportAdvance::Advance(DeliveryReport::Sent)
        );
        assert_eq!(
            advance_report(None, DeliveryReport::Delivered),
            ReportAdvance::Advance(DeliveryReport::Delivered)
        );
    }

    #[test]
    fn a_duplicate_report_is_a_no_op() {
        assert_eq!(
            advance_report(Some(DeliveryReport::Sent), DeliveryReport::Sent),
            ReportAdvance::NoChange
        );
        assert_eq!(
            advance_report(Some(DeliveryReport::Delivered), DeliveryReport::Delivered),
            ReportAdvance::NoChange
        );
    }

    #[test]
    fn a_report_never_regresses() {
        assert_eq!(
            advance_report(Some(DeliveryReport::Delivered), DeliveryReport::Sent),
            ReportAdvance::NoChange
        );
        assert_eq!(
            advance_report(Some(DeliveryReport::Undelivered), DeliveryReport::Sent),
            ReportAdvance::NoChange
        );
    }

    #[test]
    fn sent_advances_to_either_terminal_state() {
        assert_eq!(
            advance_report(Some(DeliveryReport::Sent), DeliveryReport::Delivered),
            ReportAdvance::Advance(DeliveryReport::Delivered)
        );
        assert_eq!(
            advance_report(Some(DeliveryReport::Sent), DeliveryReport::Undelivered),
            ReportAdvance::Advance(DeliveryReport::Undelivered)
        );
    }

    /// `Delivered` and `Undelivered` are both terminal: once one is stored,
    /// the other is refused too, not just a repeat of the same state.
    #[test]
    fn a_terminal_state_is_never_displaced_by_the_other_terminal_state() {
        assert_eq!(
            advance_report(Some(DeliveryReport::Delivered), DeliveryReport::Undelivered),
            ReportAdvance::NoChange
        );
        assert_eq!(
            advance_report(Some(DeliveryReport::Undelivered), DeliveryReport::Delivered),
            ReportAdvance::NoChange
        );
    }

    #[test]
    fn a_receipt_is_checked_for_shape() {
        let valid = Receipt {
            provider_reference: "provider-ref-1".to_owned(),
            report: DeliveryReport::Delivered,
            code: None,
        };
        assert_eq!(valid.validate(), Ok(()));

        let empty_reference = Receipt {
            provider_reference: String::new(),
            ..valid.clone()
        };
        assert_eq!(
            empty_reference.validate(),
            Err(ReceiptError::InvalidProviderReference)
        );

        let oversized_reference = Receipt {
            provider_reference: "x".repeat(MAXIMUM_PROVIDER_REFERENCE_BYTES + 1),
            ..valid.clone()
        };
        assert_eq!(
            oversized_reference.validate(),
            Err(ReceiptError::InvalidProviderReference)
        );

        let empty_code = Receipt {
            code: Some(String::new()),
            ..valid.clone()
        };
        assert_eq!(empty_code.validate(), Err(ReceiptError::InvalidCode));

        let oversized_code = Receipt {
            code: Some("x".repeat(MAXIMUM_RECEIPT_CODE_BYTES + 1)),
            ..valid
        };
        assert_eq!(oversized_code.validate(), Err(ReceiptError::InvalidCode));
    }

    #[test]
    fn a_receipt_deserializes_with_camel_case_keys() {
        let receipt: Receipt = serde_json::from_value(serde_json::json!({
            "providerReference": "provider-ref-1",
            "report": "delivered",
            "code": null
        }))
        .unwrap();
        assert_eq!(receipt.report, DeliveryReport::Delivered);
    }
}
