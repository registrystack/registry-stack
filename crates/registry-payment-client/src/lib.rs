// SPDX-License-Identifier: Apache-2.0

//! Bounded client for Adapter collection and disbursement capabilities.
//!
//! The client sends only the authoritative bill identifier and version a
//! service workflow supplies. Amount, provider state, and receipt evidence
//! are decoded from the Adapter's typed responses and validated before they
//! leave this crate. Reads are single exchanges. Keyed mutations may resend
//! only the exact request under the caller's original key, within the bounded
//! retry policy selected in [`PaymentClientConfig`].

#![deny(unsafe_code)]

mod client;
mod config;
mod error;

pub use client::{PaymentClient, PaymentComplete};
pub use config::PaymentClientConfig;
pub use error::{PaymentClientError, PaymentProtocolFailure};
pub use registry_payment_protocol::{
    CollectionAccepted, CollectionState, CollectionStatus, DisbursementAccepted, DisbursementState,
    DisbursementStatus, Money, PaymentProblem, PaymentProblemCode, ProviderConfirmation,
    ReadCollection, ReadDisbursement, RecordProviderConfirmation, RecordReceipt, RegistryReceipt,
    RequestCollection, RequestDisbursement,
};
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
