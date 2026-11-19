// SPDX-License-Identifier: Apache-2.0

//! Bounded client for Adapter collection and disbursement capabilities.
//!
//! The client requests a collection by bill identity and version, or a
//! disbursement by instruction record identity and version. It validates
//! amount, provider state, and evidence in the Adapter's typed responses.
//! Reads are single exchanges. Disbursement submission sends once and uses a
//! read-only lookup to reconcile an unknown result. For mutations that permit
//! a resend, the bounded policy in [`PaymentClientConfig`] preserves the exact
//! request and the caller's original key.

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
