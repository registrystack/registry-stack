// SPDX-License-Identifier: Apache-2.0
//! Pure verification of holder-presented credentials for Evidence.
//!
//! [`verify_sd_jwt_vc`] checks an SD-JWT VC (with an optional key-binding JWT)
//! that a holder's wallet presented, issued by a third party. It performs no
//! I/O: no network, no filesystem, no clock (the evaluation time is a
//! parameter), and no async runtime. Issuer trust is the configured
//! [`IssuerTrust`]; nothing the presentation carries chooses its own trust
//! anchor or key.
//!
//! Refusals are a closed set of categories ([`PresentationRefusal`]) that never
//! contain presented bytes, claim names or values, keys, or the session nonce.

mod policy;
mod refusal;
mod trust;
mod verify;

pub use policy::{ChannelPolicy, IssuerAlgorithm, SessionContext};
pub use refusal::PresentationRefusal;
pub use trust::{
    IssuerDenyList, IssuerDenyListConfig, IssuerTrust, KeySource, KeySourceConfig,
    LeafKeyTypeConfig, TrustConfigError, TrustEntry, TrustEntryConfig, X5cConfig,
};
pub use verify::{verify_sd_jwt_vc, VerifiedCredential};
