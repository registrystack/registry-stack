// SPDX-License-Identifier: Apache-2.0
//! X.509 chain validation and `x5c` handling outside TLS.
//!
//! The crate is pure: callers pass certificate bytes and the verification time, and it reads no
//! files, network, or clock. Trust anchors come only from the caller's configuration.

mod error;
mod input;
mod signer;
mod verify;

pub use error::X509Error;
pub use input::{
    TrustAnchors, X5cChain, MAX_CERT_DER_LEN, MAX_PEM_LEN, MAX_TRUST_ANCHORS, MAX_X5C_CERTS,
};
pub use signer::CertifiedSigner;
pub use verify::{verify_chain, x509_hash, ChainPolicy, LeafKeyType, VerifiedLeaf};
