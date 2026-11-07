// SPDX-License-Identifier: Apache-2.0
//! The closed error vocabulary. No variant carries certificate bytes, so Display and Debug are
//! safe to log.

/// Why an `x5c` chain, trust-anchor set, or certified signer was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum X509Error {
    #[error("x5c holds no certificates")]
    EmptyChain,
    #[error("x5c holds more certificates than the limit")]
    TooManyCertificates,
    #[error("certificate exceeds the size limit")]
    CertificateTooLarge,
    #[error("x5c entry is not standard base64")]
    BadEncoding,
    #[error("input is not a DER certificate")]
    BadCertificate,
    #[error("input is not a PEM certificate bundle")]
    BadPem,
    #[error("PEM input exceeds the size limit")]
    PemTooLarge,
    #[error("no trust anchors configured")]
    NoTrustAnchors,
    #[error("more trust anchors than the limit")]
    TooManyTrustAnchors,
    #[error("a configured trust anchor cannot be used")]
    UnusableTrustAnchor,
    #[error("verification time is not a valid Unix time")]
    InvalidTime,
    #[error("a certificate in the chain has expired")]
    Expired,
    #[error("a certificate in the chain is not yet valid")]
    NotYetValid,
    #[error("the chain does not lead to a configured trust anchor")]
    UnknownIssuer,
    #[error("the leaf is a CA certificate")]
    CaAsLeaf,
    #[error("the chain exceeds the permitted path length")]
    PathLengthExceeded,
    #[error("the leaf key usage does not allow digitalSignature")]
    KeyUsage,
    #[error("the leaf public key type is not supported")]
    UnsupportedLeafKey,
    #[error("the leaf public key type is not allowed by policy")]
    LeafKeyTypeNotAllowed,
    #[error("the chain was rejected")]
    ChainRejected,
    #[error("the signer public key differs from the certificate leaf key")]
    SignerKeyMismatch,
}
