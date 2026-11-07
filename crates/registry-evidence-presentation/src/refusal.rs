// SPDX-License-Identifier: Apache-2.0
//! The closed refusal vocabulary.

use thiserror::Error;

/// Why a presentation was refused. Each variant is a category with a fixed
/// message: neither `Display` nor `Debug` carries presented bytes, claim names
/// or values, keys, certificates, or the session nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PresentationRefusal {
    #[error("presentation exceeds a size limit")]
    PresentationTooLarge,
    #[error("presentation is malformed")]
    MalformedPresentation,
    #[error("issuer JWT type is not dc+sd-jwt")]
    IssuerTypeInvalid,
    #[error("issuer JWT algorithm is not allowed")]
    IssuerAlgorithmNotAllowed,
    #[error("issuer JWT header carries a forbidden parameter")]
    ForbiddenHeaderParameter,
    #[error("credential names no issuer")]
    IssuerMissing,
    #[error("credential issuer or issuer certificate is on the deny-list")]
    IssuerDenied,
    #[error("credential issuer is not trusted")]
    IssuerUntrusted,
    #[error("issuer certificate chain is missing or not valid for the configured anchors")]
    CertificateChainInvalid,
    #[error("credential issuer is not bound to the issuer certificate")]
    IssuerNotBoundToCertificate,
    #[error("issuer key identifier is missing or unknown")]
    IssuerKeyIdUnknown,
    #[error("issuer signature is not valid")]
    IssuerSignatureInvalid,
    #[error("credential type is missing")]
    CredentialTypeMissing,
    #[error("credential type is not accepted")]
    CredentialTypeNotAccepted,
    #[error("a claim that may not be selectively disclosed was disclosed")]
    ClaimNotDisclosable,
    #[error("disclosures are not valid")]
    DisclosureInvalid,
    #[error("a time claim is malformed")]
    TimeClaimMalformed,
    #[error("credential has expired")]
    CredentialExpired,
    #[error("credential is not yet valid")]
    CredentialNotYetValid,
    #[error("credential carries no issue time")]
    IssuedAtMissing,
    #[error("credential issue time is in the future")]
    IssuedAtInFuture,
    #[error("holder confirmation key is missing or unsupported")]
    HolderKeyInvalid,
    #[error("key binding is required and absent")]
    KeyBindingRequired,
    #[error("key binding is not valid")]
    KeyBindingInvalid,
}
