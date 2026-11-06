// SPDX-License-Identifier: Apache-2.0
//! Document signature primitives: certificate chains, detached CMS signed
//! data for PAdES baseline signatures, and RFC 3161 signature timestamps.
//!
//! "Seal" in this module, as in "seal certificate", means a document seal (an
//! electronic seal under ETSI EN 319 142-1). Elsewhere in this crate,
//! `sealed_value::seal` and `field_encryption::seal_field` mean authenticated
//! encryption of a stored value, which is unrelated.
//!
//! The caller owns the document format. For a PDF it computes the byte ranges
//! a signature covers, passes them to [`sign_detached`], and embeds the
//! returned CMS in the signature dictionary. For PAdES B-T it then sends
//! [`timestamp_request`] to its timestamp authority, checks the reply with
//! [`accept_timestamp_response`], and adds the token with
//! [`add_signature_timestamp`].
//!
//! This module checks what the signer itself can know: the configured
//! certificate holds the signing key, the key may sign, the certificate is
//! within its validity, the produced signature verifies, and a timestamp token
//! covers this signature and verifies under a timestamping certificate. It
//! performs no path validation to a trust anchor, no revocation checking and
//! no long-term validation; relying parties and their validators do that.

mod asn1;
mod certificate;
mod signed_data;
mod timestamp;
mod verify;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod tests;

pub use certificate::{CertificateChain, CertificateError, CertificateFingerprint};
pub use signed_data::{add_signature_timestamp, sign_detached, CmsError, DetachedSignature};
pub use timestamp::{
    accept_timestamp_response, random_timestamp_nonce, timestamp_request, SignatureTimestamp,
    TimestampError, MAX_TIMESTAMP_RESPONSE_BYTES,
};
pub use verify::SignerVerificationError;
