// SPDX-License-Identifier: Apache-2.0
//! Relay-facing SD-JWT VC helpers.
//!
//! Registry Relay delegates the shared SD-JWT issuance, holder-proof,
//! digest-ordering, and JWK logic to `registry-platform` so verifier
//! behavior stays consistent across platform consumers.

pub use registry_platform_crypto::{PrivateJwk, PublicJwk};
pub use registry_platform_sdjwt::{
    sort_sd_digests, validate_holder_proof, Disclosure, HolderConfirmation, HolderProofBindings,
    HolderProofClaims, HolderProofPolicy, SdJwtError, SdJwtIssuanceInput, SdJwtIssuer, SignedSdJwt,
};
