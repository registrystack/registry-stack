// SPDX-License-Identifier: Apache-2.0
//! Concrete [`Signer`](super::signer::Signer) implementations.
//!
//! * [`software`] reads a private JWK from an environment variable and
//!   signs in-process. EdDSA is fully wired; ES256 is deferred to a
//!   follow-up (see the impl note).
//!
//! Future remote signers should implement the same
//! [`Signer`](super::signer::Signer) trait and be wired through the
//! provenance state builder. V1 intentionally ships no KMS provider
//! implementation.

pub mod software;
