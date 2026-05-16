// SPDX-License-Identifier: Apache-2.0
//! Concrete [`Signer`](super::signer::Signer) implementations.
//!
//! * [`software`] reads a private JWK from an environment variable and
//!   signs in-process. EdDSA is fully wired; ES256 is deferred to a
//!   follow-up (see the impl note).
//! * [`kms`] holds the trait-level KMS hooks: a deterministic
//!   [`kms::MockKmsSigner`] used by tests, and a documented TODO for
//!   the AWS KMS backend behind a future `kms-aws` feature.

pub mod kms;
pub mod software;
