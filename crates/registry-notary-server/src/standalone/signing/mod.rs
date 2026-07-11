// SPDX-License-Identifier: Apache-2.0
//! Signing-provider implementations used by the standalone server.

pub(super) mod providers;

#[cfg(feature = "pkcs11")]
mod pkcs11;

#[cfg(feature = "pkcs11")]
pub(in crate::standalone) use pkcs11::Pkcs11SigningProvider;
