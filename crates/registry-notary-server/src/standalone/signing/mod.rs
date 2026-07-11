// SPDX-License-Identifier: Apache-2.0
//! Signing-provider implementations used by the standalone server.

mod pkcs11;

pub(in crate::standalone) use pkcs11::Pkcs11SigningProvider;
