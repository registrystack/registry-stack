// SPDX-License-Identifier: Apache-2.0
//! Bounded authenticated values for product-owned durable state.
//!
//! Callers own key custody, versions and the contextual identity of each value.
//! This profile reuses the field-encryption AES envelope mechanism while keeping
//! BReg's existing derivation, AAD, bounds and wire bytes unchanged.

use crate::field_encryption::{self as field, FieldCryptoError};
use zeroize::Zeroizing;

/// Maximum one protected product value may contain. Products may impose less.
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Exact identity authenticated with a value. All members are wire contract.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub domain: &'a str,
    pub scope: &'a [&'a str],
    pub key_version: u32,
}

fn material(
    key: &[u8; 32],
    context: &Context<'_>,
) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), FieldCryptoError> {
    if context.domain.is_empty()
        || context.domain.len() > 256
        || context.scope.len() > 16
        || context.scope.iter().any(|part| part.len() > 1024)
        || context.key_version == 0
    {
        return Err(FieldCryptoError::MalformedEnvelope);
    }
    let mut parts = Vec::with_capacity(context.scope.len() + 1);
    parts.push(context.domain);
    parts.extend_from_slice(context.scope);
    let info = field::domain_prefixed_info(b"registry-platform/sealed-value-key/v1", &parts);
    let mut derived = Zeroizing::new([0u8; 32]);
    field::hkdf_expand_sha256(key, &info, derived.as_mut())?;
    let mut aad = field::domain_prefixed_info(b"registry-platform/sealed-value-aad/v1", &parts);
    aad.extend_from_slice(&context.key_version.to_be_bytes());
    Ok((derived, aad))
}

/// Seal under a fresh random nonce, with a domain-separated derived key.
pub fn seal(
    key: &[u8; 32],
    context: &Context<'_>,
    plaintext: &[u8],
) -> Result<Vec<u8>, FieldCryptoError> {
    let (derived, aad) = material(key, context)?;
    field::seal_with_aad(
        &derived,
        context.key_version,
        &aad,
        plaintext,
        MAX_PLAINTEXT_BYTES,
    )
}

/// Authenticate before returning zeroized-on-drop plaintext.
pub fn open(
    key: &[u8; 32],
    context: &Context<'_>,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FieldCryptoError> {
    let (derived, aad) = material(key, context)?;
    field::open_with_aad(
        &derived,
        context.key_version,
        &aad,
        envelope,
        MAX_PLAINTEXT_BYTES,
    )
}

/// Untrusted version hint used only to choose a key; `open` authenticates it.
pub fn key_version(envelope: &[u8]) -> Result<u32, FieldCryptoError> {
    field::key_version_with_bound(envelope, MAX_PLAINTEXT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_version_key_and_bytes_are_authenticated() {
        let key = [0x42; 32];
        let context = Context {
            domain: "coordinator/value/v1",
            scope: &["database", "run", "input", ""],
            key_version: 7,
        };
        let sealed = seal(&key, &context, b"protected-person").unwrap();
        assert_eq!(
            &**open(&key, &context, &sealed).unwrap(),
            b"protected-person"
        );
        assert_ne!(sealed, seal(&key, &context, b"protected-person").unwrap());
        assert!(open(&[0x43; 32], &context, &sealed).is_err());
        for changed in [
            Context {
                domain: "other-product/value/v1",
                ..context
            },
            Context {
                scope: &["database", "other-run", "input", ""],
                ..context
            },
            Context {
                scope: &["database", "run", "output", ""],
                ..context
            },
            Context {
                key_version: 8,
                ..context
            },
        ] {
            assert!(open(&key, &changed, &sealed).is_err());
        }
        for offset in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[offset] ^= 1;
            assert!(open(&key, &context, &changed).is_err());
        }
    }

    #[test]
    fn ambiguous_part_boundaries_and_invalid_context_are_refused() {
        let a = Context {
            domain: "test/v1",
            scope: &["ab", "c"],
            key_version: 1,
        };
        let b = Context {
            scope: &["a", "bc"],
            ..a
        };
        let sealed = seal(&[1; 32], &a, b"value").unwrap();
        assert!(open(&[1; 32], &b, &sealed).is_err());
        assert!(seal(
            &[1; 32],
            &Context {
                key_version: 0,
                ..a
            },
            b"value"
        )
        .is_err());
        assert!(open(&[1; 32], &a, &[]).is_err());
    }
}
