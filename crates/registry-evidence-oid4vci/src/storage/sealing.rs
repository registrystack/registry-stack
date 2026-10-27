//! How a prepared request is held outside process memory.
//!
//! A prepared request carries the selector values an adopter sent to create
//! the offer. Anything that writes it somewhere other than this process's
//! memory writes it sealed: `XChaCha20Poly1305` under a versioned key, a fresh
//! random nonce per seal, and associated data that binds the ciphertext to the
//! entry it was made for. A ciphertext copied onto another entry, another
//! purpose, another key version or another catalog generation fails to open.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::{CatalogGeneration, KeyRing};
use crate::store::PreparedRequest;

/// The length of the random nonce stored beside every ciphertext.
pub(crate) const NONCE_LENGTH: usize = 24;

/// Labels the plaintext layout, so a later layout can be told apart.
const LAYOUT: u8 = 1;
const AAD_DOMAIN: &str = "oid4vci.prepared-request";

/// Which entry a sealed request belongs to.
#[derive(Clone, Copy)]
pub(crate) enum Purpose {
    Offer,
    AccessToken,
}

impl Purpose {
    const fn label(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::AccessToken => "access-token",
        }
    }
}

/// What a sealed request is bound to. Every field is stored beside the
/// ciphertext; none of it is secret.
pub(crate) struct Binding<'a> {
    pub(crate) purpose: Purpose,
    pub(crate) tag: &'a str,
    pub(crate) tag_key_version: u32,
    pub(crate) generation: &'a CatalogGeneration,
}

/// A prepared request as it is stored.
pub(crate) struct Sealed {
    pub(crate) key_version: u32,
    pub(crate) nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SealError {
    /// The key the request was sealed under is no longer accepted.
    RetiredKey,
    /// The seal could not be made or did not open. Either the randomness or
    /// the cipher failed, or the stored value is not what was sealed.
    Refused,
}

fn associated_data(binding: &Binding<'_>, sealing_key_version: u32) -> Vec<u8> {
    format!(
        "{AAD_DOMAIN}\u{0}{}\u{0}{}\u{0}{}\u{0}{sealing_key_version}\u{0}{}",
        binding.purpose.label(),
        binding.tag,
        binding.tag_key_version,
        binding.generation.as_str(),
    )
    .into_bytes()
}

/// Seal `prepared` under the current key of `keys`.
pub(crate) fn seal(
    keys: &KeyRing,
    binding: &Binding<'_>,
    prepared: &PreparedRequest,
) -> Result<Sealed, SealError> {
    let key = keys.current();
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| SealError::Refused)?;
    let mut nonce = [0u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| SealError::Refused)?;
    let plaintext = encode(prepared);
    let aad = associated_data(binding, key.version());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| SealError::Refused)?;
    Ok(Sealed {
        key_version: key.version(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Open a sealed request made for `binding`.
pub(crate) fn open(
    keys: &KeyRing,
    binding: &Binding<'_>,
    sealed: &Sealed,
) -> Result<PreparedRequest, SealError> {
    let key = keys
        .accepted_version(sealed.key_version)
        .ok_or(SealError::RetiredKey)?;
    let nonce: [u8; NONCE_LENGTH] = sealed
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Refused)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| SealError::Refused)?;
    let aad = associated_data(binding, key.version());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: sealed.ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Refused)?,
    );
    decode(&plaintext).ok_or(SealError::Refused)
}

/// The plaintext layout: a layout byte, three length-prefixed UTF-8 fields,
/// then the batch ceiling. Lengths and the ceiling are big-endian.
fn encode(prepared: &PreparedRequest) -> Zeroizing<Vec<u8>> {
    let fields = [prepared.exchange_id(), prepared.kind(), prepared.body()];
    let length = 1 + fields.iter().map(|field| 4 + field.len()).sum::<usize>() + 8;
    let mut encoded = Zeroizing::new(Vec::with_capacity(length));
    encoded.push(LAYOUT);
    for field in fields {
        // A field past u32::MAX bytes cannot reach here: the service bounds
        // every request body far below it. Saturating keeps the layout
        // well-formed and makes such a field fail to decode rather than wrap.
        let field_length = u32::try_from(field.len()).unwrap_or(u32::MAX);
        encoded.extend_from_slice(&field_length.to_be_bytes());
        encoded.extend_from_slice(field.as_bytes());
    }
    encoded.extend_from_slice(&(prepared.maximum_holder_keys() as u64).to_be_bytes());
    encoded
}

fn decode(encoded: &[u8]) -> Option<PreparedRequest> {
    let (&layout, mut rest) = encoded.split_first()?;
    if layout != LAYOUT {
        return None;
    }
    let mut fields: [&str; 3] = [""; 3];
    for field in &mut fields {
        let (length, tail) = rest.split_first_chunk::<4>()?;
        let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
        if tail.len() < length {
            return None;
        }
        let (value, tail) = tail.split_at(length);
        *field = std::str::from_utf8(value).ok()?;
        rest = tail;
    }
    let ceiling: [u8; 8] = rest.try_into().ok()?;
    let ceiling = usize::try_from(u64::from_be_bytes(ceiling)).ok()?;
    let [exchange_id, kind, body] = fields;
    Some(PreparedRequest::new(exchange_id, kind, body, ceiling))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::VersionedKey;

    const BODY: &str = r#"{"selector":"held-by-the-adopter"}"#;

    fn ring(current: u32, previous: Option<u32>) -> KeyRing {
        let key = |version: u32| {
            VersionedKey::new(
                version,
                &[u8::try_from(version).expect("a small version"); 32],
            )
            .expect("a key")
        };
        KeyRing::new(key(current), previous.map(key)).expect("a ring")
    }

    fn prepared() -> PreparedRequest {
        PreparedRequest::new("exchange-1", "urn:example:kind", BODY, 4)
    }

    #[test]
    fn the_cipher_wipes_its_copy_of_the_sealing_key_when_it_drops() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<XChaCha20Poly1305>();
    }

    fn binding<'a>(tag: &'a str, generation: &'a CatalogGeneration) -> Binding<'a> {
        Binding {
            purpose: Purpose::Offer,
            tag,
            tag_key_version: 1,
            generation,
        }
    }

    #[test]
    fn a_sealed_request_opens_to_what_was_sealed_and_never_shows_it() {
        let generation = CatalogGeneration::default();
        let keys = ring(1, None);
        let sealed = seal(&keys, &binding("tag-1", &generation), &prepared()).expect("a seal");
        assert_eq!(sealed.key_version, 1);
        assert_eq!(sealed.nonce.len(), NONCE_LENGTH);
        let held = String::from_utf8_lossy(&sealed.ciphertext);
        for value in ["exchange-1", "urn:example:kind", "held-by-the-adopter"] {
            assert!(!held.contains(value), "the ciphertext shows {value}");
        }

        let opened = open(&keys, &binding("tag-1", &generation), &sealed).expect("it opens");
        assert_eq!(opened, prepared());
    }

    #[test]
    fn two_seals_of_one_request_differ() {
        let generation = CatalogGeneration::default();
        let keys = ring(1, None);
        let first = seal(&keys, &binding("tag-1", &generation), &prepared()).expect("a seal");
        let second = seal(&keys, &binding("tag-1", &generation), &prepared()).expect("a seal");
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn a_seal_opens_only_for_the_binding_it_was_made_for() {
        let generation = CatalogGeneration::default();
        let other_generation = CatalogGeneration::new("catalog-2").expect("a generation");
        let keys = ring(1, None);
        let sealed = seal(&keys, &binding("tag-1", &generation), &prepared()).expect("a seal");

        let token = Binding {
            purpose: Purpose::AccessToken,
            ..binding("tag-1", &generation)
        };
        let other_tag_key = Binding {
            tag_key_version: 2,
            ..binding("tag-1", &generation)
        };
        for (case, moved) in [
            ("another tag", binding("tag-2", &generation)),
            ("another generation", binding("tag-1", &other_generation)),
            ("another purpose", token),
            ("another tagging key", other_tag_key),
        ] {
            assert_eq!(
                open(&keys, &moved, &sealed).err(),
                Some(SealError::Refused),
                "{case}"
            );
        }

        let mut altered = Sealed {
            key_version: sealed.key_version,
            nonce: sealed.nonce.clone(),
            ciphertext: sealed.ciphertext.clone(),
        };
        altered.ciphertext[0] ^= 1;
        assert_eq!(
            open(&keys, &binding("tag-1", &generation), &altered).err(),
            Some(SealError::Refused)
        );
        altered.ciphertext[0] ^= 1;
        altered.nonce.pop();
        assert_eq!(
            open(&keys, &binding("tag-1", &generation), &altered).err(),
            Some(SealError::Refused)
        );
    }

    #[test]
    fn a_rotation_opens_previous_seals_and_a_retired_key_opens_nothing() {
        let generation = CatalogGeneration::default();
        let sealed =
            seal(&ring(1, None), &binding("tag-1", &generation), &prepared()).expect("a seal");

        let rotated = ring(2, Some(1));
        assert_eq!(
            open(&rotated, &binding("tag-1", &generation), &sealed).expect("it opens"),
            prepared()
        );
        assert_eq!(
            seal(&rotated, &binding("tag-1", &generation), &prepared())
                .expect("a seal")
                .key_version,
            2
        );
        assert_eq!(
            open(&ring(3, Some(2)), &binding("tag-1", &generation), &sealed).err(),
            Some(SealError::RetiredKey)
        );
    }

    #[test]
    fn a_malformed_plaintext_is_refused_rather_than_guessed_at() {
        let encoded = encode(&prepared());
        assert!(decode(&encoded).is_some());
        assert!(decode(&encoded[..encoded.len() - 1]).is_none());
        let mut wrong_layout = encoded.to_vec();
        wrong_layout[0] = LAYOUT + 1;
        assert!(decode(&wrong_layout).is_none());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode(&trailing).is_none());
        assert!(decode(&[]).is_none());
    }
}
