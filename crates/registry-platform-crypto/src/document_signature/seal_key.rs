// SPDX-License-Identifier: Apache-2.0
//! Seal keys as private JWKs: generated here, or imported from an
//! unencrypted PKCS #8 PEM a deployment already holds.
//!
//! A seal signs with ES256, ES384, RS256 or RS384, the algorithms
//! [`sign_detached`](super::sign_detached) accepts. Import reads one form
//! only. Encrypted PKCS #8, the SEC 1 and PKCS #1 PEM forms and PKCS #12 are
//! recognised and refused by their markers, before any key material in them
//! is decoded, so the caller can name the conversion that produces PKCS #8.

use super::asn1::oid;
use super::certificate::{PEM_BEGIN, PEM_DASHES, PEM_END};
use crate::{
    ecdsa_private_jwk, generate_private_jwk, rsa_private_jwk_from_pkcs8, CryptoError,
    GeneratedKeyAlgorithm, JwkError, PrivateJwk, SigningAlgorithm, P256_COORDINATE_BYTES,
    P384_COORDINATE_BYTES,
};
use aws_lc_rs::rsa::KeyPair as AwsRsaKeyPair;
use aws_lc_rs::signature::{
    EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use der::asn1::ObjectIdentifier;
use der::{Decode as _, Header, SliceReader, Tag};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SealKeyError {
    #[error("seal keys use ES256, ES384, RS256 or RS384, not {}", .0.jwa_name())]
    UnsupportedAlgorithm(SigningAlgorithm),
    #[error("the file holds no PEM `PRIVATE KEY` block")]
    NoPrivateKey,
    #[error("the file holds more than one PEM `PRIVATE KEY` block")]
    MultipleKeys,
    #[error("the private key is encrypted PKCS #8; decrypt it to unencrypted PKCS #8 first")]
    EncryptedPkcs8,
    #[error("the private key is a {form} PEM; convert it to unencrypted PKCS #8 first")]
    LegacyPem {
        /// `SEC 1` for `EC PRIVATE KEY`, `PKCS #1` for `RSA PRIVATE KEY`.
        form: &'static str,
    },
    #[error("the file is PKCS #12; export its private key as unencrypted PKCS #8 first")]
    Pkcs12,
    #[error("the `PRIVATE KEY` block is not well-formed PEM over DER PKCS #8")]
    Malformed,
    #[error("the private key is {0}; seal keys are P-256, P-384 or RSA")]
    UnsupportedKey(&'static str),
    #[error("the private key was refused: {0}")]
    Rejected(&'static str),
    #[error("a {key} key cannot sign {requested}")]
    AlgorithmMismatch {
        /// `P-256`, `P-384` or `RSA`.
        key: &'static str,
        requested: &'static str,
    },
    #[error("the private key cannot be written as a JWK: {0}")]
    Jwk(#[from] JwkError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// The private JWK `jwk` as the one line of JSON a seal key file holds,
/// secret members included, ending in a newline.
///
/// [`PrivateJwk`] serializes its public half only, so the file is written
/// here. Every member is written straight into one zeroizing buffer sized
/// for the largest RSA key aws-lc-rs accepts, so no unwiped copy of a
/// secret member is left behind by a reallocation.
pub fn private_seal_key_json(jwk: &PrivateJwk) -> Result<Zeroizing<Vec<u8>>, SealKeyError> {
    let mut json = Zeroizing::new(Vec::with_capacity(SEAL_KEY_JSON_CAPACITY));
    json.push(b'{');
    let members = [
        ("kty", Some(jwk.kty.as_str())),
        ("crv", jwk.crv.as_deref()),
        ("x", jwk.x.as_deref()),
        ("y", jwk.y.as_deref()),
        ("n", jwk.n.as_deref()),
        ("e", jwk.e.as_deref()),
        ("d", jwk.d.as_deref()),
        ("p", jwk.p.as_deref()),
        ("q", jwk.q.as_deref()),
        ("dp", jwk.dp.as_deref()),
        ("dq", jwk.dq.as_deref()),
        ("qi", jwk.qi.as_deref()),
        ("alg", jwk.alg.as_deref()),
        ("kid", jwk.kid.as_deref()),
    ];
    for (name, value) in members {
        let Some(value) = value else { continue };
        if json.len() > 1 {
            json.push(b',');
        }
        let unwritable = |_| CryptoError::Crypto("the private JWK could not be written as JSON");
        serde_json::to_writer(&mut *json, name).map_err(unwritable)?;
        json.push(b':');
        serde_json::to_writer(&mut *json, value).map_err(unwritable)?;
    }
    json.extend_from_slice(b"}\n");
    if json.capacity() > SEAL_KEY_JSON_CAPACITY {
        // A reallocation left an earlier buffer unwiped; refuse rather than
        // write a key whose copies this function cannot account for.
        return Err(SealKeyError::Crypto(CryptoError::Crypto(
            "the private JWK outgrew the seal key file buffer",
        )));
    }
    Ok(json)
}

/// Room for an 8192-bit RSA private JWK, the largest aws-lc-rs signs with:
/// eight members of at most 1366 base64url characters, the public members
/// and the punctuation.
const SEAL_KEY_JSON_CAPACITY: usize = 16 * 1024;

/// Generate a seal key for `algorithm`, carrying its `alg` and a `kid` that
/// is the RFC 7638 thumbprint of its public half. An RSA key has a 2048-bit
/// modulus and serves either hash, so RS256 and RS384 differ only in `alg`.
pub fn generate_seal_key(algorithm: SigningAlgorithm) -> Result<PrivateJwk, SealKeyError> {
    let generated = match algorithm {
        SigningAlgorithm::Es256 => GeneratedKeyAlgorithm::Es256,
        SigningAlgorithm::Es384 => GeneratedKeyAlgorithm::Es384,
        // The thumbprint `kid` covers `kty`, `n` and `e`, not `alg`.
        SigningAlgorithm::Rs256 | SigningAlgorithm::Rs384 => GeneratedKeyAlgorithm::Rs384,
        SigningAlgorithm::EdDsa => return Err(SealKeyError::UnsupportedAlgorithm(algorithm)),
    };
    let mut jwk = generate_private_jwk(generated)?;
    jwk.alg = Some(algorithm.jwa_name().to_owned());
    Ok(jwk)
}

/// Read a seal key from the unencrypted PKCS #8 `PRIVATE KEY` PEM block in
/// `pem` (RFC 7468 section 10), as a private JWK carrying its `alg` and a
/// thumbprint `kid`.
///
/// Text outside the block is ignored, as `openssl` writes bag attributes
/// before a key it exports. A P-256 key signs ES256 and a P-384 key ES384; an
/// RSA key signs RS256 unless `algorithm` asks for RS384. An `algorithm` the
/// key cannot sign is refused rather than adjusted.
pub fn seal_key_from_pkcs8_pem(
    pem: &[u8],
    algorithm: Option<SigningAlgorithm>,
) -> Result<PrivateJwk, SealKeyError> {
    if is_pkcs12(pem) {
        return Err(SealKeyError::Pkcs12);
    }
    let text = std::str::from_utf8(pem).map_err(|_| SealKeyError::NoPrivateKey)?;
    let pkcs8 = private_key_block(text)?;
    let info =
        pkcs8::PrivateKeyInfo::try_from(pkcs8.as_slice()).map_err(|_| SealKeyError::Malformed)?;

    let rejected =
        |error: aws_lc_rs::error::KeyRejected| SealKeyError::Rejected(error.description_());
    let (mut jwk, key, accepted): (_, _, &[SigningAlgorithm]) = match info.algorithm.oid {
        oid::EC_PUBLIC_KEY => {
            let curve: ObjectIdentifier = info
                .algorithm
                .parameters_oid()
                .map_err(|_| SealKeyError::Malformed)?;
            let (signing, name, width, accepted) = match curve {
                oid::SECP256R1 => (
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    "P-256",
                    P256_COORDINATE_BYTES,
                    &[SigningAlgorithm::Es256][..],
                ),
                oid::SECP384R1 => (
                    &ECDSA_P384_SHA384_FIXED_SIGNING,
                    "P-384",
                    P384_COORDINATE_BYTES,
                    &[SigningAlgorithm::Es384][..],
                ),
                _ => {
                    return Err(SealKeyError::UnsupportedKey(
                        "an EC key on a curve other than P-256 or P-384",
                    ))
                }
            };
            let key_pair = EcdsaKeyPair::from_pkcs8(signing, &pkcs8).map_err(rejected)?;
            (ecdsa_private_jwk(&key_pair, name, width)?, name, accepted)
        }
        oid::RSA_ENCRYPTION => {
            AwsRsaKeyPair::from_pkcs8(&pkcs8).map_err(rejected)?;
            (
                rsa_private_jwk_from_pkcs8(&pkcs8)?,
                "RSA",
                &[SigningAlgorithm::Rs256, SigningAlgorithm::Rs384][..],
            )
        }
        _ => return Err(SealKeyError::UnsupportedKey("neither an EC nor an RSA key")),
    };
    let chosen = algorithm.unwrap_or(accepted[0]);
    if !accepted.contains(&chosen) {
        return Err(SealKeyError::AlgorithmMismatch {
            key,
            requested: chosen.jwa_name(),
        });
    }
    jwk.alg = Some(chosen.jwa_name().to_owned());
    jwk.validate_private()?;
    jwk.kid = Some(jwk.public().jkt()?);
    Ok(jwk)
}

/// A DER PKCS #12 `PFX`: a SEQUENCE whose first member is the INTEGER 3
/// (RFC 7292 section 4).
fn is_pkcs12(bytes: &[u8]) -> bool {
    let Ok(mut reader) = SliceReader::new(bytes) else {
        return false;
    };
    Header::decode(&mut reader).is_ok_and(|header| header.tag == Tag::Sequence)
        && u8::decode(&mut reader).is_ok_and(|version| version == 3)
}

/// The DER body of the one `PRIVATE KEY` block in `text`. Every other key
/// label is refused by name before its body is read.
fn private_key_block(text: &str) -> Result<Zeroizing<Vec<u8>>, SealKeyError> {
    let mut lines = text.lines().map(str::trim);
    let mut found: Option<Zeroizing<Vec<u8>>> = None;
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix(PEM_BEGIN)
            .and_then(|rest| rest.strip_suffix(PEM_DASHES))
        else {
            continue;
        };
        match label {
            "PRIVATE KEY" => {}
            "ENCRYPTED PRIVATE KEY" => return Err(SealKeyError::EncryptedPkcs8),
            "EC PRIVATE KEY" => return Err(SealKeyError::LegacyPem { form: "SEC 1" }),
            "RSA PRIVATE KEY" => return Err(SealKeyError::LegacyPem { form: "PKCS #1" }),
            _ => continue,
        }
        if found.is_some() {
            return Err(SealKeyError::MultipleKeys);
        }
        let mut body = Zeroizing::new(String::new());
        let mut ended = false;
        for line in lines.by_ref() {
            if let Some(end_label) = line
                .strip_prefix(PEM_END)
                .and_then(|rest| rest.strip_suffix(PEM_DASHES))
            {
                if end_label != label {
                    return Err(SealKeyError::Malformed);
                }
                ended = true;
                break;
            }
            // RFC 1421 encapsulated headers mark an encrypted or legacy block.
            if line.contains(':') || line.starts_with(PEM_BEGIN) {
                return Err(SealKeyError::Malformed);
            }
            body.push_str(line);
        }
        if !ended {
            return Err(SealKeyError::Malformed);
        }
        let der = STANDARD
            .decode(body.as_bytes())
            .map_err(|_| SealKeyError::Malformed)?;
        found = Some(Zeroizing::new(der));
    }
    found.ok_or(SealKeyError::NoPrivateKey)
}
