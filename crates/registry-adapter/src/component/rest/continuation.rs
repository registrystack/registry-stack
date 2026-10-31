// SPDX-License-Identifier: Apache-2.0

//! The continuation cursor codec (`products/adapter/CONCEPT.md` section
//! 8.11.2): the route owns the upstream position, the engine owns the
//! caller's cursor.
//!
//! A search route that can return more sets `AdapterNextContinuation`
//! to a JSON value of at most [`CONTINUATION_MAXIMUM_BYTES`] serialized.
//! [`ContinuationCodec::seal`] turns it into the opaque `nextCursor`
//! slot of section 7, and [`ContinuationCodec::open`] turns the cursor
//! the caller sends back into the value the `rest` consumer places as
//! `AdapterContinuation`. An absent or `null` value is the last page and
//! seals to no cursor at all.
//!
//! # What a cursor is bound to
//!
//! Every cursor is bound to a [`CursorBinding`]: the concrete operation,
//! the binding id, the caller's authenticated issuer and `sub`, the
//! deployment the runtime serves, and the [`FilterDigest`] of the
//! validated facade inputs and page size, plus an expiry. The binding travels in the AEAD's associated data, never
//! on the wire, so a cursor presented under any other binding fails
//! authentication exactly as a tampered one does; there is no field
//! comparison to get wrong. The expiry is the issue time sealed inside
//! the ciphertext plus the codec's configured [`CursorTtl`], evaluated
//! when the cursor is opened, so shortening `cursorTtlSeconds` shortens
//! the cursors already issued as well.
//!
//! # Caller obligations
//!
//! The codec is a pure library; the `rest` consumer owns the ordering
//! section 8.11.2 requires and must enforce it:
//!
//! - open the cursor only after authentication and authorization, so an
//!   unauthenticated caller with a forged cursor gets
//!   `facade.unauthenticated`, never a cursor refusal;
//! - open it before any route step runs, and answer every
//!   [`CursorRefusal`] as the one problem [`CursorRefusal::error_class`]
//!   names, `facade.invalid-cursor`, journaling only
//!   [`CursorRefusal::reason`];
//! - compute the [`FilterDigest`] once per request with
//!   [`filter_digest`], over the same validated inputs on the request
//!   that seals and the request that opens.
//!
//! # Wire format, version 1
//!
//! The cursor is unpadded base64url (RFC 4648 section 5) of
//! `version (1) || nonce (24) || ciphertext || tag (16)`, where the
//! plaintext is `issued_at (8, big-endian Unix seconds) || value` and
//! `value` is the compact JSON serialization of the continuation. The
//! associated data is a fixed domain label, the version byte, the four
//! binding strings each prefixed by its big-endian 64-bit length, and the
//! 32-byte filter digest, so no field boundary can shift between two
//! bindings. The token length is bounded by
//! [`CURSOR_MAXIMUM_TOKEN_BYTES`] before any decode.
//!
//! # Algorithm: XChaCha20-Poly1305
//!
//! The AEAD is `chacha20poly1305`'s `XChaCha20Poly1305`, chosen over
//! `aws-lc-rs` AES-256-GCM, both of which the workspace already carries:
//!
//! - Nonce safety under random nonces. Cursors are minted by every
//!   facade instance concurrently under one long-lived key with no shared
//!   counter, so the nonce must be random. XChaCha20's 192-bit nonce
//!   makes a random collision negligible at any cursor volume; AES-GCM's
//!   96-bit random nonce caps one key at about 2^32 seals (NIST SP
//!   800-38D section 8.3), a budget a busy search facade approaches
//!   without rotation, and a GCM nonce reuse leaks the authentication
//!   key. `registry-platform-crypto` can use AES-256-GCM safely for field
//!   encryption because it derives a subkey per field; a cursor key has
//!   no such per-message subkey.
//! - Consistency. Base Registry Engine's cursor codec
//!   (`crates/registry-breg/src/cursor.rs`) and the OID4VCI front end's
//!   sealing (`crates/registry-evidence-oid4vci/src/storage/sealing.rs`)
//!   make the same choice for the same job; the Adapter depends on
//!   neither.
//! - The FIPS build. The workspace builds `aws-lc-rs` with its `fips`
//!   feature as the provider behind TLS and JOSE signatures, and
//!   ChaCha20-Poly1305 is not a FIPS-approved algorithm. The cursor is an
//!   engine-internal token that only this engine ever opens; it protects
//!   no data in transit to or at rest for a third party. A deployment
//!   that must run approved algorithms only for every internal token
//!   would need AES-256-GCM with per-cursor derived subkeys here, a
//!   wire-version change.
//!
//! # Keys
//!
//! `cursorKeyRef` must resolve to exactly [`CURSOR_KEY_BYTES`] bytes or
//! [`CursorKey::new`] fails, and the runtime refuses to start. The AEAD
//! key is derived from the configured secret with domain separation, as
//! HKDF-Expand (RFC 5869 section 2.3) with the secret as the
//! pseudorandom key: the configured secret is already 32 bytes of key
//! material, so HKDF-Extract is skipped as section 3.3 allows. Only the
//! derived key is held, in a buffer wiped on drop, and no `Debug` or
//! `Display` in this module prints key material, the continuation value,
//! the subject, the filter digest, or any cursor byte. Sealing always
//! uses the current key; the optional `previousCursorKeyRef` key only
//! decrypts, which keeps cursors valid across one rotation.
//!
//! The codec is security-sensitive (it carries source state through the
//! caller) and its review notes are recorded with the change that added
//! it (section 13.7).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use registry_adapter_core::ErrorClass;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::replay::ReplayCursorNonce;

/// The exact length of the secret `cursorKeyRef` and
/// `previousCursorKeyRef` resolve to, in bytes.
pub const CURSOR_KEY_BYTES: usize = 32;

/// The largest continuation value, as compact JSON, in bytes
/// (section 8.11.2: at most 2 KiB serialized).
pub const CONTINUATION_MAXIMUM_BYTES: usize = 2_048;

/// The shortest `cursorTtlSeconds` the codec accepts.
pub const CURSOR_TTL_MINIMUM_SECONDS: u64 = 60;

/// The longest `cursorTtlSeconds` the codec accepts.
pub const CURSOR_TTL_MAXIMUM_SECONDS: u64 = 86_400;

/// `cursorTtlSeconds` when the runtime configuration leaves it out.
pub const CURSOR_TTL_DEFAULT_SECONDS: u64 = 900;

const WIRE_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const ISSUED_AT_BYTES: usize = 8;
const HEADER_BYTES: usize = 1 + NONCE_BYTES;
/// Header, issue time, a one-byte JSON value, and the tag: anything
/// shorter cannot be a cursor this codec sealed.
const MINIMUM_ENVELOPE_BYTES: usize = HEADER_BYTES + ISSUED_AT_BYTES + 1 + TAG_BYTES;
const MAXIMUM_ENVELOPE_BYTES: usize =
    HEADER_BYTES + ISSUED_AT_BYTES + CONTINUATION_MAXIMUM_BYTES + TAG_BYTES;

/// The longest cursor [`ContinuationCodec::open`] decodes: the unpadded
/// base64url length of the largest envelope a sealed
/// [`CONTINUATION_MAXIMUM_BYTES`] value produces. Anything longer is
/// refused as [`CursorRefusal::Oversize`] before any decode, and a
/// profile's contract may publish it as the cursor parameter's
/// `maxLength`.
pub const CURSOR_MAXIMUM_TOKEN_BYTES: usize = (MAXIMUM_ENVELOPE_BYTES * 4).div_ceil(3);

const AEAD_KEY_INFO: &[u8] = b"registry-adapter/continuation-cursor/v1/aead-key";
const AAD_DOMAIN: &[u8] = b"registry-adapter/continuation-cursor";

type HmacSha256 = Hmac<Sha256>;

/// One configured cursor key, held as its derived AEAD key.
///
/// The configured secret is consumed and wiped on construction; the
/// derived key is wiped when the value drops.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CursorKey {
    aead: [u8; CURSOR_KEY_BYTES],
}

impl CursorKey {
    /// Derive the cursor AEAD key from the secret a `cursorKeyRef` or
    /// `previousCursorKeyRef` resolved to.
    ///
    /// # Errors
    ///
    /// [`ContinuationConfigError::KeyLength`] unless `secret` is exactly
    /// [`CURSOR_KEY_BYTES`] long.
    pub fn new(secret: Zeroizing<Vec<u8>>) -> Result<Self, ContinuationConfigError> {
        if secret.len() != CURSOR_KEY_BYTES {
            return Err(ContinuationConfigError::KeyLength);
        }
        // HKDF-Expand with L = 32: T(1) = HMAC(PRK, info || 0x01).
        let mut mac = HmacSha256::new_from_slice(secret.as_slice())
            .map_err(|_| ContinuationConfigError::KeyLength)?;
        mac.update(AEAD_KEY_INFO);
        mac.update(&[1]);
        Ok(Self {
            aead: mac.finalize().into_bytes().into(),
        })
    }

    fn cipher(&self) -> Option<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(&self.aead).ok()
    }
}

impl fmt::Debug for CursorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorKey(<redacted>)")
    }
}

/// A validated `cursorTtlSeconds`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorTtl(u64);

impl CursorTtl {
    /// # Errors
    ///
    /// [`ContinuationConfigError::TtlOutOfBounds`] unless `seconds` lies
    /// within [`CURSOR_TTL_MINIMUM_SECONDS`] and
    /// [`CURSOR_TTL_MAXIMUM_SECONDS`], both inclusive.
    pub fn from_seconds(seconds: u64) -> Result<Self, ContinuationConfigError> {
        if (CURSOR_TTL_MINIMUM_SECONDS..=CURSOR_TTL_MAXIMUM_SECONDS).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(ContinuationConfigError::TtlOutOfBounds)
        }
    }

    /// The lifetime in seconds.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

impl Default for CursorTtl {
    fn default() -> Self {
        Self(CURSOR_TTL_DEFAULT_SECONDS)
    }
}

/// A configuration value the codec refuses; the runtime refuses to
/// start on either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationConfigError {
    /// A cursor key secret is not exactly [`CURSOR_KEY_BYTES`] long.
    KeyLength,
    /// `cursorTtlSeconds` lies outside its bounds.
    TtlOutOfBounds,
}

impl fmt::Display for ContinuationConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyLength => write!(
                formatter,
                "a cursor key must resolve to exactly {CURSOR_KEY_BYTES} bytes"
            ),
            Self::TtlOutOfBounds => write!(
                formatter,
                "cursorTtlSeconds must lie between {CURSOR_TTL_MINIMUM_SECONDS} and \
                 {CURSOR_TTL_MAXIMUM_SECONDS}"
            ),
        }
    }
}

impl std::error::Error for ContinuationConfigError {}

/// SHA-256 over the RFC 8785 canonical JSON of the validated facade
/// inputs, without the cursor, plus the page size (section 8.11.2).
///
/// The digest is opaque: it compares equal or not, and its `Debug`
/// prints nothing of it, because an unkeyed digest of low-entropy
/// filter values can be reversed by guessing and so counts as content.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FilterDigest([u8; 32]);

impl fmt::Debug for FilterDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FilterDigest(<redacted>)")
    }
}

/// The facade inputs could not be canonicalized under RFC 8785, for
/// example an integer outside the exactly representable binary64 range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilterDigestError;

impl fmt::Display for FilterDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the facade inputs have no RFC 8785 canonical form")
    }
}

impl std::error::Error for FilterDigestError {}

/// Digest the validated facade inputs and the page size.
///
/// `inputs` is the validated facade inputs of section 8.11.1 without the
/// continuation (the record type and the `AdapterFilters` object, as the
/// `rest` consumer arranges them); `page_size` is the effective page
/// size, the profile's default when the caller sent none. The digested
/// document is the canonical JSON of `{"inputs": inputs, "pageSize":
/// page_size}`, so member order never matters and the page size can
/// never be confused with an input.
///
/// # Errors
///
/// [`FilterDigestError`] when `inputs` has no RFC 8785 canonical form.
pub fn filter_digest(inputs: &Value, page_size: u32) -> Result<FilterDigest, FilterDigestError> {
    let document = json!({"inputs": inputs, "pageSize": page_size});
    let canonical = canonicalize_json(&document).map_err(|_| FilterDigestError)?;
    Ok(FilterDigest(Sha256::digest(&canonical).into()))
}

/// What a cursor is bound to (section 8.11.2).
#[derive(Clone, Copy)]
pub struct CursorBinding<'a> {
    /// The concrete operation the request resolved to.
    pub operation: &'a str,
    /// The id of the operation binding that serves it.
    pub binding_id: &'a str,
    /// The authenticated caller's token issuer.
    pub issuer: &'a str,
    /// The authenticated caller's `sub`.
    pub subject: &'a str,
    /// An identifier of the loaded project the runtime serves, so a
    /// cursor minted before a redeploy that changes route meaning is
    /// refused; the `rest` consumer supplies the project lock digest.
    pub deployment: &'a str,
    /// The digest of the validated facade inputs and page size.
    pub filters: FilterDigest,
}

impl CursorBinding<'_> {
    fn associated_data(&self) -> Vec<u8> {
        let fields = [
            self.operation,
            self.binding_id,
            self.issuer,
            self.subject,
            self.deployment,
        ];
        let length = AAD_DOMAIN.len()
            + 2
            + fields.iter().map(|field| 8 + field.len()).sum::<usize>()
            + self.filters.0.len();
        let mut aad = Vec::with_capacity(length);
        aad.extend_from_slice(AAD_DOMAIN);
        aad.push(0);
        aad.push(WIRE_VERSION);
        for field in fields {
            // usize is at most 64 bits on every target Rust supports.
            aad.extend_from_slice(&(field.len() as u64).to_be_bytes());
            aad.extend_from_slice(field.as_bytes());
        }
        aad.extend_from_slice(&self.filters.0);
        aad
    }
}

impl fmt::Debug for CursorBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorBinding")
            .field("operation", &self.operation)
            .field("binding_id", &self.binding_id)
            .field("issuer", &self.issuer)
            .field("subject", &"<redacted>")
            .field("deployment", &self.deployment)
            .field("filters", &self.filters)
            .finish()
    }
}

/// Why a cursor was refused. Every reason is the one caller-facing
/// `facade.invalid-cursor` ([`CursorRefusal::error_class`]); the
/// reason itself is for the journal and tests, and none carries any
/// cursor content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorRefusal {
    /// Longer than [`CURSOR_MAXIMUM_TOKEN_BYTES`]; refused before any
    /// decode.
    Oversize,
    /// Not unpadded base64url, or not shaped like an envelope this codec
    /// seals.
    Malformed,
    /// A wire version this codec does not open.
    UnsupportedVersion,
    /// Failed authentication under every accepted key: tampered, sealed
    /// under a key no longer accepted, or minted for another operation,
    /// binding, caller, filter set, or page size. The associated data
    /// carries the binding, so these cases are one by construction.
    Unauthenticated,
    /// At or past its issue time plus the configured TTL.
    Expired,
    /// The clock reads before the Unix epoch, so expiry cannot be
    /// established; the cursor is refused rather than trusted.
    Clock,
}

impl CursorRefusal {
    /// The error class the `rest` consumer raises for every refusal.
    #[must_use]
    pub const fn error_class(self) -> ErrorClass {
        ErrorClass::FacadeInvalidCursor
    }

    /// The value-free reason, for the journal.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Oversize => "oversize",
            Self::Malformed => "malformed",
            Self::UnsupportedVersion => "unsupported-version",
            Self::Unauthenticated => "unauthenticated",
            Self::Expired => "expired",
            Self::Clock => "clock",
        }
    }
}

impl fmt::Display for CursorRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "continuation cursor refused: {}", self.reason())
    }
}

impl std::error::Error for CursorRefusal {}

/// Why a continuation could not be sealed. None is the caller's doing:
/// the route set too large a value, or the engine's clock, randomness, or
/// cipher failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealError {
    /// The value serializes to more than [`CONTINUATION_MAXIMUM_BYTES`].
    ValueTooLarge,
    /// The clock reads before the Unix epoch.
    Clock,
    /// The operating system's random source failed to supply a nonce.
    Randomness,
    /// The value could not be serialized or the cipher refused it.
    Encryption,
}

impl fmt::Display for SealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLarge => write!(
                formatter,
                "the continuation value is over the {CONTINUATION_MAXIMUM_BYTES}-byte bound"
            ),
            Self::Clock => formatter.write_str("the clock reads before the Unix epoch"),
            Self::Randomness => formatter.write_str("no nonce could be drawn"),
            Self::Encryption => formatter.write_str("the continuation could not be sealed"),
        }
    }
}

impl std::error::Error for SealError {}

/// Seals continuations into cursors and opens them back.
pub struct ContinuationCodec {
    current: CursorKey,
    previous: Option<CursorKey>,
    ttl: CursorTtl,
}

impl ContinuationCodec {
    /// A codec that seals under `current`, also opens what `previous`
    /// sealed, and refuses cursors older than `ttl`.
    #[must_use]
    pub fn new(current: CursorKey, previous: Option<CursorKey>, ttl: CursorTtl) -> Self {
        Self {
            current,
            previous,
            ttl,
        }
    }

    /// The configured cursor lifetime.
    #[must_use]
    pub const fn ttl(&self) -> CursorTtl {
        self.ttl
    }

    /// Seal the route's `AdapterNextContinuation` as a `nextCursor`, or
    /// return `None` when it is absent or `null` (the last page).
    ///
    /// # Errors
    ///
    /// [`SealError::ValueTooLarge`] when the value serializes to more
    /// than [`CONTINUATION_MAXIMUM_BYTES`]; [`SealError::Clock`],
    /// [`SealError::Randomness`], or [`SealError::Encryption`] when the
    /// engine cannot seal.
    pub fn seal(
        &self,
        next: Option<&Value>,
        binding: &CursorBinding<'_>,
        now: SystemTime,
    ) -> Result<Option<String>, SealError> {
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| SealError::Randomness)?;
        self.seal_with_nonce(next, binding, now, nonce)
    }

    /// Seal with a deterministic nonce that only offline fixture replay can
    /// construct. Production callers use [`Self::seal`] and OS randomness.
    pub(crate) fn seal_replay(
        &self,
        nonce: ReplayCursorNonce,
        next: Option<&Value>,
        binding: &CursorBinding<'_>,
        now: SystemTime,
    ) -> Result<Option<String>, SealError> {
        self.seal_with_nonce(next, binding, now, nonce.into_bytes())
    }

    fn seal_with_nonce(
        &self,
        next: Option<&Value>,
        binding: &CursorBinding<'_>,
        now: SystemTime,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Option<String>, SealError> {
        let Some(value) = next.filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let serialized =
            Zeroizing::new(serde_json::to_vec(value).map_err(|_| SealError::Encryption)?);
        if serialized.len() > CONTINUATION_MAXIMUM_BYTES {
            return Err(SealError::ValueTooLarge);
        }
        let issued_at = unix_seconds(now).ok_or(SealError::Clock)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(ISSUED_AT_BYTES + serialized.len()));
        plaintext.extend_from_slice(&issued_at.to_be_bytes());
        plaintext.extend_from_slice(&serialized);

        let cipher = self.current.cipher().ok_or(SealError::Encryption)?;
        let aad = binding.associated_data();
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Encryption)?;

        let mut envelope = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
        envelope.push(WIRE_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(Some(URL_SAFE_NO_PAD.encode(envelope)))
    }

    /// Verify and decrypt a cursor the caller sent back, returning the
    /// continuation value to place as `AdapterContinuation`.
    ///
    /// The caller must have authenticated and authorized the request
    /// first, and must call this before any route step runs (module
    /// documentation).
    ///
    /// # Errors
    ///
    /// A [`CursorRefusal`] naming why; every one is answered as
    /// `facade.invalid-cursor`.
    pub fn open(
        &self,
        cursor: &str,
        binding: &CursorBinding<'_>,
        now: SystemTime,
    ) -> Result<Value, CursorRefusal> {
        if cursor.len() > CURSOR_MAXIMUM_TOKEN_BYTES {
            return Err(CursorRefusal::Oversize);
        }
        let envelope = URL_SAFE_NO_PAD
            .decode(cursor)
            .map_err(|_| CursorRefusal::Malformed)?;
        if !(MINIMUM_ENVELOPE_BYTES..=MAXIMUM_ENVELOPE_BYTES).contains(&envelope.len()) {
            return Err(CursorRefusal::Malformed);
        }
        if envelope[0] != WIRE_VERSION {
            return Err(CursorRefusal::UnsupportedVersion);
        }
        let (nonce, ciphertext) = envelope[1..].split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| CursorRefusal::Malformed)?;
        let aad = binding.associated_data();
        let plaintext = self
            .decrypt(&nonce, ciphertext, &aad)
            .ok_or(CursorRefusal::Unauthenticated)?;

        let (issued_at, value) = plaintext
            .split_first_chunk::<ISSUED_AT_BYTES>()
            .ok_or(CursorRefusal::Malformed)?;
        let issued_at = u64::from_be_bytes(*issued_at);
        let now = unix_seconds(now).ok_or(CursorRefusal::Clock)?;
        issued_at
            .checked_add(self.ttl.seconds())
            .filter(|expires_at| now < *expires_at)
            .ok_or(CursorRefusal::Expired)?;
        serde_json::from_slice(value).map_err(|_| CursorRefusal::Malformed)
    }

    /// Decrypt under the current key, then the previous one.
    fn decrypt(
        &self,
        nonce: &[u8; NONCE_BYTES],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        std::iter::once(&self.current)
            .chain(self.previous.as_ref())
            .find_map(|key| {
                key.cipher()?
                    .decrypt(
                        &XNonce::from(*nonce),
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .ok()
                    .map(Zeroizing::new)
            })
    }
}

impl fmt::Debug for ContinuationCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuationCodec")
            .field("current", &self.current)
            .field("previous", &self.previous)
            .field("ttl", &self.ttl)
            .finish()
    }
}

fn unix_seconds(now: SystemTime) -> Option<u64> {
    now.duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}
