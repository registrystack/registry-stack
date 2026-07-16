// SPDX-License-Identifier: Apache-2.0
//! Encrypted PostgreSQL state for the OID4VCI pre-authorized-code flow.
//!
//! The database sees only keyed identifiers, an authenticated ciphertext for
//! the eSignet login state, and a keyed transaction-code verifier. The master
//! key is read only at the asynchronous state-plane activation boundary and is
//! never retained as text.

use std::{env, sync::Arc};

use aws_lc_rs::{
    aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM},
    hmac,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_replay::ReplayScope;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{NotaryPostgresStatePlaneError, NotaryPostgresStatePlaneRuntime};
use crate::preauth_state::{LoginState, VerifiedTransactionCode};

const KEY_BYTES: usize = 32;
const LOGIN_RECORD_VERSION: u8 = 1;
const KDF_CONTEXT: &[u8] = b"registry-notary/preauthorization/kdf/v1";
const LOGIN_AAD_CONTEXT: &[u8] = b"registry-notary/preauthorization/login-aad/v1";
const STATE_IDENTIFIER_CONTEXT: &[u8] = b"login-state";
const JTI_IDENTIFIER_CONTEXT: &[u8] = b"code-jti";
const REPLAY_SCOPE_IDENTIFIER_CONTEXT: &[u8] = b"replay-scope";
const PIN_VERIFIER_CONTEXT: &[u8] = b"transaction-code";

/// The configured environment variable name is retained, but its value is
/// read only by [`PostgresSensitiveState::activate`].
#[derive(Clone)]
pub(crate) struct SensitiveStateKeyConfig {
    environment: String,
}

impl SensitiveStateKeyConfig {
    pub(crate) fn new(environment: impl Into<String>) -> Result<Self, SensitiveStateError> {
        let environment = environment.into();
        if environment.trim().is_empty() {
            return Err(SensitiveStateError::InvalidKeyConfiguration);
        }
        Ok(Self { environment })
    }
}

impl std::fmt::Debug for SensitiveStateKeyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SensitiveStateKeyConfig")
            .field("environment", &"<redacted>")
            .finish()
    }
}

/// Closed, value-free failures for sensitive state activation and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SensitiveStateError {
    #[error("Notary sensitive-state key configuration is invalid")]
    InvalidKeyConfiguration,
    #[error("Notary sensitive-state key environment variable is unavailable")]
    KeyEnvironmentUnavailable,
    #[error("Notary sensitive-state key must be unpadded base64url")]
    InvalidKeyEncoding,
    #[error("Notary sensitive-state key must decode to exactly 32 bytes")]
    InvalidKeyLength,
    #[error("Notary sensitive-state cryptographic operation is unavailable")]
    CryptographyUnavailable,
    #[error("Notary sensitive state was not activated before use")]
    NotActivated,
    #[error("Notary sensitive-state record is invalid or cannot be decrypted")]
    InvalidStoredRecord,
    #[error(transparent)]
    StatePlane(#[from] NotaryPostgresStatePlaneError),
}

/// Typed adapter for Notary-owned preauthorization PostgreSQL transactions.
pub(crate) struct PostgresSensitiveState {
    runtime: Arc<NotaryPostgresStatePlaneRuntime>,
    keys: Arc<SensitiveStateKeys>,
}

impl PostgresSensitiveState {
    /// Load and derive sensitive state keys at the asynchronous activation
    /// boundary. No caller can perform a PostgreSQL preauthorization operation
    /// before this succeeds.
    pub(crate) async fn activate(
        runtime: Arc<NotaryPostgresStatePlaneRuntime>,
        config: &SensitiveStateKeyConfig,
    ) -> Result<Self, SensitiveStateError> {
        let encoded = Zeroizing::new(
            env::var(&config.environment)
                .map_err(|_| SensitiveStateError::KeyEnvironmentUnavailable)?,
        );
        if encoded.trim().is_empty() {
            return Err(SensitiveStateError::KeyEnvironmentUnavailable);
        }
        let master = decode_master_key(&encoded)?;
        let keys = SensitiveStateKeys::derive(&master);
        let state = Self {
            runtime,
            keys: Arc::new(keys),
        };
        state.attest_key_generation().await?;
        Ok(state)
    }

    /// Re-attest that every live encrypted or keyed preauthorization record
    /// belongs to this process key generation. This is intentionally checked
    /// during activation and on every readiness probe so a restore with the
    /// wrong operator key cannot become ready.
    pub(crate) async fn attest_key_generation(&self) -> Result<(), SensitiveStateError> {
        let session = self.runtime.open_domain_session().await?;
        let row = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.preauthorization_key_attest_v1($1::bytea) AS attested",
                &[&&self.keys.key_id[..]],
            ))
            .await?;
        if row
            .try_get::<_, bool>("attested")
            .map_err(|_| SensitiveStateError::InvalidStoredRecord)?
        {
            Ok(())
        } else {
            Err(SensitiveStateError::InvalidStoredRecord)
        }
    }

    pub(crate) async fn reserve_login(
        &self,
        opaque_state: &str,
        login: &LoginState,
        expires_at: OffsetDateTime,
    ) -> Result<LoginReserveOutcome, SensitiveStateError> {
        let expires_at = normalize_expiry(expires_at)?;
        let state_hash = self
            .keys
            .identifier_hash(STATE_IDENTIFIER_CONTEXT, opaque_state);
        let aad = login_aad(
            &state_hash,
            &self.keys.key_id,
            &login.credential_configuration_id,
            expires_at,
        )?;
        let plaintext = EncryptedLoginState {
            version: LOGIN_RECORD_VERSION,
            pkce_verifier: &login.pkce_verifier,
            nonce: &login.nonce,
        };
        let mut ciphertext = Zeroizing::new(
            serde_json::to_vec(&plaintext)
                .map_err(|_| SensitiveStateError::CryptographyUnavailable)?,
        );
        let aead = RandomizedNonceKey::new(&AES_256_GCM, &self.keys.aead)
            .map_err(|_| SensitiveStateError::CryptographyUnavailable)?;
        let nonce = aead
            .seal_in_place_append_tag(Aad::from(aad.as_slice()), &mut *ciphertext)
            .map_err(|_| SensitiveStateError::CryptographyUnavailable)?;
        let nonce = nonce.as_ref().as_slice();
        let session = self.runtime.open_domain_session().await?;
        let row = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.preauthorization_login_reserve_v1(\
                     $1::bytea, $2::text, $3::bytea, $4::bytea, $5::bytea, $6::timestamptz)",
                &[
                    &&state_hash[..],
                    &login.credential_configuration_id,
                    &&self.keys.key_id[..],
                    &nonce,
                    &&ciphertext[..],
                    &expires_at,
                ],
            ))
            .await?;
        match row.get::<_, i16>(0) {
            1 => Ok(LoginReserveOutcome::Reserved),
            0 => Ok(LoginReserveOutcome::Duplicate),
            -1 => Ok(LoginReserveOutcome::Capacity),
            _ => Err(SensitiveStateError::InvalidStoredRecord),
        }
    }

    pub(crate) async fn consume_login(
        &self,
        opaque_state: &str,
    ) -> Result<Option<LoginState>, SensitiveStateError> {
        let state_hash = self
            .keys
            .identifier_hash(STATE_IDENTIFIER_CONTEXT, opaque_state);
        let session = self.runtime.open_domain_session().await?;
        let row = session
            .run_operation(session.client().query_opt(
                "SELECT credential_configuration_id, key_id, aead_nonce, ciphertext, expires_at \
                   FROM registry_notary_api.preauthorization_login_consume_v1($1::bytea)",
                &[&&state_hash[..]],
            ))
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let configuration_id: String = row.get(0);
        let key_id: Vec<u8> = row.get(1);
        let nonce: Vec<u8> = row.get(2);
        let mut ciphertext = Zeroizing::new(row.get::<_, Vec<u8>>(3));
        let expires_at: OffsetDateTime = row.get(4);
        if key_id.ct_eq(&self.keys.key_id).unwrap_u8() != 1 {
            return Err(SensitiveStateError::InvalidStoredRecord);
        }
        let nonce = Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| SensitiveStateError::InvalidStoredRecord)?;
        let aad = login_aad(
            &state_hash,
            &self.keys.key_id,
            &configuration_id,
            expires_at,
        )?;
        let aead = RandomizedNonceKey::new(&AES_256_GCM, &self.keys.aead)
            .map_err(|_| SensitiveStateError::CryptographyUnavailable)?;
        let plaintext = aead
            .open_in_place(nonce, Aad::from(aad.as_slice()), &mut ciphertext)
            .map_err(|_| SensitiveStateError::InvalidStoredRecord)?;
        let mut decrypted = Zeroizing::new(
            serde_json::from_slice::<DecryptedLoginState>(plaintext)
                .map_err(|_| SensitiveStateError::InvalidStoredRecord)?,
        );
        if decrypted.version != LOGIN_RECORD_VERSION {
            return Err(SensitiveStateError::InvalidStoredRecord);
        }
        Ok(Some(LoginState {
            pkce_verifier: std::mem::take(&mut decrypted.pkce_verifier),
            nonce: std::mem::take(&mut decrypted.nonce),
            credential_configuration_id: configuration_id,
        }))
    }

    pub(crate) async fn reserve_transaction_code(
        &self,
        jti: &str,
        pin: &str,
        pin_length: u64,
        expires_at: OffsetDateTime,
    ) -> Result<bool, SensitiveStateError> {
        let expires_at = normalize_expiry(expires_at)?;
        let pin_length =
            i16::try_from(pin_length).map_err(|_| SensitiveStateError::InvalidStoredRecord)?;
        let jti_hash = self.keys.identifier_hash(JTI_IDENTIFIER_CONTEXT, jti);
        let verifier = self.keys.pin_verifier(&jti_hash, pin);
        let session = self.runtime.open_domain_session().await?;
        let row = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.preauthorization_tx_code_reserve_v1(\
                     $1::bytea, $2::bytea, $3::bytea, $4::smallint, $5::timestamptz)",
                &[
                    &&jti_hash[..],
                    &&self.keys.key_id[..],
                    &&verifier[..],
                    &pin_length,
                    &expires_at,
                ],
            ))
            .await?;
        Ok(row.get(0))
    }

    /// Verify without mutating the transaction-code row. A wrong PIN returns
    /// `None`, leaving the offer available for a bounded retry.
    pub(crate) async fn verify_transaction_code(
        &self,
        jti: &str,
        presented_pin: &str,
    ) -> Result<Option<VerifiedTransactionCode>, SensitiveStateError> {
        let jti_hash = self.keys.identifier_hash(JTI_IDENTIFIER_CONTEXT, jti);
        let session = self.runtime.open_domain_session().await?;
        let row = session
            .run_operation(session.client().query_opt(
                "SELECT key_id, pin_verifier, pin_length, expires_at \
                   FROM registry_notary_api.preauthorization_tx_code_peek_v1($1::bytea)",
                &[&&jti_hash[..]],
            ))
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let key_id: Vec<u8> = row.get(0);
        let stored_verifier: Vec<u8> = row.get(1);
        let pin_length: i16 = row.get(2);
        let _expires_at: OffsetDateTime = row.get(3);
        if key_id.ct_eq(&self.keys.key_id).unwrap_u8() != 1 || stored_verifier.len() != KEY_BYTES {
            return Err(SensitiveStateError::InvalidStoredRecord);
        }
        let expected = self.keys.pin_verifier(&jti_hash, presented_pin);
        let correct_length = usize::try_from(pin_length)
            .ok()
            .is_some_and(|length| presented_pin.len() == length);
        if !correct_length || expected.ct_eq(stored_verifier.as_slice()).unwrap_u8() != 1 {
            return Ok(None);
        }
        Ok(Some(VerifiedTransactionCode::new(jti_hash, expected)))
    }

    /// Return whether a live transaction-code verifier exists for this JTI.
    /// This lets the typed redemption boundary reject a signed no-PIN policy
    /// if storage contains a contradictory live PIN row.
    pub(crate) async fn has_live_transaction_code(
        &self,
        jti: &str,
    ) -> Result<bool, SensitiveStateError> {
        let jti_hash = self.keys.identifier_hash(JTI_IDENTIFIER_CONTEXT, jti);
        let session = self.runtime.open_domain_session().await?;
        let row = session
            .run_operation(session.client().query_opt(
                "SELECT key_id \
                   FROM registry_notary_api.preauthorization_tx_code_peek_v1($1::bytea)",
                &[&&jti_hash[..]],
            ))
            .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let key_id: Vec<u8> = row.get(0);
        if key_id.ct_eq(&self.keys.key_id).unwrap_u8() != 1 {
            return Err(SensitiveStateError::InvalidStoredRecord);
        }
        Ok(true)
    }

    /// Atomically claim the replay identifier and remove the transaction-code
    /// verifier. The proof is bound to the same keyed JTI hash.
    pub(crate) async fn redeem(
        &self,
        scope: &ReplayScope,
        jti: &str,
        code_expires_at: OffsetDateTime,
        transaction_code: Option<VerifiedTransactionCode>,
    ) -> Result<bool, SensitiveStateError> {
        let code_expires_at = normalize_expiry(code_expires_at)?;
        let scope_hash = self.keys.replay_scope_hash(scope);
        let jti_hash = self.keys.identifier_hash(JTI_IDENTIFIER_CONTEXT, jti);
        let expected_verifier = match transaction_code {
            Some(proof) => Some(
                proof
                    .into_verifier_for(&jti_hash)
                    .ok_or(SensitiveStateError::InvalidStoredRecord)?,
            ),
            None => None,
        };
        let pin_required = expected_verifier.is_some();
        let expected_parameter = expected_verifier.as_ref().map(<[u8; KEY_BYTES]>::as_slice);
        let session = self.runtime.open_domain_session().await?;
        let row = session
            .run_operation(session.client().query_one(
                "SELECT registry_notary_api.preauthorization_redeem_v1(\
                     $1::bytea, $2::bytea, $3::timestamptz, $4::boolean, $5::bytea)",
                &[
                    &&scope_hash[..],
                    &&jti_hash[..],
                    &code_expires_at,
                    &pin_required,
                    &expected_parameter,
                ],
            ))
            .await?;
        Ok(row.get(0))
    }
}

impl std::fmt::Debug for PostgresSensitiveState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresSensitiveState")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginReserveOutcome {
    Reserved,
    Duplicate,
    Capacity,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SensitiveStateKeys {
    aead: [u8; KEY_BYTES],
    pin_mac: [u8; KEY_BYTES],
    identifier: [u8; KEY_BYTES],
    key_id: [u8; KEY_BYTES],
}

impl SensitiveStateKeys {
    pub(crate) fn random() -> Result<Self, SensitiveStateError> {
        let mut master = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(master.as_mut_slice())
            .map_err(|_| SensitiveStateError::CryptographyUnavailable)?;
        Ok(Self::derive(&master))
    }

    fn derive(master: &[u8; KEY_BYTES]) -> Self {
        Self {
            aead: derive_key(master, b"login-aead"),
            pin_mac: derive_key(master, b"pin-mac"),
            identifier: derive_key(master, b"identifier-mac"),
            key_id: derive_key(master, b"key-id"),
        }
    }

    pub(crate) fn identifier_hash(&self, domain: &[u8], value: &str) -> [u8; KEY_BYTES] {
        hmac_framed(&self.identifier, &[domain, value.as_bytes()])
    }

    pub(crate) fn login_state_hash(&self, opaque_state: &str) -> [u8; KEY_BYTES] {
        self.identifier_hash(STATE_IDENTIFIER_CONTEXT, opaque_state)
    }

    pub(crate) fn jti_hash(&self, jti: &str) -> [u8; KEY_BYTES] {
        self.identifier_hash(JTI_IDENTIFIER_CONTEXT, jti)
    }

    pub(crate) fn replay_scope_hash(&self, scope: &ReplayScope) -> [u8; KEY_BYTES] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.identifier);
        let mut context = hmac::Context::with_key(&key);
        update_frame(&mut context, REPLAY_SCOPE_IDENTIFIER_CONTEXT);
        for (name, value) in scope.parts() {
            update_frame(&mut context, name.as_bytes());
            update_frame(&mut context, value.as_bytes());
        }
        tag_bytes(context.sign())
    }

    pub(crate) fn pin_verifier(&self, jti_hash: &[u8; KEY_BYTES], pin: &str) -> [u8; KEY_BYTES] {
        hmac_framed(
            &self.pin_mac,
            &[PIN_VERIFIER_CONTEXT, jti_hash, pin.as_bytes()],
        )
    }
}

impl std::fmt::Debug for SensitiveStateKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SensitiveStateKeys")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct EncryptedLoginState<'a> {
    version: u8,
    pkce_verifier: &'a str,
    nonce: &'a str,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct DecryptedLoginState {
    version: u8,
    pkce_verifier: String,
    nonce: String,
}

fn derive_key(master: &[u8; KEY_BYTES], label: &[u8]) -> [u8; KEY_BYTES] {
    hmac_framed(master, &[KDF_CONTEXT, label])
}

fn hmac_framed(key_bytes: &[u8], fields: &[&[u8]]) -> [u8; KEY_BYTES] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
    let mut context = hmac::Context::with_key(&key);
    for field in fields {
        update_frame(&mut context, field);
    }
    tag_bytes(context.sign())
}

fn update_frame(context: &mut hmac::Context, value: &[u8]) {
    context.update(&(value.len() as u64).to_be_bytes());
    context.update(value);
}

fn tag_bytes(tag: hmac::Tag) -> [u8; KEY_BYTES] {
    let mut bytes = [0_u8; KEY_BYTES];
    bytes.copy_from_slice(tag.as_ref());
    bytes
}

fn login_aad(
    state_hash: &[u8; KEY_BYTES],
    key_id: &[u8; KEY_BYTES],
    configuration_id: &str,
    expires_at: OffsetDateTime,
) -> Result<Vec<u8>, SensitiveStateError> {
    let mut aad = Vec::with_capacity(128 + configuration_id.len());
    aad.extend_from_slice(LOGIN_AAD_CONTEXT);
    aad.push(LOGIN_RECORD_VERSION);
    aad.extend_from_slice(state_hash);
    aad.extend_from_slice(key_id);
    aad.extend_from_slice(&expires_at.unix_timestamp().to_be_bytes());
    let length = u32::try_from(configuration_id.len())
        .map_err(|_| SensitiveStateError::InvalidStoredRecord)?;
    aad.extend_from_slice(&length.to_be_bytes());
    aad.extend_from_slice(configuration_id.as_bytes());
    Ok(aad)
}

fn normalize_expiry(expires_at: OffsetDateTime) -> Result<OffsetDateTime, SensitiveStateError> {
    OffsetDateTime::from_unix_timestamp(expires_at.unix_timestamp())
        .map_err(|_| SensitiveStateError::InvalidStoredRecord)
}

fn decode_master_key(encoded: &str) -> Result<Zeroizing<[u8; KEY_BYTES]>, SensitiveStateError> {
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| SensitiveStateError::InvalidKeyEncoding)?,
    );
    if decoded.len() != KEY_BYTES {
        return Err(SensitiveStateError::InvalidKeyLength);
    }
    let mut master = Zeroizing::new([0_u8; KEY_BYTES]);
    master.copy_from_slice(&decoded);
    Ok(master)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys(byte: u8) -> SensitiveStateKeys {
        SensitiveStateKeys::derive(&[byte; KEY_BYTES])
    }

    #[test]
    fn subkeys_and_identifier_domains_are_separate_and_stable() {
        let keys = test_keys(7);
        assert_ne!(keys.aead, keys.pin_mac);
        assert_ne!(keys.pin_mac, keys.identifier);
        assert_ne!(keys.identifier, keys.key_id);
        assert_ne!(
            keys.identifier_hash(STATE_IDENTIFIER_CONTEXT, "same"),
            keys.identifier_hash(JTI_IDENTIFIER_CONTEXT, "same")
        );
        assert_ne!(test_keys(7).key_id, test_keys(8).key_id);
    }

    #[test]
    fn login_aad_binds_identifier_configuration_and_expiry() {
        let keys = test_keys(9);
        let first_hash = keys.identifier_hash(STATE_IDENTIFIER_CONTEXT, "first");
        let other_hash = keys.identifier_hash(STATE_IDENTIFIER_CONTEXT, "other");
        let expiry = OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap();
        let aad = login_aad(&first_hash, &keys.key_id, "person", expiry).unwrap();
        assert_ne!(
            aad,
            login_aad(&other_hash, &keys.key_id, "person", expiry).unwrap()
        );
        assert_ne!(
            aad,
            login_aad(&first_hash, &keys.key_id, "other", expiry).unwrap()
        );
        assert_ne!(
            aad,
            login_aad(
                &first_hash,
                &keys.key_id,
                "person",
                expiry + time::Duration::seconds(1)
            )
            .unwrap()
        );
    }

    #[test]
    fn debug_and_errors_do_not_disclose_sensitive_values() {
        let config = SensitiveStateKeyConfig::new("SENTINEL_SECRET_ENV").unwrap();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("SENTINEL"));
        let keys = test_keys(11);
        let rendered = format!("{keys:?}");
        assert!(!rendered.contains("11"));
    }

    #[test]
    fn master_key_requires_unpadded_base64url_and_exactly_32_bytes() {
        let encoded = URL_SAFE_NO_PAD.encode([42_u8; KEY_BYTES]);
        assert_eq!(&*decode_master_key(&encoded).unwrap(), &[42_u8; KEY_BYTES]);
        assert_eq!(
            decode_master_key(&format!("{encoded}=")).unwrap_err(),
            SensitiveStateError::InvalidKeyEncoding
        );
        let short = URL_SAFE_NO_PAD.encode([42_u8; KEY_BYTES - 1]);
        assert_eq!(
            decode_master_key(&short).unwrap_err(),
            SensitiveStateError::InvalidKeyLength
        );
    }

    #[test]
    fn login_encryption_uses_fresh_nonces() {
        let keys = test_keys(13);
        let aead = RandomizedNonceKey::new(&AES_256_GCM, &keys.aead).unwrap();
        let mut first = b"sensitive-login-state".to_vec();
        let mut second = first.clone();
        let first_nonce = aead
            .seal_in_place_append_tag(Aad::from(LOGIN_AAD_CONTEXT), &mut first)
            .unwrap();
        let second_nonce = aead
            .seal_in_place_append_tag(Aad::from(LOGIN_AAD_CONTEXT), &mut second)
            .unwrap();
        assert_ne!(first_nonce.as_ref(), second_nonce.as_ref());
    }
}
