// SPDX-License-Identifier: Apache-2.0

//! Field-encryption key state for restricted Registry Engine fields.
//!
//! One [`FieldEncryptionService`] holds the active data-encryption key (DEK)
//! for a registry. Envelopes are produced and opened by
//! `registry-platform-crypto`'s field primitives under the active key version;
//! older key versions are not held in memory, so a read of an envelope sealed
//! under a superseded version fails closed instead of being skipped.
//!
//! Key state lives in `registry_internal.registry_field_encryption_keys`. The
//! Transit provider activates key version 1 by generating a data key and
//! inserting its wrapped form with `ON CONFLICT DO NOTHING`; when another
//! concurrent activation won the insert, the existing row is loaded and
//! unwrapped instead. Phase 1 holds exactly one row, at key version 1:
//! activation refuses a store that already holds more than one row or a row
//! from any other version, because envelopes sealed under a superseded
//! version cannot be opened and a second row would strand every earlier one.
//! The local-file provider stores only a domain-separated SHA-256 identifier
//! for its uniformly random DEK. The identifier lets startup refuse a changed
//! or mis-mounted file before admitting writes, without persisting the key.
//!
//! Call sites hold an `Option<Arc<FieldEncryptionService>>`; `None` means
//! field encryption is not ready, which is only acceptable while the active
//! package declares no encrypted field.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use registry_platform_config::{SecretError, SecretProvider, SecretReference, SecretResolver};
use registry_platform_crypto::field_encryption::{
    blind_index_hmac, derive_field_aead_key, derive_field_index_key, envelope_key_version,
    open_field, parse_envelope_member, seal_field, FieldAad, FieldCryptoError, FieldKeyInfo,
    FIELD_ENCRYPTION_ALGORITHM,
};
use registry_platform_crypto::transit_datakey::{
    transit_wrapped_key_version, TransitDataKeyClient, TransitDataKeyConfig,
};
use registry_platform_crypto::KeyProviderKind;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_postgres::GenericClient;
use zeroize::Zeroizing;

use crate::contract::{FieldTypeSource, NormalizationStep};

/// The label recorded for the Transit datakey provider in key rows.
pub const TRANSIT_PROVIDER_KIND: &str = "transit_datakey";
/// The label recorded for the local-file datakey provider in key rows.
pub const LOCAL_FILE_PROVIDER_KIND: &str = "local_datakey_file";

/// Value-free failure while activating or using field-encryption key state.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FieldEncryptionError {
    #[error("the field-encryption data key is unavailable")]
    DataKeyUnavailable,
    #[error("the field-encryption key state is invalid")]
    KeyStateInvalid,
    #[error("the field-encryption key state belongs to another provider")]
    ProviderMismatch,
    #[error("the field-encryption key store is unavailable")]
    KeyStoreUnavailable,
}

impl From<FieldCryptoError> for FieldEncryptionError {
    fn from(_: FieldCryptoError) -> Self {
        Self::KeyStateInvalid
    }
}

impl From<SecretError> for FieldEncryptionError {
    fn from(_: SecretError) -> Self {
        Self::DataKeyUnavailable
    }
}

/// Which custodian holds the registry's field-encryption data keys.
#[derive(Clone, Debug)]
pub enum FieldEncryptionProvider {
    /// Vault/OpenBao Transit, reached through a local Unix-socket proxy.
    Transit(TransitDataKeyConfig),
    /// A base64-encoded 32-byte data key in one owner-only secret file.
    LocalFile { dek_ref: SecretReference },
}

/// One stored key row, as the runtime reads it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredFieldKey {
    pub key_version: i32,
    pub provider_kind: String,
    pub algorithm: String,
    pub key_identifier: String,
    pub wrapped_dek: Option<String>,
    pub transit_key_version: Option<i32>,
}

/// A key row the Transit provider proposes at first activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewFieldKey {
    pub key_version: i32,
    pub provider_kind: &'static str,
    pub algorithm: &'static str,
    pub key_identifier: String,
    pub wrapped_dek: Option<String>,
    pub transit_key_version: Option<i32>,
    pub activated_package_revision: String,
}

/// Read and first-write access to `registry_field_encryption_keys`.
///
/// Implemented for every PostgreSQL client the runtime can hold, so
/// activation runs on the same connection and transaction discipline as its
/// caller.
#[async_trait]
pub trait FieldKeyStore: Send + Sync {
    /// The newest key row, or `None` before the first activation.
    async fn latest_field_key(&self) -> Result<Option<StoredFieldKey>, FieldEncryptionError>;

    /// The number of stored key rows.
    async fn field_key_row_count(&self) -> Result<u32, FieldEncryptionError>;

    /// Insert the first key row. Returns `false` when a concurrent activation
    /// already inserted a row for that version.
    async fn insert_first_field_key(&self, key: &NewFieldKey)
        -> Result<bool, FieldEncryptionError>;
}

#[async_trait]
impl<T: GenericClient + Send + Sync> FieldKeyStore for T {
    async fn latest_field_key(&self) -> Result<Option<StoredFieldKey>, FieldEncryptionError> {
        let row = self
            .query_opt(
                "SELECT key_version, provider_kind, algorithm, key_identifier,
                        wrapped_dek, transit_key_version
                 FROM registry_internal.registry_field_encryption_keys
                 ORDER BY key_version DESC
                 LIMIT 1",
                &[],
            )
            .await
            .map_err(|_| FieldEncryptionError::KeyStoreUnavailable)?;
        Ok(row.map(|row| StoredFieldKey {
            key_version: row.get(0),
            provider_kind: row.get(1),
            algorithm: row.get(2),
            key_identifier: row.get(3),
            wrapped_dek: row.get(4),
            transit_key_version: row.get(5),
        }))
    }

    async fn field_key_row_count(&self) -> Result<u32, FieldEncryptionError> {
        let count: i64 = self
            .query_one(
                "SELECT count(*) FROM registry_internal.registry_field_encryption_keys",
                &[],
            )
            .await
            .map_err(|_| FieldEncryptionError::KeyStoreUnavailable)?
            .get(0);
        u32::try_from(count).map_err(|_| FieldEncryptionError::KeyStoreUnavailable)
    }

    async fn insert_first_field_key(
        &self,
        key: &NewFieldKey,
    ) -> Result<bool, FieldEncryptionError> {
        let changed = self
            .execute(
                "INSERT INTO registry_internal.registry_field_encryption_keys (
                     key_version, provider_kind, algorithm, key_identifier,
                     wrapped_dek, transit_key_version, activated_package_revision
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (key_version) DO NOTHING",
                &[
                    &key.key_version,
                    &key.provider_kind,
                    &key.algorithm,
                    &key.key_identifier,
                    &key.wrapped_dek,
                    &key.transit_key_version,
                    &key.activated_package_revision,
                ],
            )
            .await
            .map_err(|_| FieldEncryptionError::KeyStoreUnavailable)?;
        Ok(changed == 1)
    }
}

/// The active field-encryption key state of one registry.
///
/// `Debug` never renders the data key. A constructed service is always ready;
/// readiness questions live with the caller's `Option<Arc<_>>`.
pub struct FieldEncryptionService {
    registry_id: String,
    key_version: u32,
    dek: Zeroizing<[u8; 32]>,
    provider_kind: KeyProviderKind,
}

impl FieldEncryptionService {
    /// Activate key version 1 during governed package apply, or open the
    /// already-activated key on an exact-target retry.
    ///
    /// # Errors
    /// [`FieldEncryptionError`] when the provider is unreachable, the stored
    /// rows disagree with the configured provider, or the data key cannot be
    /// unwrapped or decoded. Every failure is fail-closed.
    pub async fn activate(
        provider: &FieldEncryptionProvider,
        registry_id: &str,
        activated_package_revision: &str,
        secrets: &SecretResolver,
        store: &impl FieldKeyStore,
    ) -> Result<Self, FieldEncryptionError> {
        match provider {
            FieldEncryptionProvider::Transit(config) => {
                // Phase 1 holds exactly one key row, at version 1. Zero rows
                // mean first activation; anything else fails closed before the
                // provider is reached, because the runtime below opens
                // envelopes only under the active version and a second row
                // would strand every earlier one.
                let stored = singleton_stored_key(store).await?;
                if stored
                    .as_ref()
                    .is_some_and(|stored| stored.key_version != 1)
                {
                    return Err(FieldEncryptionError::KeyStateInvalid);
                }
                let client = TransitDataKeyClient::initialize(config.clone())
                    .await
                    .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?;
                if let Some(stored) = stored {
                    let (key_version, dek) = unwrap_stored_transit_key(&client, &stored).await?;
                    verify_key_identifier(registry_id, &dek, &stored.key_identifier)?;
                    return Ok(Self::from_data_key(
                        registry_id.to_owned(),
                        key_version,
                        dek,
                        KeyProviderKind::TransitDatakey,
                    ));
                }
                let (dek, wrapped) = client
                    .generate_datakey()
                    .await
                    .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?;
                let unwrapped = client
                    .unwrap_datakey(&wrapped)
                    .await
                    .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?;
                // Verify the exact pair that will become durable. The
                // client's startup self-test exercises a separate pair.
                if dek.as_ref() != unwrapped.as_ref() {
                    return Err(FieldEncryptionError::DataKeyUnavailable);
                }
                drop(unwrapped);
                let transit_key_version = transit_wrapped_key_version(&wrapped)
                    .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?;
                let proposed = NewFieldKey {
                    key_version: 1,
                    provider_kind: TRANSIT_PROVIDER_KIND,
                    algorithm: FIELD_ENCRYPTION_ALGORITHM,
                    key_identifier: key_identifier(registry_id, &dek),
                    wrapped_dek: Some(wrapped),
                    transit_key_version: Some(
                        i32::try_from(transit_key_version)
                            .map_err(|_| FieldEncryptionError::KeyStateInvalid)?,
                    ),
                    activated_package_revision: activated_package_revision.to_owned(),
                };
                if store.insert_first_field_key(&proposed).await? {
                    return Ok(Self::from_data_key(
                        registry_id.to_owned(),
                        1,
                        dek,
                        KeyProviderKind::TransitDatakey,
                    ));
                }
                // A concurrent activation won the first write. The winner's
                // row is now authoritative, so the proposed key is discarded
                // and the stored row is unwrapped instead.
                let stored = store
                    .latest_field_key()
                    .await?
                    .ok_or(FieldEncryptionError::KeyStateInvalid)?;
                let (key_version, dek) = unwrap_stored_transit_key(&client, &stored).await?;
                verify_key_identifier(registry_id, &dek, &stored.key_identifier)?;
                Ok(Self::from_data_key(
                    registry_id.to_owned(),
                    key_version,
                    dek,
                    KeyProviderKind::TransitDatakey,
                ))
            }
            FieldEncryptionProvider::LocalFile { dek_ref } => {
                if dek_ref.provider() != SecretProvider::File {
                    return Err(FieldEncryptionError::DataKeyUnavailable);
                }
                let dek = resolve_local_dek(dek_ref, secrets)?;
                let identifier = key_identifier(registry_id, &dek);
                if let Some(stored) = singleton_stored_key(store).await? {
                    validate_local_stored_key(&stored, &identifier)?;
                } else {
                    let proposed = NewFieldKey {
                        key_version: 1,
                        provider_kind: LOCAL_FILE_PROVIDER_KIND,
                        algorithm: FIELD_ENCRYPTION_ALGORITHM,
                        key_identifier: identifier.clone(),
                        wrapped_dek: None,
                        transit_key_version: None,
                        activated_package_revision: activated_package_revision.to_owned(),
                    };
                    if !store.insert_first_field_key(&proposed).await? {
                        let stored = store
                            .latest_field_key()
                            .await?
                            .ok_or(FieldEncryptionError::KeyStateInvalid)?;
                        validate_local_stored_key(&stored, &identifier)?;
                    }
                }
                Ok(Self::from_data_key(
                    registry_id.to_owned(),
                    1,
                    dek,
                    KeyProviderKind::LocalDatakeyFile,
                ))
            }
        }
    }

    /// Open only previously activated key state. Runtime startup and
    /// diagnostics use this path, so neither can select a first custodian.
    pub async fn open_existing(
        provider: &FieldEncryptionProvider,
        registry_id: &str,
        secrets: &SecretResolver,
        store: &impl FieldKeyStore,
    ) -> Result<Self, FieldEncryptionError> {
        let stored = singleton_stored_key(store)
            .await?
            .ok_or(FieldEncryptionError::KeyStateInvalid)?;
        if stored.key_version != 1 {
            return Err(FieldEncryptionError::KeyStateInvalid);
        }
        match provider {
            FieldEncryptionProvider::Transit(config) => {
                let client = TransitDataKeyClient::initialize(config.clone())
                    .await
                    .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?;
                let (key_version, dek) = unwrap_stored_transit_key(&client, &stored).await?;
                verify_key_identifier(registry_id, &dek, &stored.key_identifier)?;
                Ok(Self::from_data_key(
                    registry_id.to_owned(),
                    key_version,
                    dek,
                    KeyProviderKind::TransitDatakey,
                ))
            }
            FieldEncryptionProvider::LocalFile { dek_ref } => {
                if dek_ref.provider() != SecretProvider::File {
                    return Err(FieldEncryptionError::DataKeyUnavailable);
                }
                let dek = resolve_local_dek(dek_ref, secrets)?;
                validate_local_stored_key(&stored, &key_identifier(registry_id, &dek))?;
                Ok(Self::from_data_key(
                    registry_id.to_owned(),
                    1,
                    dek,
                    KeyProviderKind::LocalDatakeyFile,
                ))
            }
        }
    }

    /// Assemble key state from an already-resolved data key.
    pub(crate) fn from_data_key(
        registry_id: String,
        key_version: u32,
        dek: Zeroizing<[u8; 32]>,
        provider_kind: KeyProviderKind,
    ) -> Self {
        Self {
            registry_id,
            key_version,
            dek,
            provider_kind,
        }
    }

    /// The active key version, recorded in every sealed envelope.
    #[must_use]
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// The shared provider-kind label for posture and diagnostics.
    #[must_use]
    pub fn provider_kind(&self) -> KeyProviderKind {
        self.provider_kind
    }

    /// A constructed service is always ready to seal and open fields.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        true
    }

    /// Seal one field value into a Version 1 envelope under a fresh nonce.
    ///
    /// # Errors
    /// [`FieldCryptoError::FieldTooLarge`] when the value exceeds the field
    /// encryption size limit.
    pub fn seal(
        &self,
        entity_id: &str,
        field_id: &str,
        record_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, FieldCryptoError> {
        let key = derive_field_aead_key(&self.dek, &self.key_info(entity_id, field_id));
        seal_field(
            &key,
            &self.aad(entity_id, field_id, record_id, self.key_version),
            plaintext,
        )
    }

    /// Open one Version 1 envelope. The envelope's recorded key version is
    /// read before any authentication attempt, and anything but the active
    /// version fails closed.
    ///
    /// # Errors
    /// [`FieldCryptoError`] for any structural defect, any version other than
    /// the active one, or any tamper with the envelope.
    pub fn open(
        &self,
        entity_id: &str,
        field_id: &str,
        record_id: &str,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, FieldCryptoError> {
        let stored_version = envelope_key_version(envelope)?;
        if stored_version != self.key_version {
            return Err(FieldCryptoError::AuthenticationFailed);
        }
        let key = derive_field_aead_key(&self.dek, &self.key_info(entity_id, field_id));
        open_field(
            &key,
            &self.aad(entity_id, field_id, record_id, stored_version),
            envelope,
        )
    }

    /// The blind index of one normalized value under this key state.
    #[must_use]
    pub fn blind_index(&self, entity_id: &str, field_id: &str, normalized: &str) -> [u8; 32] {
        let key = derive_field_index_key(&self.dek, &self.key_info(entity_id, field_id));
        blind_index_hmac(&key, normalized)
    }

    /// Apply the declared normalization steps in order. The vocabulary is the
    /// authored `NormalizationStep` list; unknown steps cannot occur.
    #[must_use]
    pub fn normalize(steps: &[NormalizationStep], value: &str) -> String {
        let mut normalized = value.to_owned();
        for step in steps {
            normalized = match step {
                NormalizationStep::Trim => normalized.trim().to_owned(),
                NormalizationStep::Uppercase => normalized.to_uppercase(),
                NormalizationStep::Lowercase => normalized.to_lowercase(),
                NormalizationStep::CollapseWhitespace => normalized
                    .split_whitespace()
                    .collect::<Vec<&str>>()
                    .join(" "),
                NormalizationStep::RemoveSeparators => normalized
                    .chars()
                    .filter(|character| !matches!(character, ' ' | '-' | '/' | '.'))
                    .collect(),
            };
        }
        normalized
    }

    fn key_info<'a>(&'a self, entity_id: &'a str, field_id: &'a str) -> FieldKeyInfo<'a> {
        FieldKeyInfo {
            registry_id: &self.registry_id,
            entity_id,
            field_id,
        }
    }

    fn aad<'a>(
        &'a self,
        entity_id: &'a str,
        field_id: &'a str,
        record_id: &'a str,
        key_version: u32,
    ) -> FieldAad<'a> {
        FieldAad {
            registry_id: &self.registry_id,
            entity_id,
            field_id,
            record_id,
            key_version,
        }
    }
}

impl fmt::Debug for FieldEncryptionService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FieldEncryptionService")
            .field("key_version", &self.key_version)
            .field("provider_kind", &self.provider_kind)
            .finish_non_exhaustive()
    }
}

async fn singleton_stored_key(
    store: &impl FieldKeyStore,
) -> Result<Option<StoredFieldKey>, FieldEncryptionError> {
    match store.field_key_row_count().await? {
        0 => Ok(None),
        1 => store
            .latest_field_key()
            .await?
            .ok_or(FieldEncryptionError::KeyStateInvalid)
            .map(Some),
        _ => Err(FieldEncryptionError::KeyStateInvalid),
    }
}

fn resolve_local_dek(
    dek_ref: &SecretReference,
    secrets: &SecretResolver,
) -> Result<Zeroizing<[u8; 32]>, FieldEncryptionError> {
    let secret = secrets.resolve_reference(dek_ref)?;
    let decoded = Zeroizing::new(
        STANDARD
            .decode(secret.expose_secret().trim_ascii())
            .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?,
    );
    let dek: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?;
    Ok(Zeroizing::new(dek))
}

fn key_identifier(registry_id: &str, dek: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"breg-field-dek-identifier/v1");
    digest.update(
        u32::try_from(registry_id.len())
            .expect("registry identifiers are bounded")
            .to_be_bytes(),
    );
    digest.update(registry_id.as_bytes());
    digest.update(dek);
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn verify_key_identifier(
    registry_id: &str,
    dek: &[u8; 32],
    stored: &str,
) -> Result<(), FieldEncryptionError> {
    if stored == key_identifier(registry_id, dek) {
        Ok(())
    } else {
        Err(FieldEncryptionError::KeyStateInvalid)
    }
}

fn validate_local_stored_key(
    stored: &StoredFieldKey,
    identifier: &str,
) -> Result<(), FieldEncryptionError> {
    if stored.key_version == 1
        && stored.provider_kind == LOCAL_FILE_PROVIDER_KIND
        && stored.algorithm == FIELD_ENCRYPTION_ALGORITHM
        && stored.key_identifier == identifier
        && stored.wrapped_dek.is_none()
        && stored.transit_key_version.is_none()
    {
        Ok(())
    } else if stored.provider_kind != LOCAL_FILE_PROVIDER_KIND {
        Err(FieldEncryptionError::ProviderMismatch)
    } else {
        Err(FieldEncryptionError::KeyStateInvalid)
    }
}

/// Validate one stored Transit row and unwrap its data key.
async fn unwrap_stored_transit_key(
    client: &TransitDataKeyClient,
    stored: &StoredFieldKey,
) -> Result<(u32, Zeroizing<[u8; 32]>), FieldEncryptionError> {
    if stored.provider_kind != TRANSIT_PROVIDER_KIND
        || stored.algorithm != FIELD_ENCRYPTION_ALGORITHM
        // Phase 1: exactly version 1; multi-version support arrives with
        // rotation in Phase 2.
        || stored.key_version != 1
        || stored
            .transit_key_version
            .is_none_or(|version| version <= 0)
        || stored.wrapped_dek.as_deref().is_none_or(str::is_empty)
    {
        return Err(FieldEncryptionError::KeyStateInvalid);
    }
    let dek = client
        .unwrap_datakey(
            stored
                .wrapped_dek
                .as_deref()
                .ok_or(FieldEncryptionError::KeyStateInvalid)?,
        )
        .await
        .map_err(|_| FieldEncryptionError::DataKeyUnavailable)?;
    let key_version =
        u32::try_from(stored.key_version).map_err(|_| FieldEncryptionError::KeyStateInvalid)?;
    Ok((key_version, dek))
}

/// Convenience alias for the shared service handle type.
pub type SharedFieldEncryptionService = Arc<FieldEncryptionService>;

/// Open one stored envelope member into its JSON value at a response edge.
///
/// Row decode keeps the tagged member so journal snapshots and captured rows
/// canonicalize byte-identically; only the enumerated response edges call this.
/// A null member stays null. A member that is neither null nor the tagged
/// envelope shape, and any open failure, is a fail-closed
/// [`FieldCryptoError`] carrying no value.
pub(crate) fn open_member_value(
    service: &FieldEncryptionService,
    entity_id: &str,
    field_id: &str,
    record_id: &str,
    field_type: &FieldTypeSource,
    member: &Value,
) -> Result<Option<Value>, FieldCryptoError> {
    if member.is_null() {
        return Ok(None);
    }
    let envelope = parse_envelope_member(member).ok_or(FieldCryptoError::MalformedEnvelope)?;
    let plaintext = service.open(entity_id, field_id, record_id, &envelope)?;
    let value = match field_type {
        FieldTypeSource::Structured { .. } => serde_json::from_slice::<Value>(&plaintext)
            .map_err(|_| FieldCryptoError::MalformedEnvelope)?,
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Decimal { .. } => Value::String(
            String::from_utf8(plaintext.as_slice().to_vec())
                .map_err(|_| FieldCryptoError::MalformedEnvelope)?,
        ),
        // The compiler refuses encrypted storage for every other type.
        _ => return Err(FieldCryptoError::MalformedEnvelope),
    };
    Ok(Some(value))
}

/// Open every encrypted member of one caller-facing member map.
///
/// Members stay tagged until the enumerated response edges call this, so
/// stored, cached, and frozen maps never depend on decryption; opening at the
/// edge fails the whole map closed, value-free. A member key names the field's
/// active API name for row-shaped maps and the field id for retained-snapshot
/// maps. An entity without encrypted fields returns without touching key
/// state, and a map that simply omits an encrypted field leaves it omitted.
pub(crate) fn open_member_map(
    entity: &crate::model::CompiledEntity,
    record_id: &str,
    members: &mut serde_json::Map<String, Value>,
    service: &FieldEncryptionService,
    keyed_by_api_name: bool,
) -> Result<(), FieldCryptoError> {
    for field in entity
        .stored_fields
        .iter()
        .filter(|field| field.logical.encryption.is_some())
    {
        let key = if keyed_by_api_name {
            field.logical.api_name.as_str()
        } else {
            field.logical.id.as_str()
        };
        let Some(member) = members.get_mut(key) else {
            continue;
        };
        let opened = open_member_value(
            service,
            &entity.id,
            &field.logical.id,
            record_id,
            &field.logical.field_type,
            member,
        )?;
        *member = opened.unwrap_or(Value::Null);
    }
    Ok(())
}

/// The failure of opening one batch answer's sealed result members at a serve
/// edge. Value-free by construction: neither variant carries member material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchOpenError {
    /// Key state is absent while a result carries members that need opening.
    KeyStateUnavailable,
    /// A result lacks the record id its sealed members are bound to, or an
    /// open failed, so the answer cannot serve opened.
    OpenFailed,
}

/// Open the sealed members of one batch answer's results at a serve edge.
///
/// Fresh batch bodies, retained ingestion receipts, and their replays all
/// name each record by `id` beside a `data` member map keyed by API name;
/// this is the one per-record opening for every such results array. Entities
/// without encrypted fields and results without a `data` map never touch key
/// state, which resolves lazily on the first map that needs opening. Returns
/// whether any map was opened, so a caller can serve unopened bytes through
/// exactly as stored.
///
/// The per-field pass reads only the active entity's encrypted members, so an
/// envelope stored under a member name the active package no longer declares
/// would otherwise survive untouched. Any member that still parses as a
/// sealed envelope after opening fails the whole answer closed: sealed
/// ciphertext never leaves as an answer.
pub(crate) fn open_batch_result_members(
    entity: &crate::model::CompiledEntity,
    results: &mut [Value],
    service: Option<&FieldEncryptionService>,
) -> Result<bool, BatchOpenError> {
    if !entity
        .fields
        .values()
        .any(|field| field.encryption.is_some())
    {
        return Ok(false);
    }
    let mut opened = false;
    for item in results {
        let record_id = item
            .get("id")
            .and_then(Value::as_str)
            .filter(|identifier| !identifier.is_empty())
            .ok_or(BatchOpenError::OpenFailed)?
            .to_owned();
        if let Some(data) = item.get_mut("data").and_then(Value::as_object_mut) {
            let service = service.ok_or(BatchOpenError::KeyStateUnavailable)?;
            open_member_map(entity, &record_id, data, service, true)
                .map_err(|_| BatchOpenError::OpenFailed)?;
            if data
                .values()
                .any(|member| parse_envelope_member(member).is_some())
            {
                return Err(BatchOpenError::OpenFailed);
            }
            opened = true;
        }
    }
    Ok(opened)
}

/// Default Transit request timeout, matching the attachment transports.
const DEFAULT_TRANSIT_TIMEOUT_MILLISECONDS: u64 = 5_000;
/// Upper bound on a configured Unix-socket path.
const MAX_UNIX_SOCKET_PATH_CHARS: usize = 4_096;

/// Raw `fieldEncryption` deployment block, absent by default.
#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RawFieldEncryptionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<RawFieldEncryptionProvider>,
}

/// Raw provider binding; the `kind` member selects the custodian.
#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum RawFieldEncryptionProvider {
    Transit {
        #[cfg_attr(feature = "schema", schemars(length(min = 2, max = 4096)))]
        unix_socket_path: String,
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
        mount: String,
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
        key_name: String,
        #[serde(default = "default_transit_timeout_milliseconds")]
        #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 30_000)))]
        timeout_milliseconds: u64,
    },
    LocalFile {
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 140)))]
        dek_ref: String,
    },
}

fn default_transit_timeout_milliseconds() -> u64 {
    DEFAULT_TRANSIT_TIMEOUT_MILLISECONDS
}

/// Validated field-encryption deployment settings. `Debug` reveals only the
/// provider kind label.
#[derive(Clone, Default)]
pub struct FieldEncryptionConfig {
    provider: Option<FieldEncryptionProvider>,
}

/// The single reason raw field-encryption settings are refused.
#[derive(Debug, Error)]
#[error("the field encryption binding is invalid")]
pub struct InvalidFieldEncryptionConfig;

impl FieldEncryptionConfig {
    /// Validate one raw block.
    pub(crate) fn from_raw(
        raw: RawFieldEncryptionConfig,
    ) -> Result<Self, InvalidFieldEncryptionConfig> {
        let provider = match raw.provider {
            None => None,
            Some(RawFieldEncryptionProvider::Transit {
                unix_socket_path,
                mount,
                key_name,
                timeout_milliseconds,
            }) => {
                if unix_socket_path.len() > MAX_UNIX_SOCKET_PATH_CHARS {
                    return Err(InvalidFieldEncryptionConfig);
                }
                Some(FieldEncryptionProvider::Transit(
                    TransitDataKeyConfig::new(
                        unix_socket_path,
                        mount,
                        key_name,
                        Duration::from_millis(timeout_milliseconds),
                    )
                    .map_err(|_| InvalidFieldEncryptionConfig)?,
                ))
            }
            Some(RawFieldEncryptionProvider::LocalFile { dek_ref }) => {
                let dek_ref =
                    SecretReference::parse(dek_ref).map_err(|_| InvalidFieldEncryptionConfig)?;
                if dek_ref.provider() != SecretProvider::File {
                    return Err(InvalidFieldEncryptionConfig);
                }
                Some(FieldEncryptionProvider::LocalFile { dek_ref })
            }
        };
        Ok(Self { provider })
    }

    /// The configured provider, when field encryption is configured at all.
    #[must_use]
    pub fn provider(&self) -> Option<&FieldEncryptionProvider> {
        self.provider.as_ref()
    }
}

impl fmt::Debug for FieldEncryptionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match &self.provider {
            None => "none",
            Some(FieldEncryptionProvider::Transit(_)) => TRANSIT_PROVIDER_KIND,
            Some(FieldEncryptionProvider::LocalFile { .. }) => LOCAL_FILE_PROVIDER_KIND,
        };
        write!(formatter, "FieldEncryptionConfig({label})")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::contract::NormalizationStep as Step;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::sync::Mutex;

    const REGISTRY_ID: &str = "example-licensing";
    const ENTITY_ID: &str = "professional_licence";
    const FIELD_ID: &str = "holder_name";
    const RECORD_ID: &str = "rec-000042";
    const DEK: [u8; 32] = [0x5A; 32];

    fn service(key_version: u32) -> FieldEncryptionService {
        FieldEncryptionService::from_data_key(
            REGISTRY_ID.to_owned(),
            key_version,
            Zeroizing::new(DEK),
            KeyProviderKind::TransitDatakey,
        )
    }

    /// In-memory key store for activation logic that must not touch
    /// PostgreSQL.
    struct MemoryKeyStore {
        rows: Mutex<Vec<StoredFieldKey>>,
    }

    impl MemoryKeyStore {
        fn new(rows: Vec<StoredFieldKey>) -> Self {
            Self {
                rows: Mutex::new(rows),
            }
        }
    }

    #[async_trait]
    impl FieldKeyStore for MemoryKeyStore {
        async fn latest_field_key(&self) -> Result<Option<StoredFieldKey>, FieldEncryptionError> {
            Ok(self
                .rows
                .lock()
                .expect("test key store locks")
                .last()
                .cloned())
        }

        async fn field_key_row_count(&self) -> Result<u32, FieldEncryptionError> {
            Ok(
                u32::try_from(self.rows.lock().expect("test key store locks").len())
                    .expect("test rows fit a u32"),
            )
        }

        async fn insert_first_field_key(
            &self,
            key: &NewFieldKey,
        ) -> Result<bool, FieldEncryptionError> {
            let mut rows = self.rows.lock().expect("test key store locks");
            if rows.iter().any(|row| row.key_version == key.key_version) {
                return Ok(false);
            }
            rows.push(StoredFieldKey {
                key_version: key.key_version,
                provider_kind: key.provider_kind.to_owned(),
                algorithm: key.algorithm.to_owned(),
                key_identifier: key.key_identifier.clone(),
                wrapped_dek: key.wrapped_dek.clone(),
                transit_key_version: key.transit_key_version,
            });
            Ok(true)
        }
    }

    fn stored_row(key_version: i32, provider_kind: &str) -> StoredFieldKey {
        StoredFieldKey {
            key_version,
            provider_kind: provider_kind.to_owned(),
            algorithm: FIELD_ENCRYPTION_ALGORITHM.to_owned(),
            key_identifier: key_identifier(REGISTRY_ID, &DEK),
            wrapped_dek: Some(String::new()),
            transit_key_version: Some(3),
        }
    }

    #[test]
    fn normalize_composes_declared_steps_in_order() {
        use Step::*;
        assert_eq!(
            FieldEncryptionService::normalize(&[Trim, Uppercase], "  ada lovelace  "),
            "ADA LOVELACE"
        );
        assert_eq!(
            FieldEncryptionService::normalize(&[CollapseWhitespace], " Ada\tlovelace \n  Jr. "),
            "Ada lovelace Jr."
        );
        assert_eq!(
            FieldEncryptionService::normalize(&[RemoveSeparators], "123 456-789/0.1"),
            "12345678901"
        );
        assert_eq!(
            FieldEncryptionService::normalize(
                &[Lowercase, CollapseWhitespace, RemoveSeparators, Trim],
                " A-B C D "
            ),
            "abcd"
        );
        assert_eq!(
            FieldEncryptionService::normalize(&[], " Ada Lovelace "),
            " Ada Lovelace "
        );
    }

    #[test]
    fn seal_open_and_blind_index_round_trip_under_the_active_version() {
        let service = service(7);
        assert_eq!(service.key_version(), 7);
        assert_eq!(service.provider_kind(), KeyProviderKind::TransitDatakey);
        assert!(service.is_ready());
        let envelope = service
            .seal(ENTITY_ID, FIELD_ID, RECORD_ID, b"restricted holder name")
            .expect("field seals");
        let opened = service
            .open(ENTITY_ID, FIELD_ID, RECORD_ID, &envelope)
            .expect("field opens");
        assert_eq!(opened.as_slice(), b"restricted holder name");
        let normalized =
            FieldEncryptionService::normalize(&[Step::Trim, Step::Uppercase], " Ada Lovelace ");
        let index = service.blind_index(ENTITY_ID, FIELD_ID, &normalized);
        assert_eq!(index.len(), 32);
        assert_eq!(
            index,
            service.blind_index(ENTITY_ID, FIELD_ID, "ADA LOVELACE")
        );
        assert_ne!(
            index,
            service.blind_index("other_entity", FIELD_ID, "ADA LOVELACE")
        );
    }

    #[test]
    fn open_fails_closed_on_any_other_key_version() {
        let sealing = service(2);
        let envelope = sealing
            .seal(ENTITY_ID, FIELD_ID, RECORD_ID, b"restricted holder name")
            .expect("field seals");
        assert_eq!(
            sealing
                .open(ENTITY_ID, FIELD_ID, RECORD_ID, &envelope)
                .expect("field opens")
                .as_slice(),
            b"restricted holder name"
        );
        let rotated = service(3);
        assert_eq!(
            rotated.open(ENTITY_ID, FIELD_ID, RECORD_ID, &envelope),
            Err(FieldCryptoError::AuthenticationFailed)
        );
        // The wrong record id or field also fails closed.
        assert_eq!(
            sealing.open(ENTITY_ID, FIELD_ID, "rec-000043", &envelope),
            Err(FieldCryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn debug_never_renders_the_data_key() {
        let rendered = format!("{:?}", service(1));
        assert!(rendered.contains("key_version"), "{rendered}");
        assert!(!rendered.contains("Zz"), "no data-key bytes in {rendered}");
    }

    fn secret_root(case: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "breg-field-encryption-{case}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("secret root creates");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secret root is owner-only");
        root
    }

    fn write_local_dek(root: &std::path::Path, contents: &[u8]) -> SecretReference {
        let path = root.join("breg-field-dek");
        fs::write(&path, contents).expect("data key file writes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("data key file is owner-only");
        SecretReference::parse("secret:file/breg-field-dek").expect("fixture reference parses")
    }

    #[tokio::test]
    async fn local_file_provider_activates_bound_version_one() {
        let root = secret_root("activates");
        let dek_ref = write_local_dek(&root, format!("{}\n", STANDARD.encode(DEK)).as_bytes());
        let secrets =
            SecretResolver::new([SecretProvider::File], &root).expect("fixture resolver builds");
        let store = MemoryKeyStore::new(Vec::new());
        let service = FieldEncryptionService::activate(
            &FieldEncryptionProvider::LocalFile { dek_ref },
            REGISTRY_ID,
            "sha256:fixture",
            &secrets,
            &store,
        )
        .await
        .expect("local file activates");
        assert_eq!(store.field_key_row_count().await.unwrap(), 1);
        assert_eq!(service.key_version(), 1);
        assert_eq!(service.provider_kind(), KeyProviderKind::LocalDatakeyFile);
        let envelope = service
            .seal(ENTITY_ID, FIELD_ID, RECORD_ID, b"restricted holder name")
            .expect("field seals");
        assert_eq!(
            service
                .open(ENTITY_ID, FIELD_ID, RECORD_ID, &envelope)
                .expect("field opens")
                .as_slice(),
            b"restricted holder name"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn local_file_provider_refuses_wrong_lengths_and_existing_rows() {
        let root = secret_root("refuses");
        let secrets =
            SecretResolver::new([SecretProvider::File], &root).expect("fixture resolver builds");
        for contents in [
            STANDARD.encode([0x41; 31]),
            STANDARD.encode([0x41; 33]),
            "not base64!".to_owned(),
        ] {
            let dek_ref = write_local_dek(&root, contents.as_bytes());
            let result = FieldEncryptionService::activate(
                &FieldEncryptionProvider::LocalFile { dek_ref },
                REGISTRY_ID,
                "sha256:fixture",
                &secrets,
                &MemoryKeyStore::new(Vec::new()),
            )
            .await;
            assert!(
                matches!(result, Err(FieldEncryptionError::DataKeyUnavailable)),
                "a malformed data-key file must never activate"
            );
        }
        let dek_ref = write_local_dek(&root, STANDARD.encode(DEK).as_bytes());
        let conflicting = MemoryKeyStore::new(vec![stored_row(1, TRANSIT_PROVIDER_KIND)]);
        let result = FieldEncryptionService::activate(
            &FieldEncryptionProvider::LocalFile { dek_ref },
            REGISTRY_ID,
            "sha256:fixture",
            &secrets,
            &conflicting,
        )
        .await;
        assert!(
            matches!(result, Err(FieldEncryptionError::ProviderMismatch)),
            "stored key rows from another provider must block local-file activation"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn local_file_provider_binds_restart_to_the_activated_key() {
        let root = secret_root("restart-key-binding");
        let dek_ref = write_local_dek(&root, STANDARD.encode(DEK).as_bytes());
        let secrets =
            SecretResolver::new([SecretProvider::File], &root).expect("fixture resolver builds");
        let store = MemoryKeyStore::new(Vec::new());

        FieldEncryptionService::activate(
            &FieldEncryptionProvider::LocalFile {
                dek_ref: dek_ref.clone(),
            },
            REGISTRY_ID,
            "sha256:fixture",
            &secrets,
            &store,
        )
        .await
        .expect("governed apply activates the local key identifier");
        FieldEncryptionService::open_existing(
            &FieldEncryptionProvider::LocalFile {
                dek_ref: dek_ref.clone(),
            },
            REGISTRY_ID,
            &secrets,
            &store,
        )
        .await
        .expect("the unchanged key opens on restart");

        write_local_dek(&root, STANDARD.encode([0x6B; 32]).as_bytes());
        let result = FieldEncryptionService::open_existing(
            &FieldEncryptionProvider::LocalFile { dek_ref },
            REGISTRY_ID,
            &secrets,
            &store,
        )
        .await;
        assert!(matches!(result, Err(FieldEncryptionError::KeyStateInvalid)));
        fs::remove_dir_all(&root).ok();
    }

    /// A Transit binding whose socket is never reached: the refusals below
    /// fail closed on the stored rows before the provider is contacted.
    fn transit_provider_config() -> FieldEncryptionProvider {
        FieldEncryptionProvider::Transit(
            TransitDataKeyConfig::new(
                "/nonexistent/transit-proxy.sock",
                "transit",
                "breg-field-dek",
                Duration::from_millis(1),
            )
            .expect("fixture config builds"),
        )
    }

    #[tokio::test]
    async fn transit_activation_refuses_more_than_one_key_row() {
        let root = secret_root("refuses-second-row");
        let secrets =
            SecretResolver::new([SecretProvider::File], &root).expect("fixture resolver builds");
        let conflicting = MemoryKeyStore::new(vec![
            stored_row(1, TRANSIT_PROVIDER_KIND),
            stored_row(2, TRANSIT_PROVIDER_KIND),
        ]);
        let result = FieldEncryptionService::activate(
            &transit_provider_config(),
            REGISTRY_ID,
            "sha256:fixture",
            &secrets,
            &conflicting,
        )
        .await;
        assert!(
            matches!(result, Err(FieldEncryptionError::KeyStateInvalid)),
            "a second key row must never activate"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn transit_activation_refuses_a_row_from_another_version() {
        let root = secret_root("refuses-version-two");
        let secrets =
            SecretResolver::new([SecretProvider::File], &root).expect("fixture resolver builds");
        let conflicting = MemoryKeyStore::new(vec![stored_row(2, TRANSIT_PROVIDER_KIND)]);
        let result = FieldEncryptionService::activate(
            &transit_provider_config(),
            REGISTRY_ID,
            "sha256:fixture",
            &secrets,
            &conflicting,
        )
        .await;
        assert!(
            matches!(result, Err(FieldEncryptionError::KeyStateInvalid)),
            "a key row from any version but the first must never activate"
        );
        fs::remove_dir_all(&root).ok();
    }
}
