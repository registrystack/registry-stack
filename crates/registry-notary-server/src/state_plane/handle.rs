// SPDX-License-Identifier: Apache-2.0
//! Activation boundary for Notary correctness state.
//!
//! This handle owns only storage-mode selection and PostgreSQL lifecycle. The
//! domain modules retain their typed transaction APIs and never route through
//! an opaque key-value interface.

use std::sync::{Arc, OnceLock};

use registry_notary_core::{StateConfig, STATE_STORAGE_IN_MEMORY};

use super::{
    runtime::{start_postgres_retention_maintenance, PostgresRetentionMaintenance},
    NotaryPostgresStatePlaneError, NotaryPostgresStatePlaneReadiness,
    NotaryPostgresStatePlaneRuntime, PostgresSensitiveState, PostgresStatePlaneAttestation,
    PostgresStatePlaneConfig, SensitiveStateError, SensitiveStateKeyConfig,
};

#[derive(Clone)]
enum StatePlaneMode {
    InMemory,
    Postgresql(PostgresStatePlaneConfig),
}

/// Shared activation state used by the typed Notary domain adapters.
pub(crate) struct NotaryStatePlaneHandle {
    mode: StatePlaneMode,
    runtime: OnceLock<Arc<NotaryPostgresStatePlaneRuntime>>,
    retention_maintenance: OnceLock<PostgresRetentionMaintenance>,
    sensitive_key: Option<SensitiveStateKeyConfig>,
    sensitive: OnceLock<Arc<PostgresSensitiveState>>,
}

impl NotaryStatePlaneHandle {
    pub(crate) fn from_config(
        config: &StateConfig,
        preauthorization_enabled: bool,
    ) -> Result<Self, SensitiveStateError> {
        let mode = if config.storage == STATE_STORAGE_IN_MEMORY {
            StatePlaneMode::InMemory
        } else {
            StatePlaneMode::Postgresql(PostgresStatePlaneConfig::try_from(&config.postgresql)?)
        };
        let sensitive_key = (!matches!(mode, StatePlaneMode::InMemory) && preauthorization_enabled)
            .then(|| {
                SensitiveStateKeyConfig::new(config.postgresql.sensitive_state_key_env.clone())
            })
            .transpose()?;
        Ok(Self {
            mode,
            runtime: OnceLock::new(),
            retention_maintenance: OnceLock::new(),
            sensitive_key,
            sensitive: OnceLock::new(),
        })
    }

    #[must_use]
    pub(crate) fn is_in_memory(&self) -> bool {
        matches!(self.mode, StatePlaneMode::InMemory)
    }

    #[must_use]
    pub(crate) fn is_activated(&self) -> bool {
        self.is_in_memory()
            || (self.runtime.get().is_some()
                && (self.sensitive_key.is_none() || self.sensitive.get().is_some()))
    }

    pub(crate) async fn activate(&self) -> Result<(), SensitiveStateError> {
        let StatePlaneMode::Postgresql(config) = &self.mode else {
            return Ok(());
        };
        if self.is_activated() {
            return Ok(());
        }
        let runtime = Arc::new(NotaryPostgresStatePlaneRuntime::connect(config).await?);
        let sensitive = match &self.sensitive_key {
            Some(key) => Some(Arc::new(
                PostgresSensitiveState::activate(Arc::clone(&runtime), key).await?,
            )),
            None => None,
        };
        if let Some(sensitive) = sensitive {
            let _ = self.sensitive.set(sensitive);
        }
        let _ = self.runtime.set(runtime);
        if self.is_activated() {
            Ok(())
        } else {
            Err(SensitiveStateError::NotActivated)
        }
    }

    pub(crate) fn runtime(
        &self,
    ) -> Result<Arc<NotaryPostgresStatePlaneRuntime>, NotaryPostgresStatePlaneError> {
        self.runtime
            .get()
            .cloned()
            .ok_or(NotaryPostgresStatePlaneError::DatabaseUnavailable)
    }

    /// Start the PostgreSQL retention worker only at the serving activation
    /// boundary. Operator state checks activate and attest without calling it.
    pub(crate) fn start_retention_maintenance(&self) -> Result<(), NotaryPostgresStatePlaneError> {
        if self.is_in_memory() {
            return Ok(());
        }
        let runtime = self.runtime()?;
        self.retention_maintenance
            .get_or_init(|| start_postgres_retention_maintenance(runtime));
        Ok(())
    }

    pub(crate) fn sensitive_state(
        &self,
    ) -> Result<Arc<PostgresSensitiveState>, SensitiveStateError> {
        self.sensitive
            .get()
            .cloned()
            .ok_or(SensitiveStateError::NotActivated)
    }

    pub(crate) async fn readiness(&self) -> NotaryPostgresStatePlaneReadiness {
        match &self.mode {
            StatePlaneMode::InMemory => NotaryPostgresStatePlaneReadiness::Ready,
            StatePlaneMode::Postgresql(_) => match self.runtime.get() {
                Some(_) if self.sensitive_key.is_some() && self.sensitive.get().is_none() => {
                    NotaryPostgresStatePlaneReadiness::ConfigurationInvalid
                }
                Some(runtime) => {
                    let readiness = runtime.readiness().await;
                    if readiness != NotaryPostgresStatePlaneReadiness::Ready {
                        return readiness;
                    }
                    match self.sensitive.get() {
                        Some(sensitive) => sensitive
                            .attest_key_generation()
                            .await
                            .map_or_else(readiness_from_sensitive_error, |_| readiness),
                        None => readiness,
                    }
                }
                None => NotaryPostgresStatePlaneReadiness::DatabaseUnavailable,
            },
        }
    }
}

impl std::fmt::Debug for NotaryStatePlaneHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotaryStatePlaneHandle")
            .field("in_memory", &self.is_in_memory())
            .field("activated", &self.is_activated())
            .field(
                "retention_maintenance",
                &self.retention_maintenance.get().is_some(),
            )
            .field("sensitive_state_required", &self.sensitive_key.is_some())
            .finish()
    }
}

impl Drop for NotaryStatePlaneHandle {
    fn drop(&mut self) {
        if let Some(maintenance) = self.retention_maintenance.get() {
            maintenance.shutdown();
        }
        if let Some(runtime) = self.runtime.get() {
            runtime.shutdown();
        }
    }
}

/// Activate the same PostgreSQL and sensitive-state boundary used by serving
/// startup, then return a fresh runtime attestation for operator diagnostics.
pub async fn attest_postgres_state_plane_runtime(
    config: &StateConfig,
    preauthorization_enabled: bool,
) -> Result<PostgresStatePlaneAttestation, NotaryPostgresStatePlaneReadiness> {
    let handle = NotaryStatePlaneHandle::from_config(config, preauthorization_enabled)
        .map_err(readiness_from_sensitive_error)?;
    handle
        .activate()
        .await
        .map_err(readiness_from_sensitive_error)?;
    let runtime = handle
        .runtime()
        .map_err(NotaryPostgresStatePlaneReadiness::from_error)?;
    let attestation = runtime
        .attestation()
        .await
        .map_err(NotaryPostgresStatePlaneReadiness::from_error);
    runtime.shutdown();
    attestation
}

const fn readiness_from_sensitive_error(
    error: SensitiveStateError,
) -> NotaryPostgresStatePlaneReadiness {
    match error {
        SensitiveStateError::StatePlane(error) => {
            NotaryPostgresStatePlaneReadiness::from_error(error)
        }
        SensitiveStateError::InvalidKeyConfiguration
        | SensitiveStateError::KeyEnvironmentUnavailable
        | SensitiveStateError::InvalidKeyEncoding
        | SensitiveStateError::InvalidKeyLength
        | SensitiveStateError::CryptographyUnavailable
        | SensitiveStateError::NotActivated
        | SensitiveStateError::InvalidStoredRecord => {
            NotaryPostgresStatePlaneReadiness::ConfigurationInvalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_serving_activation_does_not_start_postgres_maintenance() {
        let config = StateConfig {
            storage: STATE_STORAGE_IN_MEMORY.to_string(),
            ..StateConfig::default()
        };
        let handle = NotaryStatePlaneHandle::from_config(&config, false)
            .expect("in-memory state handle is valid");

        handle
            .activate()
            .await
            .expect("in-memory activation succeeds");
        handle
            .start_retention_maintenance()
            .expect("in-memory serving activation is a no-op");

        assert!(handle.runtime.get().is_none());
        assert!(handle.retention_maintenance.get().is_none());
    }

    #[test]
    fn sensitive_activation_errors_map_to_value_free_doctor_components() {
        let configuration_errors = [
            SensitiveStateError::InvalidKeyConfiguration,
            SensitiveStateError::KeyEnvironmentUnavailable,
            SensitiveStateError::InvalidKeyEncoding,
            SensitiveStateError::InvalidKeyLength,
            SensitiveStateError::CryptographyUnavailable,
            SensitiveStateError::NotActivated,
            SensitiveStateError::InvalidStoredRecord,
        ];
        for error in configuration_errors {
            assert_eq!(
                readiness_from_sensitive_error(error).doctor_component_code(),
                "configuration_invalid"
            );
        }
        assert_eq!(
            readiness_from_sensitive_error(SensitiveStateError::StatePlane(
                NotaryPostgresStatePlaneError::SchemaIncompatible,
            ))
            .doctor_component_code(),
            "schema_incompatible"
        );
    }
}
