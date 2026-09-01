// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL storage for retained history schema descriptors.

use crate::history_schema::{
    parse_descriptor, serialize_descriptor, HistorySchemaDescriptor, HistorySchemaError,
    MAX_HISTORY_SCHEMA_DESCRIPTOR_BYTES,
};
use crate::model::CompiledRegistry;
use crate::postgres::SqlIdentifier;

#[cfg(feature = "runtime")]
use tokio_postgres::GenericClient;

const MAX_PACKAGE_REVISION_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum HistoryStoreError {
    #[error("history schema store input is invalid")]
    InvalidInput,
    #[error("retained history schema descriptor is unavailable")]
    Unavailable,
    #[error("retained history schema descriptor conflicts with verified package")]
    DescriptorConflict,
    #[error("retained history schema descriptor is malformed")]
    MalformedDescriptor,
}

impl From<HistorySchemaError> for HistoryStoreError {
    fn from(error: HistorySchemaError) -> Self {
        match error {
            HistorySchemaError::DescriptorUnavailable => Self::Unavailable,
            HistorySchemaError::MalformedDescriptor
            | HistorySchemaError::UnsupportedDescriptorVersion
            | HistorySchemaError::MissingEntity
            | HistorySchemaError::MissingRequiredField
            | HistorySchemaError::IncompatibleField
            | HistorySchemaError::MalformedSnapshot => Self::MalformedDescriptor,
        }
    }
}

#[cfg(feature = "runtime")]
pub(crate) async fn install_history_schema_store(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), HistoryStoreError> {
    migration
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_history_schemas (
                 package_revision text PRIMARY KEY
                     CHECK (
                         package_revision <> ''
                         AND octet_length(package_revision) <= {MAX_PACKAGE_REVISION_BYTES}
                     ),
                 descriptor bytea NOT NULL
                     CHECK (
                         octet_length(descriptor) > 0
                         AND octet_length(descriptor) <= {MAX_HISTORY_SCHEMA_DESCRIPTOR_BYTES}
                     ),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             REVOKE ALL ON registry_internal.registry_history_schemas FROM PUBLIC, {};
             GRANT SELECT ON registry_internal.registry_history_schemas TO {};",
            quoted_identifier(runtime_role.as_str()),
            quoted_identifier(runtime_role.as_str()),
        ))
        .await
        .map_err(|_| HistoryStoreError::Unavailable)?;
    Ok(())
}

#[cfg(feature = "runtime")]
pub(crate) async fn retain_descriptor(
    migration: &impl GenericClient,
    registry: &CompiledRegistry,
    verified_package_revision: &str,
) -> Result<HistorySchemaDescriptor, HistoryStoreError> {
    validate_package_revision(verified_package_revision)?;
    let descriptor =
        HistorySchemaDescriptor::from_compiled_registry(registry, verified_package_revision);
    let canonical = serialize_descriptor(&descriptor)?;
    let inserted = migration
        .execute(
            "INSERT INTO registry_internal.registry_history_schemas
                 (package_revision, descriptor)
             VALUES ($1, $2)
             ON CONFLICT (package_revision) DO NOTHING",
            &[&verified_package_revision, &canonical],
        )
        .await
        .map_err(|_| HistoryStoreError::Unavailable)?;
    if inserted == 1 {
        return Ok(descriptor);
    }

    let stored = load_descriptor_bytes(migration, verified_package_revision).await?;
    if stored != canonical {
        return Err(HistoryStoreError::DescriptorConflict);
    }
    Ok(parse_descriptor(&stored)?)
}

#[cfg(feature = "runtime")]
pub(crate) async fn retain_verified_descriptor(
    migration: &impl GenericClient,
    descriptor: &HistorySchemaDescriptor,
) -> Result<(), HistoryStoreError> {
    validate_package_revision(&descriptor.package_revision)?;
    let canonical = serialize_descriptor(descriptor)?;
    let inserted = migration
        .execute(
            "INSERT INTO registry_internal.registry_history_schemas
                 (package_revision, descriptor)
             VALUES ($1, $2)
             ON CONFLICT (package_revision) DO NOTHING",
            &[&descriptor.package_revision, &canonical],
        )
        .await
        .map_err(|_| HistoryStoreError::Unavailable)?;
    if inserted == 1 {
        return Ok(());
    }

    let stored = load_descriptor_bytes(migration, &descriptor.package_revision).await?;
    if stored != canonical {
        return Err(HistoryStoreError::DescriptorConflict);
    }
    Ok(())
}

#[cfg(feature = "runtime")]
pub(crate) async fn load_descriptor(
    client: &impl GenericClient,
    package_revision: &str,
) -> Result<HistorySchemaDescriptor, HistoryStoreError> {
    validate_package_revision(package_revision)?;
    let bytes = load_descriptor_bytes(client, package_revision).await?;
    Ok(parse_descriptor(&bytes)?)
}

#[cfg(feature = "runtime")]
async fn load_descriptor_bytes(
    client: &impl GenericClient,
    package_revision: &str,
) -> Result<Vec<u8>, HistoryStoreError> {
    let row = client
        .query_opt(
            "SELECT descriptor
               FROM registry_internal.registry_history_schemas
              WHERE package_revision = $1",
            &[&package_revision],
        )
        .await
        .map_err(|_| HistoryStoreError::Unavailable)?
        .ok_or(HistoryStoreError::Unavailable)?;
    Ok(row.get(0))
}

fn validate_package_revision(package_revision: &str) -> Result<(), HistoryStoreError> {
    if package_revision.is_empty() || package_revision.len() > MAX_PACKAGE_REVISION_BYTES {
        return Err(HistoryStoreError::InvalidInput);
    }
    Ok(())
}

#[cfg(feature = "runtime")]
fn quoted_identifier(identifier: &str) -> String {
    format!("\"{identifier}\"")
}
