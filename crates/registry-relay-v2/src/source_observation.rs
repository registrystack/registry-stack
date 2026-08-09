// SPDX-License-Identifier: Apache-2.0
//! Production source-schema observation shared by startup and adopter tooling.

use std::path::{Path, PathBuf};
use std::time::Duration;

use registry_platform_sqlite::{
    inspect_schema, CapturedSnapshot, DatabaseProfile, InspectionLimits, LiveDatabaseFile,
    SchemaObjectKind,
};

use crate::contract::{RegistryContract, RelayRuntime, SourceProfile};
use crate::model::{ObservedColumn, ObservedSourceSchema, ObservedView};

const MAXIMUM_OBJECTS: usize = 10_000;
const MAXIMUM_SQL_BYTES: usize = 8 * 1024 * 1024;
const MAXIMUM_STEPS: u64 = 1_000_000;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
pub(crate) struct SourceObservationError;

pub(crate) fn observe_sources(
    root: &Path,
    contract: &RegistryContract,
    runtime: &RelayRuntime,
) -> Result<Vec<ObservedSourceSchema>, SourceObservationError> {
    let mut observed = Vec::new();
    for (source_id, source) in contract.sources.iter() {
        let Some(binding) = runtime.sources.get(source_id) else {
            continue;
        };
        let path = resolve_source_path(root, &binding.path);
        if !path.is_file() {
            continue;
        }
        let profile = match source.profile {
            SourceProfile::Snapshot => DatabaseProfile::Snapshot(
                CapturedSnapshot::capture(&path).map_err(|_| SourceObservationError)?,
            ),
            SourceProfile::LiveReadOnly => DatabaseProfile::LiveReadOnly(
                LiveDatabaseFile::bind(&path).map_err(|_| SourceObservationError)?,
            ),
        };
        let catalog =
            inspect_schema(&profile, &inspection_limits()).map_err(|_| SourceObservationError)?;
        let views = catalog
            .objects
            .iter()
            .filter(|object| matches!(object.kind, SchemaObjectKind::View))
            .map(|object| ObservedView {
                name: object.name.clone(),
                columns: object
                    .columns
                    .iter()
                    .map(|column| ObservedColumn {
                        name: column.name.clone(),
                        declared_type: column.declared_type.clone(),
                        nullable: column.nullable,
                        primary_key: column.primary_key,
                    })
                    .collect(),
            })
            .collect();
        observed.push(ObservedSourceSchema {
            source: source_id.into(),
            fingerprint: catalog.fingerprint,
            views,
        });
    }
    Ok(observed)
}

pub(crate) fn inspection_limits() -> InspectionLimits {
    InspectionLimits {
        maximum_objects: MAXIMUM_OBJECTS,
        maximum_sql_bytes: MAXIMUM_SQL_BYTES,
        maximum_statement_steps: MAXIMUM_STEPS,
        timeout: TIMEOUT,
    }
}

fn resolve_source_path(root: &Path, configured: &str) -> PathBuf {
    let path = Path::new(configured);
    if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    }
}
