// SPDX-License-Identifier: Apache-2.0

//! Deterministic public contracts for authored template versions.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::path::Path;

use registry_messaging::package::{package_inputs, PackageLoadError, SCHEMA_FILE, TEMPLATE_FILE};
use registry_messaging_core::TemplateDocument;
use registry_platform_config::AuthoredExpressions;
use registry_platform_yaml::Reader;
use serde::Serialize;
use serde_json::Value;

const API_VERSION: &str = "id.registrystack.org/formats/messaging/template-contracts/v1";
const KIND: &str = "MessagingTemplateContracts";

#[derive(Debug)]
pub(crate) enum ExportError {
    Package(PackageLoadError),
    Snapshot,
    Encode(serde_json::Error),
    Write(io::Error),
}

impl From<PackageLoadError> for ExportError {
    fn from(error: PackageLoadError) -> Self {
        Self::Package(error)
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(error) => error.fmt(formatter),
            Self::Snapshot => formatter
                .write_str("the checked project snapshot could not produce template contracts"),
            Self::Encode(error) => {
                write!(
                    formatter,
                    "the template contracts could not be encoded: {error}"
                )
            }
            Self::Write(error) => write!(
                formatter,
                "the output file could not be created or written: {error}"
            ),
        }
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Package(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Write(error) => Some(error),
            Self::Snapshot => None,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateContracts {
    api_version: &'static str,
    kind: &'static str,
    templates: Vec<TemplateContract>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateContract {
    id: String,
    version: String,
    locales: Vec<String>,
    data_schema: Value,
}

/// Validate `project`, then write one create-only export outside its package
/// inputs. The returned count is the number of template versions exported.
pub(crate) fn write(project: &Path, output: &Path) -> Result<usize, ExportError> {
    let inputs = package_inputs(project)?;
    let mut templates = Vec::new();
    for (schema_path, schema_bytes) in &inputs {
        let Some((id, version)) = template_schema_reference(schema_path) else {
            continue;
        };
        let template_path = format!("templates/{id}/{version}/{TEMPLATE_FILE}");
        let template_bytes = inputs.get(&template_path).ok_or(ExportError::Snapshot)?;
        let mut hook = AuthoredExpressions;
        let document = TemplateDocument::decode(
            Reader::new(project.join(&template_path).display().to_string()).with_hook(&mut hook),
            template_bytes,
        )
        .map_err(|_| ExportError::Snapshot)?;
        let data_schema = serde_json::from_slice(schema_bytes).map_err(ExportError::Encode)?;
        let mut locales = document.value.locales;
        locales.sort();
        templates.push(TemplateContract {
            id: id.to_owned(),
            version: version.to_owned(),
            locales,
            data_schema,
        });
    }
    templates.sort_by(|left, right| (&left.id, &left.version).cmp(&(&right.id, &right.version)));
    let count = templates.len();
    let mut bytes = serde_json::to_vec(&TemplateContracts {
        api_version: API_VERSION,
        kind: KIND,
        templates,
    })
    .map_err(ExportError::Encode)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(ExportError::Write)?;
    file.write_all(&bytes).map_err(ExportError::Write)?;
    Ok(count)
}

fn template_schema_reference(path: &str) -> Option<(&str, &str)> {
    let mut parts = path.split('/');
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("templates"), Some(id), Some(version), Some(file), None) if file == SCHEMA_FILE => {
            Some((id, version))
        }
        _ => None,
    }
}
