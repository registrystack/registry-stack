// SPDX-License-Identifier: Apache-2.0
//! A minimal editable starter. Local runtime setup never becomes portable authority.
use crate::{PocError, Result};
use std::{io::Write as _, path::Path};

const WORKFLOW: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/workflow.yaml");
const FUNCTIONS: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/functions.rhai");
const RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml");

/// Write exactly the three authored files into a previously absent directory.
/// Existing destinations are refused, and an IO failure preserves created files
/// so the caller can inspect them without any cleanup deleting user work.
pub fn init(path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| failure(path, "name a new project directory"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|_| failure(path, "create or select an existing parent directory"))?;
    let destination = parent.join(name);
    if registry_platform_config::contains_environment_expression(&destination.to_string_lossy()) {
        return Err(failure(
            path,
            "choose a project path without environment-expression syntax",
        ));
    }
    let loader = registry_platform_config::RuntimeConfigLoader::new(
        registry_platform_config::RuntimeEnvelope {
            api_version: crate::runtime::API_VERSION,
            kind: crate::runtime::KIND,
        },
    );
    let mut runtime = loader
        .parse_str::<serde_json::Value>(RUNTIME, |_| None)
        .map_err(|_| failure(path, "restore the embedded runtime starter"))?
        .config;
    runtime["secretProviders"]["file"]["root"] =
        serde_json::json!(destination.join(".coordinator/secrets"));
    if let Some(members) = runtime.as_object_mut() {
        members.remove("apiVersion");
        members.remove("kind");
    }
    let runtime = serde_norway::to_string(&runtime)
        .map_err(|_| failure(path, "restore the runtime starter serializer"))?;
    let runtime = format!("# yaml-language-server: $schema=https://id.registrystack.org/schemas/coordinator/runtime/runtime.v1alpha1.schema.json\napiVersion: {}\nkind: {}\n{runtime}", crate::runtime::API_VERSION, crate::runtime::KIND);
    std::fs::create_dir(&destination).map_err(|_| {
        failure(
            path,
            "choose an absent directory; existing projects are never overwritten",
        )
    })?;
    for (file, text) in [
        ("workflow.yaml", WORKFLOW),
        ("functions.rhai", FUNCTIONS),
        ("runtime.yaml", runtime.as_str()),
    ] {
        let file_path = destination.join(file);
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&file_path)
            .map_err(|_| {
                failure(
                    &file_path,
                    "inspect the project directory and its permissions; preserve any existing file",
                )
            })?;
        output.write_all(text.as_bytes()).map_err(|_| {
            failure(
                &file_path,
                "restore writable storage; inspect the partially created project",
            )
        })?;
    }
    Ok(())
}
fn failure(path: &Path, action: &str) -> PocError {
    PocError::new(
        "coordinator.project.init",
        "the starter project could not be created",
    )
    .at(path, "/")
    .suggest(action)
}
