// SPDX-License-Identifier: Apache-2.0
//! A minimal editable starter. Local runtime setup never becomes portable authority.
use crate::{CoordinatorError, Result};
use std::{io::Write as _, path::Path};

const WORKFLOW: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/workflow.yaml");
const FUNCTIONS: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/functions.rhai");
const RUNTIME: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml");
const SCENARIOS: &str =
    include_str!("../../../products/coordinator/examples/delayed-follow-up/scenarios.yaml");

/// Write exactly the four authored files and a `.gitignore` for the local
/// `.coordinator/` directory into an absent or empty directory and name them.
/// The project id is `id` or, without one, the directory name. A directory with content is refused, and an IO failure preserves
/// created files so the caller can inspect them without any cleanup deleting
/// user work.
pub fn init(path: &Path, id: Option<&str>) -> Result<Vec<&'static str>> {
    let destination = match path.canonicalize() {
        Ok(existing) => existing,
        Err(_) => {
            let name = path
                .file_name()
                .ok_or_else(|| failure(path, "name a new project directory"))?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            parent
                .canonicalize()
                .map_err(|_| failure(path, "create or select an existing parent directory"))?
                .join(name)
        }
    };
    let name = destination
        .file_name()
        .ok_or_else(|| failure(path, "name a new project directory"))?;
    let project_id = match id {
        Some(id) => registry_platform_yaml::LocalId::new(id).map_err(|_| {
            CoordinatorError::new(
                "project.init",
                "--id is not a project id: a lowercase letter, then up to 63 lowercase letters, digits, `_` or `-`",
            )
            .at(path, "/")
            .suggest("Pass --id with a project id such as `claims-follow-up`.")
        })?,
        None => registry_platform_yaml::LocalId::new(name.to_string_lossy()).map_err(|_| {
            CoordinatorError::new(
                "project.init",
                "the directory name is not a project id: a lowercase letter, then up to 63 lowercase letters, digits, `_` or `-`",
            )
            .at(path, "/")
            .suggest("Pass --id with a project id such as `claims-follow-up`, or name the directory that way.")
        })?,
    };
    if registry_platform_config::contains_environment_expression(&destination.to_string_lossy()) {
        return Err(failure(
            path,
            "choose a project path without environment-expression syntax",
        ));
    }
    let secrets = destination.join(".coordinator/secrets");
    let secrets = secrets
        .to_str()
        .ok_or_else(|| failure(path, "choose a project path that is UTF-8 text"))?;
    let workflow = WORKFLOW.replacen(
        "\n  id: delayed-follow-up\n",
        &format!("\n  id: {}\n", yaml_scalar(project_id.as_str())),
        1,
    );
    let runtime = RUNTIME.replacen(
        "root: /run/registry-coordinator/secrets\n",
        &format!("root: {}\n", yaml_scalar(secrets)),
        1,
    );
    let occupied = |message| {
        CoordinatorError::new("project.init", message)
            .at(path, "/")
            .suggest("Choose a new or empty directory with --directory; init never writes into existing content.")
    };
    match std::fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&destination)
                .map_err(|_| failure(path, "inspect the parent directory and its permissions"))?;
        }
        Ok(metadata) if metadata.is_dir() => {
            let mut entries = std::fs::read_dir(&destination)
                .map_err(|_| failure(path, "inspect the directory and its permissions"))?;
            if entries.next().is_some() {
                return Err(occupied("the directory is not empty"));
            }
        }
        _ => return Err(occupied("the path exists and is not a directory")),
    }
    let files = [
        ("workflow.yaml", workflow.as_str()),
        ("functions.rhai", FUNCTIONS),
        ("runtime.yaml", runtime.as_str()),
        ("scenarios.yaml", SCENARIOS),
        (".gitignore", ".coordinator/\n"),
    ];
    for (file, text) in files {
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
    Ok(files.map(|(file, _)| file).to_vec())
}
/// One YAML scalar for `text`, quoted only when plain text would read differently.
fn yaml_scalar(text: &str) -> String {
    serde_norway::to_string(text)
        .map(|scalar| scalar.trim_end().to_owned())
        .unwrap_or_else(|_| serde_json::Value::from(text).to_string())
}
fn failure(path: &Path, action: &str) -> CoordinatorError {
    CoordinatorError::new("project.init", "the starter project could not be created")
        .at(path, "/")
        .suggest(action)
}
