// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::ApiError;

pub(crate) fn find_project(product: &str, start: &Path) -> Result<PathBuf, ApiError> {
    let marker = product_marker(product).ok_or_else(|| {
        ApiError::Usage(format!("{product} does not define an API project marker"))
    })?;
    let canonical = start.canonicalize().map_err(|_| {
        ApiError::Usage("the project search path does not exist or is not accessible".to_owned())
    })?;
    let mut candidate = if canonical.is_file() {
        canonical
            .parent()
            .ok_or_else(|| ApiError::Usage("the project path has no parent".to_owned()))?
            .to_path_buf()
    } else {
        canonical
    };
    loop {
        if candidate.join(marker).is_file() {
            return Ok(candidate);
        }
        if !candidate.pop() {
            return Err(ApiError::Usage(format!(
                "no {product} project ({marker}) was found from the selected path"
            )));
        }
    }
}

fn product_marker(product: &str) -> Option<&'static str> {
    match product {
        "breg" => Some("registry.yaml"),
        "casework" => Some("casework.yaml"),
        "coordinator" => Some("workflow.yaml"),
        "discovery" => Some("origins.yaml"),
        "documents" => Some("documents.yaml"),
        "evidence" => Some("evidence.yaml"),
        "messaging" => Some("messaging.yaml"),
        "scheduling" => Some("scheduling.yaml"),
        _ => None,
    }
}
