// SPDX-License-Identifier: Apache-2.0
//! File handling for the shared project check acceptances.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use registry_platform_yaml::{
    check_scope_path, read_check_acceptances, CheckAcceptances, CheckScope, Decoded, Diagnostic,
    Expect, Reader, Report, Severity, Source, CHECK_ACCEPTANCES_FILE, CHECK_ACCEPTANCES_FORMAT,
    MAXIMUM_DOCUMENT_BYTES,
};
use serde_json::Value;

/// Read project acceptances under the same expression policy as other
/// authored files. No environment value or secret is resolved.
pub fn read_project_check_acceptances(
    file: &str,
    bytes: &[u8],
) -> Result<Decoded<CheckAcceptances>, Report> {
    let mut hook = crate::AuthoredExpressions;
    Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::one(&CHECK_ACCEPTANCES_FORMAT))?;
    read_check_acceptances(file, bytes)
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAXIMUM_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn unreadable(path: &Path) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        "config.check-acceptances-unreadable",
        "",
        "the project check acceptances could not be read",
        "Make check-acceptances.yaml a readable file, or remove it to use no acceptances.",
    );
    diagnostic.source = Some(Source {
        file: path.display().to_string(),
        line: None,
        column: None,
    });
    diagnostic
}

fn source_path(root: &Path, file: &str) -> Option<PathBuf> {
    let path = Path::new(file);
    let resolved = if path.is_absolute() {
        path.canonicalize()
    } else {
        // Some callers report a path relative to their working directory,
        // others a file relative to their project.
        root.join(path)
            .canonicalize()
            .or_else(|_| path.canonicalize())
    };
    match resolved {
        Ok(path) if path.starts_with(root) => Some(path),
        _ => None,
    }
}

/// Add portable scopes and apply the optional check-acceptances.yaml once
/// after a product has collected its project check diagnostics. This changes
/// advisory reporting only; no runtime authorization or validation is bypassed.
pub fn apply_check_acceptances(project_root: &Path, report: &mut Report) {
    let acceptance_path = project_root.join(CHECK_ACCEPTANCES_FILE);
    let bytes = std::fs::symlink_metadata(&acceptance_path).and_then(|metadata| {
        if metadata.is_file() {
            read_bounded(&acceptance_path)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a regular project file is required",
            ))
        }
    });
    let accepted = match bytes {
        Ok(bytes) => {
            match read_project_check_acceptances(&acceptance_path.display().to_string(), &bytes) {
                Ok(decoded) => {
                    report.extend(decoded.document.report_with(Vec::new()));
                    Some(decoded.value)
                }
                Err(errors) => {
                    report.extend(errors);
                    None
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => {
            report.push(unreadable(&acceptance_path));
            None
        }
    };

    // Error findings stay blocking while warnings retain their own disposition.
    let root = match project_root.canonicalize() {
        Ok(root) => root,
        Err(_) if report.has_errors() => return,
        Err(_) => {
            report.push(unreadable(project_root));
            return;
        }
    };
    let mut documents: BTreeMap<PathBuf, Value> = BTreeMap::new();
    let mut failures = Vec::new();
    for diagnostic in report.diagnostics_mut() {
        if diagnostic.severity != Severity::Warning {
            continue;
        }
        let Some(source) = &diagnostic.source else {
            continue;
        };
        let Some(path) = source_path(&root, &source.file) else {
            continue;
        };
        let Ok(relative) = path.strip_prefix(&root) else {
            continue;
        };
        let file = relative.to_string_lossy().replace('\\', "/");
        let mut scope_path = diagnostic.path.clone();
        if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yaml" | "yml" | "json")
        ) && !diagnostic.path.is_empty()
        {
            if !documents.contains_key(&path) {
                match read_bounded(&path) {
                    Ok(bytes) => match Reader::new(&source.file).scan(&bytes) {
                        Ok(Some(node)) => {
                            documents.insert(path.clone(), node.to_json_value());
                        }
                        Ok(None) => {}
                        Err(errors) => failures.extend(errors.into_diagnostics()),
                    },
                    Err(_) => failures.push(unreadable(&path)),
                }
            }
            if let Some(document) = documents.get(&path) {
                scope_path = check_scope_path(document, &diagnostic.path);
            }
        }
        diagnostic.scope = Some(CheckScope {
            file,
            path: scope_path,
        });
    }
    for diagnostic in failures {
        report.push(diagnostic);
    }
    if let Some(accepted) = accepted {
        accepted.apply(report);
    }
}
