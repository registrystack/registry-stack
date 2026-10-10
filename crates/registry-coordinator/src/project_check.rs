// SPDX-License-Identifier: Apache-2.0
//! Root-level authored companions. Owned state and secrets are never traversed.
use crate::{authoring, definition::Definition, runtime, scenarios};
use registry_platform_yaml::{
    ApiVersion, Diagnostic, EnvelopeRule, Expect, FormatSpec, Reader, Report, Severity, Source,
};
use std::{fs, io::Read as _, path::Path};

const MAXIMUM_ENTRIES: usize = 1024;
const FORMATS: &[FormatSpec<'static>] = &[
    FormatSpec {
        kind: authoring::KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(authoring::API_VERSION)],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    },
    FormatSpec {
        kind: runtime::KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(runtime::API_VERSION)],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    },
    FormatSpec {
        kind: scenarios::KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(scenarios::API_VERSION)],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    },
];

pub(crate) fn check_runtime(
    path: &Path,
    definition: Option<&Definition>,
    environment: bool,
) -> (Report, u8) {
    let mut checked = runtime::RuntimeConfig::check_file(path, environment);
    if let (Some(loaded), Some(definition)) = (&checked.loaded, definition) {
        if !checked.defers_within("/connections") {
            if let Err(error) = loaded.config.validate_workflow(&definition.workflow) {
                let field = error.field.as_deref().unwrap_or("");
                let pointer = field
                    .strip_prefix("steps.")
                    .and_then(|field| field.strip_suffix(".call"))
                    .and_then(|step| definition.workflow.steps.get(step))
                    .and_then(|step| match step {
                        crate::definition::Step::Call { call, .. } => Some(format!(
                            "/connections/{}/authorization/taskAuthority",
                            call.connection
                        )),
                        _ => None,
                    })
                    .unwrap_or_else(|| {
                        if field.starts_with('/') {
                            field.to_owned()
                        } else {
                            format!("/{}", field.replace('.', "/"))
                        }
                    });
                let mut diagnostic = checked.error_at(
                    runtime::KIND,
                    &error.code,
                    &pointer,
                    error.message,
                    error.suggested_action.unwrap_or_else(|| {
                        "Use the same logical connection name in the project and runtime.".into()
                    }),
                );
                // A missing member has no span. Anchor it to its nearest
                // existing runtime container while retaining the missing path.
                if diagnostic
                    .source
                    .as_ref()
                    .is_some_and(|source| source.line.is_none())
                {
                    let mut container = pointer.as_str();
                    while let Some((parent, _)) = container.rsplit_once('/') {
                        let source = checked
                            .error_at(runtime::KIND, &error.code, parent, "", "")
                            .source;
                        if source.as_ref().is_some_and(|source| source.line.is_some()) {
                            diagnostic.source = source;
                            break;
                        }
                        container = parent;
                    }
                }
                checked.diagnostics.push(diagnostic);
            }
        }
    }
    (
        Report::new(checked.diagnostics),
        if checked.unavailable { 3 } else { 1 },
    )
}

pub(crate) fn check_directory(
    root: &Path,
    definition: Option<&Definition>,
    explicit_runtime: Option<&Path>,
    environment: bool,
) -> (Report, u8) {
    let mut report = Report::default();
    let mut exit = 1;
    // Project selection accepts relative paths. Discovered operator files are
    // passed to their owning loader using the resolved absolute project root.
    let root = match root.canonicalize() {
        Ok(root) => root,
        Err(_) => {
            report.push(unreadable(root));
            return (report, 3);
        }
    };
    let root = root.as_path();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries
            .take(MAXIMUM_ENTRIES + 1)
            .collect::<std::io::Result<Vec<_>>>(),
        Err(error) => Err(error),
    };
    let mut entries = match entries {
        Ok(entries) if entries.len() <= MAXIMUM_ENTRIES => entries,
        Ok(_) => {
            report.push(file_error(
                root,
                "coordinator.project.too-many-files",
                "the project root exceeds 1024 entries",
                "Keep at most 1024 entries in the project root.",
            ));
            return (report, exit);
        }
        Err(_) => {
            report.push(unreadable(root));
            return (report, 3);
        }
    };
    entries.sort_by_key(fs::DirEntry::file_name);
    let explicit = explicit_runtime.and_then(|path| path.canonicalize().ok());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        // Runtime custody belongs to deployment commands, never author checking.
        if name == ".coordinator" || name == "workflow.yaml" {
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(_) => {
                report.push(unreadable(&path));
                exit = 3;
                continue;
            }
        };
        if kind.is_dir() {
            let mut diagnostic = file_error(&path, "coordinator.project.unread-directory", "check reads only the project root; this child directory was not checked", "Move authored YAML companions into the project root, or check the child as a separate project.");
            diagnostic.severity = Severity::Warning;
            report.push(diagnostic);
            continue;
        }
        if !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yaml" | "yml")
        ) {
            continue;
        }
        if !kind.is_file() {
            report.push(file_error(
                &path,
                "coordinator.project.not-a-regular-file",
                "the authored YAML path is not a regular file",
                "Replace the link or special file with a regular authored file.",
            ));
            continue;
        }
        if explicit
            .as_ref()
            .is_some_and(|explicit| path.canonicalize().ok().as_ref() == Some(explicit))
        {
            continue;
        }
        let mut bytes = Vec::new();
        if fs::File::open(&path)
            .and_then(|file| {
                file.take(registry_platform_yaml::MAXIMUM_DOCUMENT_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
            })
            .is_err()
        {
            report.push(unreadable(&path));
            exit = 3;
            continue;
        }
        let document =
            match Reader::new(path.display().to_string()).read(&bytes, &Expect::new(FORMATS)) {
                Ok(document) => document,
                Err(errors) => {
                    report.extend(errors);
                    continue;
                }
            };
        let expected = match document.envelope().kind.as_str() {
            runtime::KIND => "runtime.yaml",
            scenarios::KIND => "scenarios.yaml",
            _ => "workflow.yaml",
        };
        if name != expected {
            report.push(document.diagnostic_at_value(
                Severity::Error,
                "coordinator.project.misplaced-kind",
                "/kind",
                &format!("this document belongs in {expected}"),
                &format!("Keep exactly the owned {expected} companion at the project root."),
            ));
            continue;
        }
        if expected == "runtime.yaml" {
            let (findings, runtime_exit) = check_runtime(&path, definition, environment);
            report.extend(findings);
            exit = exit.max(runtime_exit);
        } else {
            match scenarios::decode_bytes(&bytes, &path.display().to_string()) {
                Ok(scenarios) => {
                    if let Some(definition) = definition {
                        for (index, scenario) in scenarios.cases.iter().enumerate() {
                            let mut invalid_reference = false;
                            for (member, step) in scenario
                                .replies
                                .keys()
                                .map(|step| ("replies", step))
                                .chain(scenario.recovery.keys().map(|step| ("recovery", step)))
                            {
                                if !definition.workflow.steps.contains_key(step) {
                                    invalid_reference = true;
                                    report.push(document.diagnostic_at_value(
                                        Severity::Error,
                                        "coordinator.scenarios.unknown-reference",
                                        &format!("/cases/{index}/{member}/{step}"),
                                        "the scenario names a step outside this workflow",
                                        "Name a declared workflow step.",
                                    ));
                                }
                            }
                            for (path_index, step) in scenario.expect.path.iter().enumerate() {
                                if !definition.workflow.steps.contains_key(step) {
                                    invalid_reference = true;
                                    report.push(document.diagnostic_at_value(
                                        Severity::Error,
                                        "coordinator.scenarios.unknown-reference",
                                        &format!("/cases/{index}/expect/path/{path_index}"),
                                        "the expected path names a step outside this workflow",
                                        "Name a declared workflow step.",
                                    ));
                                }
                            }
                            if scenario.expect.outcome.as_ref().is_some_and(|outcome| {
                                !definition.workflow.outcomes.contains_key(outcome)
                            }) {
                                invalid_reference = true;
                                report.push(document.diagnostic_at_value(
                                    Severity::Error,
                                    "coordinator.scenarios.unknown-reference",
                                    &format!("/cases/{index}/expect/outcome/value"),
                                    "the expected outcome is not declared by this workflow",
                                    "Name a declared workflow outcome.",
                                ));
                            }
                            if invalid_reference {
                                continue;
                            }
                            if let Err(error) = scenarios::run(definition, scenario) {
                                report.extend(error.at(&path, format!("/cases/{index}")).report());
                            }
                        }
                    }
                }
                Err(error) => report.extend(error.report()),
            }
        }
    }
    (report, exit)
}

fn file_error(path: &Path, code: &'static str, message: &str, action: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(code, "", message, action);
    diagnostic.source = Some(Source {
        file: path.display().to_string(),
        line: None,
        column: None,
    });
    diagnostic
}

fn unreadable(path: &Path) -> Diagnostic {
    file_error(
        path,
        registry_platform_config::UNAVAILABLE_CODE,
        "the project entry could not be read",
        "Restore a readable project root and regular authored files.",
    )
}
