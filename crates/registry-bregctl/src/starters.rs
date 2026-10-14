// SPDX-License-Identifier: Apache-2.0
//! `init --template <ID>`: one of the shipped starter registry projects.
//!
//! Each starter under `products/breg/examples/refactor/` is an ordinary
//! authored BReg project checked in to the repository. This module embeds
//! those files verbatim at compile time, so `init --template` writes an
//! unmodified copy of the checked-in project without reading the source tree
//! at runtime.

use std::collections::BTreeMap;
use std::path::Path;

use clap::builder::PossibleValuesParser;

use crate::{
    artifact_report, compile, compiler_findings, diagnostic, init_media_type, source_failure,
    tool_diagnostic, DiagnosticArtifact, FailureReport, ProfileArg, SuccessReport, SuggestedAction,
};

/// One starter's embedded files: the path it is written at, relative to the
/// project root, paired with its contents exactly as checked in under
/// `core/`.
struct Starter {
    id: &'static str,
    files: &'static [(&'static str, &'static [u8])],
}

const STARTERS: &[Starter] = &[
    Starter {
        id: "minimal-directory",
        files: &[(
            "registry.yaml",
            include_bytes!("../../../products/breg/examples/refactor/minimal/registry.yaml"),
        )],
    },
    Starter {
        id: "facility-registry",
        files: &[
            (
                "registry.yaml",
                include_bytes!("../../../products/breg/examples/refactor/facility/registry.yaml"),
            ),
            (
                "plans/correct-address.rhai",
                include_bytes!(
                    "../../../products/breg/examples/refactor/facility/plans/correct-address.rhai"
                ),
            ),
        ],
    },
];

/// The starter ids this binary ships, in the order they are declared.
pub(crate) fn ids() -> Vec<&'static str> {
    STARTERS.iter().map(|starter| starter.id).collect()
}

/// A Clap parser exposing the shipped starter ids from the catalog itself.
pub(crate) fn value_parser() -> PossibleValuesParser {
    PossibleValuesParser::new(ids())
}

fn lookup(id: &str) -> Option<&'static Starter> {
    STARTERS.iter().find(|starter| starter.id == id)
}

/// The starter ids, quoted and comma-joined, for a refusal message.
fn names() -> String {
    ids()
        .iter()
        .map(|id| format!("`{id}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Writes the shipped starter project named `id` into `destination`.
pub(crate) fn run(destination: &Path, id: &str) -> Result<SuccessReport, FailureReport> {
    let Some(starter) = lookup(id) else {
        return Err(source_failure(
            "init",
            diagnostic(
                "init.template.unknown",
                "arguments",
                &format!(
                    "`{id}` is not a shipped starter template; the templates are {}",
                    names()
                ),
            ),
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        ));
    };
    let files: BTreeMap<String, Vec<u8>> = starter
        .files
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
        .collect();
    crate::write_source_files(destination, &files).map_err(|diagnostic| FailureReport {
        ok: false,
        command: "init",
        diagnostics: vec![tool_diagnostic(
            diagnostic,
            DiagnosticArtifact::ProjectInitialization,
            SuggestedAction::ChooseSafeOutputDirectory,
        )],
    })?;
    let compiled = compile(destination, ProfileArg::Authoring, "init")?;
    Ok(SuccessReport {
        ok: true,
        command: "init",
        profile: ProfileArg::Authoring,
        revision: Some(compiled.revision().to_owned()),
        registry_revision: None,
        package_digest: None,
        findings: compiler_findings(&compiled),
        artifacts: files
            .iter()
            .map(|(path, bytes)| artifact_report(path, init_media_type(path), bytes))
            .collect(),
        explanation: None,
        next_steps: next_steps(destination, starter.id),
    })
}

/// What a reader does after writing the `id` starter, named against the
/// directory just written.
fn next_steps(destination: &Path, id: &str) -> Vec<String> {
    vec![
        format!(
            "wrote the `{id}` template; run 'bregctl check {}'",
            destination.display()
        ),
        format!(
            "inspect its Actions with 'bregctl explain actions {}'",
            destination.display()
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn an_unknown_template_is_refused_and_lists_every_shipped_id() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let destination = directory
            .path()
            .canonicalize()
            .expect("a canonical path")
            .join("project");
        let error = match run(&destination, "not-a-real-starter") {
            Ok(_) => panic!("an unknown template must be refused"),
            Err(failure) => failure,
        };
        assert_eq!(error.command, "init");
        assert_eq!(error.diagnostics.len(), 1);
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "init.template.unknown");
        for id in ids() {
            assert!(
                diagnostic.message.contains(&format!("`{id}`")),
                "{}",
                diagnostic.message
            );
        }
        assert!(!destination.exists());
    }

    #[test]
    fn every_shipped_starter_writes_its_exact_checked_in_files_and_passes_check() {
        for id in ids() {
            let directory = tempfile::tempdir().expect("a temporary directory");
            let destination = directory
                .path()
                .canonicalize()
                .expect("a canonical path")
                .join("project");
            let report = run(&destination, id).unwrap_or_else(|failure| {
                panic!("{id}: {}", serde_json::to_string_pretty(&failure).unwrap())
            });
            assert_eq!(report.command, "init");

            let expected = read_core_directory(id);
            let written = read_written_directory(&destination);
            assert_eq!(
                written.keys().collect::<Vec<_>>(),
                expected.keys().collect::<Vec<_>>(),
                "{id}: the written files must match the checked-in core/ directory exactly"
            );
            for (path, contents) in &expected {
                assert_eq!(
                    &written[path], contents,
                    "{id}: {path} must be written byte for byte"
                );
            }

            let request = crate::check::Request {
                project: Some(&destination),
                package: None,
                production: false,
                deny_warnings: false,
                runtime_config: None,
                environment: false,
            };
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            let exit = crate::check::run(
                &request,
                crate::OutputFormat::Json,
                &mut stdout,
                &mut stderr,
            );
            assert_eq!(
                exit,
                std::process::ExitCode::SUCCESS,
                "{id}: {}",
                String::from_utf8_lossy(&stdout)
            );
        }
    }

    /// Read the canonical authored inputs independently of their embedded bytes.
    fn read_core_directory(id: &str) -> BTreeMap<String, Vec<u8>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/examples/refactor")
            .join(match id {
                "minimal-directory" => "minimal",
                "facility-registry" => "facility",
                _ => panic!("unregistered template"),
            });
        lookup(id)
            .unwrap()
            .files
            .iter()
            .map(|(path, _)| {
                (
                    (*path).to_owned(),
                    fs::read(root.join(path)).expect("canonical authored input"),
                )
            })
            .collect()
    }

    /// The files `run` wrote into `destination`, keyed by path relative to
    /// `destination`.
    fn read_written_directory(destination: &Path) -> BTreeMap<String, Vec<u8>> {
        walk_files(destination)
    }

    fn walk_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        walk_files_into(root, root, &mut files);
        files
    }

    fn walk_files_into(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(directory).expect("a readable directory") {
            let entry = entry.expect("a readable directory entry");
            let path = entry.path();
            if path.is_dir() {
                walk_files_into(root, &path, files);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("a path under root")
                    .to_str()
                    .expect("a UTF-8 relative path")
                    .to_owned();
                files.insert(relative, fs::read(&path).expect("a readable file"));
            }
        }
    }

    #[test]
    fn the_shipped_ids_are_the_canonical_projects() {
        assert_eq!(ids(), vec!["minimal-directory", "facility-registry",]);
    }
}
