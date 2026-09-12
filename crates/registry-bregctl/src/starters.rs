// SPDX-License-Identifier: Apache-2.0
//! `init --template <ID>`: one of the shipped starter registry projects.
//!
//! Each starter under `products/breg/starters/<id>/core` is an ordinary
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
        id: "professional-licences",
        files: &[
            (
                "ATTRIBUTION.md",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/ATTRIBUTION.md"
                ),
            ),
            (
                "dev-clients.yaml",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/dev-clients.yaml"
                ),
            ),
            (
                "examples/inputs/first-record.json",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/examples/inputs/first-record.json"
                ),
            ),
            (
                "examples/inputs/reviewed-change.json",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/examples/inputs/reviewed-change.json"
                ),
            ),
            (
                "examples/inputs/starter-data.json",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/examples/inputs/starter-data.json"
                ),
            ),
            (
                "examples/scenarios.json",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/examples/scenarios.json"
                ),
            ),
            (
                "MODEL.md",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/MODEL.md"
                ),
            ),
            (
                "PUBLICSCHEMA-LICENSE.txt",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/PUBLICSCHEMA-LICENSE.txt"
                ),
            ),
            (
                "registry.yaml",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/registry.yaml"
                ),
            ),
            (
                "starter-template.json",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/starter-template.json"
                ),
            ),
            (
                "tests/journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/tests/journeys.yaml"
                ),
            ),
            (
                "tests/security-journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/professional-licences/core/tests/security-journeys.yaml"
                ),
            ),
        ],
    },
    Starter {
        id: "agricultural-holdings",
        files: &[
            (
                "ATTRIBUTION.md",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/ATTRIBUTION.md"
                ),
            ),
            (
                "dev-clients.yaml",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/dev-clients.yaml"
                ),
            ),
            (
                "examples/inputs/first-record.json",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/examples/inputs/first-record.json"
                ),
            ),
            (
                "examples/inputs/reviewed-change.json",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/examples/inputs/reviewed-change.json"
                ),
            ),
            (
                "examples/inputs/starter-data.json",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/examples/inputs/starter-data.json"
                ),
            ),
            (
                "examples/scenarios.json",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/examples/scenarios.json"
                ),
            ),
            (
                "MODEL.md",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/MODEL.md"
                ),
            ),
            (
                "PUBLICSCHEMA-LICENSE.txt",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/PUBLICSCHEMA-LICENSE.txt"
                ),
            ),
            (
                "registry.yaml",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/registry.yaml"
                ),
            ),
            (
                "starter-template.json",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/starter-template.json"
                ),
            ),
            (
                "tests/journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/tests/journeys.yaml"
                ),
            ),
            (
                "tests/security-journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/agricultural-holdings/core/tests/security-journeys.yaml"
                ),
            ),
        ],
    },
    Starter {
        id: "public-organizations",
        files: &[
            (
                "ATTRIBUTION.md",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/ATTRIBUTION.md"
                ),
            ),
            (
                "dev-clients.yaml",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/dev-clients.yaml"
                ),
            ),
            (
                "examples/inputs/first-record.json",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/examples/inputs/first-record.json"
                ),
            ),
            (
                "examples/inputs/reviewed-change.json",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/examples/inputs/reviewed-change.json"
                ),
            ),
            (
                "examples/inputs/starter-data.json",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/examples/inputs/starter-data.json"
                ),
            ),
            (
                "examples/scenarios.json",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/examples/scenarios.json"
                ),
            ),
            (
                "MODEL.md",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/MODEL.md"
                ),
            ),
            (
                "PUBLICSCHEMA-LICENSE.txt",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/PUBLICSCHEMA-LICENSE.txt"
                ),
            ),
            (
                "registry.yaml",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/registry.yaml"
                ),
            ),
            (
                "starter-template.json",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/starter-template.json"
                ),
            ),
            (
                "tests/journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/tests/journeys.yaml"
                ),
            ),
            (
                "tests/security-journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/public-organizations/core/tests/security-journeys.yaml"
                ),
            ),
        ],
    },
    Starter {
        id: "seed-lots",
        files: &[
            (
                "ATTRIBUTION.md",
                include_bytes!("../../../products/breg/starters/seed-lots/core/ATTRIBUTION.md"),
            ),
            (
                "dev-clients.yaml",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/dev-clients.yaml"
                ),
            ),
            (
                "examples/inputs/first-record.json",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/examples/inputs/first-record.json"
                ),
            ),
            (
                "examples/inputs/reviewed-change.json",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/examples/inputs/reviewed-change.json"
                ),
            ),
            (
                "examples/inputs/starter-data.json",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/examples/inputs/starter-data.json"
                ),
            ),
            (
                "examples/scenarios.json",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/examples/scenarios.json"
                ),
            ),
            (
                "MODEL.md",
                include_bytes!("../../../products/breg/starters/seed-lots/core/MODEL.md"),
            ),
            (
                "PUBLICSCHEMA-LICENSE.txt",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/PUBLICSCHEMA-LICENSE.txt"
                ),
            ),
            (
                "registry.yaml",
                include_bytes!("../../../products/breg/starters/seed-lots/core/registry.yaml"),
            ),
            (
                "starter-template.json",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/starter-template.json"
                ),
            ),
            (
                "tests/journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/tests/journeys.yaml"
                ),
            ),
            (
                "tests/security-journeys.yaml",
                include_bytes!(
                    "../../../products/breg/starters/seed-lots/core/tests/security-journeys.yaml"
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
        revision: compiled.revision().to_owned(),
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
            "wrote the `{id}` starter; read {}, then run 'bregctl check {}'",
            destination.join("MODEL.md").display(),
            destination.display()
        ),
        format!(
            "run 'bregctl dev {}' to start the registry locally and replay {}",
            destination.display(),
            destination.join(crate::FIXTURE_JOURNEYS_PATH).display()
        ),
        format!(
            "replace canonicalBaseIri in {} before you build a production package; the starter value is a reserved example.org name standing in for your registry's real identity",
            destination.join("registry.yaml").display()
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

            crate::check(&destination, ProfileArg::Authoring).unwrap_or_else(|failure| {
                panic!("{id}: {}", serde_json::to_string_pretty(&failure).unwrap())
            });
        }
    }

    /// The files checked in under a starter's `core/` directory, read from
    /// the source tree at test time, keyed by path relative to `core/`.
    fn read_core_directory(id: &str) -> BTreeMap<String, Vec<u8>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/starters")
            .join(id)
            .join("core");
        walk_files(&root)
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
    fn the_shipped_ids_are_the_four_published_starters() {
        assert_eq!(
            ids(),
            vec![
                "professional-licences",
                "agricultural-holdings",
                "public-organizations",
                "seed-lots",
            ]
        );
    }
}
