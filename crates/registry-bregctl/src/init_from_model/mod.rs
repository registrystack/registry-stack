// SPDX-License-Identifier: Apache-2.0
//! `init --from <MODEL>`: a registry project derived from a reference model.
//!
//! A plain `init` writes one fixed example project. This path writes a
//! project whose entities, fields, and vocabularies come from a selection over
//! an embedded reference model, so an adopter starts from the concepts their
//! registry is about instead of renaming an example. The selection is read
//! from a file, taken from a shipped starter, or gathered at the terminal; the
//! three converge on one document before anything is derived, and that
//! document is echoed into the written project.
//!
//! The derivation adds nothing the runtime does not already have: the written
//! project is ordinary source that `check`, `dev`, and `build` read as they
//! read any other. No concept of the model becomes a Rust type here, and the
//! command's own text names none of them.

mod render;
mod resolve;
mod selection;
mod wizard;

use std::io::IsTerminal;
use std::path::Path;

use registry_breg::Diagnostic;
use registry_linkml::publicschema;

use crate::{
    artifact_report, compile, compiler_findings, diagnostic, init_media_type, tool_diagnostic,
    DiagnosticArtifact, FailureReport, ProfileArg, SuccessReport, SuggestedAction,
};

pub(crate) use selection::ModelName;

/// The largest selection file the command reads.
const MAX_SELECTION_FILE_BYTES: u64 = 256 * 1024;

/// Where the selection comes from.
pub(crate) enum Source<'a> {
    /// A selection document on disk.
    File(&'a Path),
    /// A selection shipped with the model, by name.
    Starter(&'a str),
    /// The terminal, when there is one.
    Interactive,
}

/// Derives a project from `model` into `destination`.
pub(crate) fn run(
    destination: &Path,
    model: ModelName,
    source: Source<'_>,
) -> Result<SuccessReport, FailureReport> {
    // The model is read before the selection, because the wizard asks its
    // questions about the concepts and properties this snapshot carries.
    let model_data = match model {
        ModelName::Publicschema => publicschema::model().map_err(|error| {
            selection_failure(diagnostic(
                "init.model.unreadable",
                "model",
                &format!("the embedded {model} snapshot does not read: {error}"),
            ))
        })?,
    };
    let selection = match source {
        Source::File(path) => read_selection_file(path).map_err(selection_failure)?,
        Source::Starter(name) => starter_selection(model, name).map_err(usage_failure)?,
        Source::Interactive => {
            if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
                return Err(usage_failure(diagnostic(
                    "init.selection.missing",
                    "arguments",
                    &format!(
                        "`init --from {model}` asks its questions at a terminal; without one, \
                         pass `--selection <FILE>` or `--starter <NAME>` (one of {})",
                        starter_names(model)
                    ),
                )));
            }
            wizard::gather(model, &model_data).map_err(usage_failure)?
        }
    };
    if selection.model != model {
        return Err(selection_failure(diagnostic(
            "init.selection.model",
            "selection",
            &format!(
                "the selection was written for `{}`, and this run derives from `{model}`",
                selection.model
            ),
        )));
    }
    let plan = resolve::resolve(&selection, &model_data).map_err(selection_failure)?;
    let files = render::render(&plan, &selection);
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
        next_steps: next_steps(destination, &plan),
    })
}

fn read_selection_file(path: &Path) -> Result<selection::Selection, Diagnostic> {
    let source = path.display().to_string();
    let bytes = crate::read_bounded_source_file(
        path,
        "init.selection.unreadable",
        &source,
        MAX_SELECTION_FILE_BYTES,
    )
    .map_err(|refusal| {
        if refusal.code == "source.file.bounds" {
            diagnostic(
                "init.selection.size",
                &source,
                &format!("a selection document must be at most {MAX_SELECTION_FILE_BYTES} bytes"),
            )
        } else {
            diagnostic(
                "init.selection.unreadable",
                &source,
                &format!("the selection file cannot be read: {}", refusal.message),
            )
        }
    })?;
    selection::Selection::parse(&source, &bytes)
}

fn starter_selection(model: ModelName, name: &str) -> Result<selection::Selection, Diagnostic> {
    let starters = match model {
        ModelName::Publicschema => publicschema::starters(),
    };
    let Some(starter) = starters.iter().find(|starter| starter.name == name) else {
        return Err(diagnostic(
            "init.starter.unknown",
            "arguments",
            &format!(
                "`{name}` is not a starter of `{model}`; the starters are {}",
                starter_names(model)
            ),
        ));
    };
    selection::Selection::parse(&format!("starter {name}"), starter.contents.as_bytes())
}

/// The starter names of `model`, quoted and comma-joined.
fn starter_names(model: ModelName) -> String {
    let starters = match model {
        ModelName::Publicschema => publicschema::starters(),
    };
    starters
        .iter()
        .map(|starter| format!("`{}`", starter.name))
        .collect::<Vec<_>>()
        .join(", ")
}

fn selection_failure(diagnostic: Diagnostic) -> FailureReport {
    crate::source_failure(
        "init",
        diagnostic,
        DiagnosticArtifact::ModelSelection,
        SuggestedAction::CorrectModelSelection,
    )
}

fn usage_failure(diagnostic: Diagnostic) -> FailureReport {
    crate::source_failure(
        "init",
        diagnostic,
        DiagnosticArtifact::CommandArguments,
        SuggestedAction::CorrectCommandUsage,
    )
}

/// What a reader does after a derived `init`, named against the directory
/// just written and the profiles it declares.
fn next_steps(destination: &Path, plan: &resolve::Plan) -> Vec<String> {
    let readme = destination.join("README.md");
    let profiles = if render::reader_entities(plan).is_empty() {
        format!(
            "the `{}` profile lists whole collections",
            render::OPERATOR_PROFILE
        )
    } else {
        format!(
            "the `{}` and `{}` profiles list whole collections",
            render::OPERATOR_PROFILE,
            render::READER_PROFILE
        )
    };
    let elevated = render::elevated_fields(plan);
    let findings = if elevated.is_empty() {
        format!("{profiles} on purpose")
    } else {
        format!(
            "{profiles} on purpose, and the `{}` profile reads {} the model marks sensitive",
            render::OPERATOR_PROFILE,
            if elevated.len() == 1 {
                "a field".to_owned()
            } else {
                format!("{} fields", elevated.len())
            }
        )
    };
    vec![
        format!(
            "read {}, then run 'bregctl check {}'",
            readme.display(),
            destination.display()
        ),
        format!(
            "leave the findings above as they are; {findings}, and {} says where to narrow them",
            readme.display()
        ),
        format!(
            "run 'bregctl dev {}' to start the registry locally and replay {}",
            destination.display(),
            destination.join(crate::FIXTURE_JOURNEYS_PATH).display()
        ),
        format!(
            "replace canonicalBaseIri in {} before you build a production package; the derived value is a reserved .invalid name that never resolves",
            destination.join("registry.yaml").display()
        ),
        format!(
            "keep {} beside the project: edit it and pass it back with --selection to derive a fresh project",
            destination.join(render::SELECTION_PATH).display()
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_starter_is_found_by_name_and_an_unknown_name_lists_the_starters() {
        let selection = starter_selection(ModelName::Publicschema, "household").expect("ships");
        assert_eq!(selection.model, ModelName::Publicschema);
        let error = starter_selection(ModelName::Publicschema, "missing").expect_err("refused");
        assert_eq!(error.code, "init.starter.unknown");
        assert!(error.message.contains("`household`"), "{}", error.message);
    }

    #[test]
    fn a_selection_file_is_read_within_its_bound() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().canonicalize().expect("a canonical path");
        let path = root.join("selection.yaml");
        let starter = publicschema::starters()
            .iter()
            .find(|starter| starter.name == "household")
            .expect("ships");
        std::fs::write(&path, starter.contents).expect("written");
        assert!(read_selection_file(&path).is_ok());
        let missing = read_selection_file(&root.join("absent.yaml")).expect_err("refused");
        assert_eq!(missing.code, "init.selection.unreadable");
        let oversized = root.join("large.yaml");
        std::fs::write(
            &oversized,
            vec![b' '; MAX_SELECTION_FILE_BYTES as usize + 1],
        )
        .expect("written");
        assert_eq!(
            read_selection_file(&oversized).expect_err("refused").code,
            "init.selection.size"
        );
        assert_eq!(
            read_selection_file(root.as_path())
                .expect_err("refused")
                .code,
            "init.selection.unreadable"
        );
        let linked = root.join("linked.yaml");
        std::os::unix::fs::symlink(&path, &linked).expect("linked");
        let refused = read_selection_file(&linked).expect_err("a symbolic link is refused");
        assert_eq!(refused.code, "init.selection.unreadable");
        assert!(
            refused.message.contains("symbolic link"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_derived_project_is_written_and_compiles() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let destination = directory
            .path()
            .canonicalize()
            .expect("a canonical path")
            .join("project");
        let report = run(
            &destination,
            ModelName::Publicschema,
            Source::Starter("household"),
        )
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string_pretty(&failure).unwrap()));
        assert_eq!(report.command, "init");
        assert!(destination.join(render::SELECTION_PATH).is_file());
        assert!(destination.join("registry.yaml").is_file());
        assert!(report.findings.iter().all(|finding| {
            finding.code == "access.profile.unrestricted_collection"
                || finding.code == "access.profile.higher_classification"
        }));
        assert!(report.next_steps[1].contains("reads 2 fields the model marks sensitive"));
        assert_eq!(report.next_steps.len(), 5);
        match run(
            &destination,
            ModelName::Publicschema,
            Source::Starter("household"),
        ) {
            Ok(_) => panic!("an existing destination is refused"),
            Err(again) => assert_eq!(again.command, "init"),
        }
    }

    #[test]
    fn a_selection_for_another_model_is_refused() {
        // There is one model today, so the check is exercised through the
        // starter path: every starter matches its own model.
        let selection = starter_selection(ModelName::Publicschema, "household").expect("ships");
        assert_eq!(selection.model, ModelName::Publicschema);
    }
}
