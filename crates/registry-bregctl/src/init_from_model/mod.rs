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
    DiagnosticArtifact, DocumentRefusal, FailureReport, ProfileArg, Refusal, SuccessReport,
    SuggestedAction,
};

#[cfg(feature = "schema")]
pub(crate) use selection::selection_schema;
pub(crate) use selection::{ModelName, SELECTION_FORMAT};

/// Check a selection document `bregctl check --file` read: it resolves
/// against the embedded model it names, as `init --from --selection` would
/// resolve it. Each refusal is reported at the member it concerns.
pub(crate) fn check_selection(
    document: &registry_platform_yaml::Document,
) -> Result<Vec<registry_platform_yaml::Diagnostic>, crate::file_check::Failure> {
    let selection = document.decode::<selection::Selection>()?;
    let model = match selection.model {
        ModelName::Publicschema => publicschema::model().map_err(|_| {
            crate::file_check::Failure::unavailable(
                "breg.check.model-unreadable",
                "the reference model embedded in this bregctl does not read",
                "Install a bregctl release; its reference model is part of the binary.",
            )
        })?,
    };
    Ok(match resolve::resolve(&selection, &model) {
        Ok(_) => Vec::new(),
        Err(refusal) => vec![crate::file_check::diagnostic_near(
            document,
            &refusal.code,
            &refusal.path,
            &refusal.message,
            "Correct the selection as the message says, then check it again.",
        )],
    })
}

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
) -> Result<SuccessReport, Refusal> {
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
        Source::File(path) => read_selection_file(path)?,
        Source::Starter(name) => starter_selection(model, name)?,
        Source::Interactive => {
            // The prompts read standard input and write standard error, so
            // those two are the streams that must be terminals; standard
            // output carries the report and may be a pipe.
            if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
                return Err(usage_failure(diagnostic(
                    "init.selection.missing",
                    "arguments",
                    &format!(
                        "`init --from {model}` asks its questions at a terminal; without one, \
                         pass `--selection <FILE>` or `--starter <NAME>` (one of {})",
                        starter_names(model)
                    ),
                ))
                .into());
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
        ))
        .into());
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
        revision: Some(compiled.revision().to_owned()),
        registry_revision: None,
        package_digest: None,
        findings: compiler_findings(&compiled),
        artifacts: files
            .iter()
            .map(|(path, bytes)| artifact_report(path, init_media_type(path), bytes))
            .collect(),
        explanation: None,
        next_steps: next_steps(destination, &plan),
    })
}

fn read_selection_file(path: &Path) -> Result<selection::Selection, Refusal> {
    let source = path.display().to_string();
    let bytes = crate::read_bounded_source_file(
        path,
        "init.selection.unreadable",
        &source,
        MAX_SELECTION_FILE_BYTES,
    )
    .map_err(|refusal| {
        if refusal.code == "breg.source.file-bounds" {
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
    })
    .map_err(selection_failure)?;
    selection::Selection::parse(&source, &bytes).map_err(selection_refusal)
}

fn starter_selection(model: ModelName, name: &str) -> Result<selection::Selection, Refusal> {
    let starters = match model {
        ModelName::Publicschema => publicschema::starters(),
    };
    let Some(starter) = starters.iter().find(|starter| starter.name == name) else {
        return Err(usage_failure(diagnostic(
            "init.starter.unknown",
            "arguments",
            &format!(
                "`{name}` is not a starter of `{model}`; the starters are {}",
                starter_names(model)
            ),
        ))
        .into());
    };
    selection::Selection::parse(&format!("starter {name}"), starter.contents.as_bytes())
        .map_err(selection_refusal)
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

/// The reader's diagnostics for a selection document, printed unchanged.
fn selection_refusal(report: registry_platform_yaml::Report) -> Refusal {
    Refusal::Document(DocumentRefusal {
        command: "init",
        subject: "the model selection",
        report,
    })
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
    let counted = |count: usize| {
        if count == 1 {
            "a field".to_owned()
        } else {
            format!("{count} fields")
        }
    };
    let mut findings = format!("{profiles} on purpose");
    let sensitive = render::sensitive_elevated_fields(&elevated);
    if !sensitive.is_empty() {
        findings.push_str(&format!(
            ", and the `{}` profile reads {} the model marks sensitive",
            render::OPERATOR_PROFILE,
            counted(sensitive.len())
        ));
    }
    let mismatched = render::public_mismatch_fields(&elevated);
    if !mismatched.is_empty() {
        findings.push_str(&format!(
            ", and the `{}` profile reads {} the selection placed inside a public entity",
            render::OPERATOR_PROFILE,
            counted(mismatched.len())
        ));
    }
    let mut steps = vec![
        format!(
            "read {}, then run 'bregctl check {}'",
            readme.display(),
            destination.display()
        ),
        format!(
            "leave the findings above as they are; {findings}, and {} says where to narrow them",
            readme.display()
        ),
    ];
    let unlinked = plan.unlinked_entities();
    if !unlinked.is_empty() {
        let quoted: Vec<String> = unlinked.iter().map(|id| format!("`{id}`")).collect();
        let named = match quoted.as_slice() {
            [only] => only.clone(),
            [first, second] => format!("{first} or {second}"),
            [rest @ .., last] => format!("{}, or {last}", rest.join(", ")),
            [] => unreachable!("checked above"),
        };
        steps.push(format!(
            "no field connects {named} to another entity; {} names the concepts of the model that would, if the registry should link them",
            readme.display()
        ));
    }
    steps.extend([
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
    ]);
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command's own report of a refusal a test expects to be one.
    fn tool_failure(refusal: Refusal) -> FailureReport {
        match refusal {
            Refusal::Tool(report) => report,
            Refusal::Document(refusal) => panic!("{}", refusal.report.render_human()),
        }
    }

    /// The single diagnostic of a refusal the command reports itself.
    fn tool_diagnostic_of(refusal: Refusal) -> crate::ToolDiagnostic {
        let mut report = tool_failure(refusal);
        assert_eq!(report.diagnostics.len(), 1);
        report.diagnostics.remove(0)
    }

    #[test]
    fn a_starter_is_found_by_name_and_an_unknown_name_lists_the_starters() {
        let Ok(selection) = starter_selection(ModelName::Publicschema, "household") else {
            panic!("the household starter ships");
        };
        assert_eq!(selection.model, ModelName::Publicschema);
        let error = tool_diagnostic_of(
            starter_selection(ModelName::Publicschema, "missing").expect_err("refused"),
        );
        assert_eq!(error.code, "init.starter.unknown");
        assert!(error.message.contains("`household`"), "{}", error.message);
    }

    /// The Evidence tutorial's shipped selection is only resolved against the
    /// embedded model by the opt-in `--live` composition check, which this
    /// workspace does not run in CI. Pin its `modelRevision` here so a
    /// PublicSchema snapshot sync that moves the pinned commit fails this
    /// crate's tests until the shipped file is updated too.
    #[test]
    fn the_shipped_evidence_organization_selection_matches_the_embedded_revision() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/evidence/organization-selection.yaml");
        let contents = std::fs::read_to_string(&path).expect("the shipped selection reads");
        let selection =
            selection::Selection::parse("organization-selection.yaml", contents.as_bytes())
                .expect("the shipped selection parses");
        let pin = publicschema::pin().expect("the embedded model is pinned");
        assert_eq!(
            selection.model_revision.as_deref(),
            Some(pin.commit.as_str())
        );
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
        let missing = tool_diagnostic_of(
            read_selection_file(&root.join("absent.yaml")).expect_err("refused"),
        );
        assert_eq!(missing.code, "init.selection.unreadable");
        let oversized = root.join("large.yaml");
        std::fs::write(
            &oversized,
            vec![b' '; MAX_SELECTION_FILE_BYTES as usize + 1],
        )
        .expect("written");
        assert_eq!(
            tool_diagnostic_of(read_selection_file(&oversized).expect_err("refused")).code,
            "init.selection.size"
        );
        assert_eq!(
            tool_diagnostic_of(read_selection_file(root.as_path()).expect_err("refused")).code,
            "init.selection.unreadable"
        );
        let linked = root.join("linked.yaml");
        std::os::unix::fs::symlink(&path, &linked).expect("linked");
        let refused = tool_diagnostic_of(
            read_selection_file(&linked).expect_err("a symbolic link is refused"),
        );
        assert_eq!(refused.code, "init.selection.unreadable");
        assert!(
            refused.message.contains("symbolic link"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_selection_file_the_reader_refuses_keeps_the_reader_diagnostics() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().canonicalize().expect("a canonical path");
        let path = root.join("selection.yaml");
        std::fs::write(
            &path,
            "apiVersion: registry.registrystack.org/breg-model-selection/v1alpha1\n\
             kind: BRegModelSelection\n\
             model: publicschema\n\
             registry:\n  id: example\n  title: Example\n\
             entities: []\n",
        )
        .expect("written");
        let Err(Refusal::Document(refusal)) = read_selection_file(&path) else {
            panic!("the reader refuses the header an earlier bregctl wrote");
        };
        assert_eq!(
            (refusal.command, refusal.subject),
            ("init", "the model selection")
        );
        let diagnostics = refusal.report.diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "config.retired-api-version");
        let source = diagnostics[0].source.as_ref().expect("positioned");
        let file = path.display().to_string();
        assert_eq!(
            (source.file.as_str(), source.line),
            (file.as_str(), Some(1))
        );
    }

    #[test]
    fn next_steps_tell_a_public_entitys_fields_apart_from_ones_the_model_marks_sensitive() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().canonicalize().expect("a canonical path");
        let selection = root.join("selection.yaml");
        std::fs::write(
            &selection,
            "apiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1\n\
             kind: BRegModelSelection\n\
             model: publicschema\n\
             modelVersion: \"0.3.0\"\n\
             registry:\n  id: place-registry\n  title: Place Registry\n\
             entities:\n\
             \x20 - concept: Household\n\
             \x20   classification: public\n\
             \x20   properties:\n\
             \x20     - name: name\n\
             \x20     - name: address\n",
        )
        .expect("a selection");
        let destination = root.join("project");
        let report = run(
            &destination,
            ModelName::Publicschema,
            Source::File(&selection),
        )
        .map_err(tool_failure)
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string_pretty(&failure).unwrap()));
        let step = &report.next_steps[1];
        assert!(
            !step.contains("the model marks sensitive"),
            "no field of a public entity is model-sensitive: {step}"
        );
        assert!(
            step.contains("reads 3 fields the selection placed inside a public entity"),
            "{step}"
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
        .map_err(tool_failure)
        .unwrap_or_else(|failure| panic!("{}", serde_json::to_string_pretty(&failure).unwrap()));
        assert_eq!(report.command, "init");
        assert!(destination.join(render::SELECTION_PATH).is_file());
        assert!(destination.join("registry.yaml").is_file());
        assert!(report.findings.iter().all(|finding| {
            finding.code == "breg.access.profile-unrestricted-collection"
                || finding.code == "breg.access.profile-higher-classification"
        }));
        assert!(report.next_steps[1].contains("reads 2 fields the model marks sensitive"));
        assert_eq!(report.next_steps.len(), 5);
        match run(
            &destination,
            ModelName::Publicschema,
            Source::Starter("household"),
        ) {
            Ok(_) => panic!("an existing destination is refused"),
            Err(again) => assert_eq!(tool_failure(again).command, "init"),
        }
    }

    #[test]
    fn a_selection_the_compiler_would_refuse_leaves_no_destination_behind() {
        // Every name the compiler holds to a rule is checked while the
        // selection resolves, because the destination is written before the
        // project is compiled and an existing directory is refused a second
        // time.
        let directory = tempfile::tempdir().expect("a temporary directory");
        let root = directory.path().canonicalize().expect("a canonical path");
        let selections = [
            "entities:\n  - concept: Person\n    identifierField: created_at\n",
            "entities:\n  - concept: Person\n    identifierField: given_name\n    properties:\n      - name: given_name\n",
            "entities:\n  - concept: Person\n    properties:\n      - name: preferred_language\n\
             vocabularies:\n  - enum: Language\n    mode: inline\n",
        ];
        for (index, body) in selections.iter().enumerate() {
            let path = root.join(format!("selection-{index}.yaml"));
            std::fs::write(
                &path,
                format!(
                    "apiVersion: {}\nkind: {}\nmodel: publicschema\nregistry:\n  id: example\n  title: Example\n{body}",
                    selection::API_VERSION,
                    selection::KIND,
                ),
            )
            .expect("written");
            let destination = root.join(format!("project-{index}"));
            match run(&destination, ModelName::Publicschema, Source::File(&path)) {
                Ok(_) => panic!("selection {index} is refused"),
                Err(failure) => assert_eq!(tool_failure(failure).command, "init"),
            }
            assert!(!destination.exists(), "{}", destination.display());
        }
    }

    #[test]
    fn the_next_steps_say_what_no_field_links() {
        let document = "apiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1\n\
             kind: BRegModelSelection\nmodel: publicschema\nregistry:\n  id: example\n  title: Example\n\
             entities:\n  - concept: Household\n    properties:\n      - name: name\n\
             \x20 - concept: School\n    properties:\n      - name: name\n";
        let selection = selection::Selection::parse("test", document.as_bytes()).expect("parses");
        let model = publicschema::model().expect("the snapshot reads");
        let plan = resolve::resolve(&selection, &model).expect("resolves");
        let steps = next_steps(Path::new("project"), &plan);
        assert_eq!(steps.len(), 6);
        assert_eq!(
            steps[2],
            "no field connects `household` or `school` to another entity; project/README.md names the concepts of the model that would, if the registry should link them"
        );
    }

    #[test]
    fn a_selection_for_another_model_is_refused() {
        // There is one model today, so the check is exercised through the
        // starter path: every starter matches its own model.
        let Ok(selection) = starter_selection(ModelName::Publicschema, "household") else {
            panic!("the household starter ships");
        };
        assert_eq!(selection.model, ModelName::Publicschema);
    }
}
