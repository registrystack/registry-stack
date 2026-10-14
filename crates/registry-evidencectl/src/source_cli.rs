//! Native source lifecycle commands. The importer owns artifact comparison
//! and transactions; this module validates complete candidates and reports
//! target revisions returned by the ordinary compiler and runtime.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};

use crate::{authoring, build, source_add, source_import, source_mock, suggest, OutputFormat};

#[derive(Debug, Subcommand)]
pub(crate) enum SourceCommand {
    /// Connect a retained local registry through its public lookup export.
    ///
    /// This command reviews the connection by default and reports the choices
    /// it would apply; re-run it with --apply to perform them.
    ///
    /// It drives the public Base Registry Engine commands, so a bregctl binary
    /// of this same version must be on PATH, or named by --bregctl-bin or
    /// BREGCTL_BIN.
    Add(source_add::SourceAddArgs),
    /// Suggest source configuration from an OpenAPI document.
    Suggest(suggest::SuggestArgs),
    /// Generate, inspect, and serve a local synthetic source API.
    #[command(subcommand)]
    Mock(source_mock::MockCommand),
    /// Compare complete local source exports with the editable project.
    Diff(SourceImportArgs),
    /// Import complete local source exports after compiler validation.
    Import(SourceImportArgs),
    /// Update previously imported source exports after compiler validation.
    Update(SourceImportArgs),
    /// Fork one installed source into ordinary maintained authored files.
    Detach(SourceDetachArgs),
}

#[derive(Debug, Args)]
pub(crate) struct SourceImportArgs {
    /// Complete local export directories; pass shared owners together.
    #[arg(required = true, num_args = 1..)]
    pub(crate) exports: Vec<PathBuf>,
    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project containing evidence.yaml and its
    /// named Function assets.
    #[arg(long, default_value = ".")]
    pub(crate) project: PathBuf,
    /// Closed versioned file choosing keep, adopt, or an explicitly resolved file.
    #[arg(long)]
    pub(crate) resolutions: Option<PathBuf>,
    /// Complete target used by the compiler to compare actual definition revisions.
    #[arg(long)]
    pub(crate) target: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct SourceDetachArgs {
    /// Installed source to fork into ordinary maintained authored files.
    pub(crate) source_id: String,
    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project containing evidence.yaml and its
    /// named Function assets.
    #[arg(value_name = "PROJECT", default_value = ".")]
    pub(crate) project: PathBuf,
}

pub(crate) fn run(command: SourceCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        SourceCommand::Add(args) => source_add::run(args, format),
        SourceCommand::Suggest(args) => suggest::run(suggest::SourceCommand::Suggest(args), format),
        SourceCommand::Mock(command) => source_mock::run(command, format),
        SourceCommand::Diff(args) => diff(args, format),
        SourceCommand::Import(args) => apply(args, "source import", format),
        SourceCommand::Update(args) => apply(args, "source update", format),
        SourceCommand::Detach(args) => detach(args),
    }
}

fn diff(args: SourceImportArgs, format: OutputFormat) -> Result<ExitCode> {
    review(
        args.into_import_args(),
        false,
        &mut std::io::stdout().lock(),
        Emit {
            command: "source diff",
            format,
        },
    )
}

fn apply(args: SourceImportArgs, command: &'static str, format: OutputFormat) -> Result<ExitCode> {
    review(
        args.into_import_args(),
        true,
        &mut std::io::stdout().lock(),
        Emit { command, format },
    )
}

/// How one review reports: the command path its JSON report names, and the
/// output format.
#[derive(Clone, Copy)]
struct Emit {
    command: &'static str,
    format: OutputFormat,
}

fn review(
    args: source_import::ImportArgs,
    apply: bool,
    output: &mut impl Write,
    emit: Emit,
) -> Result<ExitCode> {
    review_with_revisions_in_format(
        args,
        apply,
        output,
        emit,
        build::validated_question_revisions,
    )
}

fn review_with_revisions_in_format(
    args: source_import::ImportArgs,
    apply: bool,
    output: &mut impl Write,
    emit: Emit,
    mut target_revisions: impl FnMut(&Path, &Path) -> Result<BTreeMap<String, String>>,
) -> Result<ExitCode> {
    let format = emit.format;
    let lock = source_import::ProjectLock::acquire(&args.project)
        .with_context(|| format!("locking editable project {}", args.project.display()))?;
    let resolutions = source_import::read_resolutions(args.resolutions.as_deref())?;
    let mut candidate = source_import::prepare(&lock, &args.exports, &resolutions)?;
    let mut report =
        serde_json::to_value(candidate.report()).context("encoding source comparison")?;
    let validation_kind = if args.target.is_some() {
        "target"
    } else {
        "structural"
    };
    if !candidate.report().conflicts.is_empty() {
        report["validation"] = json!({"kind": validation_kind, "status": "conflict"});
        if apply {
            print_report_before_error(output, &report, format)?;
            bail!("source candidate has unresolved conflicts; choose keep, adopt, or an explicit resolved file");
        }
        print_report(output, &report, emit, "conflict")?;
        return Ok(ExitCode::SUCCESS);
    }

    let mut next_revisions = None;
    let validation = candidate.validate(|project| {
        authoring::validate_source_artifact_graph(project)?;
        if let Some(target) = args.target.as_deref() {
            next_revisions = Some(target_revisions(project, target)?);
        }
        Ok(())
    });
    if let Err(error) = validation {
        report["validation"] = json!({"kind": validation_kind, "status": "failed"});
        print_report_before_error(output, &report, format)?;
        return Err(error);
    }
    report["validation"] = json!({"kind": validation_kind, "status": "passed"});
    if let (Some(target), Some(next)) = (args.target.as_deref(), next_revisions) {
        let previous = target_revisions(&args.project, target);
        report["target"] = json!(target);
        report["previousValidation"] = if previous.is_ok() {
            json!({"status": "passed"})
        } else {
            // Initial import may complete a question whose source did not yet
            // exist. Failed old compilation is not an invented old revision.
            json!({"status": "unavailable", "reason": "current-project-not-buildable-with-target"})
        };
        report["definitionRevisions"] = revision_changes(previous.ok().as_ref(), &next);
    }
    if apply {
        if let Err(error) = candidate.apply(&lock) {
            report["application"] = json!("failed");
            print_report_before_error(output, &report, format)?;
            return Err(error);
        }
        report["application"] = json!("accepted");
    }
    let status = if apply { "applied" } else { "complete" };
    print_report(output, &report, emit, status)?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
fn review_with_revisions(
    args: source_import::ImportArgs,
    apply: bool,
    output: &mut impl Write,
    target_revisions: impl FnMut(&Path, &Path) -> Result<BTreeMap<String, String>>,
) -> Result<ExitCode> {
    review_with_revisions_in_format(
        args,
        apply,
        output,
        Emit {
            command: "source diff",
            format: OutputFormat::Human,
        },
        target_revisions,
    )
}

fn print_report_before_error(
    output: &mut impl Write,
    report: &Value,
    format: OutputFormat,
) -> Result<()> {
    if format == OutputFormat::Human {
        write_pretty(output, report)?;
    }
    Ok(())
}

/// Write the comparison report: indented JSON for a human run, or the shared
/// one-line envelope under `--format json`.
fn print_report(output: &mut impl Write, report: &Value, emit: Emit, status: &str) -> Result<()> {
    match emit.format {
        OutputFormat::Human => write_pretty(output, report),
        OutputFormat::Json => {
            let report = crate::report::success(emit.command, status, report.clone());
            writeln!(output, "{}", crate::report::render(&report))
                .context("writing source comparison report")?;
            output.flush().context("flushing source comparison report")
        }
    }
}

fn write_pretty(output: &mut impl Write, report: &Value) -> Result<()> {
    serde_json::to_writer_pretty(&mut *output, report)
        .context("writing source comparison report")?;
    writeln!(output).context("finishing source comparison report")?;
    output.flush().context("flushing source comparison report")
}

fn revision_changes(
    previous: Option<&BTreeMap<String, String>>,
    next: &BTreeMap<String, String>,
) -> Value {
    let ids: BTreeSet<_> = previous
        .into_iter()
        .flat_map(BTreeMap::keys)
        .chain(next.keys())
        .collect();
    Value::Array(
        ids.into_iter()
            .map(|id| {
                let before = previous.and_then(|revisions| revisions.get(id));
                let after = next.get(id);
                let change = if previous.is_none() {
                    "previous-unavailable"
                } else if before == after {
                    "unchanged"
                } else if before.is_none() {
                    "added"
                } else if after.is_none() {
                    "removed"
                } else {
                    "changed"
                };
                json!({"requirement": id, "previous": before, "next": after, "change": change})
            })
            .collect(),
    )
}

fn detach(args: SourceDetachArgs) -> Result<ExitCode> {
    let args = args.into_detach_args();
    let lock = source_import::ProjectLock::acquire(&args.project)
        .with_context(|| format!("locking editable project {}", args.project.display()))?;
    source_import::detach(&lock, &args.source_id)?;
    println!(
        "Detached source `{}` into ordinary authored files in {}",
        args.source_id,
        args.project.display()
    );
    Ok(ExitCode::SUCCESS)
}

impl SourceImportArgs {
    fn into_import_args(self) -> source_import::ImportArgs {
        source_import::ImportArgs {
            exports: self.exports,
            project: self.project,
            resolutions: self.resolutions,
            target: self.target,
        }
    }
}

impl SourceDetachArgs {
    fn into_detach_args(self) -> source_import::DetachArgs {
        source_import::DetachArgs {
            source_id: self.source_id,
            project: self.project,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::fs;

    const SOURCE: &str = "type: http-json\nposture: record-transformed\nconnection: remote\nrequest:\n  method: GET\n  path: /lookup\n  selectorInputs:\n    - role: subject\n      alternatives: [{profile: record-code, fields: [code]}]\n  projection: [/matched]\n  prepareScript: adapters/lookup-prepare.rhai\n  adapterParametersSchema: schemas/lookup-parameters.yaml\n  attemptTimeoutMilliseconds: 1000\n  maximumResponseBytes: 1024\nresponseSchema: schemas/lookup-response.yaml\nfactSchema: schemas/lookup-facts.yaml\nextractScript: adapters/lookup-extract.rhai\n";
    const EXTRACT_ONE: &str = "fn extract(response, context) { #{outcome: \"no_match\"} } // one\n";
    const EXTRACT_TWO: &str = "fn extract(response, context) { #{outcome: \"no_match\"} } // two\n";

    struct Fixture {
        root: tempfile::TempDir,
        project: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            fs::create_dir(&project).unwrap();
            fs::write(
                project.join(registry_evidence_authoring::project::PROJECT_FILE),
                r#"apiVersion: id.registrystack.org/formats/evidence/project/v1alpha1
kind: EvidenceProject
id: source-command-test
selectorProfiles:
  baseline-reference:
    maximumAggregateBytes: 64
    fields: {value: {type: string, minimumBytes: 1, maximumBytes: 64}}
functions:
  - {id: baseline-extract, interface: source-extract/v1, source: functions/baseline-extract.rhai}
  - {id: baseline-derive, interface: assertion-derive/v1, source: functions/baseline-derive.rhai}
sources:
  baseline:
    type: http-json
    connection: baseline
    acquisitionPosture: record-transformed
    selectors: [{role: subject, profiles: [baseline-reference]}]
    request: {method: GET, path: /baseline}
    response: {projection: [/matched], shape: {type: object, properties: {matched: {type: boolean}}}, maximumBytes: 1024}
    extract: {function: baseline-extract}
    facts: {matched: {type: boolean}}
    limits: {attemptTimeoutMilliseconds: 1000, maximumConcurrency: 1}
assertionDefinitions:
  baseline:
    question: Is the synthetic baseline matched?
    semantics: {requirement: "urn:test:requirement:baseline", kind: criterion, evidenceType: "urn:test:evidence:baseline", referenceFrameworks: ["urn:test:framework"]}
    purpose: source-command-test
    grantCeiling: {authorities: [organizational], actorKinds: [service], valueOrigins: [request], audiences: ["urn:test:audience"]}
    subjects: [{role: subject, selectors: [baseline-reference]}]
    acquisition: {type: single, source: baseline}
    derive: {function: baseline-derive}
    outputs: {matched: {concept: "urn:test:concept:matched", type: boolean}}
    validitySeconds: 60
    subjectBinding: audience-scoped
    representations: [signed-jws]
"#,
            )
            .unwrap();
            fs::create_dir(project.join("functions")).unwrap();
            fs::write(
                project.join("functions/baseline-extract.rhai"),
                "fn extract(response, context) { #{outcome: \"match\", facts: #{matched: response[\"matched\"]}} }\n",
            )
            .unwrap();
            fs::write(
                project.join("functions/baseline-derive.rhai"),
                "fn derive(facts, selectors, context) { [#{output: \"matched\", value: facts[\"matched\"]}] }\n",
            )
            .unwrap();
            Self { root, project }
        }

        fn export(&self, name: &str, extract: &str) -> PathBuf {
            self.export_with_facts(
                name,
                extract,
                "type: object\nrequired: [matched]\nproperties: {matched: {type: boolean}}\nadditionalProperties: false\n",
            )
        }

        fn export_with_facts(&self, name: &str, extract: &str, facts: &str) -> PathBuf {
            let root = self.root.path().join(name);
            let artifacts = [
                ("sources/lookup.yaml", SOURCE),
                (
                    "selectors/record-code.yaml",
                    "maximumAggregateBytes: 128\nfields: {code: {type: string, minimumBytes: 1, maximumBytes: 128}}\n",
                ),
                (
                    "schemas/lookup-parameters.yaml",
                    "type: object\nrequired: [matched]\nproperties: {matched: {type: boolean}}\nadditionalProperties: false\n",
                ),
                (
                    "schemas/lookup-response.yaml",
                    "type: object\nproperties: {}\nadditionalProperties: false\n",
                ),
                ("schemas/lookup-facts.yaml", facts),
                (
                    "adapters/lookup-prepare.rhai",
                    "fn prepare(selectors, context) { #{query: [], body: ()} }\n",
                ),
                ("adapters/lookup-extract.rhai", extract),
            ];
            for (path, text) in &artifacts {
                fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
                fs::write(root.join(path), text).unwrap();
            }
            fs::write(root.join("source-export.json"), serde_json::to_vec(&json!({
                "apiVersion": source_import::EXPORT_API_VERSION, "kind": source_import::EXPORT_KIND,
                "sourceId": "lookup", "provenance": {"producer": "source-command-test", "revision": name},
                "artifacts": artifacts.iter().map(|(path, text)| json!({"path": path, "digest": format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))})).collect::<Vec<_>>()
            })).unwrap()).unwrap();
            root
        }

        fn args(&self, export: PathBuf) -> source_import::ImportArgs {
            source_import::ImportArgs {
                exports: vec![export],
                project: self.project.clone(),
                resolutions: None,
                target: None,
            }
        }
    }

    fn no_target(_: &Path, _: &Path) -> Result<BTreeMap<String, String>> {
        panic!("structural source import must not manufacture a target or invoke its runtime");
    }

    fn parsed(output: &[u8]) -> Value {
        serde_json::from_slice(output).unwrap()
    }

    #[test]
    fn connected_source_import_and_diff_work_before_questions_targets_or_credentials_exist() {
        let fixture = Fixture::new();
        let export = fixture.export("first", EXTRACT_ONE);
        let mut output = Vec::new();
        review_with_revisions(fixture.args(export), true, &mut output, no_target).unwrap();
        assert_eq!(
            parsed(&output)["validation"],
            json!({"kind": "structural", "status": "passed"})
        );
        assert_eq!(parsed(&output)["application"], "accepted");
        assert!(!fixture.project.join("secrets").exists());
        assert!(!fixture.project.join("targets").exists());
        assert!(!fixture.project.join("questions").exists());

        let before = fs::read(fixture.project.join(".evidence/source-imports/state.json")).unwrap();
        let next = fixture.export("next", EXTRACT_TWO);
        output.clear();
        review_with_revisions(fixture.args(next), false, &mut output, no_target).unwrap();
        assert_eq!(parsed(&output)["validation"]["status"], "passed");
        assert!(parsed(&output).get("definitionRevisions").is_none());
        assert_eq!(
            fs::read(fixture.project.join(".evidence/source-imports/state.json")).unwrap(),
            before
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("functions/lookup-extract.rhai")).unwrap(),
            EXTRACT_ONE
        );
    }

    #[test]
    fn diff_and_apply_refuse_a_next_fact_schema_that_drops_a_fact_a_derivation_reads() {
        let facts = |name: &str| {
            format!(
                "type: object\nrequired: [{name}]\nproperties:\n  {name}: {{type: string}}\nadditionalProperties: false\n"
            )
        };
        let fixture = Fixture::new();
        let first = fixture.export_with_facts("first", EXTRACT_ONE, &facts("status"));
        review_with_revisions(fixture.args(first), true, &mut Vec::new(), no_target).unwrap();
        let project_file = fixture
            .project
            .join(registry_evidence_authoring::project::PROJECT_FILE);
        let mut project: Value =
            serde_norway::from_slice(&fs::read(&project_file).unwrap()).unwrap();
        project["functions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"record-active-derive","interface":"assertion-derive/v1","source":"functions/record-active-derive.rhai"}));
        project["assertionDefinitions"]["record-active"] = json!({
            "question":"Is the record active?",
            "semantics":{"requirement":"urn:test:record-active","kind":"criterion","evidenceType":"urn:test:evidence:record-active","referenceFrameworks":["urn:test:framework"]},
            "purpose":"record-verification",
            "grantCeiling":{"authorities":["organizational"],"actorKinds":["service"],"valueOrigins":["request"],"audiences":["urn:test:audience"]},
            "subjects":[{"role":"subject","selectors":["record-code"]}],
            "acquisition":{"type":"single","source":"lookup"},
            "derive":{"function":"record-active-derive"},
            "outputs":{"active":{"concept":"urn:test:concept:active","type":"boolean"}},
            "validitySeconds":60,
            "subjectBinding":"audience-scoped",
            "representations":["signed-jws"]
        });
        fs::write(
            &project_file,
            serde_json::to_string_pretty(&project).unwrap(),
        )
        .unwrap();
        fs::write(
            fixture.project.join("functions/record-active-derive.rhai"),
            "fn derive(facts, selectors, context) {\n    let status = required(facts[\"status\"], \"status_missing\");\n    [#{output: \"active\", value: status == \"active\"}]\n}\n",
        )
        .unwrap();
        let installed = fs::read(&project_file).unwrap();

        for apply in [false, true] {
            let renamed =
                fixture.export_with_facts("renamed", EXTRACT_ONE, &facts("lifecycle_status"));
            let mut output = Vec::new();
            let error = review_with_revisions(fixture.args(renamed), apply, &mut output, no_target)
                .expect_err("a renamed fact the derivation still reads");
            assert!(
                format!("{error:#}").contains("reads fact `status`"),
                "error was: {error:#}"
            );
            let report = parsed(&output);
            assert_eq!(report["validation"]["status"], "failed");
            assert_eq!(fs::read(&project_file).unwrap(), installed);
            fs::remove_dir_all(fixture.root.path().join("renamed")).unwrap();
        }
    }

    #[test]
    fn diff_and_apply_validate_the_complete_graph_and_report_failure_without_installing_files() {
        for apply in [false, true] {
            let fixture = Fixture::new();
            let malformed = fixture.export("invalid", "fn extract( { incomplete\n");
            let mut output = Vec::new();
            assert!(
                review_with_revisions(fixture.args(malformed), apply, &mut output, no_target)
                    .is_err()
            );
            let report = parsed(&output);
            assert_eq!(report["validation"]["status"], "failed");
            assert!(report["changes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|change| change["path"] == "functions/lookup-extract.rhai"));
            assert!(!fixture.project.join("sources/lookup.yaml").exists());
            assert!(!fixture
                .project
                .join(".evidence/source-imports/state.json")
                .exists());
        }
    }

    #[test]
    fn conflicts_print_the_full_report_before_failure_and_explicit_keep_finishes_update() {
        let fixture = Fixture::new();
        let export = fixture.export("first", EXTRACT_ONE);
        review_with_revisions(fixture.args(export), true, &mut Vec::new(), no_target).unwrap();
        let custom = "fn extract(response, context) { #{outcome: \"no_match\"} } // customized\n";
        fs::write(
            fixture.project.join("functions/lookup-extract.rhai"),
            custom,
        )
        .unwrap();
        let next = fixture.export("next", EXTRACT_TWO);
        let mut output = Vec::new();
        assert!(
            review_with_revisions(fixture.args(next.clone()), true, &mut output, no_target)
                .is_err()
        );
        assert_eq!(parsed(&output)["validation"]["status"], "conflict");
        assert_eq!(
            parsed(&output)["conflicts"],
            json!(["functions/lookup-extract.rhai"])
        );
        assert_eq!(
            fs::read_to_string(fixture.project.join("functions/lookup-extract.rhai")).unwrap(),
            custom
        );

        let resolutions = fixture.root.path().join("resolutions.json");
        fs::write(&resolutions, serde_json::to_vec(&json!({"apiVersion": "id.registrystack.org/formats/evidence/source-resolution/v1alpha1", "kind": "EvidenceSourceResolution", "artifacts": {"functions/lookup-extract.rhai": {"type": "keep"}}})).unwrap()).unwrap();
        let mut args = fixture.args(next);
        args.resolutions = Some(resolutions);
        output.clear();
        review_with_revisions(args, true, &mut output, no_target).unwrap();
        assert_eq!(parsed(&output)["application"], "accepted");
        assert_eq!(
            fs::read_to_string(fixture.project.join("functions/lookup-extract.rhai")).unwrap(),
            custom
        );
    }

    #[test]
    fn target_reports_exact_revisions_from_both_compiler_results_under_the_same_named_target() {
        let fixture = Fixture::new();
        let export = fixture.export("first", EXTRACT_ONE);
        review_with_revisions(fixture.args(export), true, &mut Vec::new(), no_target).unwrap();
        let target = fixture.root.path().join("institution-target");
        let mut args = fixture.args(fixture.export("next", EXTRACT_TWO));
        args.target = Some(target.clone());
        let mut output = Vec::new();
        let mut calls = Vec::new();
        // This test pins command-to-compiler routing. The package helper's
        // tests pin configuration revisions; this layer never hashes them.
        review_with_revisions(args, false, &mut output, |project, selected| {
            assert_eq!(selected, target);
            calls.push(project.to_path_buf());
            let revision = if fs::read_to_string(project.join("functions/lookup-extract.rhai"))?
                == EXTRACT_ONE
            {
                "sha256:before"
            } else {
                "sha256:after"
            };
            Ok(BTreeMap::from([
                ("urn:test:changed".to_owned(), revision.to_owned()),
                (
                    "urn:test:unrelated".to_owned(),
                    "sha256:unchanged".to_owned(),
                ),
            ]))
        })
        .unwrap();
        assert_eq!(calls.len(), 2);
        assert_ne!(calls[0], fixture.project);
        assert_eq!(calls[1], fixture.project);
        let report = parsed(&output);
        assert_eq!(report["previousValidation"]["status"], "passed");
        assert_eq!(
            report["definitionRevisions"][0],
            json!({"requirement": "urn:test:changed", "previous": "sha256:before", "next": "sha256:after", "change": "changed"})
        );
        assert_eq!(report["definitionRevisions"][1]["change"], "unchanged");
        assert_eq!(
            fs::read_to_string(fixture.project.join("functions/lookup-extract.rhai")).unwrap(),
            EXTRACT_ONE
        );
    }

    #[test]
    fn unbuildable_prior_target_has_no_fabricated_revision_and_invalid_next_never_applies() {
        for candidate_valid in [false, true] {
            let fixture = Fixture::new();
            let mut args = fixture.args(fixture.export("initial", EXTRACT_ONE));
            args.target = Some(fixture.root.path().join("target"));
            let mut output = Vec::new();
            let result = review_with_revisions(args, true, &mut output, |project, _| {
                if candidate_valid && project != fixture.project {
                    Ok(BTreeMap::from([(
                        "urn:test:question".to_owned(),
                        "sha256:from-runtime".to_owned(),
                    )]))
                } else {
                    bail!("sensitive-diagnostic-canary");
                }
            });
            let report = parsed(&output);
            assert!(!String::from_utf8(output)
                .unwrap()
                .contains("sensitive-diagnostic-canary"));
            if candidate_valid {
                result.unwrap();
                assert_eq!(report["previousValidation"]["status"], "unavailable");
                assert!(report["definitionRevisions"][0]["previous"].is_null());
                assert_eq!(
                    report["definitionRevisions"][0]["change"],
                    "previous-unavailable"
                );
                assert_eq!(
                    report["definitionRevisions"][0]["next"],
                    "sha256:from-runtime"
                );
            } else {
                assert!(result.is_err());
                assert_eq!(report["validation"]["status"], "failed");
                assert!(!fixture.project.join("sources/lookup.yaml").exists());
                assert!(!fixture
                    .project
                    .join(".evidence/source-imports/state.json")
                    .exists());
            }
        }
    }
}
