// SPDX-License-Identifier: Apache-2.0

//! `adapterctl mapping`: check an `AdapterMapping` model against the target
//! schema it names, generate the Rhai script it describes, and preview that
//! script over sample inputs, all offline (`products/adapter/VISUAL-MAPPING.md`).
//!
//! The model is the reviewed source of truth; the generated script is the
//! pinned artifact the sandboxed engine runs. `generate` writes the script
//! beside the model and prints the digest to pin; `check` and `job check`
//! warn when a script that carries a generated header no longer matches the
//! model it names, and `mapping check` warns when the script at the model's
//! own path is not what the model generates now.

use clap::{Args, Subcommand};
use registry_adapter::engine::artifacts::ProjectArtifactBytes;
use registry_adapter::engine::project_transform::{
    CompiledProjectTransform, ProjectTransformError,
};
use registry_adapter::engine::public_schema::{check_public_schema, PublicSchemaError};
use registry_adapter::engine::scripts::CodeMaps;
use registry_adapter_core::{
    canonical_target_path, check_mapping_file, check_mapping_findings, check_preview_expectations,
    generate, is_clean_mapping_path, model_reference_from, parse_generated_header, parse_selector,
    refusal_names_target, target_tree, AdapterMapping, AdapterPreviewExpectations,
    BindingTransform, GeneratedHeaderState, IngestionMode, MappingTarget, ProjectSchema,
    ProjectScript, SampleExpectation, ADAPTER_MAPPING_API_VERSION, ADAPTER_MAPPING_KIND,
    ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION, ADAPTER_PREVIEW_EXPECTATIONS_KIND,
    MAXIMUM_GENERATED_SCRIPT_BYTES,
};
use registry_platform_config::{sha256_uri, AuthoredExpressions};
use registry_platform_yaml::{
    ApiVersion, Diagnostic, EnvelopeRule, Expect, FormatSpec, Reader, Report, Severity, Source,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use crate::check::{read, CheckFailure};

/// The authored mapping format.
pub(crate) const MAPPING_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_MAPPING_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_MAPPING_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// A preview input is one source value in a YAML file, which has no envelope.
const INPUT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: "PreviewInput",
    envelope: EnvelopeRule::Exempt {
        reason: "a preview input is one bare source value, not an authored document",
    },
    removed_keys: &[],
};

/// The authored preview expectations format.
const EXPECTATIONS_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PREVIEW_EXPECTATIONS_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(
            ADAPTER_PREVIEW_EXPECTATIONS_API_VERSION,
        )],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The file that records the expected result of each sample, beside the
/// samples. It is never a sample itself.
const EXPECTATIONS_FILE: &str = "expected.yaml";

/// The warning code for a generated script that no longer matches its model.
pub(crate) const SCRIPT_DRIFT_CODE: &str = "adapter.mapping.script-drift";

/// The job-check warning for a mapping assignment that reads a source key the
/// job's projection does not hand over.
pub(crate) const UNPROJECTED_CODE: &str = "adapter.job.mapping-unprojected";

const MAXIMUM_SCHEMA_BYTES: u64 = 256 * 1024;
const MAXIMUM_INPUT_BYTES: u64 = 1024 * 1024;
const PREVIEW_DEADLINE: Duration = Duration::from_secs(5);

/// The `mapping` command group.
#[derive(Debug, Args)]
pub struct MappingArgs {
    #[command(subcommand)]
    pub command: MappingCommand,
}

/// The subcommands of `mapping`.
#[derive(Debug, Subcommand)]
pub enum MappingCommand {
    /// Check a mapping model against the target schema it names.
    Check(MappingCheckArgs),
    /// Check the model, then write the Rhai script it describes beside it.
    Generate(MappingGenerateArgs),
    /// Generate the script in memory and run it over sample inputs, printing
    /// the validated outputs or the categorical refusals; writes nothing, so
    /// `generate` need not run first.
    Preview(MappingPreviewArgs),
}

/// The arguments of `mapping check`.
#[derive(Debug, Args)]
pub struct MappingCheckArgs {
    /// The mapping model (`*.mapping.yaml`).
    #[arg(value_name = "MODEL")]
    pub model: PathBuf,

    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,
}

/// The arguments of `mapping generate`.
#[derive(Debug, Args)]
pub struct MappingGenerateArgs {
    /// The mapping model (`*.mapping.yaml`).
    #[arg(value_name = "MODEL")]
    pub model: PathBuf,

    /// Overwrite a handwritten script (one without the generated header)
    /// at the path the model names.
    #[arg(long)]
    pub force: bool,
}

/// The arguments of `mapping preview`.
#[derive(Debug, Args)]
pub struct MappingPreviewArgs {
    /// The mapping model (`*.mapping.yaml`).
    #[arg(value_name = "MODEL")]
    pub model: PathBuf,

    /// A JSON or YAML file holding one source value; repeatable. A YAML
    /// input cannot hold `null`; use JSON for that. An `expected.yaml` beside
    /// the inputs records the result each sample should give, named by its
    /// file name without the extension; the run exits 1 when a result
    /// differs. The `expected.yaml` itself is never a sample.
    #[arg(long, value_name = "FILE", required = true)]
    pub input: Vec<PathBuf>,

    /// Exit 1 when a warning is reported.
    #[arg(long)]
    pub deny_warnings: bool,
}

/// Why a mapping command could not run to a verdict.
pub(crate) enum MappingFailure {
    /// A required file could not be read or written: the environment is
    /// broken, not the authoring.
    Io { path: String, source: io::Error },
    /// The command refused the input; the diagnostics carry the reasons.
    Refused {
        diagnostics: Vec<Diagnostic>,
        files_checked: usize,
        /// The command's own report members, when the refusal still has some.
        members: Vec<(&'static str, Value)>,
        annotations: Vec<Annotation>,
    },
}

/// A report member added to one diagnostic, addressed by its position in the
/// report's diagnostics. The shared diagnostic type has no member for these
/// mapping facts, so the report adds them where it renders the diagnostics.
pub(crate) struct Annotation {
    pub index: usize,
    pub member: &'static str,
    pub value: Value,
}

/// Add each annotation's member to the diagnostic it addresses.
pub(crate) fn annotate(diagnostics: &mut Value, annotations: &[Annotation]) {
    for annotation in annotations {
        diagnostics[annotation.index][annotation.member] = annotation.value.clone();
    }
}

impl From<CheckFailure> for MappingFailure {
    fn from(failure: CheckFailure) -> Self {
        let CheckFailure::Io { path, source } = failure;
        Self::Io { path, source }
    }
}

/// One completed mapping command: the warnings, the files read, and the
/// command's own report members.
pub(crate) struct MappingRun {
    pub warnings: Vec<Diagnostic>,
    pub files_checked: usize,
    pub members: Vec<(&'static str, Value)>,
    pub annotations: Vec<Annotation>,
    pub deny_warnings: bool,
}

/// The command name a report carries.
pub(crate) fn command_name(command: &MappingCommand) -> &'static str {
    match command {
        MappingCommand::Check(_) => "mapping check",
        MappingCommand::Generate(_) => "mapping generate",
        MappingCommand::Preview(_) => "mapping preview",
    }
}

/// Run one `mapping` subcommand.
pub(crate) fn run(command: &MappingCommand) -> Result<MappingRun, MappingFailure> {
    match command {
        MappingCommand::Check(args) => run_check(args),
        MappingCommand::Generate(args) => run_generate(args),
        MappingCommand::Preview(args) => run_preview(args),
    }
}

/// A model read with the target schema it names.
pub(crate) struct Loaded {
    pub mapping: AdapterMapping,
    /// The target schema, `None` when it could not be read (a finding says
    /// why) or its path is not clean (the model check says so).
    pub schema: Option<Value>,
    pub directory: PathBuf,
    pub file_name: String,
}

impl Loaded {
    /// The digest of the model's meaning: its parsed value, serialized. A
    /// layout-only edit (comments, a byte order mark, line endings, document
    /// markers) keeps it, so the generated script stays current; any change
    /// to what the model says changes it.
    fn digest(&self) -> String {
        let value =
            serde_json::to_vec(&self.mapping).expect("a parsed mapping model serializes to JSON");
        sha256_uri(&value)
    }

    /// The model reference and digest the generated header carries.
    fn header(&self) -> (String, String) {
        (
            model_reference_from(&self.mapping.mapping.script, &self.file_name),
            self.digest(),
        )
    }

    fn script_path(&self) -> PathBuf {
        self.directory.join(&self.mapping.mapping.script)
    }
}

fn model_failure(report: &mut Report, model: &Path, mut diagnostic: Diagnostic) {
    diagnostic.source = Some(Source {
        file: model.display().to_string(),
        line: None,
        column: None,
    });
    report.push(diagnostic);
}

/// Read the model through the shared reader and the target schema it names.
/// `None` means the reader refused the model.
pub(crate) fn load(
    model: &Path,
    report: &mut Report,
    files: &mut usize,
) -> Result<Option<Loaded>, CheckFailure> {
    let Some((decoded, _bytes)) = read::<AdapterMapping>(model, &MAPPING_FORMAT, report, files)?
    else {
        return Ok(None);
    };
    let mapping = decoded.value;
    let directory = model.parent().map(Path::to_path_buf).unwrap_or_default();
    let file_name = model
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let schema = if is_clean_mapping_path(&mapping.mapping.target_schema) {
        match contained_schema(&directory, &mapping.mapping.target_schema)? {
            Some(path) => read_schema(&path, model, report, files)?,
            None => {
                model_failure(
                    report,
                    model,
                    Diagnostic::error(
                        "adapterctl.mapping-schema-outside",
                        "/mapping/targetSchema",
                        "the target schema file resolves, through a symbolic link, outside the model's directory",
                        "Place the JSON Schema inside the model's directory, or point mapping.targetSchema at a file there.",
                    ),
                );
                None
            }
        }
    } else {
        // The model check reports the unclean path; nothing is read for it.
        Some(Value::Null)
    };
    Ok(Some(Loaded {
        mapping,
        schema,
        directory,
        file_name,
    }))
}

/// The target schema path to read, or `None` when the file, after following
/// links, lies outside the model's directory (CFG-VAL-8). Links that stay
/// inside are followed, as the script write does. A missing file is left
/// for `read_schema` to report.
fn contained_schema(
    directory: &Path,
    target_schema: &str,
) -> Result<Option<PathBuf>, CheckFailure> {
    let path = directory.join(target_schema);
    let io_failure = |path: &Path, source: io::Error| CheckFailure::Io {
        path: path.display().to_string(),
        source,
    };
    let root_directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    let root = std::fs::canonicalize(root_directory)
        .map_err(|source| io_failure(root_directory, source))?;
    match std::fs::canonicalize(&path) {
        Ok(resolved) if resolved.starts_with(&root) => Ok(Some(resolved)),
        Ok(_) => Ok(None),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(Some(path)),
        Err(source) => Err(io_failure(&path, source)),
    }
}

fn read_schema(
    path: &Path,
    model: &Path,
    report: &mut Report,
    files: &mut usize,
) -> Result<Option<Value>, CheckFailure> {
    let unreadable = |why: &str| {
        Diagnostic::error(
            "adapterctl.mapping-schema-unreadable",
            "/mapping/targetSchema",
            format!("the target schema file {why}"),
            "Restore the JSON Schema beside the model at mapping.targetSchema, or correct the path.",
        )
    };
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAXIMUM_SCHEMA_BYTES => {
            model_failure(
                report,
                model,
                unreadable("is over the 256 KiB authoring bound"),
            );
            return Ok(None);
        }
        Ok(_) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            model_failure(report, model, unreadable("does not exist"));
            return Ok(None);
        }
        Err(source) => {
            return Err(CheckFailure::Io {
                path: path.display().to_string(),
                source,
            })
        }
    }
    let bytes = std::fs::read(path).map_err(|source| CheckFailure::Io {
        path: path.display().to_string(),
        source,
    })?;
    *files += 1;
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok(Some(value)),
        Err(_) => {
            model_failure(report, model, unreadable("is not valid JSON"));
            Ok(None)
        }
    }
}

/// Run the pure model checks and attach the model file to each finding.
/// A finding about one target field comes back as an annotation naming it.
fn model_findings(loaded: &Loaded, model: &Path, report: &mut Report) -> Vec<Annotation> {
    let Some(schema) = &loaded.schema else {
        return Vec::new();
    };
    let mut annotations = Vec::new();
    for finding in check_mapping_findings(&loaded.mapping, schema) {
        if let Some(target) = finding.target {
            annotations.push(Annotation {
                index: report.diagnostics().len(),
                member: "target",
                value: json!(target),
            });
        }
        model_failure(report, model, finding.diagnostic);
    }
    for diagnostic in check_mapping_file(&loaded.mapping, &loaded.file_name) {
        model_failure(report, model, diagnostic);
    }
    annotations
}

fn refusal(report: Report, files_checked: usize) -> MappingFailure {
    refusal_with(report, files_checked, Vec::new(), Vec::new())
}

fn refusal_with(
    report: Report,
    files_checked: usize,
    members: Vec<(&'static str, Value)>,
    annotations: Vec<Annotation>,
) -> MappingFailure {
    MappingFailure::Refused {
        diagnostics: report.into_diagnostics(),
        files_checked,
        members,
        annotations,
    }
}

fn run_check(args: &MappingCheckArgs) -> Result<MappingRun, MappingFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;
    let loaded = load(&args.model, &mut report, &mut files)?;
    let mut annotations = Vec::new();
    // The target as the checker reads it, whenever the schema was readable
    // and its root supported: a refusal still carries it, since the refused
    // findings are about its fields.
    let mut tree_members = Vec::new();
    if let Some(loaded) = &loaded {
        annotations = model_findings(loaded, &args.model, &mut report);
        // Display text only: it never affects checking, generation or preview.
        if let Some(title) = loaded.schema.as_ref().and_then(target_title) {
            tree_members.push(("targetTitle", json!(title)));
        }
        if let Some(tree) = loaded.schema.as_ref().and_then(target_tree) {
            tree_members.push((
                "targetTree",
                serde_json::to_value(tree).expect("a target tree serializes to JSON"),
            ));
        }
    }
    if report.has_errors() {
        return Err(refusal_with(report, files, tree_members, annotations));
    }
    let loaded = loaded.expect("the model decoded");
    let Some(script) = generated(&loaded, &args.model, &mut report) else {
        return Err(refusal_with(report, files, tree_members, annotations));
    };
    // The script on disk is judged as generate would judge it: a missing
    // script is fine (generate writes it), any other difference warns.
    let path = loaded.script_path();
    let existing = existing_script(&path, &args.model, &script, &loaded.digest())?;
    if let Some(mut conflict) = script_conflict(&existing, &args.model) {
        conflict.severity = Severity::Warning;
        model_failure(&mut report, &args.model, conflict);
    } else if let ExistingScript::Stale(cause) = existing {
        if let Some(warning) = drift_warning(&path, "/mapping/script", None, cause.why()) {
            annotations.push(Annotation {
                index: report.diagnostics().len(),
                member: "cause",
                value: json!(cause.name()),
            });
            report.push(warning);
        }
    }
    let header = &loaded.mapping.mapping;
    let mut members = vec![
        ("model", json!(args.model.display().to_string())),
        ("target", json!(target_name(header.target))),
        ("script", json!(header.script)),
        ("assignments", json!(loaded.mapping.assignments.len())),
    ];
    members.extend(tree_members);
    Ok(MappingRun {
        warnings: report.into_diagnostics(),
        files_checked: files,
        members,
        annotations,
        deny_warnings: args.deny_warnings,
    })
}

/// The title of the target schema's root, when it is non-empty text.
fn target_title(schema: &Value) -> Option<&str> {
    schema
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.is_empty())
}

fn target_name(target: MappingTarget) -> &'static str {
    match target {
        MappingTarget::Consultation => "consultation",
        MappingTarget::Evidence => "evidence",
        MappingTarget::Ingestion => "ingestion",
        MappingTarget::SourceRequest => "source-request",
    }
}

/// Load, check, and generate; the script bytes come back with the model.
fn generate_script(
    model: &Path,
    report: &mut Report,
    files: &mut usize,
) -> Result<Option<(Loaded, String)>, MappingFailure> {
    let Some(loaded) = load(model, report, files)? else {
        return Ok(None);
    };
    if report.has_errors() {
        return Ok(None);
    }
    Ok(generated(&loaded, model, report).map(|script| (loaded, script)))
}

/// The script a loaded model generates, or `None` with the generator's
/// findings reported against the model. The caller has checked the model
/// reads cleanly. A target the runtime runs as a project transformation is
/// also compiled exactly as preview compiles it, so a schema the runtime
/// refuses is refused here, at the schema.
fn generated(loaded: &Loaded, model: &Path, report: &mut Report) -> Option<String> {
    let schema = loaded
        .schema
        .as_ref()
        .expect("an error reports an unread schema");
    let (reference, digest) = loaded.header();
    let script = match generate(&loaded.mapping, schema, &reference, &digest) {
        Ok(script) => script,
        Err(findings) => {
            for finding in findings {
                model_failure(report, model, finding);
            }
            return None;
        }
    };
    if loaded.mapping.mapping.target != MappingTarget::SourceRequest {
        if let Err(error) = compile_preview(loaded, &script) {
            model_failure(report, model, compile_refusal(loaded, schema, error));
            return None;
        }
    }
    Some(script)
}

/// Why the runtime would not compile the generated script: the public-schema
/// rule the target schema breaks, or the compile error itself.
fn compile_refusal(loaded: &Loaded, schema: &Value, error: ProjectTransformError) -> Diagnostic {
    let Err(rule) = check_public_schema(schema.clone()) else {
        return Diagnostic::error(
            "adapterctl.mapping-compile",
            "/mapping",
            format!("the generated script does not compile for the runtime: {error}"),
            "Check the model's entrypoint and target schema, then retry.",
        );
    };
    let action = match rule {
        PublicSchemaError::Identity => {
            "Give the schema a public versioned HTTPS $id, such as https://example.org/schemas/<name>/1/schema.json."
        }
        PublicSchemaError::RootNotClosed | PublicSchemaError::ObjectNotClosed => {
            "Make the root and every object schema \"type\": \"object\" with \"additionalProperties\": false."
        }
        PublicSchemaError::ArrayNotBounded => "Give every array schema a finite maxItems.",
        PublicSchemaError::ExternalReference => {
            "Inline the referenced schema or use a local #/ reference."
        }
        PublicSchemaError::Bound => "Split or simplify the schema to fit the bound.",
        PublicSchemaError::Invalid => "Fix the schema so it is valid JSON Schema 2020-12.",
    };
    Diagnostic::error(
        "adapterctl.mapping-schema-not-public",
        "/mapping/targetSchema",
        format!(
            "the target schema {} is not one the runtime accepts: {rule}",
            loaded.mapping.mapping.target_schema
        ),
        action,
    )
}

fn run_generate(args: &MappingGenerateArgs) -> Result<MappingRun, MappingFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;
    let Some((loaded, script)) = generate_script(&args.model, &mut report, &mut files)? else {
        return Err(refusal(report, files));
    };
    let path = loaded.script_path();
    let existing = existing_script(&path, &args.model, &script, &loaded.digest())?;
    if !args.force {
        if let Some(conflict) = script_conflict(&existing, &args.model) {
            model_failure(&mut report, &args.model, conflict);
            return Err(refusal(report, files));
        }
    }
    let changed = existing != ExistingScript::Current;
    let existed = existing != ExistingScript::Missing;
    if changed {
        write_atomically(&path, &loaded.directory, script.as_bytes())?;
    }
    let digest = sha256_uri(script.as_bytes());
    let next_step = match loaded.mapping.mapping.target {
        MappingTarget::Ingestion => {
            "Run adapterctl job lock on the job to pin the script digest, then adapterctl job check."
        }
        _ => "Run adapterctl project lock to pin the script digest, then adapterctl check.",
    };
    Ok(MappingRun {
        warnings: report.into_diagnostics(),
        files_checked: files,
        members: vec![
            ("model", json!(args.model.display().to_string())),
            ("modelDigest", json!(loaded.digest())),
            ("script", json!(path.display().to_string())),
            ("scriptDigest", json!(digest)),
            ("changed", json!(changed)),
            ("existed", json!(existed)),
            ("nextStep", json!(next_step)),
        ],
        annotations: Vec::new(),
        deny_warnings: false,
    })
}

/// What stands at a model's script path, judged against the script the
/// model generates now.
#[derive(Debug, PartialEq, Eq)]
enum ExistingScript {
    Missing,
    /// The bytes are what the model generates.
    Current,
    /// Generated from this model, or opening with the generated marker
    /// under an edited header, but the bytes differ: ours to regenerate.
    Stale(DriftCause),
    /// Generated from another model, named by its path.
    Owned(PathBuf),
    /// No generated header: a person wrote it.
    Handwritten,
}

/// Why a script generated from a model no longer matches it, as far as the
/// script's header lets the check tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DriftCause {
    /// The header's model digest is not the model's digest now: the model
    /// changed after generation. The script may carry hand edits too; the
    /// header cannot say.
    ModelChanged,
    /// The header's model digest is the model's digest now (or the header
    /// itself was edited), yet the bytes differ from what the model
    /// generates: the script was changed outside the model, or a different
    /// generator version wrote it. The name states what was observed, not
    /// who changed the bytes.
    ScriptDiffers,
}

impl DriftCause {
    fn name(self) -> &'static str {
        match self {
            Self::ModelChanged => "model-changed",
            Self::ScriptDiffers => "script-differs",
        }
    }

    fn why(self) -> &'static str {
        match self {
            Self::ModelChanged => "the model changed since the script was generated",
            Self::ScriptDiffers => {
                "the model's digest still matches the script's header, but the script bytes differ from what the model generates"
            }
        }
    }
}

/// What stands at `path`, judged against `script`, the text `model` generates
/// now, whose digest is `model_digest`.
fn existing_script(
    path: &Path,
    model: &Path,
    script: &str,
    model_digest: &str,
) -> Result<ExistingScript, MappingFailure> {
    let existing = match std::fs::read(path) {
        Ok(existing) => existing,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(ExistingScript::Missing)
        }
        Err(source) => {
            return Err(MappingFailure::Io {
                path: path.display().to_string(),
                source,
            })
        }
    };
    if existing == script.as_bytes() {
        return Ok(ExistingScript::Current);
    }
    let state =
        std::str::from_utf8(&existing).map_or(GeneratedHeaderState::Absent, parse_generated_header);
    Ok(match state {
        GeneratedHeaderState::Absent => ExistingScript::Handwritten,
        GeneratedHeaderState::Malformed => ExistingScript::Stale(DriftCause::ScriptDiffers),
        GeneratedHeaderState::Parsed(header) => {
            let script_directory = path.parent().unwrap_or_else(|| Path::new(""));
            let owner = script_directory.join(&header.model_reference);
            if lexical(&owner) == lexical(model) {
                ExistingScript::Stale(if header.model_digest == model_digest {
                    DriftCause::ScriptDiffers
                } else {
                    DriftCause::ModelChanged
                })
            } else {
                ExistingScript::Owned(owner)
            }
        }
    })
}

/// The finding for a script `generate` refuses to replace without
/// `--force`: an error from `generate`, a warning from `check`.
fn script_conflict(existing: &ExistingScript, model: &Path) -> Option<Diagnostic> {
    match existing {
        ExistingScript::Owned(owner) => Some(Diagnostic::error(
            "adapterctl.mapping-script-owned",
            "/mapping/script",
            format!(
                "the script at mapping.script was generated from {}, not from {}; generate would overwrite it",
                owner.display(),
                model.display()
            ),
            "Point mapping.script at a path of its own, or pass --force to replace the other model's script.",
        )),
        ExistingScript::Handwritten => Some(Diagnostic::error(
            "adapterctl.mapping-script-handwritten",
            "/mapping/script",
            "the script at mapping.script exists and carries no generated header, so it is handwritten; generate would overwrite it",
            "Point mapping.script at a new path, move the handwritten script away, or pass --force to replace it.",
        )),
        ExistingScript::Missing | ExistingScript::Current | ExistingScript::Stale(_) => None,
    }
}

/// Write `bytes` to `path` through a temporary file in the same directory
/// and a rename, so a reader never sees a half-written script. The script
/// must land inside the model's directory. A file that already stands at
/// `path` keeps its permissions.
pub(crate) fn write_atomically(
    path: &Path,
    model_directory: &Path,
    bytes: &[u8],
) -> Result<(), MappingFailure> {
    let io_failure = |target: &Path, source: io::Error| MappingFailure::Io {
        path: target.display().to_string(),
        source,
    };
    // A bare file name has an empty parent: the current directory.
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let root_directory = if model_directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        model_directory
    };
    let root = std::fs::canonicalize(root_directory)
        .map_err(|source| io_failure(root_directory, source))?;
    let escape = || {
        io_failure(
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the script path leaves the model's directory through a symbolic link",
            ),
        )
    };
    // Containment is decided on the deepest directory that already exists,
    // before anything is created, so a refused write leaves nothing behind.
    let existing = parent
        .ancestors()
        .find(|ancestor| ancestor.symlink_metadata().is_ok())
        .unwrap_or_else(|| Path::new("."));
    let existing = if existing.as_os_str().is_empty() {
        Path::new(".")
    } else {
        existing
    };
    let landed = std::fs::canonicalize(existing).map_err(|source| io_failure(existing, source))?;
    if !landed.starts_with(&root) {
        return Err(escape());
    }
    std::fs::create_dir_all(parent).map_err(|source| io_failure(parent, source))?;
    let landed = std::fs::canonicalize(parent).map_err(|source| io_failure(parent, source))?;
    if !landed.starts_with(&root) {
        return Err(escape());
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let written = (|| -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        match std::fs::metadata(path) {
            Ok(replaced) => file.set_permissions(replaced.permissions())?,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(source),
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    })();
    if let Err(source) = written {
        // The temporary file is this call's own; a failed rename leaves it.
        let _ = std::fs::remove_file(&temporary);
        return Err(io_failure(path, source));
    }
    Ok(())
}

fn run_preview(args: &MappingPreviewArgs) -> Result<MappingRun, MappingFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;
    let loaded = load(&args.model, &mut report, &mut files)?;
    if let Some(loaded) = &loaded {
        if loaded.mapping.mapping.target == MappingTarget::SourceRequest && !report.has_errors() {
            model_failure(
                &mut report,
                &args.model,
                Diagnostic::error(
                    "adapterctl.mapping-preview-unsupported",
                    "/mapping/target",
                    "the source-request target has no preview: its write direction is checked and generated only",
                    "Run adapterctl mapping check or adapterctl mapping generate for this model.",
                ),
            );
            return Err(refusal(report, files));
        }
    }
    drop(loaded);
    let Some((loaded, script)) = generate_script(&args.model, &mut report, &mut files)? else {
        return Err(refusal(report, files));
    };
    let compiled = compile_preview(&loaded, &script).map_err(|error| {
        let schema = loaded.schema.as_ref().expect("a checked schema");
        model_failure(
            &mut report,
            &args.model,
            compile_refusal(&loaded, schema, error),
        );
        refusal(Report::new(report.diagnostics().to_vec()), files)
    })?;
    let fields: Vec<&str> = loaded
        .mapping
        .assignments
        .iter()
        .filter(|assignment| assignment.from.is_some())
        .map(|assignment| assignment.target.as_str())
        .collect();

    // The expectations file is not a sample, so `--input preview/*` works.
    let inputs: Vec<&PathBuf> = args
        .input
        .iter()
        .filter(|input| {
            input
                .file_name()
                .is_none_or(|name| name != EXPECTATIONS_FILE)
        })
        .collect();
    let expectations = read_expectations(&inputs, &fields, &mut report, &mut files)?;
    if report.has_errors() {
        return Err(refusal(report, files));
    }

    let mut results = Vec::new();
    let (mut accepted, mut refused) = (0usize, 0usize);
    for input in inputs {
        let shown = input.display().to_string();
        let value = match read_input(input, &mut files)? {
            Ok(value) => value,
            Err(why) => {
                refused += 1;
                results.push(json!({"input": shown, "outcome": "refused", "failure": why}));
                continue;
            }
        };
        match compiled.apply_for_preview(
            &CodeMaps::default(),
            &value,
            Instant::now() + PREVIEW_DEADLINE,
        ) {
            Ok(output) => {
                accepted += 1;
                results.push(json!({
                    "input": shown,
                    "outcome": "accepted",
                    "output": wrap_for_runtime(&loaded, output),
                }));
            }
            Err(refusal) => {
                refused += 1;
                let named = refusal
                    .thrown
                    .as_deref()
                    .and_then(|thrown| named_failure(thrown, &fields));
                results.push(match named {
                    Some((failure, message, field)) => json!({
                        "input": shown,
                        "outcome": "refused",
                        "failure": failure,
                        "field": field,
                        "message": message,
                    }),
                    None => json!({
                        "input": shown,
                        "outcome": "refused",
                        "failure": variant_name(refusal.error),
                        "message": refusal.error.to_string(),
                    }),
                });
            }
        }
    }
    let mismatched = judge(&mut results, &expectations, &mut report);
    let members = vec![
        ("model", json!(args.model.display().to_string())),
        ("target", json!(target_name(loaded.mapping.mapping.target))),
        ("accepted", json!(accepted)),
        ("refused", json!(refused)),
        ("mismatched", json!(mismatched)),
        ("results", Value::Array(results)),
    ];
    // A result that differs from its expectation fails the run, and the
    // report still carries every result.
    if mismatched > 0 {
        return Err(MappingFailure::Refused {
            diagnostics: report.into_diagnostics(),
            files_checked: files,
            members,
            annotations: Vec::new(),
        });
    }
    Ok(MappingRun {
        warnings: report.into_diagnostics(),
        files_checked: files,
        members,
        annotations: Vec::new(),
        deny_warnings: args.deny_warnings,
    })
}

/// The expectations file beside some samples, and the sample names it may
/// list.
struct Expectations {
    file: PathBuf,
    samples: BTreeMap<String, SampleExpectation>,
}

/// Expectations by the directory of the samples they sit beside.
type ExpectationsByDirectory = BTreeMap<PathBuf, Expectations>;

/// The directory an input sits in; a bare file name is in the current one.
fn input_directory(input: &Path) -> PathBuf {
    match input.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// A sample's name: its file name without the extension.
fn sample_name(input: &Path) -> String {
    input
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The sample files in `directory`: the JSON and YAML files other than the
/// expectations file, by sample name.
fn sample_names(directory: &Path) -> Result<Vec<String>, MappingFailure> {
    let io_failure = |source: io::Error| MappingFailure::Io {
        path: directory.display().to_string(),
        source,
    };
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(io_failure)? {
        let entry = entry.map_err(io_failure)?;
        let file = PathBuf::from(entry.file_name());
        let sample = matches!(
            file.extension().and_then(|extension| extension.to_str()),
            Some("json" | "yaml" | "yml")
        );
        if sample && file != Path::new(EXPECTATIONS_FILE) && entry.path().is_file() {
            names.push(sample_name(&file));
        }
    }
    Ok(names)
}

/// Read the expectations file beside each input's directory, when there is
/// one, and check it against the sample files and the targets the model
/// reads. Findings go to the report; the caller refuses on an error.
fn read_expectations(
    inputs: &[&PathBuf],
    read_targets: &[&str],
    report: &mut Report,
    files: &mut usize,
) -> Result<ExpectationsByDirectory, MappingFailure> {
    let mut found = ExpectationsByDirectory::new();
    let targets: Vec<String> = read_targets.iter().map(ToString::to_string).collect();
    for input in inputs {
        let directory = input_directory(input);
        if found.contains_key(&directory) {
            continue;
        }
        let file = directory.join(EXPECTATIONS_FILE);
        if !file.is_file() {
            continue;
        }
        let Some((decoded, _bytes)) =
            read::<AdapterPreviewExpectations>(&file, &EXPECTATIONS_FORMAT, report, files)?
        else {
            // The reader reported why; nothing else can be said of the file.
            found.insert(
                directory,
                Expectations {
                    file,
                    samples: BTreeMap::new(),
                },
            );
            continue;
        };
        let expectations = decoded.value;
        for mut finding in
            check_preview_expectations(&expectations, &sample_names(&directory)?, &targets)
        {
            finding.source = Some(Source {
                file: file.display().to_string(),
                line: None,
                column: None,
            });
            report.push(finding);
        }
        found.insert(
            directory,
            Expectations {
                file,
                samples: expectations
                    .samples
                    .into_iter()
                    .map(|(name, expectation)| (name.as_str().to_owned(), expectation))
                    .collect(),
            },
        );
    }
    Ok(found)
}

/// Whether a preview result is the one its expectation asks for. A sample
/// that could not be read as a source value matches no expectation.
fn matches(expectation: &SampleExpectation, result: &Value) -> bool {
    let outcome = result["outcome"].as_str();
    let read_failure = matches!(
        result["failure"].as_str(),
        Some("input-too-large" | "input-unreadable")
    );
    match expectation {
        SampleExpectation::Accepted {} => outcome == Some("accepted"),
        SampleExpectation::Refused { target: None } => outcome == Some("refused") && !read_failure,
        // A refusal names one target field, so it is a refusal at the target
        // exactly when that field is the target.
        SampleExpectation::Refused {
            target: Some(target),
        } => {
            outcome == Some("refused")
                && result["field"]
                    .as_str()
                    .is_some_and(|field| refusal_names_target(target.as_str(), field))
        }
    }
}

/// How an expectation reads in a report.
fn expectation_member(expectation: &SampleExpectation) -> Value {
    match expectation {
        SampleExpectation::Accepted {} => json!({"outcome": "accepted"}),
        SampleExpectation::Refused { target: None } => json!({"outcome": "refused"}),
        SampleExpectation::Refused {
            target: Some(target),
        } => json!({"outcome": "refused", "field": target.as_str()}),
    }
}

/// Add each result's expectation and whether it matched, raise one finding
/// per mismatch, and count the mismatches. A result whose sample the file
/// does not list is left as it is.
fn judge(
    results: &mut [Value],
    expectations: &ExpectationsByDirectory,
    report: &mut Report,
) -> usize {
    let mut mismatched = 0;
    for result in results {
        let input = PathBuf::from(result["input"].as_str().unwrap_or_default());
        let name = sample_name(&input);
        let Some(found) = expectations.get(&input_directory(&input)) else {
            continue;
        };
        let Some(expectation) = found.samples.get(&name) else {
            continue;
        };
        let matched = matches(expectation, result);
        result["expected"] = expectation_member(expectation);
        result["matched"] = json!(matched);
        if matched {
            continue;
        }
        mismatched += 1;
        let mut finding = Diagnostic::error(
            "adapterctl.mapping-preview-mismatch",
            format!("/samples/{}", name.replace('~', "~0").replace('/', "~1")),
            format!(
                "the sample was {}, but the expectations record {}",
                describe_result(result),
                describe_expectation(expectation),
            ),
            "Fix the mapping or the sample, or correct the expectation in expected.yaml.",
        );
        finding.source = Some(Source {
            file: found.file.display().to_string(),
            line: None,
            column: None,
        });
        report.push(finding);
    }
    mismatched
}

/// A result in words, without the source value.
fn describe_result(result: &Value) -> String {
    let mut text = result["outcome"].as_str().unwrap_or("unknown").to_owned();
    if let Some(failure) = result["failure"].as_str() {
        text.push_str(&format!(" ({failure}"));
        if let Some(field) = result["field"].as_str() {
            text.push_str(&format!(" at {field}"));
        }
        text.push(')');
    }
    text
}

fn describe_expectation(expectation: &SampleExpectation) -> String {
    match expectation {
        SampleExpectation::Accepted {} => "accepted".to_owned(),
        SampleExpectation::Refused { target: None } => "refused".to_owned(),
        SampleExpectation::Refused {
            target: Some(target),
        } => format!("refused at {}", target.as_str()),
    }
}

/// Compile the generated script through the same seam the runtime uses for
/// project transformations; an ingestion mapping previews its inner
/// `<entrypoint>_input` function.
fn compile_preview(
    loaded: &Loaded,
    script: &str,
) -> Result<CompiledProjectTransform, ProjectTransformError> {
    let header = &loaded.mapping.mapping;
    let schema_bytes = serde_json::to_vec(loaded.schema.as_ref().expect("a checked schema"))
        .map_err(|_| ProjectTransformError::SchemaInvalid)?;
    let entrypoint = match header.target {
        MappingTarget::Ingestion => format!("{}_input", header.entrypoint),
        _ => header.entrypoint.clone(),
    };
    let script_ref: ProjectScript = serde_json::from_value(json!({
        "id": "mapping-script",
        "file": header.script,
        "digest": sha256_uri(script.as_bytes()),
    }))
    .map_err(|_| ProjectTransformError::ScriptInvalid)?;
    let schema_ref: ProjectSchema = serde_json::from_value(json!({
        "id": "mapping-schema",
        "file": header.target_schema,
        "digest": sha256_uri(&schema_bytes),
    }))
    .map_err(|_| ProjectTransformError::SchemaInvalid)?;
    let transform: BindingTransform = serde_json::from_value(json!({
        "script": "mapping-script",
        "entrypoint": entrypoint,
    }))
    .map_err(|_| ProjectTransformError::ScriptInvalid)?;
    let artifacts = ProjectArtifactBytes::new([
        (header.script.clone(), script.as_bytes().to_vec()),
        (header.target_schema.clone(), schema_bytes),
    ]);
    CompiledProjectTransform::compile_parts(&script_ref, &transform, &schema_ref, &artifacts)
}

/// Show an ingestion result as the runtime sees it: a proposal mapping's
/// output is wrapped as the start input of the Proposal.
fn wrap_for_runtime(loaded: &Loaded, output: Value) -> Value {
    match (
        loaded.mapping.mapping.target,
        loaded.mapping.mapping.ingestion_mode,
    ) {
        (MappingTarget::Ingestion, Some(IngestionMode::Proposal)) => {
            json!({"startInput": {"input": output}, "submitBody": {}})
        }
        _ => output,
    }
}

/// A refusal the generated script raises, as its category, a value-free
/// message and the target field. Only the exact text the generator throws,
/// `mapping.<category>: <target>` for a target the model reads from the
/// source, is recognised; any other text may carry a value and is not shown.
fn named_failure<'a>(
    thrown: &str,
    fields: &[&'a str],
) -> Option<(&'static str, &'static str, &'a str)> {
    let (category, field) = thrown.split_once(": ")?;
    let (failure, message) = match category {
        "mapping.missing" => ("mapping.missing", "the source has no value for the field"),
        "mapping.duplicate" => (
            "mapping.duplicate",
            "the selector matched more than one source value for the field",
        ),
        "mapping.conversion" => (
            "mapping.conversion",
            "the source value does not convert to the field's type",
        ),
        _ => return None,
    };
    let field = fields.iter().find(|known| **known == field)?;
    Some((failure, message, field))
}

fn variant_name(error: ProjectTransformError) -> &'static str {
    match error {
        ProjectTransformError::TransformMissing => "transform-missing",
        ProjectTransformError::ScriptMissing => "script-missing",
        ProjectTransformError::SchemaMissing => "schema-missing",
        ProjectTransformError::ScriptInvalid => "script-invalid",
        ProjectTransformError::SchemaInvalid => "schema-invalid",
        ProjectTransformError::Budget => "budget",
        ProjectTransformError::Failed => "failed",
        ProjectTransformError::OutputInvalid => "output-invalid",
    }
}

/// Read one preview input. The outer error is the environment; the inner
/// error is a categorical, value-free reason the file is not a source value.
fn read_input(
    path: &Path,
    files: &mut usize,
) -> Result<Result<Value, &'static str>, MappingFailure> {
    let io_failure = |source: io::Error| MappingFailure::Io {
        path: path.display().to_string(),
        source,
    };
    let length = std::fs::metadata(path).map_err(io_failure)?.len();
    if length > MAXIMUM_INPUT_BYTES {
        return Ok(Err("input-too-large"));
    }
    let bytes = std::fs::read(path).map_err(io_failure)?;
    *files += 1;
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return Ok(Ok(value));
    }
    let mut hook = AuthoredExpressions;
    let decoded = Reader::new(path.display().to_string())
        .with_hook(&mut hook)
        .decode::<Value>(&bytes, &Expect::one(&INPUT_FORMAT));
    Ok(decoded
        .map(|decoded| decoded.value)
        .map_err(|_| "input-unreadable"))
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

/// Resolve `.` and `..` lexically.
fn lexical(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => match resolved.components().next_back() {
                Some(Component::Normal(_)) => {
                    resolved.pop();
                }
                // `..` at the root is the root.
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => resolved.push(".."),
            },
            Component::CurDir => {}
            other => resolved.push(other.as_os_str()),
        }
    }
    resolved
}

fn drift_warning(
    script: &Path,
    pointer: &str,
    model_reference: Option<&str>,
    why: &str,
) -> Option<Diagnostic> {
    let model = model_reference
        .map(|reference| format!(" {reference}"))
        .unwrap_or_default();
    let mut diagnostic = Diagnostic::warning(
        SCRIPT_DRIFT_CODE,
        pointer,
        format!(
            "the generated script {} no longer matches its model{model}: {why}",
            script.display()
        ),
        "The model changed since generation or the script was hand-edited; adapterctl mapping generate on the model regenerates the script, so move any hand edit into the model first.",
    );
    diagnostic.source = Some(Source {
        file: script.display().to_string(),
        line: None,
        column: None,
    });
    Some(diagnostic)
}

/// The drift warning for one script, or `None` when it carries no generated
/// header (a handwritten script), or cannot be read (the artifact checks
/// report that). The header names the model, relative to the script; the
/// model must lie inside `owner_directory`, the directory of the document that inventories the
/// script. The model is read, the script regenerated, and the bytes compared;
/// a mismatch, a missing model, or an invalid model all warn.
pub(crate) fn script_drift(
    script: &Path,
    owner_directory: &Path,
    pointer: &str,
) -> Option<Diagnostic> {
    if std::fs::metadata(script).ok()?.len() > MAXIMUM_GENERATED_SCRIPT_BYTES as u64 {
        return None;
    }
    let text = String::from_utf8(std::fs::read(script).ok()?).ok()?;
    let header =
        match parse_generated_header(&text) {
            GeneratedHeaderState::Absent => return None,
            GeneratedHeaderState::Malformed => return drift_warning(
                script,
                pointer,
                None,
                "the script opens with the generated marker but the generated header is malformed",
            ),
            GeneratedHeaderState::Parsed(header) => header,
        };
    let drift = |why: &str| drift_warning(script, pointer, Some(&header.model_reference), why);

    let script_directory = script.parent().unwrap_or_else(|| Path::new(""));
    let model = script_directory.join(&header.model_reference);
    if !lexical(&model).starts_with(lexical(owner_directory)) {
        return drift("the header names a model outside the directory that owns the script");
    }
    let Ok(canonical) = std::fs::canonicalize(&model) else {
        return drift("the model file is missing");
    };
    let owner = std::fs::canonicalize(if owner_directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        owner_directory
    })
    .ok()?;
    if !canonical.starts_with(&owner) {
        return drift("the header names a model outside the directory that owns the script");
    }

    let mut scratch = Report::new(Vec::new());
    let mut files = 0usize;
    let loaded = match load(&model, &mut scratch, &mut files) {
        Ok(Some(loaded)) if !scratch.has_errors() => loaded,
        _ => return drift("the model cannot be read or no longer passes its schema checks"),
    };
    if lexical(&loaded.script_path()) != lexical(script) {
        return drift("the model names a different script");
    }
    let schema = loaded.schema.as_ref()?;
    let (reference, digest) = loaded.header();
    match generate(&loaded.mapping, schema, &reference, &digest) {
        Ok(regenerated) if regenerated == text => None,
        Ok(_) => drift("the script bytes differ from what the model generates"),
        Err(_) => drift("the model no longer generates a script"),
    }
}

/// One warning per assignment of a current generated script's model whose
/// source key (the first segment of `from`) is not in `projected`, each with
/// the assignment's canonical target. A script that is handwritten, has
/// drifted from its model, or whose model does not check cleanly yields
/// nothing: the drift warning already speaks for those.
pub(crate) fn unprojected_sources(
    script: &Path,
    owner_directory: &Path,
    projected: &[String],
) -> Vec<(Diagnostic, String)> {
    let Ok(text) = std::fs::read_to_string(script) else {
        return Vec::new();
    };
    let GeneratedHeaderState::Parsed(header) = parse_generated_header(&text) else {
        return Vec::new();
    };
    if script_drift(script, owner_directory, "/destination/mapping").is_some() {
        return Vec::new();
    }
    let model = script
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(&header.model_reference);
    let mut scratch = Report::new(Vec::new());
    let mut files = 0usize;
    let loaded = match load(&model, &mut scratch, &mut files) {
        Ok(Some(loaded)) if !scratch.has_errors() => loaded,
        _ => return Vec::new(),
    };
    let Some(schema) = loaded.schema.as_ref() else {
        return Vec::new();
    };
    if !check_mapping_findings(&loaded.mapping, schema).is_empty() {
        return Vec::new();
    }
    let mut warnings = Vec::new();
    for (index, assignment) in loaded.mapping.assignments.iter().enumerate() {
        let Some(from) = &assignment.from else {
            continue;
        };
        let Some(root) = parse_selector(from)
            .ok()
            .and_then(|segments| segments.into_iter().next())
            .map(|segment| segment.name)
        else {
            continue;
        };
        let Some(target) = canonical_target_path(&assignment.target) else {
            continue;
        };
        if projected.contains(&root) {
            continue;
        }
        let mut warning = Diagnostic::warning(
            UNPROJECTED_CODE,
            format!("/assignments/{index}/from"),
            format!(
                "the mapping reads the source key `{root}` for `{target}`, but the job's projection.fields does not list it, so every live item reaches the mapping without it"
            ),
            "Add the key to projection.fields in the job, or map a field the projection already lists.",
        );
        warning.source = Some(Source {
            file: model.display().to_string(),
            line: None,
            column: None,
        });
        warnings.push((warning, target));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::{lexical, named_failure};
    use std::path::{Path, PathBuf};

    /// Only the generator's exact text for a known field is named; anything
    /// else stays a plain `failed` refusal.
    #[test]
    fn named_failure_accepts_only_the_generator_text_for_a_known_field() {
        let fields = ["source.id", "household.size"];
        assert_eq!(
            named_failure("mapping.missing: source.id", &fields).map(|(f, _, p)| (f, p)),
            Some(("mapping.missing", "source.id"))
        );
        assert_eq!(
            named_failure("mapping.duplicate: household.size", &fields).map(|(f, _, p)| (f, p)),
            Some(("mapping.duplicate", "household.size"))
        );
        for thrown in [
            "mapping.missing: other.field",
            "mapping.missing: source.id ",
            "mapping.missing: source.id: SECRET",
            "mapping.missing:source.id",
            "mapping.unknown: source.id",
            "SECRET",
            "",
        ] {
            assert!(named_failure(thrown, &fields).is_none(), "{thrown}");
        }
    }

    /// A `..` cancels only a named component, never an earlier `..`, so two
    /// different files above the working directory stay different.
    #[test]
    fn lexical_keeps_leading_parent_components() {
        assert_eq!(
            lexical(Path::new("../../m.mapping.yaml")),
            PathBuf::from("../../m.mapping.yaml")
        );
        assert_eq!(
            lexical(Path::new("../../s/../../../m.mapping.yaml")),
            PathBuf::from("../../../../m.mapping.yaml")
        );
        assert_eq!(
            lexical(Path::new("a/./b/../m.mapping.yaml")),
            PathBuf::from("a/m.mapping.yaml")
        );
    }
}
