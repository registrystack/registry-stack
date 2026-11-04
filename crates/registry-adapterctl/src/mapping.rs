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
    check_mapping, check_mapping_file, generate, is_clean_mapping_path, model_reference_from,
    parse_generated_header, AdapterMapping, BindingTransform, GeneratedHeaderState, IngestionMode,
    MappingTarget, ProjectSchema, ProjectScript, ADAPTER_MAPPING_API_VERSION, ADAPTER_MAPPING_KIND,
    MAXIMUM_GENERATED_SCRIPT_BYTES,
};
use registry_platform_config::{sha256_uri, AuthoredExpressions};
use registry_platform_yaml::{
    ApiVersion, Diagnostic, EnvelopeRule, Expect, FormatSpec, Reader, Report, Severity, Source,
};
use serde_json::{json, Value};
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

/// The warning code for a generated script that no longer matches its model.
pub(crate) const SCRIPT_DRIFT_CODE: &str = "adapter.mapping.script-drift";

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
    /// input cannot hold `null`; use JSON for that.
    #[arg(long, value_name = "FILE", required = true)]
    pub input: Vec<PathBuf>,
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
    },
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
    pub bytes: Vec<u8>,
    /// The target schema, `None` when it could not be read (a finding says
    /// why) or its path is not clean (the model check says so).
    pub schema: Option<Value>,
    pub directory: PathBuf,
    pub file_name: String,
}

impl Loaded {
    fn digest(&self) -> String {
        sha256_uri(&self.bytes)
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
    let Some((decoded, bytes)) = read::<AdapterMapping>(model, &MAPPING_FORMAT, report, files)?
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
        read_schema(
            &directory.join(&mapping.mapping.target_schema),
            model,
            report,
            files,
        )?
    } else {
        // The model check reports the unclean path; nothing is read for it.
        Some(Value::Null)
    };
    Ok(Some(Loaded {
        mapping,
        bytes,
        schema,
        directory,
        file_name,
    }))
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
fn model_findings(loaded: &Loaded, model: &Path, report: &mut Report) {
    let Some(schema) = &loaded.schema else {
        return;
    };
    for diagnostic in check_mapping(&loaded.mapping, schema)
        .into_iter()
        .chain(check_mapping_file(&loaded.mapping, &loaded.file_name))
    {
        model_failure(report, model, diagnostic);
    }
}

fn refusal(report: Report, files_checked: usize) -> MappingFailure {
    MappingFailure::Refused {
        diagnostics: report.into_diagnostics(),
        files_checked,
    }
}

fn run_check(args: &MappingCheckArgs) -> Result<MappingRun, MappingFailure> {
    let mut report = Report::new(Vec::new());
    let mut files = 0usize;
    let loaded = load(&args.model, &mut report, &mut files)?;
    if let Some(loaded) = &loaded {
        model_findings(loaded, &args.model, &mut report);
    }
    if report.has_errors() {
        return Err(refusal(report, files));
    }
    let loaded = loaded.expect("the model decoded");
    let Some(script) = generated(&loaded, &args.model, &mut report) else {
        return Err(refusal(report, files));
    };
    // The script on disk is judged as generate would judge it: a missing
    // script is fine (generate writes it), any other difference warns.
    let path = loaded.script_path();
    let existing = existing_script(&path, &args.model, &script)?;
    if let Some(mut conflict) = script_conflict(&existing, &args.model) {
        conflict.severity = Severity::Warning;
        model_failure(&mut report, &args.model, conflict);
    } else if existing == ExistingScript::Stale {
        if let Some(warning) = drift_warning(
            &path,
            "/mapping/script",
            None,
            "the script bytes differ from what the model generates",
        ) {
            report.push(warning);
        }
    }
    let header = &loaded.mapping.mapping;
    Ok(MappingRun {
        warnings: report.into_diagnostics(),
        files_checked: files,
        members: vec![
            ("model", json!(args.model.display().to_string())),
            ("target", json!(target_name(header.target))),
            ("script", json!(header.script)),
            ("assignments", json!(loaded.mapping.assignments.len())),
        ],
        deny_warnings: args.deny_warnings,
    })
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
    let existing = existing_script(&path, &args.model, &script)?;
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
    Stale,
    /// Generated from another model, named by its path.
    Owned(PathBuf),
    /// No generated header: a person wrote it.
    Handwritten,
}

fn existing_script(
    path: &Path,
    model: &Path,
    script: &str,
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
        GeneratedHeaderState::Malformed => ExistingScript::Stale,
        GeneratedHeaderState::Parsed(header) => {
            let script_directory = path.parent().unwrap_or_else(|| Path::new(""));
            let owner = script_directory.join(&header.model_reference);
            if lexical(&owner) == lexical(model) {
                ExistingScript::Stale
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
        ExistingScript::Missing | ExistingScript::Current | ExistingScript::Stale => None,
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
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
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

    let mut results = Vec::new();
    let (mut accepted, mut refused) = (0usize, 0usize);
    for input in &args.input {
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
    Ok(MappingRun {
        warnings: report.into_diagnostics(),
        files_checked: files,
        members: vec![
            ("model", json!(args.model.display().to_string())),
            ("target", json!(target_name(loaded.mapping.mapping.target))),
            ("accepted", json!(accepted)),
            ("refused", json!(refused)),
            ("results", Value::Array(results)),
        ],
        deny_warnings: false,
    })
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
