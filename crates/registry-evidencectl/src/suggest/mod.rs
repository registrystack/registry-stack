//! `evidencectl source suggest`: turn one OpenAPI operation into draft
//! Evidence source artifacts.
//!
//! The tool derives what the specification can state, asks (or accepts flags)
//! for what it cannot, and never invents a bound: every unresolved decision
//! is emitted as an explicit TODO that `evidence check` rejects, so the
//! runtime stays the only validator of the closed schema subset. The
//! interactive mode is a thin front-end over the same deterministic pipeline
//! and ends by printing the equivalent fully-flagged command.

pub mod emit;
pub mod flatten;
pub mod interactive;
pub mod narrow;
pub mod openapi;
pub mod sample;
pub mod types;

use std::{collections::BTreeMap, path::Path, process::ExitCode};

use anyhow::{bail, Result};
use clap::{Args, Subcommand};

use emit::{CheckClassification, EmitInputs};
use openapi::Spec;
use types::{
    BoundKind, BoundNeed, BoundValues, CandidateLeaf, Decisions, DraftArtifacts, Observations,
    OperationKey, OperationSummary, Provenance, SuggestedBound,
};

#[derive(Debug, Subcommand)]
pub enum SourceCommand {
    /// Suggest source configuration from an OpenAPI document.
    Suggest(SuggestArgs),
}

#[derive(Debug, Args)]
pub struct SuggestArgs {
    /// OpenAPI 3.0 or 3.1 document (YAML or JSON, local file only).
    #[arg(long)]
    pub openapi: std::path::PathBuf,

    /// Operation as "METHOD /path/template"; interactive selection if absent.
    #[arg(long)]
    pub operation: Option<String>,

    /// Response status code to read the schema from.
    #[arg(long, default_value = "200")]
    pub status: String,

    /// Response media type to read the schema from.
    #[arg(long, default_value = "application/json")]
    pub media_type: String,

    /// Projection pointer to select; repeat once per leaf. Interactive
    /// selection if absent.
    #[arg(long = "select")]
    pub selection: Vec<String>,

    /// Sample response JSON file used to suggest bounds. Read only; nothing
    /// from it is copied into any artifact except derived bounds.
    #[arg(long)]
    pub sample: Option<std::path::PathBuf>,

    /// Source identifier for the generated artifacts.
    #[arg(long)]
    pub source_id: Option<String>,

    /// Deployment project to write the draft into; print-only if absent.
    #[arg(long)]
    pub project: Option<std::path::PathBuf>,

    /// Verify a written draft by running `evidence check` with this binary.
    /// Verification is opt-in: a project being drafted into is normally
    /// neither frozen nor provisioned yet, and `check` reports that state
    /// rather than anything about the draft.
    #[arg(long)]
    pub evidence_bin: Option<std::path::PathBuf>,
}

pub fn run(command: SourceCommand) -> Result<ExitCode> {
    match command {
        SourceCommand::Suggest(args) => suggest(args),
    }
}

/// The largest `maxItems` the closed schema subset admits, and therefore the
/// ceiling any page-size-derived suggestion is clamped to.
const MAX_PROJECTED_ITEMS: i64 = 256;

/// The identifier used when an operation's path yields no usable one.
const FALLBACK_SOURCE_ID: &str = "source-a";

/// Run one drafting pass.
///
/// The pipeline is the same in both front-ends and runs in one order:
/// load the document, pick the operation, resolve its response schema,
/// flatten it into candidate leaves, take a selection, observe an optional
/// sample, plan the bounds the closed subset still demands, resolve those
/// bounds, then narrow, draft, and either write or print. Only the two
/// resolution steps differ: prompts when a terminal is driving the run,
/// announced auto-acceptance of the pipeline's own suggestions when flags
/// are. Both produce the same [`Decisions`], and the printed equivalent
/// command reproduces either run exactly, because every suggestion is
/// derived deterministically from the same inputs.
fn suggest(args: SuggestArgs) -> Result<ExitCode> {
    let spec = Spec::load(&args.openapi)?;
    let operations = spec.operations();
    if operations.is_empty() {
        bail!(
            "{} declares no operation with a JSON response schema; there is nothing to draft from",
            args.openapi.display()
        );
    }

    let flag_driven = args.operation.is_some() && !args.selection.is_empty();
    if !flag_driven && !interactive::is_interactive() {
        bail!(missing_flags_message(&args));
    }

    let summary = match &args.operation {
        Some(text) => find_operation(&parse_operation(text)?, &operations)?,
        None => {
            let key = interactive::choose_operation(&operations)?;
            find_operation(&key, &operations)?
        }
    };
    if !summary
        .json_responses
        .iter()
        .any(|(status, media_type)| *status == args.status && *media_type == args.media_type)
    {
        bail!(
            "{} {} declares no `{}` `{}` response schema; it declares {}",
            summary.key.method,
            summary.key.path,
            args.status,
            args.media_type,
            describe_responses(&summary.json_responses)
        );
    }
    let operation = summary.key.clone();

    let schema = spec.response_schema(&operation, &args.status, &args.media_type)?;
    let (leaves, warnings) = flatten::candidate_leaves(&schema);
    for warning in &warnings {
        eprintln!("evidencectl: {warning}");
    }
    if leaves.is_empty() {
        bail!(
            "the `{}` `{}` response schema of {} {} has no selectable leaf; \
             nothing above can be projected",
            args.status,
            args.media_type,
            operation.method,
            operation.path
        );
    }

    let selection = if args.selection.is_empty() {
        interactive::choose_leaves(&leaves)?
    } else {
        check_selection(&args.selection, &leaves)?;
        args.selection.clone()
    };

    let observations = match &args.sample {
        Some(path) => sample::observe(&sample::load_sample(path)?, &selection)?,
        None => Observations::default(),
    };

    let plan = narrow::plan_advisories(&schema, &selection, &observations)?;
    for advisory in &plan.advisories {
        eprintln!("evidencectl: {}", advisory.message());
    }
    let mut needs = with_page_size_fallback(plan.needs, &spec, &operation)?;

    let resolutions = if flag_driven {
        accept_suggestions(&needs)
    } else {
        interactive::resolve_bounds(&needs)?
    };
    // An operator who typed over a suggestion owns that bound now, and the
    // draft must not keep crediting the source the rejected number came from.
    emit::attribute_operator_edits(&mut needs, &resolutions);

    let source_id = match &args.source_id {
        Some(id) => validate_source_id(id)?,
        None => {
            let derived = default_source_id(&operation.path);
            if flag_driven {
                eprintln!("evidencectl: naming this source `{derived}`, from the operation path");
                derived
            } else {
                interactive::choose_source_id(&derived)?
            }
        }
    };

    let decisions = Decisions {
        operation,
        status: args.status.clone(),
        media_type: args.media_type.clone(),
        source_id,
        selection,
        resolutions,
    };

    let narrowed = narrow::apply(&schema, &decisions.selection, &decisions.resolutions)?;
    let inputs = EmitInputs {
        source_id: decisions.source_id.clone(),
        operation: decisions.operation.clone(),
        status: decisions.status.clone(),
        media_type: decisions.media_type.clone(),
        // Only the first server is a candidate: a later entry is usually a
        // sandbox or a mirror, and quietly drafting against one because the
        // primary carries template variables would point the source elsewhere.
        base_url_suggestion: spec
            .servers()
            .into_iter()
            .next()
            .and_then(|url| emit::split_server_url(&url)),
        selection: decisions.selection.clone(),
        narrowed,
        needs,
        openapi_path: args.openapi.clone(),
        sample_path: args.sample.clone(),
        project: args.project.clone(),
    };
    let artifacts = emit::draft(&inputs)?;

    let code = match &args.project {
        Some(project) => deliver_into_project(
            project,
            &artifacts,
            args.evidence_bin.as_deref(),
            flag_driven,
        )?,
        None => {
            print_draft(&artifacts);
            ExitCode::SUCCESS
        }
    };

    println!("{}", artifacts.report);
    println!("Reproduce this run with:");
    println!("  {}", artifacts.equivalent_command);
    Ok(code)
}

/// Write the draft into a deployment project, then report what happened.
///
/// The write refuses to replace anything that already exists, so a repeated
/// run never silently discards an edited draft. Verification runs only when
/// the operator supplied a runtime binary to run it with.
fn deliver_into_project(
    project: &Path,
    artifacts: &DraftArtifacts,
    evidence_bin: Option<&Path>,
    flag_driven: bool,
) -> Result<ExitCode> {
    if !project.is_dir() {
        bail!(
            "deployment project directory {} not found; scaffold one with `evidencectl new` first",
            project.display()
        );
    }
    if !flag_driven
        && !interactive::confirm_write(&project.display().to_string(), &artifacts.files)?
    {
        eprintln!("evidencectl: nothing was written; the draft is printed below instead.");
        print_draft(artifacts);
        return Ok(ExitCode::SUCCESS);
    }

    let written = emit::write_into_project(project, &artifacts.files)?;
    for path in &written {
        println!("wrote {}", path.display());
    }
    print_block(
        "the block to paste under `sources:` in bundle/evidence.yaml",
        &artifacts.source_block,
    );

    let Some(evidence_bin) = evidence_bin else {
        println!(
            "not verified: pass --evidence-bin to run `evidence check` once the project is \
             frozen and provisioned."
        );
        return Ok(ExitCode::SUCCESS);
    };
    match emit::verify(project, Some(evidence_bin))? {
        CheckClassification::BundleAccepted => {
            println!("evidence check: bundle accepted");
            Ok(ExitCode::SUCCESS)
        }
        CheckClassification::SecretsUnprovisioned => {
            println!(
                "evidence check: bundle accepted; deployment secrets not provisioned yet \
                 (expected before keygen)"
            );
            Ok(ExitCode::SUCCESS)
        }
        CheckClassification::BundleRejected { stderr } => {
            eprintln!("evidence check: bundle rejected");
            eprint!("{stderr}");
            if !stderr.ends_with('\n') {
                eprintln!();
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Print every drafted file, and the pasteable source block, to stdout.
fn print_draft(artifacts: &DraftArtifacts) {
    for file in &artifacts.files {
        print_block(&file.bundle_relative_path, &file.contents);
    }
    print_block(
        "the block to paste under `sources:` in bundle/evidence.yaml",
        &artifacts.source_block,
    );
}

fn print_block(title: &str, body: &str) {
    println!("--- {title} ---");
    print!("{body}");
    if !body.ends_with('\n') {
        println!();
    }
    println!();
}

/// Adopt every suggestion the pipeline derived, announcing each one with its
/// provenance so a flag-driven run is auditable from its own output. A need
/// with no suggestion stays unresolved: nothing here invents a bound.
fn accept_suggestions(needs: &[BoundNeed]) -> BTreeMap<(String, BoundKind), BoundValues> {
    let mut resolutions = BTreeMap::new();
    for need in needs {
        match &need.suggestion {
            Some(suggestion) => {
                let derivation = emit::provenance_label(&suggestion.provenance)
                    .map_or_else(String::new, |label| format!(", derived from {label}"));
                let note = emit::review_note(&need.kind, &suggestion.provenance)
                    .map_or_else(String::new, |note| format!(" ({note})"));
                eprintln!(
                    "evidencectl: adopting {} for `{}`{derivation}{note}",
                    describe_bound(&suggestion.values),
                    narrow::display_pointer(&need.pointer),
                );
                resolutions.insert(
                    (need.pointer.clone(), need.kind.clone()),
                    suggestion.values.clone(),
                );
            }
            None => eprintln!(
                "evidencectl: nothing implies {} for `{}`; left as a TODO in the draft",
                need.kind.label(),
                narrow::display_pointer(&need.pointer)
            ),
        }
    }
    resolutions
}

fn describe_bound(values: &BoundValues) -> String {
    match values {
        BoundValues::MaxItems(maximum) => format!("maxItems {maximum}"),
        BoundValues::IntegerRange { minimum, maximum } => {
            format!("minimum {minimum} and maximum {maximum}")
        }
        BoundValues::StringLength {
            min_length,
            max_length,
        } => format!("minLength {min_length} and maxLength {max_length}"),
    }
}

/// Fill in the top-level collection's `maxItems` from the operation's
/// page-size parameters.
///
/// The narrowing stage sees only the response schema, so it cannot know that a
/// query parameter caps how long a page can be. What that parameter bounds is
/// exactly one array: the collection the operation pages over. It says nothing
/// about an array nested inside a record, so only a need whose pointer crosses
/// no earlier wildcard is eligible; a nested array keeps whatever narrowing
/// derived, including nothing at all.
///
/// For that one array the stated page size outranks a sample: a page of two
/// records is a fact about the request that was made, while the parameter's
/// maximum is the source's own statement about how long any page can be. A
/// bound taken from the response schema or from a format is stronger still and
/// is left alone. The largest declared maximum is used, because a smaller one
/// bounds only the requests that ask for it, and the result is clamped to the
/// subset ceiling.
fn with_page_size_fallback(
    mut needs: Vec<BoundNeed>,
    spec: &Spec,
    operation: &OperationKey,
) -> Result<Vec<BoundNeed>> {
    let eligible = |need: &BoundNeed| {
        need.kind == BoundKind::ArrayMaxItems
            && is_top_level_collection(&need.pointer)
            && need.suggestion.as_ref().is_none_or(|suggestion| {
                matches!(
                    suggestion.provenance,
                    Provenance::Sample | Provenance::PageSize
                )
            })
    };
    if !needs.iter().any(eligible) {
        return Ok(needs);
    }
    // The smallest advertised ceiling is the only one a response can actually
    // reach: a server honouring both `pageSize` (max 50) and `limit` (max 200)
    // never returns more than 50 items. Taking the largest would bound the
    // array well above anything the operation can produce, which is the wrong
    // direction for a minimum-disclosure bound.
    let Some(maximum) = spec
        .page_size_maximums(operation)?
        .into_iter()
        .filter(|maximum| *maximum > 0)
        .min()
    else {
        return Ok(needs);
    };
    let clamped = u64::try_from(maximum.min(MAX_PROJECTED_ITEMS)).unwrap_or(1);
    for need in needs.iter_mut().filter(|need| eligible(need)) {
        need.suggestion = Some(SuggestedBound {
            values: BoundValues::MaxItems(clamped),
            provenance: Provenance::PageSize,
        });
    }
    Ok(needs)
}

/// Whether `pointer` names an array the operation pages over directly, rather
/// than one reached by descending through another array's items.
fn is_top_level_collection(pointer: &str) -> bool {
    !pointer.contains("/*")
}

/// Parses `--operation`, which names one operation as `METHOD /path`.
///
/// A method outside the runtime's fixed-request enumeration is refused here,
/// naming the two it admits, rather than later as an operation the document
/// "does not declare": the document may well declare it, and the reason it
/// cannot be drafted from is the runtime's, not the document's.
fn parse_operation(text: &str) -> Result<OperationKey> {
    let mut fields = text.split_whitespace();
    let (Some(method), Some(path), None) = (fields.next(), fields.next(), fields.next()) else {
        bail!("--operation reads as \"METHOD /path\", for example \"GET /records\"; got `{text}`");
    };
    Ok(OperationKey {
        method: emit::request_method(method)?.to_owned(),
        path: path.to_owned(),
    })
}

fn find_operation<'a>(
    key: &OperationKey,
    operations: &'a [OperationSummary],
) -> Result<&'a OperationSummary> {
    operations
        .iter()
        .find(|operation| operation.key == *key)
        .ok_or_else(|| {
            let available = operations
                .iter()
                .map(|operation| format!("  {} {}", operation.key.method, operation.key.path))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::anyhow!(
                "this document declares no `{} {}` with a JSON response schema; it declares:\n{available}",
                key.method,
                key.path
            )
        })
}

fn describe_responses(responses: &[(String, String)]) -> String {
    responses
        .iter()
        .map(|(status, media_type)| format!("`{status}` `{media_type}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Rejects a `--select` pointer that names nothing in this response schema,
/// before the narrowing stage reports the same pointer in schema terms. A
/// pointer may name a leaf or a container above one: selecting a container
/// projects its whole subtree.
fn check_selection(selection: &[String], leaves: &[CandidateLeaf]) -> Result<()> {
    for pointer in selection {
        let prefix = format!("{pointer}/");
        let known = leaves
            .iter()
            .any(|leaf| leaf.pointer == *pointer || leaf.pointer.starts_with(&prefix));
        if !known {
            let available = leaves
                .iter()
                .map(|leaf| format!("  {}", leaf.pointer))
                .collect::<Vec<_>>()
                .join("\n");
            bail!("`--select {pointer}` names nothing in this response schema; it offers:\n{available}");
        }
    }
    Ok(())
}

/// Accepts an identifier that is safe as a file name, a YAML key, and a
/// bundle-relative path segment.
fn validate_source_id(candidate: &str) -> Result<String> {
    let acceptable = !candidate.is_empty()
        && candidate.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        && !candidate.starts_with('-')
        && !candidate.ends_with('-');
    if !acceptable {
        bail!(
            "`{candidate}` is not a usable source identifier: use lowercase letters, digits and \
             inner hyphens, for example `source-a`"
        );
    }
    Ok(candidate.to_owned())
}

/// Derives a source identifier from the last literal segment of the operation
/// path, so `/v1/records/{id}` suggests `records`. A path made only of
/// template parameters yields the neutral fallback.
fn default_source_id(path: &str) -> String {
    let sanitized = path
        .split('/')
        .rfind(|segment| !segment.is_empty() && !segment.starts_with('{'))
        .map(|segment| {
            segment
                .chars()
                .map(|character| {
                    let lowered = character.to_ascii_lowercase();
                    if lowered.is_ascii_lowercase() || lowered.is_ascii_digit() {
                        lowered
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
        })
        .unwrap_or_default();
    let trimmed = sanitized.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        FALLBACK_SOURCE_ID.to_owned()
    } else {
        trimmed
    }
}

/// The error a run gets when it has neither a terminal to ask on nor the
/// flags that answer the questions.
fn missing_flags_message(args: &SuggestArgs) -> String {
    let mut missing: Vec<&str> = Vec::new();
    if args.operation.is_none() {
        missing.push("--operation");
    }
    if args.selection.is_empty() {
        missing.push("--select");
    }
    format!(
        "this run has no terminal to prompt on, so it needs {} on the command line; \
         run it in a terminal to choose interactively, or pass the missing flags \
         (an interactive run prints the equivalent fully-flagged command)",
        missing.join(" and ")
    )
}
