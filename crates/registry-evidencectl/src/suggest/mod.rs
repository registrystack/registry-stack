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
pub mod fetch;
pub mod flatten;
pub mod interactive;
pub mod narrow;
pub mod openapi;
pub mod sample;
pub mod types;

use std::{collections::BTreeMap, path::Path, process::ExitCode};

use anyhow::{bail, Result};
use clap::{Args, Subcommand};

use emit::EmitInputs;
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
    /// OpenAPI 3.0 or 3.1 document for a print-only draft. With --project,
    /// the retained source.openapi.yaml is used instead.
    #[arg(long)]
    pub openapi: Option<String>,

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
pub(crate) struct PreparedSuggestion {
    pub artifacts: DraftArtifacts,
    flag_driven: bool,
}

/// Run the shared OpenAPI interpretation pipeline without writing output.
/// `source suggest` and `new --openapi` differ only in how they deliver this
/// prepared draft.
pub(crate) fn prepare(args: &SuggestArgs) -> Result<PreparedSuggestion> {
    let source = suggestion_openapi(args)?;
    let spec = Spec::open(&source)?;
    let operations = spec.operations();
    if operations.is_empty() {
        bail!(
            "{} declares no operation with a JSON response schema; there is nothing to draft from",
            source.display()
        );
    }

    let flag_driven = args.operation.is_some() && !args.selection.is_empty();
    // A run with no terminal to prompt on still gets told what it could have
    // asked for, and each answer is only knowable once the one before it is
    // settled: the operations come from the document, the leaves from the
    // chosen operation's response schema. So the two refusals happen at the two
    // points where the answer exists, not together at the top.
    if args.operation.is_none() && !interactive::is_interactive() {
        bail!(
            "{}\n\nthis document declares:\n{}",
            missing_flags_message(args),
            list_operations(&operations)
        );
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

    let resolved = spec.response_schema(&operation, &args.status, &args.media_type)?;
    for note in &resolved.notes {
        eprintln!("evidencectl: {note}");
    }
    let schema = resolved.schema;
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
        if !interactive::is_interactive() {
            bail!(
                "{}\n\nthis operation's `{}` `{}` response offers:\n{}",
                missing_flags_message(args),
                args.status,
                args.media_type,
                list_leaves(&leaves)
            );
        }
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
        openapi: source.clone(),
        sample_path: args.sample.clone(),
        project: args.project.clone(),
    };
    let artifacts = emit::draft(&inputs)?;

    Ok(PreparedSuggestion {
        artifacts,
        flag_driven,
    })
}

fn suggestion_openapi(args: &SuggestArgs) -> Result<types::SpecSource> {
    match (&args.project, &args.openapi) {
        (Some(project), None) => {
            if !project.is_dir() {
                bail!(
                    "authoring project directory {} not found; create it with `evidencectl new` first",
                    project.display()
                );
            }
            let retained = project.join("source.openapi.yaml");
            if !retained.is_file() {
                bail!(
                    "authoring project {} has no retained source.openapi.yaml",
                    project.display()
                );
            }
            fetch::spec_source(
                retained
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("retained OpenAPI path is not valid UTF-8"))?,
            )
        }
        (Some(_), Some(_)) => bail!(
            "--project uses its retained source.openapi.yaml; omit --openapi to avoid drafting from a different contract"
        ),
        (None, Some(openapi)) => fetch::spec_source(openapi),
        (None, None) => bail!("pass --openapi <path-or-https-url>, or pass --project <authoring-project>"),
    }
}

fn suggest(args: SuggestArgs) -> Result<ExitCode> {
    let prepared = prepare(&args)?;
    let artifacts = prepared.artifacts;

    let code = match &args.project {
        Some(project) => deliver_into_project(project, &artifacts, prepared.flag_driven)?,
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

/// Write the draft into an OpenAPI authoring project, then report what happened.
///
/// The write refuses to replace anything that already exists, so a repeated
/// run never silently discards an edited draft. Verification runs only when
/// the operator supplied a runtime binary to run it with.
fn deliver_into_project(
    project: &Path,
    artifacts: &DraftArtifacts,
    flag_driven: bool,
) -> Result<ExitCode> {
    if !project.is_dir() {
        bail!(
            "authoring project directory {} not found; create one with `evidencectl new` first",
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

    let written = emit::write_into_authoring_project(project, artifacts)?;
    for path in &written {
        println!("wrote {}", path.display());
    }
    println!(
        "source draft: {}",
        project
            .join("sources")
            .join(format!("{}.yaml", artifacts.source_id))
            .display()
    );

    println!(
        "not verified: complete a question and run `evidencectl dev`; the local compiler \
         delegates validation to Evidence."
    );
    Ok(ExitCode::SUCCESS)
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
    // A page size above the subset ceiling is not what the draft ends up
    // stating, so the parameter does not get the credit for what it does.
    let provenance = if maximum <= MAX_PROJECTED_ITEMS {
        Provenance::PageSize
    } else {
        Provenance::SubsetCeiling
    };
    for need in needs.iter_mut().filter(|need| eligible(need)) {
        need.suggestion = Some(SuggestedBound {
            values: BoundValues::MaxItems(clamped),
            provenance: provenance.clone(),
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
            anyhow::anyhow!(
                "this document declares no `{} {}` with a JSON response schema; it declares:\n{}",
                key.method,
                key.path,
                list_operations(operations)
            )
        })
}

/// The document's operations, one `--operation` argument per line.
fn list_operations(operations: &[OperationSummary]) -> String {
    operations
        .iter()
        .map(|operation| format!("  {} {}", operation.key.method, operation.key.path))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The response's selectable leaves, one `--select` argument per line.
fn list_leaves(leaves: &[CandidateLeaf]) -> String {
    leaves
        .iter()
        .map(|leaf| format!("  {}", leaf.pointer))
        .collect::<Vec<_>>()
        .join("\n")
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
