//! The interactive front-end of `evidencectl source suggest`.
//!
//! Every prompt the tool can raise lives in this module, so the pipeline in
//! `mod.rs` and the stages beneath it stay promptless and deterministic: the
//! front-end only turns the pipeline's own findings into questions and turns
//! the answers back into the same values a fully-flagged run would have
//! supplied. Nothing here derives a bound, validates a schema, or writes a
//! file.
//!
//! A prompt is only ever raised when [`is_interactive`] holds, which requires
//! both standard input and standard output to be terminals. A run that is
//! piped, redirected, or driven by CI therefore fails with a message naming
//! the flags it needs rather than blocking on a question nobody can answer.

use std::{collections::BTreeMap, io::IsTerminal};

use anyhow::{anyhow, Result};
use inquire::{
    error::InquireError,
    validator::{MinLengthValidator, Validation},
    Confirm, CustomUserError, MultiSelect, Select, Text,
};

use super::types::{
    BoundKind, BoundNeed, BoundValues, CandidateLeaf, DraftFile, OperationKey, OperationSummary,
    Provenance,
};

/// The longest leaf description shown beside a candidate pointer. A schema
/// description can run to paragraphs; the list stays readable instead.
const DESCRIPTION_BUDGET: usize = 60;

/// True when both standard input and standard output are terminals, which is
/// what an inquire prompt needs to draw itself and read an answer.
pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Ask which operation the source calls.
pub fn choose_operation(operations: &[OperationSummary]) -> Result<OperationKey> {
    let labels: Vec<String> = operations.iter().map(operation_label).collect();
    let chosen = Select::new("Which operation does this source call?", labels)
        .with_help_message("type to filter, arrows to move, enter to select")
        .raw_prompt()
        .map_err(prompt_error)?;
    Ok(operations[chosen.index].key.clone())
}

/// Ask which response leaves the projection allowlist should carry.
///
/// Nothing is preselected: the projection is the data-minimization boundary,
/// so every field is chosen deliberately. At least one leaf is required,
/// because a source with an empty projection reads nothing.
pub fn choose_leaves(leaves: &[CandidateLeaf]) -> Result<Vec<String>> {
    let labels: Vec<String> = leaves.iter().map(leaf_label).collect();
    let chosen = MultiSelect::new("Which response fields does this source need?", labels)
        .with_validator(MinLengthValidator::new(1))
        .with_help_message(
            "space to toggle, enter to confirm; select the smallest set the derivation needs",
        )
        .raw_prompt()
        .map_err(prompt_error)?;
    Ok(chosen
        .into_iter()
        .map(|option| leaves[option.index].pointer.clone())
        .collect())
}

/// Ask for every bound the closed subset demands and the specification does
/// not state.
///
/// A derived suggestion is offered as an editable value with its provenance in
/// the help line, never adopted silently. Clearing the value skips the
/// decision, which leaves an explicit TODO in the draft that `evidence check`
/// rejects until a human resolves it.
pub fn resolve_bounds(needs: &[BoundNeed]) -> Result<BTreeMap<(String, BoundKind), BoundValues>> {
    let mut resolutions = BTreeMap::new();
    for need in needs {
        if let Some(values) = ask_bound(need)? {
            resolutions.insert((need.pointer.clone(), need.kind.clone()), values);
        }
    }
    Ok(resolutions)
}

fn ask_bound(need: &BoundNeed) -> Result<Option<BoundValues>> {
    let message = format!("{} for {}", need.kind.label(), need.pointer);
    let help = match &need.suggestion {
        Some(suggestion) => format!(
            "suggested from {}{}; edit it, or clear the line to leave a TODO for review",
            provenance_phrase(&suggestion.provenance),
            super::emit::review_note(&need.kind, &suggestion.provenance)
                .map_or_else(String::new, |note| format!(" ({note})"))
        ),
        None => format!(
            "nothing in the specification or the sample implies one; enter {} or leave it empty to leave a TODO",
            input_shape(&need.kind)
        ),
    };
    let initial = need
        .suggestion
        .as_ref()
        .map(|suggestion| render_bound(&suggestion.values));

    let kind = need.kind.clone();
    let mut prompt = Text::new(&message).with_help_message(&help).with_validator(
        move |input: &str| -> Result<Validation, CustomUserError> {
            Ok(match parse_bound(&kind, input) {
                Ok(_) => Validation::Valid,
                Err(message) => Validation::Invalid(message.into()),
            })
        },
    );
    if let Some(initial) = &initial {
        prompt = prompt.with_initial_value(initial);
    }

    let answer = prompt.prompt().map_err(prompt_error)?;
    parse_bound(&need.kind, &answer).map_err(|message| anyhow!("{message}"))
}

/// Ask for the source identifier, offering `default_id` as an editable value.
pub fn choose_source_id(default_id: &str) -> Result<String> {
    let answer = Text::new("Identifier for this source?")
        .with_help_message("names the generated files and the `sources.<id>` key")
        .with_initial_value(default_id)
        .with_validator(|input: &str| -> Result<Validation, CustomUserError> {
            Ok(match super::validate_source_id(input) {
                Ok(_) => Validation::Valid,
                Err(error) => Validation::Invalid(format!("{error}").into()),
            })
        })
        .prompt()
        .map_err(prompt_error)?;
    super::validate_source_id(&answer)
}

/// Show the files a draft would create and ask whether to write them.
pub fn confirm_write(project_display: &str, files: &[DraftFile]) -> Result<bool> {
    eprintln!("These files will be written into {project_display}:");
    for file in files {
        eprintln!("  bundle/{}", file.bundle_relative_path);
    }
    Confirm::new("Write them?")
        .with_default(true)
        .with_help_message("nothing existing is ever overwritten; a collision stops the write")
        .prompt()
        .map_err(prompt_error)
}

/// `METHOD /path — summary`, the one-line form an operation is chosen by.
fn operation_label(operation: &OperationSummary) -> String {
    let mut label = format!("{} {}", operation.key.method, operation.key.path);
    if let Some(summary) = &operation.summary {
        label.push_str(" — ");
        label.push_str(&truncate(summary));
    }
    label
}

/// `pointer  type (nullable) — description`, the one-line form a leaf is
/// chosen by.
fn leaf_label(leaf: &CandidateLeaf) -> String {
    let mut label = format!("{}  {}", leaf.pointer, leaf.type_label);
    if leaf.nullable {
        label.push_str(" (nullable)");
    }
    if let Some(description) = &leaf.description {
        label.push_str(" — ");
        label.push_str(&truncate(description));
    }
    label
}

/// One line of `text`, cut to the description budget on a character boundary.
fn truncate(text: &str) -> String {
    let single_line = text.split('\n').next().unwrap_or(text).trim();
    if single_line.chars().count() <= DESCRIPTION_BUDGET {
        return single_line.to_owned();
    }
    let kept: String = single_line.chars().take(DESCRIPTION_BUDGET).collect();
    format!("{kept}…")
}

fn provenance_phrase(provenance: &Provenance) -> &'static str {
    match provenance {
        Provenance::Spec => "the OpenAPI schema",
        Provenance::Format => "the declared format",
        Provenance::Sample => "the sample response, widened",
        Provenance::PageSize => "a page-size parameter in the spec",
        Provenance::Operator => "your own answer",
    }
}

/// The text form of a bound value, which is also the editable initial value
/// of its prompt.
fn render_bound(values: &BoundValues) -> String {
    match values {
        BoundValues::MaxItems(maximum) => maximum.to_string(),
        BoundValues::IntegerRange { minimum, maximum } => format!("{minimum} {maximum}"),
        BoundValues::StringLength {
            min_length,
            max_length,
        } => format!("{min_length} {max_length}"),
    }
}

/// What the operator is asked to type for a bound with no suggestion.
fn input_shape(kind: &BoundKind) -> &'static str {
    match kind {
        BoundKind::ArrayMaxItems => "a maximum item count",
        BoundKind::IntegerRange => "a minimum and a maximum, separated by a space",
        BoundKind::StringLength => "a minimum and a maximum length, separated by a space",
    }
}

/// Parses one bound answer. An empty answer is a deliberate skip, not an
/// error: it leaves the bound unresolved and the draft rejected until a human
/// supplies it. The message in `Err` is shown inline by the prompt validator,
/// so the operator can correct the answer without restarting.
fn parse_bound(kind: &BoundKind, input: &str) -> std::result::Result<Option<BoundValues>, String> {
    let fields: Vec<&str> = input
        .split([' ', ',', '\t'])
        .filter(|field| !field.is_empty())
        .collect();
    if fields.is_empty() {
        return Ok(None);
    }
    match kind {
        BoundKind::ArrayMaxItems => {
            let [maximum] = fields[..] else {
                return Err("enter one maximum item count".to_owned());
            };
            let maximum = parse_unsigned(maximum)?;
            Ok(Some(BoundValues::MaxItems(maximum)))
        }
        BoundKind::IntegerRange => {
            let [minimum, maximum] = fields[..] else {
                return Err("enter a minimum and a maximum, separated by a space".to_owned());
            };
            let minimum = parse_signed(minimum)?;
            let maximum = parse_signed(maximum)?;
            if minimum > maximum {
                return Err("the minimum must not exceed the maximum".to_owned());
            }
            Ok(Some(BoundValues::IntegerRange { minimum, maximum }))
        }
        BoundKind::StringLength => {
            let [minimum, maximum] = fields[..] else {
                return Err("enter a minimum and a maximum length, separated by a space".to_owned());
            };
            let min_length = parse_unsigned(minimum)?;
            let max_length = parse_unsigned(maximum)?;
            if min_length > max_length {
                return Err("the minimum length must not exceed the maximum length".to_owned());
            }
            Ok(Some(BoundValues::StringLength {
                min_length,
                max_length,
            }))
        }
    }
}

fn parse_unsigned(field: &str) -> std::result::Result<u64, String> {
    field
        .parse::<u64>()
        .map_err(|_| format!("`{field}` is not a whole number of zero or more"))
}

fn parse_signed(field: &str) -> std::result::Result<i64, String> {
    field
        .parse::<i64>()
        .map_err(|_| format!("`{field}` is not a whole number"))
}

/// Turns an inquire failure into an actionable error. Cancelling a prompt is
/// an ordinary outcome of an interactive session, not a defect, so it reports
/// what did not happen rather than a library error.
fn prompt_error(error: InquireError) -> anyhow::Error {
    match error {
        InquireError::OperationCanceled | InquireError::OperationInterrupted => {
            anyhow!("cancelled at a prompt; nothing was written")
        }
        InquireError::NotTTY => {
            anyhow!("this run has no terminal to prompt on; pass --operation and --select instead")
        }
        other => anyhow::Error::new(other).context("reading a prompt answer"),
    }
}
