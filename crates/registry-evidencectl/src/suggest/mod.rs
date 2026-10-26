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
pub mod interactive;
pub mod load;
pub mod sample;

// The reading of an OpenAPI document is the authoring library's, and the stages
// keep the names they had here so every sibling module below still reaches them
// through `super::`.
pub use registry_evidence_authoring::openapi::{flatten, narrow, openapi, types};

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::ExitCode,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgGroup, Args, Subcommand};
use serde_json::json;

use crate::OutputFormat;
use emit::EmitInputs;
use openapi::Spec;
use types::{
    BoundKind, BoundNeed, BoundValues, CandidateLeaf, Decisions, DraftArtifacts, Observations,
    OperationKey, OperationParameter, OperationSummary, ParameterLocation, Provenance,
    RequestMapping, RequestTarget, ResolvedSchema, SelectorReference, SelectorScalarType,
    SuggestedBound,
};

#[derive(Debug, Subcommand)]
pub enum SourceCommand {
    /// Suggest source configuration from an OpenAPI document.
    Suggest(SuggestArgs),
    /// Generate, inspect, and serve a local synthetic source API.
    #[command(subcommand)]
    Mock(crate::source_mock::MockCommand),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("source")
        .required(true)
        .multiple(false)
        .args(["openapi", "project"])
))]
pub struct SuggestArgs {
    /// OpenAPI 3.0 or 3.1 document for a print-only draft. With a project,
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

    /// Print the candidate pointers the selected operation and response offer
    /// for --select, then stop without drafting.
    #[arg(long, requires = "operation")]
    pub list_pointers: bool,

    /// Sample response JSON file used to suggest bounds. Read only; nothing
    /// from it is copied into any artifact except derived bounds.
    #[arg(long)]
    pub sample: Option<std::path::PathBuf>,

    /// Source identifier for the generated artifacts.
    #[arg(long)]
    pub source_id: Option<String>,

    /// Reviewed source origin to write into a newly created source draft.
    #[arg(long)]
    pub base_url: Option<String>,

    /// Explicit selector-to-request mapping as
    /// ROLE.PROFILE.FIELD=path:NAME, query:NAME, or body:/JSON/POINTER.
    /// Repeat for each distinct request target. Requires an authoring project.
    #[arg(long = "map-selector", value_name = "SELECTOR=TARGET")]
    pub selector_mappings: Vec<String>,

    /// Evidence project directory; the draft is printed when this is absent.
    ///
    /// This command needs an editable project containing evidence.yaml and its
    /// named Function assets.
    #[arg(value_name = "PROJECT")]
    pub project: Option<std::path::PathBuf>,
}

pub fn run(command: SourceCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        SourceCommand::Suggest(args) => suggest(args, format),
        SourceCommand::Mock(command) => crate::source_mock::run(command, format),
    }
}

/// The largest `maxItems` the closed schema subset admits, and therefore the
/// ceiling any page-size-derived suggestion is clamped to.
const MAX_PROJECTED_ITEMS: i64 = 256;

/// The identifier used when an operation's path yields no usable one.
const FALLBACK_SOURCE_ID: &str = "source-a";

/// The advisories one run announces: resolver notes, flattening warnings,
/// bound advisories, and the suggestions a flag-driven run adopts. A human
/// run writes each to standard error as it happens, beside any prompt it
/// explains; a JSON run keeps them for the report's `notes` member, so
/// standard error stays silent.
pub(crate) struct Notes {
    format: OutputFormat,
    collected: Vec<String>,
}

impl Notes {
    pub(crate) fn new(format: OutputFormat) -> Self {
        Self {
            format,
            collected: Vec::new(),
        }
    }

    fn note(&mut self, note: impl std::fmt::Display) {
        match self.format {
            OutputFormat::Human => eprintln!("evidencectl: {note}"),
            OutputFormat::Json => self.collected.push(note.to_string()),
        }
    }
}

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

/// The pipeline state both pointer listing and drafting start from: the
/// loaded document, the chosen operation, its resolved response schema, and
/// the flattened candidate leaves a `--select` pointer may name.
struct ResponseLeaves {
    source: types::SpecSource,
    spec: Spec,
    operation: OperationKey,
    schema: ResolvedSchema,
    leaves: Vec<CandidateLeaf>,
}

/// Whether a run may ask its questions on the terminal. A JSON run never
/// prompts: its caller reads one report, so every answer comes from a flag.
pub(crate) fn prompts_allowed(format: OutputFormat) -> bool {
    format == OutputFormat::Human && interactive::is_interactive()
}

/// Load the document, pick the operation, resolve its response schema, and
/// flatten it into candidate leaves. Both a drafting run and a
/// `--list-pointers` run start here; only the drafting run continues.
fn resolve_response_leaves(args: &SuggestArgs, notes: &mut Notes) -> Result<ResponseLeaves> {
    let source = suggestion_openapi(args)?;
    let spec = load::open(&source)?;
    let operations = spec.operations();
    if operations.is_empty() {
        bail!(
            "{} declares no operation with a JSON response schema; there is nothing to draft from",
            source.display()
        );
    }

    // A run with no terminal to prompt on still gets told what it could have
    // asked for, and each answer is only knowable once the one before it is
    // settled: the operations come from the document, the leaves from the
    // chosen operation's response schema. So the two refusals happen at the two
    // points where the answer exists, not together at the top.
    if args.operation.is_none() && !prompts_allowed(notes.format) {
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
        notes.note(note);
    }
    let schema = resolved.schema;
    let (leaves, warnings) = flatten::candidate_leaves(&schema);
    for warning in &warnings {
        notes.note(warning);
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

    Ok(ResponseLeaves {
        source,
        spec,
        operation,
        schema,
        leaves,
    })
}

/// Run the shared OpenAPI interpretation pipeline without writing output.
/// `source suggest` and `new --openapi` differ only in how they deliver this
/// prepared draft.
pub(crate) fn prepare(args: &SuggestArgs, notes: &mut Notes) -> Result<PreparedSuggestion> {
    let flag_driven = args.operation.is_some() && !args.selection.is_empty();
    let ResponseLeaves {
        source,
        spec,
        operation,
        schema,
        leaves,
    } = resolve_response_leaves(args, notes)?;

    let selection = if args.selection.is_empty() {
        if !prompts_allowed(notes.format) {
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
        notes.note(advisory.message());
    }
    let mut needs = with_page_size_fallback(plan.needs, &spec, &operation)?;

    let resolutions = if flag_driven {
        accept_suggestions(&needs, notes)
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
                notes.note(format!(
                    "naming this source `{derived}`, from the operation path"
                ));
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
        base_url: args
            .base_url
            .as_deref()
            .map(validate_base_url)
            .transpose()?,
        selection: decisions.selection.clone(),
        narrowed,
        needs,
        openapi: source.clone(),
        sample_path: args.sample.clone(),
        project: args.project.clone(),
        request_mappings: plan_request_mappings(args, &spec, &decisions.operation)?,
    };
    let artifacts = emit::draft(&inputs)?;

    Ok(PreparedSuggestion {
        artifacts,
        flag_driven,
    })
}

/// Validate one explicit source origin without resolving or contacting it.
///
/// Evidence source policy admits HTTPS origins and canonical numeric-loopback
/// HTTP for local authoring. Paths, credentials, queries, and fragments are
/// never part of the origin.
fn validate_base_url(raw: &str) -> Result<String> {
    let parsed = url::Url::parse(raw).context("parsing --base-url as an absolute URL")?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        bail!("--base-url must be an origin with no credentials, path, query, or fragment");
    }
    let host = parsed
        .host()
        .ok_or_else(|| anyhow!("--base-url must name one host"))?;
    match parsed.scheme() {
        "https" => {}
        "http" => {
            let ip = match host {
                url::Host::Ipv4(ip) => std::net::IpAddr::V4(ip),
                url::Host::Ipv6(ip) => std::net::IpAddr::V6(ip),
                url::Host::Domain(_) => {
                    bail!("an HTTP --base-url must use a numeric loopback address")
                }
            };
            if !ip.is_loopback() || parsed.port().is_none_or(|port| port == 0) {
                bail!("an HTTP --base-url must use a numeric loopback address and non-zero port");
            }
        }
        _ => bail!("--base-url must use HTTPS or numeric-loopback HTTP"),
    }
    let canonical = parsed.origin().ascii_serialization();
    if raw != canonical {
        bail!("--base-url must use canonical origin spelling `{canonical}`");
    }
    Ok(canonical)
}

fn suggestion_openapi(args: &SuggestArgs) -> Result<types::SpecSource> {
    match (&args.project, &args.openapi) {
        (Some(project), None) => {
            if !project.is_dir() {
                bail!(
                    "authoring project directory {} not found; create it with `evidencectl init` first",
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
            "the project uses its retained source.openapi.yaml; omit --openapi to avoid drafting from a different contract"
        ),
        (None, Some(openapi)) => fetch::spec_source(openapi),
        (None, None) => bail!("pass --openapi <path-or-https-url>, or name the authoring project: `evidencectl source suggest <project>`"),
    }
}

fn plan_request_mappings(
    args: &SuggestArgs,
    spec: &Spec,
    operation: &OperationKey,
) -> Result<Vec<RequestMapping>> {
    if args.selector_mappings.is_empty() {
        return Ok(Vec::new());
    }
    let project_dir = args.project.as_ref().ok_or_else(|| {
        anyhow!("--map-selector requires an authoring PROJECT so selector profiles and types come from evidence.yaml")
    })?;
    let project_path = project_dir.join(registry_evidence_authoring::project::PROJECT_FILE);
    let bytes =
        fs::read(&project_path).with_context(|| format!("reading {}", project_path.display()))?;
    let project = registry_evidence_authoring::project::read_project(
        registry_evidence_authoring::project::PROJECT_FILE,
        &bytes,
    )
    .map_err(|report| anyhow!("the authoring project cannot supply selector mappings: {report}"))?
    .value;
    let assignments = args
        .selector_mappings
        .iter()
        .map(|raw| {
            let (selector, target) = raw.split_once('=').ok_or_else(|| {
                anyhow!("--map-selector must be ROLE.PROFILE.FIELD=path:NAME, query:NAME, or body:/JSON/POINTER")
            })?;
            Ok((raw.as_str(), selector, parse_request_target(target)?))
        })
        .collect::<Result<Vec<_>>>()?;
    let selected_parameters = assignments
        .iter()
        .filter_map(|(_, _, target)| match target {
            RequestTarget::Path(name) => Some((name.clone(), ParameterLocation::Path)),
            RequestTarget::Query(name) => Some((name.clone(), ParameterLocation::Query)),
            RequestTarget::Body(_) => None,
        })
        .collect::<BTreeSet<_>>();
    let body_selected = assignments
        .iter()
        .any(|(_, _, target)| matches!(target, RequestTarget::Body(_)));
    let parameters = spec.operation_parameters_for_targets(operation, &selected_parameters)?;
    let body = spec.request_body_schema_for_mapping(operation, body_selected)?;
    let mut mappings = Vec::new();
    let mut exact = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut role_profiles = BTreeMap::<String, String>::new();

    for (raw, selector_raw, target) in assignments {
        let parts = selector_raw.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            bail!("selector `{selector_raw}` must contain exactly ROLE.PROFILE.FIELD");
        }
        let role = parts[0];
        let profile = parts[1];
        let field = parts[2];
        let role_id = registry_platform_yaml::LocalId::new(role.to_owned())?;
        let profile_id = registry_platform_yaml::LocalId::new(profile.to_owned())?;
        let field_id = registry_platform_yaml::LocalId::new(field.to_owned())?;
        let profile_definition = project
            .selector_profiles
            .get(&profile_id)
            .ok_or_else(|| anyhow!("--map-selector names unknown selector profile `{profile}`"))?;
        let subjects = project
            .assertion_definitions
            .values()
            .flat_map(|definition| &definition.subjects)
            .collect::<Vec<_>>();
        if !subjects.iter().any(|subject| subject.role == role_id) {
            bail!("--map-selector names unknown subject role `{role}`");
        }
        if !subjects
            .iter()
            .any(|subject| subject.role == role_id && subject.selectors.contains(&profile_id))
        {
            bail!("subject role `{role}` does not declare selector profile `{profile}`");
        }
        let selector_field = profile_definition
            .fields
            .get(&field_id)
            .ok_or_else(|| anyhow!("selector profile `{profile}` has no field `{field}`"))?;
        if let Some(previous) = role_profiles.insert(role.to_owned(), profile.to_owned()) {
            if previous != profile {
                bail!("one request cannot require alternative profiles `{previous}` and `{profile}` for role `{role}`");
            }
        }
        let (scalar_type, maximum_bytes) = selector_scalar(selector_field);
        let selector = SelectorReference {
            role: role.to_owned(),
            profile: profile.to_owned(),
            field: field.to_owned(),
            scalar_type,
            maximum_bytes,
        };
        if !exact.insert((selector_raw.to_owned(), target.clone())) {
            bail!("duplicate --map-selector assignment `{raw}`");
        }
        if !targets.insert(target.clone()) {
            bail!(
                "request target `{}` is assigned more than once",
                display_target(&target)
            );
        }
        validate_target(
            &selector,
            selector_field,
            &target,
            operation,
            &parameters,
            body.as_ref(),
        )?;
        mappings.push(RequestMapping { selector, target });
    }
    validate_preparation_bounds(&mappings)?;
    validate_required_inputs(operation, &parameters, body.as_ref(), &mappings)?;
    Ok(mappings)
}

fn selector_scalar(
    field: &registry_evidence_authoring::selector::Field,
) -> (SelectorScalarType, u64) {
    use registry_evidence_authoring::selector::Field;
    match field {
        Field::String { maximum_bytes, .. } => (SelectorScalarType::String, maximum_bytes.get()),
        Field::Date { .. } => (SelectorScalarType::String, 10),
        Field::Uuid { .. } => (SelectorScalarType::String, 36),
        Field::Integer {
            minimum, maximum, ..
        } => (
            SelectorScalarType::Integer,
            minimum.to_string().len().max(maximum.to_string().len()) as u64,
        ),
        Field::Boolean { .. } => (SelectorScalarType::Boolean, 5),
        Field::ControlledCode { maximum_bytes, .. } => {
            (SelectorScalarType::String, maximum_bytes.get())
        }
    }
}

fn parse_request_target(raw: &str) -> Result<RequestTarget> {
    let (channel, value) = raw
        .split_once(':')
        .ok_or_else(|| anyhow!("request target `{raw}` must name path:, query:, or body:"))?;
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("request target `{raw}` has an empty or control-containing name");
    }
    match channel {
        "path" => Ok(RequestTarget::Path(value.to_owned())),
        "query" => Ok(RequestTarget::Query(value.to_owned())),
        "body" => { parse_body_pointer(value)?; Ok(RequestTarget::Body(value.to_owned())) }
        "header" | "cookie" | "auth" | "authentication" => bail!("request target `{channel}:` is unsupported: authentication is target configuration, and generated Functions cannot set headers or cookies"),
        _ => bail!("request target `{raw}` uses unknown channel `{channel}`; use path:, query:, or body:"),
    }
}

fn display_target(target: &RequestTarget) -> String {
    match target {
        RequestTarget::Path(value) => format!("path:{value}"),
        RequestTarget::Query(value) => format!("query:{value}"),
        RequestTarget::Body(value) => format!("body:{value}"),
    }
}

fn validate_target(
    selector: &SelectorReference,
    selector_field: &registry_evidence_authoring::selector::Field,
    target: &RequestTarget,
    operation: &OperationKey,
    parameters: &[OperationParameter],
    body: Option<&types::OperationRequestBody>,
) -> Result<()> {
    let schema = match target {
        RequestTarget::Path(name) => {
            if !operation
                .path
                .split('/')
                .any(|segment| segment == format!("{{{name}}}"))
            {
                bail!(
                    "path parameter `{name}` is not one complete placeholder in {} {}",
                    operation.method,
                    operation.path
                );
            }
            let parameter = find_parameter(parameters, name, ParameterLocation::Path)?;
            validate_parameter_serialization(parameter)?;
            &parameter.schema.0
        }
        RequestTarget::Query(name) => {
            if name.len() > 64 {
                bail!("query parameter `{name}` exceeds the 64-byte request-name ceiling");
            }
            if selector.maximum_bytes > 4096 {
                bail!(
                    "selector `{}.{}.{}` permits {} bytes, exceeding the 4096-byte query-value ceiling; use a narrower reviewed selector profile",
                    selector.role,
                    selector.profile,
                    selector.field,
                    selector.maximum_bytes
                );
            }
            let parameter = find_parameter(parameters, name, ParameterLocation::Query)?;
            validate_parameter_serialization(parameter)?;
            &parameter.schema.0
        }
        RequestTarget::Body(pointer) => {
            if !operation.method.eq_ignore_ascii_case("POST") {
                bail!("body mappings require a POST operation");
            }
            if let Some(segment) = parse_body_pointer(pointer)?
                .into_iter()
                .find(|segment| segment.len() > 16_384)
            {
                bail!(
                    "body target `{pointer}` contains a {}-byte property name, exceeding the 16384-byte prepared-string ceiling",
                    segment.len()
                );
            }
            let body = body.ok_or_else(|| {
                anyhow!(
                    "{} {} declares no application/json request body",
                    operation.method,
                    operation.path
                )
            })?;
            body_pointer_schema(&body.schema.0, pointer)?
        }
    };
    validate_scalar_compatibility(selector, selector_field, schema, target)
}

fn validate_parameter_serialization(parameter: &OperationParameter) -> Result<()> {
    let expected_style = match parameter.location {
        ParameterLocation::Path => "simple",
        ParameterLocation::Query => "form",
        ParameterLocation::Header | ParameterLocation::Cookie => {
            bail!("generated mappings cannot set headers or cookies")
        }
    };
    let actual_style = parameter.style.as_deref().unwrap_or(expected_style);
    if actual_style != expected_style {
        bail!(
            "{} parameter `{}` uses unsupported OpenAPI serialization style `{actual_style}`; scalar {} mappings support only style `{expected_style}`",
            parameter.location.as_str(),
            parameter.name,
            parameter.location.as_str()
        );
    }
    if parameter.allow_reserved {
        bail!(
            "{} parameter `{}` declares `allowReserved: true`, which the fixed request encoder does not support",
            parameter.location.as_str(),
            parameter.name
        );
    }
    Ok(())
}

fn validate_preparation_bounds(mappings: &[RequestMapping]) -> Result<()> {
    let query_count = mappings
        .iter()
        .filter(|mapping| matches!(mapping.target, RequestTarget::Query(_)))
        .count();
    let body_count = mappings
        .iter()
        .filter(|mapping| matches!(mapping.target, RequestTarget::Body(_)))
        .count();
    if query_count > 64 {
        bail!("{query_count} query mappings exceed the 64-pair request ceiling");
    }
    if body_count > 256 {
        bail!("{body_count} body mappings exceed the 256-member JSON collection ceiling");
    }
    // JSON may encode one variable input byte as a six-byte `\u00XX` escape.
    // Fixed names are serialized exactly below. The per-mapping allowance
    // covers punctuation and the fixed RequestParts envelope; this
    // intentionally overestimates rather than admitting a plan the runtime
    // might reject after authorization.
    let mut maximum_normalized_bytes = 256_u64;
    for mapping in mappings {
        match &mapping.target {
            RequestTarget::Path(_) => continue,
            RequestTarget::Query(name) => {
                let encoded_name_bytes = serde_json::to_string(name)?.len() as u64;
                maximum_normalized_bytes = maximum_normalized_bytes
                    .saturating_add(encoded_name_bytes)
                    .saturating_add(mapping.selector.maximum_bytes.saturating_mul(6))
                    .saturating_add(128);
            }
            RequestTarget::Body(pointer) => {
                let encoded_key_bytes = parse_body_pointer(pointer)?
                    .iter()
                    .map(|segment| serde_json::to_string(segment).map(|value| value.len() as u64))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .sum::<u64>();
                maximum_normalized_bytes = maximum_normalized_bytes
                    .saturating_add(encoded_key_bytes)
                    .saturating_add(mapping.selector.maximum_bytes.saturating_mul(6))
                    .saturating_add(128);
            }
        }
    }
    if maximum_normalized_bytes > 65_536 {
        bail!(
            "the mapped request can require {maximum_normalized_bytes} normalized bytes, exceeding the 65536-byte request-parts ceiling; narrow the selector profiles or request shape"
        );
    }
    Ok(())
}

fn find_parameter<'a>(
    parameters: &'a [OperationParameter],
    name: &str,
    location: ParameterLocation,
) -> Result<&'a OperationParameter> {
    parameters
        .iter()
        .find(|parameter| parameter.name == name && parameter.location == location)
        .ok_or_else(|| {
            anyhow!(
                "the selected operation declares no `{name}` {} parameter",
                location.as_str()
            )
        })
}

fn validate_scalar_compatibility(
    selector: &SelectorReference,
    selector_field: &registry_evidence_authoring::selector::Field,
    schema: &serde_json::Value,
    target: &RequestTarget,
) -> Result<()> {
    let expected = match selector.scalar_type {
        SelectorScalarType::String => "string",
        SelectorScalarType::Integer => "integer",
        SelectorScalarType::Boolean => "boolean",
    };
    let compatible = match schema.get("type") {
        Some(serde_json::Value::String(actual)) => actual == expected,
        Some(serde_json::Value::Array(values)) => {
            values.len() == 2
                && values.iter().any(|value| value == expected)
                && values.iter().any(|value| value == "null")
        }
        _ => false,
    };
    if !compatible {
        bail!(
            "selector `{}.{}.{}` has type {expected}, but `{}` does not declare that scalar type",
            selector.role,
            selector.profile,
            selector.field,
            display_target(target)
        );
    }
    if schema.get("readOnly") == Some(&serde_json::Value::Bool(true)) {
        bail!(
            "request target `{}` is readOnly and cannot be populated",
            display_target(target)
        );
    }
    validate_selector_domain(selector, selector_field, schema, target)?;
    Ok(())
}

fn validate_selector_domain(
    selector: &SelectorReference,
    field: &registry_evidence_authoring::selector::Field,
    schema: &serde_json::Value,
    target: &RequestTarget,
) -> Result<()> {
    use registry_evidence_authoring::selector::Field;
    for keyword in [
        "enum",
        "const",
        "$dynamicRef",
        "$recursiveRef",
        "pattern",
        "multipleOf",
        "not",
        "if",
        "then",
        "else",
        "dependentSchemas",
        "dependentRequired",
        "allOf",
        "anyOf",
        "oneOf",
        "unevaluatedProperties",
    ] {
        if schema.get(keyword).is_some() {
            bail!(
                "request target `{}` declares `{keyword}`, so the mapped selector domain cannot be proven compatible without a reviewed Function or narrower selector profile",
                display_target(target)
            );
        }
    }
    let format = schema.get("format").and_then(serde_json::Value::as_str);
    match field {
        Field::String {
            minimum_bytes,
            maximum_bytes,
            ..
        } => {
            if format.is_some() {
                bail!("request target `{}` declares a string format that a general string selector cannot prove", display_target(target));
            }
            validate_string_lengths(
                minimum_bytes.get().div_ceil(4),
                maximum_bytes.get(),
                schema,
                selector,
                target,
            )?;
        }
        Field::ControlledCode { maximum_bytes, .. } => {
            if format.is_some() || schema.get("minLength").is_some() {
                bail!("request target `{}` declares string constraints that a controlled-code selector cannot prove without inspecting governed codelist values", display_target(target));
            }
            validate_string_lengths(0, maximum_bytes.get(), schema, selector, target)?;
        }
        Field::Date { .. } => {
            if format.is_some_and(|value| value != "date") {
                bail!(
                    "date selector `{}.{}.{}` is incompatible with request format `{}`",
                    selector.role,
                    selector.profile,
                    selector.field,
                    format.unwrap_or_default()
                );
            }
            validate_string_lengths(10, 10, schema, selector, target)?;
        }
        Field::Uuid { .. } => {
            if format.is_some_and(|value| value != "uuid") {
                bail!(
                    "UUID selector `{}.{}.{}` is incompatible with request format `{}`",
                    selector.role,
                    selector.profile,
                    selector.field,
                    format.unwrap_or_default()
                );
            }
            validate_string_lengths(36, 36, schema, selector, target)?;
        }
        Field::Integer {
            minimum, maximum, ..
        } => {
            match schema.get("format") {
                None => {}
                Some(serde_json::Value::String(format))
                    if format == "int32"
                        && (*minimum < i32::MIN as i64 || *maximum > i32::MAX as i64) =>
                {
                    bail!(
                        "selector `{}.{}.{}` integer range does not fit request target `{}` format `int32`; use a narrower reviewed selector profile",
                        selector.role,
                        selector.profile,
                        selector.field,
                        display_target(target)
                    );
                }
                Some(serde_json::Value::String(format))
                    if matches!(format.as_str(), "int32" | "int64") => {}
                Some(serde_json::Value::String(format)) => bail!(
                    "request target `{}` declares unsupported integer format `{format}`; supported formats are `int32`, `int64`, or absent",
                    display_target(target)
                ),
                Some(_) => bail!(
                    "request target `{}` declares an unsupported integer format; supported formats are `int32`, `int64`, or absent",
                    display_target(target)
                ),
            }
            validate_integer_bounds(*minimum, *maximum, schema, selector, target)?;
        }
        Field::Boolean { .. } => {
            if format.is_some() {
                bail!(
                    "boolean request target `{}` declares an unsupported format",
                    display_target(target)
                );
            }
        }
    }
    Ok(())
}

fn validate_string_lengths(
    guaranteed_minimum_codepoints: u64,
    maximum_codepoints: u64,
    schema: &serde_json::Value,
    selector: &SelectorReference,
    target: &RequestTarget,
) -> Result<()> {
    let minimum = schema
        .get("minLength")
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                anyhow!(
                    "request target `{}` has a non-integer minLength",
                    display_target(target)
                )
            })
        })
        .transpose()?;
    let maximum = schema
        .get("maxLength")
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                anyhow!(
                    "request target `{}` has a non-integer maxLength",
                    display_target(target)
                )
            })
        })
        .transpose()?;
    if minimum.is_some_and(|minimum| guaranteed_minimum_codepoints < minimum)
        || maximum.is_some_and(|maximum| maximum_codepoints > maximum)
    {
        bail!(
            "selector `{}.{}.{}` byte bounds cannot prove the string length constraints of request target `{}`; use a narrower reviewed selector profile",
            selector.role,
            selector.profile,
            selector.field,
            display_target(target)
        );
    }
    Ok(())
}

fn validate_integer_bounds(
    selector_minimum: i64,
    selector_maximum: i64,
    schema: &serde_json::Value,
    selector: &SelectorReference,
    target: &RequestTarget,
) -> Result<()> {
    let integer = |keyword: &str| -> Result<Option<i64>> {
        schema
            .get(keyword)
            .map(|value| {
                value.as_i64().ok_or_else(|| {
                    anyhow!(
                        "request target `{}` has a non-integer `{keyword}`",
                        display_target(target)
                    )
                })
            })
            .transpose()
    };
    let minimum = integer("minimum")?;
    let maximum = integer("maximum")?;
    let exclusive_minimum = integer("exclusiveMinimum")?;
    let exclusive_maximum = integer("exclusiveMaximum")?;
    if schema
        .get("exclusiveMinimum")
        .is_some_and(serde_json::Value::is_boolean)
        || schema
            .get("exclusiveMaximum")
            .is_some_and(serde_json::Value::is_boolean)
        || minimum.is_some_and(|bound| selector_minimum < bound)
        || maximum.is_some_and(|bound| selector_maximum > bound)
        || exclusive_minimum.is_some_and(|bound| selector_minimum <= bound)
        || exclusive_maximum.is_some_and(|bound| selector_maximum >= bound)
    {
        bail!(
            "selector `{}.{}.{}` integer range is wider than request target `{}`; use a narrower reviewed selector profile",
            selector.role,
            selector.profile,
            selector.field,
            display_target(target)
        );
    }
    Ok(())
}

fn validate_required_inputs(
    operation: &OperationKey,
    parameters: &[OperationParameter],
    body: Option<&types::OperationRequestBody>,
    mappings: &[RequestMapping],
) -> Result<()> {
    for parameter in parameters.iter().filter(|parameter| parameter.required) {
        let target = match parameter.location {
            ParameterLocation::Path => RequestTarget::Path(parameter.name.clone()),
            ParameterLocation::Query => RequestTarget::Query(parameter.name.clone()),
            ParameterLocation::Header | ParameterLocation::Cookie => bail!("{} {} requires {} parameter `{}`; generated mappings cannot set headers or cookies", operation.method, operation.path, parameter.location.as_str(), parameter.name),
        };
        if !mappings.iter().any(|mapping| mapping.target == target) {
            bail!(
                "required request input `{}` has no --map-selector assignment",
                display_target(&target)
            );
        }
    }
    if let Some(body) = body {
        let mapped = mappings
            .iter()
            .filter_map(|mapping| {
                if let RequestTarget::Body(pointer) = &mapping.target {
                    Some(pointer.as_str())
                } else {
                    None
                }
            })
            .collect::<BTreeSet<_>>();
        if body.required && mapped.is_empty() {
            bail!("the required application/json request body has no --map-selector assignment");
        }
        if body.required || !mapped.is_empty() {
            let mut required = BTreeSet::new();
            collect_materialized_body_requirements(&body.schema.0, &mapped, &mut required)?;
            for pointer in required {
                if !mapped.contains(pointer.as_str()) {
                    bail!(
                        "required request input `body:{pointer}` has no --map-selector assignment"
                    );
                }
            }
        }
    }
    Ok(())
}

fn collect_materialized_body_requirements(
    schema: &serde_json::Value,
    mapped: &BTreeSet<&str>,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    collect_required_body_leaves(schema, "", out)?;
    for pointer in mapped {
        let segments = parse_body_pointer(pointer)?;
        let mut node = schema;
        let mut object_pointer = String::new();
        for segment in segments.iter().take(segments.len().saturating_sub(1)) {
            require_closed_object(
                node,
                if object_pointer.is_empty() {
                    "(root)"
                } else {
                    &object_pointer
                },
            )?;
            node = node["properties"].get(segment.as_str()).ok_or_else(|| {
                anyhow!("body target `{pointer}` names no declared request property")
            })?;
            object_pointer.push('/');
            object_pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
            let mut object_required = BTreeSet::new();
            collect_required_body_leaves(node, &object_pointer, &mut object_required)?;
            out.extend(object_required);
        }
    }
    Ok(())
}

fn parse_body_pointer(pointer: &str) -> Result<Vec<String>> {
    if !pointer.starts_with('/') || pointer == "/" {
        bail!("body target `{pointer}` must be a non-root RFC 6901 pointer");
    }
    let mut out = Vec::new();
    for encoded in pointer[1..].split('/') {
        if encoded.is_empty() || encoded == "*" {
            bail!("body target `{pointer}` must contain object-property segments only");
        }
        let mut decoded = String::new();
        let mut chars = encoded.chars();
        while let Some(character) = chars.next() {
            if character != '~' {
                decoded.push(character);
                continue;
            }
            match chars.next() {
                Some('0') => decoded.push('~'),
                Some('1') => decoded.push('/'),
                _ => bail!("body target `{pointer}` is not a valid RFC 6901 pointer"),
            }
        }
        out.push(decoded);
    }
    if out.len() > 31 {
        bail!("body target `{pointer}` exceeds the generated JSON depth ceiling");
    }
    Ok(out)
}

fn body_pointer_schema<'a>(
    schema: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a serde_json::Value> {
    let segments = parse_body_pointer(pointer)?;
    let mut node = schema;
    for segment in &segments {
        require_closed_object(node, pointer)?;
        node = node
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .and_then(|properties| properties.get(segment))
            .ok_or_else(|| anyhow!("body target `{pointer}` names no declared request property"))?;
    }
    if !matches!(
        node.get("type").and_then(serde_json::Value::as_str),
        Some("string" | "integer" | "boolean")
    ) || node.get("oneOf").is_some()
        || node.get("anyOf").is_some()
        || node.get("allOf").is_some()
    {
        bail!("body target `{pointer}` must name one scalar in a simple closed JSON object");
    }
    Ok(node)
}

fn require_closed_object(schema: &serde_json::Value, pointer: &str) -> Result<()> {
    if schema.get("type").and_then(serde_json::Value::as_str) != Some("object")
        || schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .is_none()
        || schema.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
        || schema.get("oneOf").is_some()
        || schema.get("anyOf").is_some()
        || schema.get("allOf").is_some()
    {
        bail!("body target `{pointer}` requires a simple closed object schema with `additionalProperties: false`; arrays and polymorphism are unsupported");
    }
    if schema.get("readOnly") == Some(&serde_json::Value::Bool(true)) {
        bail!("body target `{pointer}` is readOnly and cannot be populated");
    }
    for keyword in [
        "enum",
        "const",
        "minProperties",
        "maxProperties",
        "$dynamicRef",
        "$recursiveRef",
        "propertyNames",
        "patternProperties",
        "dependentRequired",
        "dependentSchemas",
        "unevaluatedProperties",
        "not",
        "if",
        "then",
        "else",
    ] {
        if schema.get(keyword).is_some() {
            bail!(
                "body target `{pointer}` uses unsupported object constraint `{keyword}`; generated bodies support only explicit closed properties and required scalar leaves"
            );
        }
    }
    Ok(())
}

fn collect_required_body_leaves(
    schema: &serde_json::Value,
    pointer: &str,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    require_closed_object(
        schema,
        if pointer.is_empty() {
            "(root)"
        } else {
            pointer
        },
    )?;
    let properties = schema["properties"]
        .as_object()
        .expect("validated properties");
    let required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten();
    for value in required {
        let name = value
            .as_str()
            .ok_or_else(|| anyhow!("request-body `required` entries must be strings"))?;
        let child = properties
            .get(name)
            .ok_or_else(|| anyhow!("request-body required property `{name}` has no schema"))?;
        let child_pointer = format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1"));
        match child.get("type").and_then(serde_json::Value::as_str) {
            Some("object") => {
                let before = out.len();
                collect_required_body_leaves(child, &child_pointer, out)?;
                if out.len() == before {
                    bail!("required request object `body:{child_pointer}` has no required scalar leaves; generated empty-object bindings are unsupported");
                }
            }
            Some("string" | "integer" | "boolean") => {
                out.insert(child_pointer);
            }
            _ => bail!("required request input `body:{child_pointer}` is not a supported scalar or closed object"),
        }
    }
    Ok(())
}

fn suggest(args: SuggestArgs, format: OutputFormat) -> Result<ExitCode> {
    let mut notes = Notes::new(format);
    if args.list_pointers {
        return list_pointers(&args, &mut notes);
    }
    let prepared = prepare(&args, &mut notes)?;
    let artifacts = prepared.artifacts;

    let delivery = match &args.project {
        Some(project) => {
            deliver_into_project(project, &artifacts, prepared.flag_driven, &mut notes)?
        }
        None => {
            if format == OutputFormat::Human {
                print_draft(&artifacts);
            }
            Delivery::Printed
        }
    };
    let (status, written) = match delivery {
        Delivery::Written(written) => ("complete", written),
        Delivery::Printed => ("complete", Vec::new()),
        Delivery::Declined => ("declined", Vec::new()),
    };

    match format {
        OutputFormat::Human => {
            println!("{}", artifacts.report);
            println!("Reproduce this run with:");
            println!("  {}", artifacts.equivalent_command);
        }
        OutputFormat::Json => crate::print_report(&crate::report::success(
            "source suggest",
            status,
            json!({
                "sourceId": artifacts.source_id,
                "files": written,
                "report": artifacts.report,
                "equivalentCommand": artifacts.equivalent_command,
                "notes": notes.collected,
            }),
        )),
    }
    Ok(ExitCode::SUCCESS)
}

/// Print the candidate pointers of the selected operation and response, the
/// same set `--select` accepts, and stop without drafting anything.
fn list_pointers(args: &SuggestArgs, notes: &mut Notes) -> Result<ExitCode> {
    let leaves = resolve_response_leaves(args, notes)?.leaves;
    match notes.format {
        OutputFormat::Human => println!("{}", list_leaves(&leaves)),
        OutputFormat::Json => crate::print_report(&crate::command_report(
            "source suggest",
            json!({
                "pointers": leaves.iter().map(|leaf| leaf.pointer.clone()).collect::<Vec<_>>(),
                "notes": notes.collected,
            }),
        )),
    }
    Ok(ExitCode::SUCCESS)
}

/// What became of a drafted source.
enum Delivery {
    /// The draft was written into the authoring project; these paths.
    Written(Vec<std::path::PathBuf>),
    /// No project was named, so the draft was printed instead.
    Printed,
    /// The operator declined the write at the confirmation prompt.
    Declined,
}

/// Write the draft into an OpenAPI authoring project, then report what happened.
///
/// The write refuses to replace anything that already exists, so a repeated
/// run never silently discards an edited draft. Verification runs only when
/// the operator supplied a runtime binary to run it with. Returns the paths
/// that were written, for the report of the run.
fn deliver_into_project(
    project: &Path,
    artifacts: &DraftArtifacts,
    flag_driven: bool,
    notes: &mut Notes,
) -> Result<Delivery> {
    let format = notes.format;
    if !project.is_dir() {
        bail!(
            "authoring project directory {} not found; create one with `evidencectl init` first",
            project.display()
        );
    }
    if !flag_driven
        && !interactive::confirm_write(&project.display().to_string(), &artifacts.files)?
    {
        notes.note("nothing was written; the draft is printed below instead.");
        if format == OutputFormat::Human {
            print_draft(artifacts);
        }
        return Ok(Delivery::Declined);
    }

    let written = emit::write_into_authoring_project(project, artifacts)?;
    if format == OutputFormat::Human {
        for path in &written {
            println!("wrote {}", path.display());
        }
        println!(
            "not verified: complete or update the AssertionDefinitions that acquire this Source, \
             then run `evidencectl check {}`. Add or update authored fixtures for the affected \
             definitions, then run `evidencectl test {}`.",
            project.display(),
            project.display()
        );
    }
    Ok(Delivery::Written(written))
}

/// Print every drafted file, and the pasteable source block, to stdout.
fn print_draft(artifacts: &DraftArtifacts) {
    for file in &artifacts.files {
        print_block(&file.bundle_relative_path, &file.contents);
    }
    print_block(
        "the block to merge at the document root in evidence.yaml",
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
fn accept_suggestions(
    needs: &[BoundNeed],
    notes: &mut Notes,
) -> BTreeMap<(String, BoundKind), BoundValues> {
    let mut resolutions = BTreeMap::new();
    for need in needs {
        match &need.suggestion {
            Some(suggestion) => {
                let derivation = emit::provenance_label(&suggestion.provenance)
                    .map_or_else(String::new, |label| format!(", derived from {label}"));
                let note = emit::review_note(&need.kind, &suggestion.provenance)
                    .map_or_else(String::new, |note| format!(" ({note})"));
                notes.note(format!(
                    "adopting {} for `{}`{derivation}{note}",
                    describe_bound(&suggestion.values),
                    narrow::display_pointer(&need.pointer),
                ));
                resolutions.insert(
                    (need.pointer.clone(), need.kind.clone()),
                    suggestion.values.clone(),
                );
            }
            None => notes.note(format!(
                "nothing implies {} for `{}`; left as a TODO in the draft",
                need.kind.label(),
                narrow::display_pointer(&need.pointer)
            )),
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
            return Err(UnknownSelectionPointer {
                pointer: pointer.clone(),
                available: leaves.iter().map(|leaf| leaf.pointer.clone()).collect(),
            }
            .into());
        }
    }
    Ok(())
}

/// A `--select` pointer that names nothing in the selected response schema,
/// carrying the pointers that were available so each output format can list
/// them: the human refusal as it has always read, and a machine-readable
/// `availablePointers` member in the JSON diagnostic.
#[derive(Debug)]
pub(crate) struct UnknownSelectionPointer {
    pointer: String,
    available: Vec<String>,
}

impl UnknownSelectionPointer {
    pub(crate) fn pointer(&self) -> &str {
        &self.pointer
    }

    pub(crate) fn available_pointers(&self) -> &[String] {
        &self.available
    }
}

impl std::fmt::Display for UnknownSelectionPointer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let available = self
            .available
            .iter()
            .map(|pointer| format!("  {pointer}"))
            .collect::<Vec<_>>()
            .join("\n");
        write!(
            formatter,
            "`--select {}` names nothing in this response schema; it offers:\n{available}",
            self.pointer
        )
    }
}

impl std::error::Error for UnknownSelectionPointer {}

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
    // A pointer listing asks nothing else, so `--select` is missing only for
    // a run that means to draft.
    if args.selection.is_empty() && !args.list_pointers {
        missing.push("--select");
    }
    format!(
        "this run has no terminal to prompt on, so it needs {} on the command line; \
         run it in a terminal to choose interactively, or pass the missing flags \
         (an interactive run prints the equivalent fully-flagged command)",
        missing.join(" and ")
    )
}

#[cfg(test)]
mod tests {
    use super::validate_base_url;

    #[test]
    fn json_runs_never_prompt() {
        assert!(!super::prompts_allowed(crate::OutputFormat::Json));
    }

    #[test]
    fn explicit_source_origins_accept_https_and_numeric_loopback_http() {
        assert_eq!(
            validate_base_url("https://registry.example.invalid").expect("HTTPS origin"),
            "https://registry.example.invalid"
        );
        assert_eq!(
            validate_base_url("http://127.0.0.1:4010").expect("loopback origin"),
            "http://127.0.0.1:4010"
        );
        assert_eq!(
            validate_base_url("http://[::1]:4010").expect("IPv6 loopback origin"),
            "http://[::1]:4010"
        );
    }

    #[test]
    fn explicit_source_origins_refuse_ambiguous_or_non_loopback_http() {
        for raw in [
            "http://localhost:4010",
            "http://192.0.2.1:4010",
            "http://127.0.0.1:0",
            "http://127.0.0.1:4010/path",
            "http://user@127.0.0.1:4010",
            "https://registry.example.invalid/extra",
            "https://registry.example.invalid?mode=mock",
        ] {
            assert!(validate_base_url(raw).is_err(), "accepted {raw}");
        }
    }
}
