// SPDX-License-Identifier: Apache-2.0
//! Bounded, explicitly initiated examples against this project's owned dev instance.
use super::{config, private, Clients, State, Status, MAX_BYTES};
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use registry_breg_client::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Args)]
pub struct ExamplesArgs {
    #[command(subcommand)]
    action: ExamplesAction,
}
#[derive(Debug, Subcommand)]
enum ExamplesAction {
    /// Describe fixed local scenarios without starting services or creating credentials.
    List {
        /// Authored project containing examples/scenarios.json.
        #[arg(default_value = ".")]
        project: PathBuf,
    },
    /// Run or resume an example against the project's ready owned development instance.
    Run(RunArgs),
}
#[derive(Debug, Args)]
struct RunArgs {
    /// Fixed teaching scenario declared by this project.
    #[arg(value_parser = ["starter-data", "first-record", "reviewed-change"])]
    scenario: String,
    /// Authored project whose owned local development instance is ready.
    #[arg(default_value = ".")]
    project: PathBuf,
    /// Editable JSON input (default: the scenario's declared examples input file).
    #[arg(long)]
    input: Option<PathBuf>,
    /// Resume exactly this retained execution attempt.
    #[arg(long, conflicts_with = "new_attempt")]
    attempt: Option<uuid::Uuid>,
    /// Start a distinct attempt, with new idempotency keys and ordinary uniqueness checks.
    #[arg(long)]
    new_attempt: bool,
    /// Completed first-record attempt whose captured UUID is the review target.
    #[arg(long)]
    from_attempt: Option<uuid::Uuid>,
    /// Reviewed changes advance one explicit stage; approval never applies a change.
    #[arg(long)]
    step: Option<ReviewStep>,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReviewStep {
    Submit,
    Inspect,
    Approve,
    Reject,
    Apply,
    History,
}
impl ReviewStep {
    fn id(self) -> &'static str {
        match self {
            Self::Submit => "submit",
            Self::Inspect => "inspect",
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Apply => "apply",
            Self::History => "history",
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Catalogue {
    version: u8,
    scenarios: Vec<Scenario>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Scenario {
    id: String,
    description: String,
    input: String,
    steps: Vec<Step>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step {
    id: String,
    operation: Operation,
    entity: String,
    client: String,
    access_profile: String,
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    capture: Option<String>,
    #[serde(default)]
    record: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Operation {
    Create,
    Get,
    Submit,
    Approve,
    Reject,
    Apply,
    History,
}
impl Operation {
    fn metadata_kind(self) -> BRegOperationKind {
        match self {
            Self::Create => BRegOperationKind::Create,
            Self::Get => BRegOperationKind::Get,
            Self::Submit => BRegOperationKind::SubmitRequest,
            Self::Approve => BRegOperationKind::ApproveRequest,
            Self::Reject => BRegOperationKind::RejectRequest,
            Self::Apply => BRegOperationKind::ApplyRequest,
            Self::History => BRegOperationKind::Revisions,
        }
    }
    fn lifecycle(self) -> Option<BRegLifecycleOperation> {
        match self {
            Self::Submit => Some(BRegLifecycleOperation::SubmitRequest),
            Self::Approve => Some(BRegLifecycleOperation::ApproveRequest),
            Self::Reject => Some(BRegLifecycleOperation::RejectRequest),
            Self::Apply => Some(BRegLifecycleOperation::ApplyRequest),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binding {
    source: String,
    package: String,
    database: String,
    clients: String,
    scenario: String,
    input: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capture {
    entity: String,
    id: uuid::Uuid,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Attempt {
    version: u8,
    id: uuid::Uuid,
    scenario: String,
    binding: Binding,
    from_attempt: Option<uuid::Uuid>,
    captures: BTreeMap<String, Capture>,
    completed: BTreeMap<String, Value>,
    pending: Option<Pending>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    step: String,
    capsule: Value,
}
impl Attempt {
    fn save(&self, directory: &Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)?;
        if bytes.len() as u64 > MAX_BYTES {
            bail!("example attempt exceeds its retained-state size bound; no further mutation was sent");
        }
        private::replace(&directory.join(format!("{}.json", self.id)), &bytes)
    }
}

fn read_source(path: &Path) -> Result<Vec<u8>> {
    crate::read_bounded_source_file(path, "examples.input", "examples", 1024 * 1024)
        .map_err(|_| anyhow::anyhow!("examples require bounded ordinary files (maximum 1 MiB)"))
}
fn catalogue(project: &Path) -> Result<(Catalogue, Vec<u8>)> {
    let bytes = read_source(&project.join("examples/scenarios.json"))?;
    let catalogue: Catalogue =
        serde_json::from_slice(&bytes).context("examples/scenarios.json must match examples v1")?;
    if catalogue.version != 1 || catalogue.scenarios.is_empty() || catalogue.scenarios.len() > 3 {
        bail!("examples v1 requires 1..3 fixed scenarios");
    }
    let mut ids = BTreeSet::new();
    for scenario in &catalogue.scenarios {
        if !["starter-data", "first-record", "reviewed-change"].contains(&scenario.id.as_str())
            || !ids.insert(&scenario.id)
            || scenario.description.is_empty()
            || scenario.description.len() > 1024
            || scenario.steps.is_empty()
            || scenario.steps.len() > 100
        {
            bail!("examples require unique fixed scenario IDs, descriptions and 1..100 steps");
        }
        let path = Path::new(&scenario.input);
        if !scenario.input.starts_with("examples/")
            || path
                .components()
                .any(|p| !matches!(p, std::path::Component::Normal(_)))
        {
            bail!("scenario input must be a relative file under examples/");
        }
        let mut steps = BTreeSet::new();
        for step in &scenario.steps {
            if [&step.id, &step.entity, &step.client, &step.access_profile]
                .iter()
                .any(|v| !config::identifier(v))
                || !steps.insert(&step.id)
            {
                bail!(
                    "steps require unique bounded IDs and explicit entity/client/profile bindings"
                );
            }
            if step.operation == Operation::Create {
                if step.input.as_deref().is_none_or(|v| !config::identifier(v))
                    || step
                        .capture
                        .as_deref()
                        .is_none_or(|v| !config::identifier(v))
                    || step.record.is_some()
                {
                    bail!("create steps require input and capture, and no record alias");
                }
            } else if step
                .record
                .as_deref()
                .is_none_or(|v| !config::identifier(v))
                || step.input.is_some()
                || step.capture.is_some()
            {
                bail!("read and lifecycle steps require a record alias and no input or capture");
            }
            if scenario.id != "reviewed-change"
                && !matches!(step.operation, Operation::Create | Operation::Get)
            {
                bail!("population and first-record examples permit only creates and reads");
            }
        }
        if scenario.id == "first-record"
            && (scenario.steps.len() != 2
                || scenario.steps[0].operation != Operation::Create
                || scenario.steps[1].operation != Operation::Get)
        {
            bail!("first-record must create one record and retrieve its returned UUID");
        }
        if scenario.id == "reviewed-change" {
            for (id, operation) in [
                ("draft", Operation::Create),
                ("submit", Operation::Submit),
                ("inspect", Operation::Get),
                ("approve", Operation::Approve),
                ("reject", Operation::Reject),
                ("apply", Operation::Apply),
                ("history", Operation::History),
            ] {
                if !scenario
                    .steps
                    .iter()
                    .any(|s| s.id == id && s.operation == operation)
                {
                    bail!("reviewed-change requires draft, submit, inspect, approve, reject, apply and history steps");
                }
            }
            if scenario.steps.len() != 7 {
                bail!("reviewed-change contains exactly seven fixed steps");
            }
        }
    }
    Ok((catalogue, bytes))
}

/// Captures carry their declared entity; metadata validates each reference field.
fn resolve(value: &Value, captures: &BTreeMap<String, Capture>, _depth: usize) -> Result<Value> {
    Ok(
        registry_breg::example_references::resolve_record_references(value, |alias| {
            captures.get(alias).map(|capture| capture.id.to_string())
        })?,
    )
}

fn validate_reference_fields(
    step: &Step,
    metadata: &BRegMetadata,
    input: &Value,
    captures: &BTreeMap<String, Capture>,
) -> Result<()> {
    let operation = metadata
        .operations()
        .iter()
        .find(|o| {
            o.source_entity() == step.entity
                && o.access_profile() == step.access_profile
                && *o.kind() == BRegOperationKind::Create
        })
        .context("create operation missing")?;
    let data = input
        .get(step.input.as_deref().context("input key missing")?)
        .and_then(Value::as_object)
        .context("create payload must be an object")?;
    for (name, value) in data {
        if let Some(alias) = registry_breg::example_references::record_reference(value)? {
            let field = operation
                .fields()
                .iter()
                .find(|f| f.api_name() == name)
                .context("reference field is not advertised")?;
            let target = field
                .reference_target_entity()
                .context("logical reference requires an advertised reference target entity")?;
            if captures.get(alias).is_none_or(|c| c.entity != target) {
                bail!("reference alias is missing or belongs to the wrong target entity");
            }
        } else {
            // Only direct reference fields advertise a target entity. Keep
            // ordinary structured values inert rather than resolving untyped
            // nested aliases through the shared fixture grammar.
            registry_breg::example_references::resolve_record_references(value, |_| None)
                .context("nested logical references require a direct advertised reference field")?;
        }
    }
    Ok(())
}

fn record<'a>(step: &Step, captures: &'a BTreeMap<String, Capture>) -> Result<&'a Capture> {
    let capture = captures
        .get(
            step.record
                .as_deref()
                .context("step lacks a record alias")?,
        )
        .context("record alias is missing; run its prerequisite first")?;
    if capture.entity != step.entity {
        bail!("record alias belongs to another entity");
    }
    Ok(capture)
}
fn payload(
    step: &Step,
    input: &Value,
    captures: &BTreeMap<String, Capture>,
) -> Result<BRegCreateRequest> {
    let key = step
        .input
        .as_deref()
        .context("create input key is missing")?;
    let value = resolve(
        input
            .get(key)
            .context("input file is missing a declared payload key")?,
        captures,
        0,
    )?;
    Ok(BRegCreateRequest::new(
        value
            .as_object()
            .context("create payload must be a JSON object")?
            .clone(),
    )?)
}
fn attempts(directory: &Path) -> Result<Vec<Attempt>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(directory)? {
        if result.len() >= 1000 {
            bail!("retained example attempt limit reached (1000)");
        }
        let entry = entry?;
        if entry.path().extension().is_none_or(|v| v != "json") {
            continue;
        }
        let attempt: Attempt = serde_json::from_slice(&private::read(&entry.path(), MAX_BYTES)?)
            .context("retained example attempt is malformed")?;
        if attempt.version != 1
            || attempt.id.is_nil()
            || attempt.from_attempt.is_some_and(|id| id.is_nil())
            || !["starter-data", "first-record", "reviewed-change"]
                .contains(&attempt.scenario.as_str())
            || entry.file_name().to_str() != Some(&format!("{}.json", attempt.id))
            || attempt.captures.len() > 100
            || attempt.completed.len() > 100
        {
            bail!("retained example attempt is incompatible or malformed");
        }
        if attempt
            .captures
            .iter()
            .any(|(k, v)| !config::identifier(k) || !config::identifier(&v.entity) || v.id.is_nil())
        {
            bail!("retained example capture is malformed");
        }
        result.push(attempt);
    }
    Ok(result)
}

pub fn run(args: ExamplesArgs) -> Result<Value> {
    match args.action {
        ExamplesAction::List { project } => {
            let project = super::project(&project)?;
            let (catalogue, _) = catalogue(&project)?;
            let directory = project.join(".breg/dev/examples");
            let retained = if directory.exists() {
                private::check(&project.join(".breg"), true)?;
                private::check(&project.join(".breg/dev"), true)?;
                private::check(&directory, true)?;
                attempts(&directory)?.iter().map(|a|json!({"attempt":a.id,"scenario":a.scenario,"completedSteps":a.completed.keys().collect::<Vec<_>>(),"pendingStep":a.pending.as_ref().map(|p|&p.step)})).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            Ok(
                json!({"ok":true,"command":"examples list","project":project,"scenarios":catalogue.scenarios,"attempts":retained}),
            )
        }
        ExamplesAction::Run(args) => run_example(args),
    }
}
fn run_example(args: RunArgs) -> Result<Value> {
    let project = super::project(&args.project)?;
    let parent = project.join(".breg");
    private::check(&parent, true).context("start this project first with bregctl dev")?;
    let _lock = private::lock(&parent.join("dev.lock"))?;
    let state = super::read_state(&parent.join("dev"))?;
    if !matches!(state.status, Status::Ready) || super::control(&state.root(), "status")? != "ready"
    {
        bail!("examples require this project's ready owned instance; run bregctl dev");
    }
    let client_bytes = crate::read_bounded_source_file(
        &state.clients_file,
        "examples.clients",
        "clients",
        MAX_BYTES,
    )
    .map_err(|_| anyhow::anyhow!("examples require the original bounded dev clients file"))?;
    if super::capture(&project, &client_bytes)?.digest != state.source_digest {
        bail!("governed source changed since dev start; restore the captured source or use the documented migration/restart workflow");
    }
    let clients = config::clients(&client_bytes)?;
    let (catalogue, bytes) = catalogue(&project)?;
    let scenario = catalogue
        .scenarios
        .iter()
        .find(|s| s.id == args.scenario)
        .context("scenario is not declared in this project")?;
    if args.scenario != "reviewed-change" && (args.step.is_some() || args.from_attempt.is_some()) {
        bail!("--step and --from-attempt are only for reviewed-change");
    }
    let input_path = args
        .input
        .clone()
        .unwrap_or_else(|| project.join(&scenario.input));
    let input_bytes = read_source(&input_path)?;
    let input: Value =
        serde_json::from_slice(&input_bytes).context("example input must be JSON")?;
    if !input.is_object() {
        bail!("example input must be an object of named payloads");
    }
    let declared_keys: BTreeSet<_> = scenario
        .steps
        .iter()
        .filter_map(|s| s.input.as_deref())
        .collect();
    let supplied_keys: BTreeSet<_> = input
        .as_object()
        .context("input object missing")?
        .keys()
        .map(String::as_str)
        .collect();
    if declared_keys != supplied_keys {
        bail!("example input must contain exactly the scenario's declared payload keys");
    }
    let directory = state.root().join("examples");
    private::directory(&directory)?;
    let retained = attempts(&directory)?;
    let binding = Binding {
        source: state.source_digest.clone(),
        package: state
            .package_revision
            .clone()
            .context("ready instance lacks package revision")?,
        database: state.container_id()?.into(),
        clients: config::hash(&client_bytes),
        scenario: config::hash(&bytes),
        input: config::hash(&input_bytes),
    };
    let mut eligible: Vec<_> = retained
        .iter()
        .filter(|a| a.scenario == args.scenario && a.binding.database == binding.database)
        .collect();
    let existing = if let Some(id) = args.attempt {
        Some(
            retained
                .iter()
                .find(|a| a.id == id)
                .context("attempt does not exist in this project")?,
        )
    } else if args.new_attempt {
        None
    } else {
        if eligible.len() > 1 {
            bail!("multiple attempts exist; select --attempt ID or start --new-attempt");
        }
        eligible.pop()
    };
    let mut attempt = if let Some(existing) = existing {
        if existing.binding != binding || existing.scenario != scenario.id {
            bail!("attempt source, input, client, scenario or database generation differs; unchanged input resumes, changed input requires --new-attempt");
        }
        if args.from_attempt.is_some() && args.from_attempt != existing.from_attempt {
            bail!("attempt already binds another first-record target; use --new-attempt");
        }
        existing.clone()
    } else {
        if retained.len() >= 1000 {
            bail!("retained example attempt limit reached (1000); resume an existing --attempt");
        }
        let mut attempt = Attempt {
            version: 1,
            id: uuid::Uuid::new_v4(),
            scenario: scenario.id.clone(),
            binding,
            from_attempt: None,
            captures: BTreeMap::new(),
            completed: BTreeMap::new(),
            pending: None,
        };
        if scenario.id == "reviewed-change" {
            let candidates: Vec<_> = retained
                .iter()
                .filter(|a| {
                    a.scenario == "first-record"
                        && a.binding.database == attempt.binding.database
                        && a.binding.source == attempt.binding.source
                        && a.binding.clients == attempt.binding.clients
                        && a.binding.scenario == attempt.binding.scenario
                        && a.pending.is_none()
                        && a.completed.len() == 2
                        && args.from_attempt.is_none_or(|id| a.id == id)
                })
                .collect();
            if candidates.len() != 1 {
                bail!(
                    "review needs one completed first-record attempt; run bregctl examples run first-record {} or select --from-attempt ID",
                    shell_path(&project)
                );
            }
            attempt.from_attempt = Some(candidates[0].id);
            attempt.captures = candidates[0].captures.clone();
        }
        attempt
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(execute(
        &state,
        &clients,
        scenario,
        &input,
        &directory,
        &mut attempt,
        &args,
    ));
    if let Err(error) = result {
        if directory.join(format!("{}.json", attempt.id)).exists() {
            let mut resume = format!(
                "bregctl examples run {} {} --attempt {}",
                scenario.id,
                shell_path(&project),
                attempt.id
            );
            if scenario.id == "reviewed-change" {
                let step = attempt
                    .pending
                    .as_ref()
                    .map(|p| p.step.as_str())
                    .unwrap_or_else(|| args.step.unwrap_or(ReviewStep::Submit).id());
                resume.push_str(&format!(
                    " --step {}",
                    if step == "draft" { "submit" } else { step }
                ));
            }
            if args.input.is_some() {
                resume.push_str(&format!(" --input {}", shell_path(&input_path)));
            }
            return Err(error.context(format!("example {} attempt {} retained {} confirmed steps; resume the original operation with: {resume}",scenario.id,attempt.id,attempt.completed.len())));
        }
        return Err(error);
    }
    result
}

fn create_binding(metadata: &BRegMetadata, step: &Step) -> Result<BRegCreateBinding> {
    let operations: Vec<_> = metadata
        .operations()
        .iter()
        .filter(|o| {
            o.source_entity() == step.entity
                && o.access_profile() == step.access_profile
                && *o.kind() == BRegOperationKind::Create
        })
        .collect();
    if operations.len() != 1 {
        bail!("example create requires one advertised direct create operation for its entity and profile");
    }
    match metadata.select_direct_write(operations[0].identifier(), &step.access_profile)? {
        BRegDirectWrite::Create(binding) => Ok(binding),
        _ => bail!("example operation does not advertise direct create"),
    }
}
fn route(metadata: &BRegMetadata, step: &Step) -> Result<String> {
    let operations: Vec<_> = metadata
        .operations()
        .iter()
        .filter(|o| {
            o.source_entity() == step.entity
                && o.access_profile() == step.access_profile
                && *o.kind() == BRegOperationKind::Get
        })
        .collect();
    if operations.len() != 1 {
        bail!("example read requires one advertised record route for its entity and profile");
    }
    let path = operations[0].path();
    let route = path
        .strip_prefix("/v1/records/")
        .and_then(|p| p.strip_suffix("/{record_id}"))
        .context("record route is incompatible with the native client")?;
    Ok(route.into())
}
fn selected_steps<'a>(
    scenario: &'a Scenario,
    attempt: &Attempt,
    requested: Option<ReviewStep>,
) -> Result<Vec<&'a Step>> {
    if scenario.id != "reviewed-change" {
        return Ok(scenario.steps.iter().collect());
    }
    let id = requested.unwrap_or(ReviewStep::Submit).id();
    let prerequisite = match id {
        "submit" => None,
        "inspect" => Some("submit"),
        "approve" | "reject" => Some("inspect"),
        "apply" => Some("approve"),
        "history" => Some("submit"),
        _ => unreachable!(),
    };
    if prerequisite.is_some_and(|p| !attempt.completed.contains_key(p)) {
        bail!("review step requires its previous explicit stage; submit, inspect, approve or reject, then apply");
    }
    if (["approve", "apply"].contains(&id) && attempt.completed.contains_key("reject"))
        || (id == "reject" && attempt.completed.contains_key("approve"))
    {
        bail!("this attempt already has a different review decision");
    }
    if id == "submit" {
        Ok(scenario
            .steps
            .iter()
            .filter(|s| s.id == "draft" || s.id == "submit")
            .collect())
    } else {
        Ok(vec![scenario
            .steps
            .iter()
            .find(|s| s.id == id)
            .context("review step is not declared")?])
    }
}
async fn execute(
    state: &State,
    clients: &Clients,
    scenario: &Scenario,
    input: &Value,
    directory: &Path,
    attempt: &mut Attempt,
    args: &RunArgs,
) -> Result<Value> {
    let selected = selected_steps(scenario, attempt, args.step)?;
    if attempt
        .pending
        .as_ref()
        .is_some_and(|p| !selected.iter().any(|s| s.id == p.step))
    {
        bail!(
            "an uncertain mutation must be resumed with its original --step before another action"
        );
    }
    let mut native = BTreeMap::new();
    let mut metadata = BTreeMap::new();
    for step in &scenario.steps {
        if !clients
            .clients
            .iter()
            .any(|c| c.id == step.client && c.access_profiles.contains(&step.access_profile))
        {
            bail!("scenario client/profile is not explicitly declared in dev clients");
        }
        if !native.contains_key(&step.client) {
            super::token(state, &step.client)?;
            let token = private::read(
                &state
                    .root()
                    .join("secrets")
                    .join(format!("{}-token", step.client)),
                65536,
            )?;
            let provider =
                StaticToken::new(String::from_utf8(token).context("retained token is invalid")?)?;
            native.insert(
                step.client.clone(),
                BaseRegistryClient::new(
                    BaseRegistryClientConfig::new(state.breg_origin().parse()?)
                        .with_token_provider(Arc::new(provider)),
                )?,
            );
        }
        let key = (step.client.clone(), step.access_profile.clone());
        if let std::collections::btree_map::Entry::Vacant(entry) = metadata.entry(key) {
            entry.insert(
                native[&step.client]
                    .registry_contract(Some(&step.access_profile))
                    .await?
                    .value,
            );
        }
    }
    // Validate every payload and dependency before the first mutation, with
    // typed placeholder UUIDs for captures not produced yet. Native metadata
    // owns the payload schema; this runner owns only dependency interpretation.
    let mut declared = attempt.captures.clone();
    for step in &scenario.steps {
        let client = &native[&step.client];
        let contract = &metadata[&(step.client.clone(), step.access_profile.clone())];
        let kind = step.operation.metadata_kind();
        if !contract.operations().iter().any(|operation| {
            operation.source_entity() == step.entity
                && operation.access_profile() == step.access_profile
                && *operation.kind() == kind
        }) {
            bail!(
                "example {} step {} requires advertised {} permission for its entity and profile",
                scenario.id,
                step.id,
                kind.as_str()
            );
        }
        if step.operation == Operation::Create {
            let binding = create_binding(contract, step)?;
            validate_reference_fields(step, contract, input, &declared).with_context(|| {
                format!(
                    "example {} step {} has an invalid reference",
                    scenario.id, step.id
                )
            })?;
            let request = payload(step, input, &declared).with_context(|| {
                format!(
                    "example {} step {} has an invalid input payload",
                    scenario.id, step.id
                )
            })?;
            let data = resolve(
                &input[step.input.as_deref().context("input key missing")?],
                &declared,
                0,
            )?;
            let schema = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(true)
                .compile(binding.request_schema())
                .map_err(|_| anyhow::anyhow!("advertised example input schema is invalid"))?;
            if !schema.is_valid(&json!({"data":data})) {
                bail!("example {} step {} input does not match its advertised create schema; inspect payload {} before running",scenario.id,step.id,step.input.as_deref().unwrap_or_default());
            }
            client.prepare_create(
                &binding,
                &request,
                &BRegIdempotencyKey::parse("example-preflight")?,
                BRegRecordFormat::Json,
            )?;
            let alias = step.capture.as_ref().context("create capture missing")?;
            if let Some(existing) = declared.get(alias) {
                if !attempt.completed.contains_key(&step.id) || existing.entity != step.entity {
                    bail!("capture aliases must be unique and match their declared entity");
                }
            } else {
                declared.insert(
                    alias.clone(),
                    Capture {
                        entity: step.entity.clone(),
                        id: uuid::Uuid::new_v4(),
                    },
                );
            }
        } else {
            record(step, &declared)?;
            route(contract, step)?;
            if step.operation.lifecycle().is_some() {
                contract.select_lifecycle(&step.entity, &step.access_profile)?;
            }
        }
    }
    if scenario.id == "first-record" {
        let create = &scenario.steps[0];
        let get = &scenario.steps[1];
        if get.record != create.capture || get.entity != create.entity {
            bail!("first-record must retrieve exactly the record it created");
        }
    }
    attempt.save(directory)?;
    let mut results = BTreeMap::new();
    for step in selected {
        // Completed mutations are observations, not permission to recreate a
        // user-deleted sample. Reads intentionally inspect the current record.
        if let Some(result) = attempt.completed.get(&step.id) {
            if step.operation != Operation::Get && step.operation != Operation::History {
                results.insert(step.id.clone(), result.clone());
                continue;
            }
        }
        let client = &native[&step.client];
        let contract = &metadata[&(step.client.clone(), step.access_profile.clone())];
        let result = if step.operation == Operation::Create {
            let binding = create_binding(contract, step)?;
            let prepared = if let Some(pending) = &attempt.pending {
                if pending.step != step.id {
                    bail!("resume the pending original step first");
                }
                BRegPreparedCreate::from_slice(&serde_json::to_vec(&pending.capsule)?)?
            } else {
                let request = payload(step, input, &attempt.captures)?;
                let key =
                    BRegIdempotencyKey::parse(format!("examples-{}-{}", attempt.id, step.id))?;
                let prepared =
                    client.prepare_create(&binding, &request, &key, BRegRecordFormat::Json)?;
                attempt.pending = Some(Pending {
                    step: step.id.clone(),
                    capsule: serde_json::from_slice(prepared.as_bytes())?,
                });
                attempt.save(directory)?;
                prepared
            };
            let expected_key =
                BRegIdempotencyKey::parse(format!("examples-{}-{}", attempt.id, step.id))?;
            let expected = client.prepare_create(
                &binding,
                &payload(step, input, &attempt.captures)?,
                &expected_key,
                BRegRecordFormat::Json,
            )?;
            if serde_json::from_slice::<Value>(prepared.as_bytes())?
                != serde_json::from_slice::<Value>(expected.as_bytes())?
            {
                bail!("pending create no longer matches its exact attempt input and captured dependencies");
            }
            let (request, key, format) = client.recover_create(&binding, &prepared)?;
            let response = client
                .create_record(&binding, &request, &key, format)
                .await?;
            let capture = Capture {
                entity: step.entity.clone(),
                id: uuid::Uuid::parse_str(&response.value.data.record_identifier)?,
            };
            attempt.captures.insert(
                step.capture.clone().context("create capture missing")?,
                capture,
            );
            serde_json::to_value(response.value)?
        } else if let Some(operation) = step.operation.lifecycle() {
            let authority = contract.select_lifecycle(&step.entity, &step.access_profile)?;
            let prepared = if let Some(pending) = &attempt.pending {
                if pending.step != step.id {
                    bail!("resume the pending original step first");
                }
                BRegPreparedLifecycle::from_slice(&serde_json::to_vec(&pending.capsule)?)?
            } else {
                let capture = record(step, &attempt.captures)?;
                let current = client
                    .get_record(
                        &route(contract, step)?,
                        &capture.id.to_string(),
                        &BRegRecordOptions::default().access_profile(&step.access_profile)?,
                    )
                    .await?;
                let actions = client.lifecycle_actions(&authority, &current.value)?;
                let matches: Vec<_> = actions
                    .iter()
                    .filter(|a| a.operation() == operation)
                    .collect();
                if matches.len() != 1 {
                    bail!("the requested lifecycle action is not uniquely available to this teaching client; inspect the request and its review state");
                }
                let key =
                    BRegIdempotencyKey::parse(format!("examples-{}-{}", attempt.id, step.id))?;
                let prepared = client.prepare_lifecycle_action(
                    &authority,
                    &current.value,
                    matches[0],
                    &key,
                )?;
                attempt.pending = Some(Pending {
                    step: step.id.clone(),
                    capsule: serde_json::from_slice(prepared.as_bytes())?,
                });
                attempt.save(directory)?;
                prepared
            };
            let (action, key) = client.recover_lifecycle_action(&authority, &prepared)?;
            let expected_key = format!("examples-{}-{}", attempt.id, step.id);
            if key.as_str() != expected_key || action.operation() != operation {
                bail!("pending lifecycle operation does not match its original attempt step");
            }
            let expected_id = record(step, &attempt.captures)?.id.to_string();
            let expected_path = format!(
                "/v1/records/{}/{expected_id}/actions/",
                route(contract, step)?
            );
            if !action.href().starts_with(&expected_path) {
                bail!("pending lifecycle action does not match its captured request record");
            }
            let receipt = client.execute_lifecycle_action(&action, &key).await?;
            json!({"recordId":receipt.value.record_identifier(),"snapshot":receipt.value.snapshot(),"operation":operation.identifier()})
        } else {
            let capture = record(step, &attempt.captures)?;
            if step.operation == Operation::History {
                let response = client
                    .record_revisions(
                        &route(contract, step)?,
                        &capture.id.to_string(),
                        Some(&step.access_profile),
                    )
                    .await?;
                serde_json::from_slice(response.value.as_bytes())?
            } else {
                let response = client
                    .get_record(
                        &route(contract, step)?,
                        &capture.id.to_string(),
                        &BRegRecordOptions::default().access_profile(&step.access_profile)?,
                    )
                    .await?;
                serde_json::to_value(response.value)?
            }
        };
        #[cfg(test)]
        tests::interrupt_after_commit(step);
        let retained = if step.operation == Operation::Create {
            let capture =
                &attempt.captures[step.capture.as_deref().context("create capture missing")?];
            json!({"recordId":capture.id,"entity":capture.entity})
        } else if matches!(step.operation, Operation::Get | Operation::History) {
            json!({"observed":true})
        } else {
            result.clone()
        };
        attempt.completed.insert(step.id.clone(), retained);
        attempt.pending = None;
        attempt.save(directory)?;
        results.insert(step.id.clone(), result);
    }
    let next_step = if !attempt.completed.contains_key("submit") {
        "submit"
    } else if !attempt.completed.contains_key("inspect") {
        "inspect"
    } else if !attempt.completed.contains_key("approve")
        && !attempt.completed.contains_key("reject")
    {
        "approve"
    } else if attempt.completed.contains_key("approve") && !attempt.completed.contains_key("apply")
    {
        "apply"
    } else {
        "history"
    };
    let next = if scenario.id == "first-record" {
        format!(
            "bregctl examples run reviewed-change {} --from-attempt {} --step submit",
            shell_path(&state.project),
            attempt.id
        )
    } else if scenario.id == "reviewed-change" {
        format!(
            "bregctl examples run reviewed-change {} --attempt {} --step {next_step}",
            shell_path(&state.project),
            attempt.id
        )
    } else {
        format!(
            "bregctl examples run first-record {}",
            shell_path(&state.project)
        )
    };
    let next = if scenario.id == "reviewed-change" {
        if let Some(input) = &args.input {
            format!("{next} --input {}", shell_path(&fs::canonicalize(input)?))
        } else {
            next
        }
    } else {
        next
    };
    Ok(
        json!({"ok":true,"command":"examples run","project":state.project,"scenario":scenario.id,"attempt":attempt.id,"captures":attempt.captures,"fromAttempt":attempt.from_attempt,"completedSteps":attempt.completed.keys().collect::<Vec<_>>(),"results":results,"nextCommand":next,"historyScope":"first-page-only","message":if args.step.is_some_and(|s|matches!(s,ReviewStep::Approve)){"Approval recorded. Approval alone does not change the target; apply is a separate command."}else{"Example progress retained. Reuse this attempt to resume."}}),
    )
}
fn shell_path(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    pub(super) fn interrupt_after_commit(step: &Step) {
        // Exists only in the Rust test harness. The released CLI has neither
        // this hook nor any environment-controlled interruption surface.
        if std::env::var("BREG_EXAMPLE_TEST_INTERRUPT").ok().as_deref() == Some(&step.id) {
            std::process::exit(79);
        }
    }
    fn assets() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/starters/public-organizations/core")
            .canonicalize()
            .unwrap()
    }
    #[test]
    fn listing_is_offline_and_does_not_create_dev_state() {
        let temp = tempfile::tempdir().unwrap();
        copy_tree(&assets(), temp.path());
        let value = run(ExamplesArgs {
            action: ExamplesAction::List {
                project: temp.path().into(),
            },
        })
        .unwrap();
        assert_eq!(value["scenarios"].as_array().unwrap().len(), 3);
        assert!(!temp.path().join(".breg").exists());
    }
    #[test]
    fn typed_references_refuse_missing_and_malformed_aliases() {
        let captures = BTreeMap::from([(
            "parent".into(),
            Capture {
                entity: "entry".into(),
                id: uuid::Uuid::new_v4(),
            },
        )]);
        assert_eq!(
            resolve(&json!({"recordRef":"parent"}), &captures, 0).unwrap(),
            json!(captures["parent"].id)
        );
        for value in [
            json!({"recordRef":"missing"}),
            json!({"recordRef":"parent","extra":true}),
            json!({"recordRef":false}),
        ] {
            assert!(resolve(&value, &captures, 0).is_err());
        }
    }
    #[test]
    fn capture_dependencies_cannot_reference_later_records() {
        let (catalogue, _) = catalogue(&assets()).unwrap();
        let scenario = &catalogue.scenarios[0];
        let input: Value =
            serde_json::from_slice(&read_source(&assets().join(&scenario.input)).unwrap()).unwrap();
        let mut captures = BTreeMap::new();
        let linked = scenario.steps.last().unwrap();
        assert!(payload(linked, &input, &captures).is_err());
        for step in &scenario.steps {
            payload(step, &input, &captures).unwrap();
            captures.insert(
                step.capture.clone().unwrap(),
                Capture {
                    entity: step.entity.clone(),
                    id: uuid::Uuid::new_v4(),
                },
            );
        }
    }
    fn attempt() -> Attempt {
        Attempt {
            version: 1,
            id: uuid::Uuid::new_v4(),
            scenario: "reviewed-change".into(),
            binding: Binding {
                source: "source".into(),
                package: "package".into(),
                database: "database".into(),
                clients: "clients".into(),
                scenario: "scenario".into(),
                input: "input".into(),
            },
            from_attempt: None,
            captures: BTreeMap::new(),
            completed: BTreeMap::new(),
            pending: None,
        }
    }
    #[test]
    fn review_stages_do_not_implicitly_approve_or_apply() {
        let (catalogue, _) = catalogue(&assets()).unwrap();
        let scenario = catalogue
            .scenarios
            .iter()
            .find(|s| s.id == "reviewed-change")
            .unwrap();
        let mut attempt = attempt();
        assert_eq!(
            selected_steps(scenario, &attempt, None)
                .unwrap()
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>(),
            ["draft", "submit"]
        );
        assert!(selected_steps(scenario, &attempt, Some(ReviewStep::Apply)).is_err());
        attempt.completed.insert("submit".into(), json!({}));
        attempt.completed.insert("inspect".into(), json!({}));
        assert_eq!(
            selected_steps(scenario, &attempt, Some(ReviewStep::Approve)).unwrap()[0].operation,
            Operation::Approve
        );
        assert!(selected_steps(scenario, &attempt, Some(ReviewStep::Apply)).is_err());
        attempt.completed.insert("reject".into(), json!({}));
        assert!(selected_steps(scenario, &attempt, Some(ReviewStep::Apply)).is_err());
        assert!(selected_steps(scenario, &attempt, Some(ReviewStep::Approve)).is_err());
    }
    #[test]
    fn attempt_files_are_private_and_generation_and_pending_operation_survive_reload() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(
            temp.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        private::directory(temp.path()).unwrap();
        let mut value = attempt();
        value.pending = Some(Pending {
            step: "submit".into(),
            capsule: json!({"exact":"original bytes"}),
        });
        value.save(temp.path()).unwrap();
        let loaded = attempts(temp.path()).unwrap().pop().unwrap();
        assert_eq!(loaded.binding, value.binding);
        assert_eq!(
            loaded.pending.unwrap().capsule,
            value.pending.as_ref().unwrap().capsule
        );
        let mut changed = value.binding.clone();
        changed.database = "replacement".into();
        assert_ne!(changed, value.binding);
        value.captures.insert(
            "bad".into(),
            Capture {
                entity: "entry".into(),
                id: uuid::Uuid::nil(),
            },
        );
        value.save(temp.path()).unwrap();
        assert!(attempts(temp.path()).is_err());
    }
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &to.join(entry.file_name()));
            } else {
                fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
            }
        }
    }

    #[test]
    #[ignore = "subprocess entry point for native recovery test"]
    fn native_child() {
        let project = PathBuf::from(
            std::env::var_os("BREG_EXAMPLE_TEST_PROJECT").expect("parent supplies owned project"),
        );
        let scenario = std::env::var("BREG_EXAMPLE_TEST_SCENARIO").unwrap();
        let step = std::env::var("BREG_EXAMPLE_TEST_STEP")
            .ok()
            .map(|v| ReviewStep::from_str(&v, false).unwrap());
        let result = run_example(RunArgs {
            scenario,
            project: project.clone(),
            input: None,
            attempt: None,
            new_attempt: false,
            from_attempt: None,
            step,
        })
        .unwrap();
        private::replace(
            &project.join(".breg/dev/example-test-result.json"),
            &serde_json::to_vec(&result).unwrap(),
        )
        .unwrap();
    }
    fn child(
        project: &Path,
        scenario: &str,
        step: Option<&str>,
        interrupt: Option<&str>,
    ) -> Option<Value> {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_remove("SSL_CERT_FILE")
            .args([
                "--ignored",
                "--exact",
                "dev::examples::tests::native_child",
                "--nocapture",
            ])
            .env("BREG_EXAMPLE_TEST_PROJECT", project)
            .env("BREG_EXAMPLE_TEST_SCENARIO", scenario);
        if let Some(step) = step {
            command.env("BREG_EXAMPLE_TEST_STEP", step);
        }
        if let Some(step) = interrupt {
            command.env("BREG_EXAMPLE_TEST_INTERRUPT", step);
        }
        let output = command.output().unwrap();
        if interrupt.is_some() {
            assert_eq!(
                output.status.code(),
                Some(79),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            None
        } else {
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            Some(
                serde_json::from_slice(
                    &private::read(
                        &project.join(".breg/dev/example-test-result.json"),
                        MAX_BYTES,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
        }
    }
    struct OwnedDev {
        ctl: PathBuf,
        project: PathBuf,
    }
    impl OwnedDev {
        fn dev(&self, args: &[&str]) -> std::process::Output {
            Command::new(&self.ctl)
                .env_remove("SSL_CERT_FILE")
                .env(
                    "PATH",
                    std::env::join_paths(
                        std::iter::once(self.ctl.parent().unwrap().to_path_buf()).chain(
                            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
                        ),
                    )
                    .unwrap(),
                )
                .args(["--format", "json", "dev"])
                .args(args)
                .arg(&self.project)
                .output()
                .unwrap()
        }
        fn succeed(&self, args: &[&str]) {
            let out = self.dev(args);
            assert!(
                out.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    impl Drop for OwnedDev {
        fn drop(&mut self) {
            let _ = self.dev(&["stop", "--remove"]);
        }
    }
    fn test_args(project: &Path, scenario: &str) -> RunArgs {
        RunArgs {
            scenario: scenario.into(),
            project: project.into(),
            input: None,
            attempt: None,
            new_attempt: false,
            from_attempt: None,
            step: None,
        }
    }
    fn observed_count_and_apply_action(project: &Path) -> (usize, bool) {
        let canonical = project.canonicalize().unwrap();
        let project = canonical.as_path();
        let state =
            super::super::read_state(&project.canonicalize().unwrap().join(".breg/dev")).unwrap();
        let (catalogue, _) = catalogue(project).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut result = (0, false);
            for role in ["editor", "reviewer"] {
                let bytes =
                    private::read(&state.root().join(format!("secrets/{role}-token")), 65536)
                        .unwrap();
                let client = BaseRegistryClient::new(
                    BaseRegistryClientConfig::new(state.breg_origin().parse().unwrap())
                        .with_token_provider(Arc::new(
                            StaticToken::new(String::from_utf8(bytes).unwrap()).unwrap(),
                        )),
                )
                .unwrap();
                let contract = client.registry_contract(Some(role)).await.unwrap().value;
                if role == "editor" {
                    let step = &catalogue
                        .scenarios
                        .iter()
                        .find(|s| s.id == "first-record")
                        .unwrap()
                        .steps[0];
                    let records = client
                        .list_records(
                            &route(&contract, step).unwrap(),
                            &BRegListRequest::default().options(
                                BRegRecordOptions::default().access_profile(role).unwrap(),
                            ),
                        )
                        .await
                        .unwrap();
                    result.0 = records.value.value.items.len();
                } else {
                    let retained = attempts(&state.root().join("examples")).unwrap();
                    if let Some(review) = retained.iter().find(|a| a.scenario == "reviewed-change")
                    {
                        let step = catalogue
                            .scenarios
                            .iter()
                            .find(|s| s.id == "reviewed-change")
                            .unwrap()
                            .steps
                            .iter()
                            .find(|s| s.id == "apply")
                            .unwrap();
                        let current = client
                            .get_record(
                                &route(&contract, step).unwrap(),
                                &review.captures["request"].id.to_string(),
                                &BRegRecordOptions::default().access_profile(role).unwrap(),
                            )
                            .await
                            .unwrap();
                        result.1 = BRegRequestMetadata::from_record(&current.value.data)
                            .unwrap()
                            .unwrap()
                            .advertised_operations()
                            .any(|op| op == BRegLifecycleOperation::ApplyRequest);
                    }
                }
            }
            result
        })
    }
    /// This permission exists only in the disposable test copy. The shipped
    /// starter intentionally denies deletion, but the retained examples runner
    /// must also preserve deletions made under a project's later chosen policy.
    /// An optional structured field exercises untyped nested reference refusal.
    fn prepare_native_fixture(project: &Path) {
        let path = project.join("registry.yaml");
        let mut source: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let entity = source["entities"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entity| entity["id"] == "institutional-relationship")
            .unwrap();
        entity["tombstone"] = json!(true);
        let editor = source["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|profile| profile["id"] == "editor")
            .unwrap();
        let grant = editor["permissions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|grant| grant["entity"] == "institutional-relationship")
            .unwrap();
        grant["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!("tombstone"));
        let entity = source["entities"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entity| entity["id"] == "public-organization")
            .unwrap();
        entity["fields"].as_array_mut().unwrap().push(json!({
            "id":"notes", "type":"structured", "required":false,
            "classification":"restricted", "maxBytes":2048,
            "schema":{"type":"object", "additionalProperties":false, "properties":{
                "related":{"type":"string", "maxLength":64},
                "items":{"type":"array", "maxItems":4, "items":{"type":"string", "maxLength":64}}
            }}
        }));
        let editor = source["accessProfiles"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|profile| profile["id"] == "editor")
            .unwrap();
        let grant = editor["permissions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|grant| grant["entity"] == "public-organization")
            .unwrap();
        for fields in ["readableFields", "writableFields"] {
            grant[fields].as_array_mut().unwrap().push(json!("notes"));
        }
        fs::write(path, serde_json::to_vec_pretty(&source).unwrap()).unwrap();
    }

    fn preflight_refuses_before_writes(project: &Path, first: &Value) {
        let canonical = project.canonicalize().unwrap();
        let project = canonical.as_path();
        let state = super::super::read_state(&canonical.join(".breg/dev")).unwrap();
        let clients = config::clients(&fs::read(&state.clients_file).unwrap()).unwrap();
        let (catalogue, _) = catalogue(project).unwrap();
        let directory = state.root().join("examples");
        let retained_before = fs::read_dir(&directory).unwrap().count();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut cases = Vec::new();
        let review = catalogue
            .scenarios
            .iter()
            .find(|s| s.id == "reviewed-change")
            .unwrap();
        for (id, profile, missing) in [
            ("history", "reader", "revisions"),
            ("reject", "editor", "reject_request"),
        ] {
            let mut scenario = review.clone();
            let step = scenario.steps.iter_mut().find(|s| s.id == id).unwrap();
            step.client = profile.into();
            step.access_profile = profile.into();
            let input =
                serde_json::from_slice(&read_source(&project.join(&scenario.input)).unwrap())
                    .unwrap();
            cases.push((
                scenario,
                input,
                format!("requires advertised {missing} permission"),
            ));
        }
        let samples = catalogue
            .scenarios
            .iter()
            .find(|s| s.id == "starter-data")
            .unwrap();
        for notes in [
            json!({"related":{"recordRef":"department"}}),
            json!({"items":[{"recordRef":"department"}]}),
        ] {
            let mut input: Value =
                serde_json::from_slice(&read_source(&project.join(&samples.input)).unwrap())
                    .unwrap();
            input["river"]["notes"] = notes;
            cases.push((samples.clone(), input, "nested logical references".into()));
        }
        for (scenario, input, message) in cases {
            let mut attempt = attempt();
            attempt.scenario = scenario.id.clone();
            if scenario.id == "reviewed-change" {
                attempt.captures = serde_json::from_value(first["captures"].clone()).unwrap();
            }
            let original_captures = attempt.captures.clone();
            let error = runtime
                .block_on(execute(
                    &state,
                    &clients,
                    &scenario,
                    &input,
                    &directory,
                    &mut attempt,
                    &test_args(project, &scenario.id),
                ))
                .unwrap_err();
            assert!(format!("{error:#}").contains(&message), "{error:#}");
            assert_eq!(
                serde_json::to_value(&attempt.captures).unwrap(),
                serde_json::to_value(&original_captures).unwrap()
            );
            assert!(attempt.pending.is_none());
            assert!(attempt.completed.is_empty());
            assert!(!directory.join(format!("{}.json", attempt.id)).exists());
            assert_eq!(fs::read_dir(&directory).unwrap().count(), retained_before);
            assert_eq!(observed_count_and_apply_action(project).0, 1);
        }
    }

    /// Exercise deletion through the runtime's ordinary authenticated HTTP
    /// contract, then observe both current absence and the retained tombstone.
    fn deleted_sample_observation(project: &Path, id: &str, delete: bool) -> (usize, Value) {
        let canonical = project.canonicalize().unwrap();
        let state = super::super::read_state(&canonical.join(".breg/dev")).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let bytes = private::read(&state.root().join("secrets/editor-token"), 65536).unwrap();
            let token = zeroize::Zeroizing::new(String::from_utf8(bytes).unwrap());
            let client = BaseRegistryClient::new(
                BaseRegistryClientConfig::new(state.breg_origin().parse().unwrap())
                    .with_token_provider(Arc::new(StaticToken::new(token.to_string()).unwrap())),
            )
            .unwrap();
            let options = BRegRecordOptions::default()
                .access_profile("editor")
                .unwrap();
            let route = "institutional-relationships";
            let url = format!(
                "{}/v1/records/{route}/{id}?accessProfile=editor",
                state.breg_origin()
            );
            let http = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap();
            if delete {
                let before = client.get_record(route, id, &options).await.unwrap();
                let etag = before.metadata.etag().unwrap().as_str();
                let response = http
                    .delete(&url)
                    .bearer_auth(token.as_str())
                    .header("if-match", etag)
                    .header("idempotency-key", "native-example-delete-sample")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    reqwest::StatusCode::OK,
                    "fixture policy authorizes a real tombstone"
                );
            }
            let current = http
                .get(&url)
                .bearer_auth(token.as_str())
                .send()
                .await
                .unwrap();
            assert_eq!(
                current.status(),
                reqwest::StatusCode::NOT_FOUND,
                "deleted sample UUID must remain absent"
            );
            let records = client
                .list_records(route, &BRegListRequest::default().options(options))
                .await
                .unwrap();
            assert!(records
                .value
                .value
                .items
                .iter()
                .all(|record| record.record_identifier != id));
            let revisions = client
                .record_revisions(route, id, Some("editor"))
                .await
                .unwrap();
            let history: Value = serde_json::from_slice(revisions.value.as_bytes()).unwrap();
            assert_eq!(
                history["items"].as_array().unwrap().len(),
                2,
                "only create and tombstone revisions remain"
            );
            assert_eq!(history["items"][0]["mutationKind"], "tombstone");
            (records.value.value.items.len(), history)
        })
    }
    #[test]
    #[ignore = "requires source-built bregctl/breg/mint and Docker; creates one disposable owned dev database"]
    fn native_create_and_apply_recover_after_process_exit_without_duplicate_revisions() {
        let temp = tempfile::Builder::new()
            .prefix("breg-example-recovery-")
            .tempdir()
            .unwrap()
            .keep();
        let project = temp.join("project with ' spaces");
        copy_tree(&assets(), &project);
        prepare_native_fixture(&project);
        let binaries = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let owned = OwnedDev {
            ctl: binaries.join("bregctl"),
            project,
        };
        let listeners: Vec<_> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<_> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().port().to_string())
            .collect();
        drop(listeners);
        // The copied starter carries dev-clients.yaml, which a first start reads.
        owned.succeed(&[
            "--breg-bin",
            binaries.join("breg").to_str().unwrap(),
            "--mint-bin",
            binaries.join("mint").to_str().unwrap(),
            "--breg-port",
            &ports[0],
            "--mint-port",
            &ports[1],
            "--database-port",
            &ports[2],
        ]);
        assert_ne!(std::env::current_dir().unwrap(), owned.project);
        let error = run_example(test_args(&owned.project, "reviewed-change"))
            .unwrap_err()
            .to_string();
        let expected_project = format!(
            "'{}/project with '\\'' spaces'",
            temp.canonicalize().unwrap().display()
        );
        assert_eq!(
            error,
            format!(
                "review needs one completed first-record attempt; run bregctl examples run first-record {expected_project} or select --from-attempt ID"
            )
        );
        assert!(attempts(&owned.project.join(".breg/dev/examples"))
            .unwrap()
            .is_empty());
        assert_eq!(observed_count_and_apply_action(&owned.project).0, 0);
        child(&owned.project, "first-record", None, Some("create"));
        let interrupted = attempts(&owned.project.join(".breg/dev/examples")).unwrap();
        assert_eq!(interrupted.len(), 1);
        assert!(interrupted[0].captures.is_empty());
        assert!(interrupted[0].pending.is_some());
        owned.succeed(&["stop"]);
        owned.succeed(&[]);
        let first = child(&owned.project, "first-record", None, None).unwrap();
        preflight_refuses_before_writes(&owned.project, &first);
        let repeated = child(&owned.project, "first-record", None, None).unwrap();
        assert_eq!(first["captures"], repeated["captures"]);
        assert_eq!(
            observed_count_and_apply_action(&owned.project).0,
            1,
            "uncertain create must not duplicate records"
        );
        let original_input =
            fs::read(owned.project.join("examples/inputs/first-record.json")).unwrap();
        let mut changed: Value = serde_json::from_slice(&original_input).unwrap();
        changed["record"]["name"] = json!("An explicitly edited input");
        fs::write(
            owned.project.join("examples/inputs/first-record.json"),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        assert!(run_example(test_args(&owned.project, "first-record"))
            .unwrap_err()
            .to_string()
            .contains("input"));
        fs::write(
            owned.project.join("examples/inputs/first-record.json"),
            original_input,
        )
        .unwrap();
        {
            let _lock = private::lock(&owned.project.join(".breg/dev.lock")).unwrap();
            assert!(
                run_example(test_args(&owned.project, "first-record")).is_err(),
                "concurrent examples cannot enter while dev lock is held"
            );
        }
        child(&owned.project, "reviewed-change", Some("submit"), None);
        child(&owned.project, "reviewed-change", Some("inspect"), None);
        child(&owned.project, "reviewed-change", Some("approve"), None);
        let before = child(&owned.project, "reviewed-change", Some("history"), None).unwrap();
        assert_eq!(
            before["results"]["history"]["items"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "approval does not mutate target"
        );
        assert!(
            observed_count_and_apply_action(&owned.project).1,
            "approved request advertises apply"
        );
        child(
            &owned.project,
            "reviewed-change",
            Some("apply"),
            Some("apply"),
        );
        assert!(
            !observed_count_and_apply_action(&owned.project).1,
            "committed apply disappears from current record before recovery"
        );
        owned.succeed(&["stop"]);
        owned.succeed(&[]);
        child(&owned.project, "reviewed-change", Some("apply"), None);
        child(&owned.project, "reviewed-change", Some("apply"), None);
        let history = child(&owned.project, "reviewed-change", Some("history"), None).unwrap();
        assert_eq!(
            history["results"]["history"]["items"]
                .as_array()
                .unwrap()
                .len(),
            2,
            "application must produce one revision despite uncertain reply and replay"
        );
        let sample_path = owned.project.join("examples/inputs/starter-data.json");
        let mut sample_input: Value =
            serde_json::from_slice(&fs::read(&sample_path).unwrap()).unwrap();
        sample_input["river"]["notes"] = json!({"related":"literal", "items":["literal"]});
        fs::write(&sample_path, serde_json::to_vec(&sample_input).unwrap()).unwrap();
        let sample_bytes = fs::read(&sample_path).unwrap();
        let mut invalid: Value = serde_json::from_slice(&sample_bytes).unwrap();
        invalid["hill-link"]["institutionFrom"] = json!({"recordRef":"river-link"});
        fs::write(&sample_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert!(format!(
            "{:#}",
            run_example(test_args(&owned.project, "starter-data")).unwrap_err()
        )
        .contains("wrong target entity"));
        assert_eq!(
            observed_count_and_apply_action(&owned.project).0,
            1,
            "invalid later alias must be refused before earlier sample creates"
        );
        fs::write(&sample_path, sample_bytes).unwrap();
        let samples = child(&owned.project, "starter-data", None, None).unwrap();
        let repeated = child(&owned.project, "starter-data", None, None).unwrap();
        assert_eq!(samples["captures"], repeated["captures"]);
        assert_eq!(
            observed_count_and_apply_action(&owned.project).0,
            4,
            "completed sample runs do not duplicate records"
        );
        let deleted_id = samples["captures"]["hill-link"]["id"].as_str().unwrap();
        let (remaining, deleted_history) =
            deleted_sample_observation(&owned.project, deleted_id, true);
        assert_eq!(remaining, 1);
        let retry = child(&owned.project, "starter-data", None, None).unwrap();
        assert_eq!(retry["captures"], samples["captures"]);
        let (remaining, retry_history) =
            deleted_sample_observation(&owned.project, deleted_id, false);
        assert_eq!(
            remaining, 1,
            "retry must not recreate the deleted sample under another UUID"
        );
        assert_eq!(retry_history, deleted_history);
        owned.succeed(&["stop"]);
        owned.succeed(&[]);
        let restarted = child(&owned.project, "starter-data", None, None).unwrap();
        assert_eq!(restarted["captures"], samples["captures"]);
        let (remaining, restart_history) =
            deleted_sample_observation(&owned.project, deleted_id, false);
        assert_eq!(remaining, 1, "restart must not repopulate a deleted sample");
        assert_eq!(restart_history, deleted_history);
        let mut duplicate = test_args(&owned.project, "first-record");
        duplicate.new_attempt = true;
        assert!(
            run_example(duplicate).is_err(),
            "explicit new attempts retain ordinary uniqueness checks"
        );
        assert_eq!(observed_count_and_apply_action(&owned.project).0, 4);
        let mut second: Value = serde_json::from_slice(
            &fs::read(owned.project.join("examples/inputs/first-record.json")).unwrap(),
        )
        .unwrap();
        second["record"]["localIdentifier"] = json!("SYNTHETIC-SECOND-INDEPENDENT");
        let second_path = owned
            .project
            .canonicalize()
            .unwrap()
            .join("examples/inputs/second-record.json");
        fs::write(&second_path, serde_json::to_vec(&second).unwrap()).unwrap();
        let mut distinct = test_args(&owned.project, "first-record");
        distinct.input = Some(second_path);
        distinct.new_attempt = true;
        run_example(distinct).unwrap();
        assert_eq!(observed_count_and_apply_action(&owned.project).0, 5);
        assert!(run_example(test_args(&owned.project, "first-record"))
            .unwrap_err()
            .to_string()
            .contains("multiple attempts"));
        let mut ambiguous = test_args(&owned.project, "reviewed-change");
        ambiguous.new_attempt = true;
        assert!(run_example(ambiguous)
            .unwrap_err()
            .to_string()
            .contains("one completed first-record attempt"));
        let old_id = uuid::Uuid::parse_str(first["attempt"].as_str().unwrap()).unwrap();
        owned.succeed(&["stop", "--remove"]);
        owned.succeed(&[]);
        let mut old = test_args(&owned.project, "first-record");
        old.attempt = Some(old_id);
        assert!(
            run_example(old)
                .unwrap_err()
                .to_string()
                .contains("database generation"),
            "removed database invalidates captures even under retained outer owner"
        );
        owned.succeed(&["stop", "--remove"]);
    }
}
