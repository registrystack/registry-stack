//! Local synthetic HTTP sources for Evidence authoring and tutorials.
//!
//! Ephemeral serving generates from one retained OpenAPI document without
//! writing project files. Materialization is an explicit create-only step;
//! once a body exists, offline checking and serving treat its exact bytes as
//! author-owned and never invoke the generator.

mod files;
mod generator;
mod infer;
mod openapi;
mod plan;
mod server;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context as _, Result};
use chrono::NaiveDate;
use clap::{Args, Subcommand};
use registry_evidence_authoring::openapi::types::OperationKey;
use registry_platform_crypto::parse_json_strict;
use serde_json::Value;

use self::{
    files::PublicationFile,
    plan::{
        Digest, GenerationSettings, MockPlan, PlanCase, PlanOperation, PlanRequest, PlanResponse,
    },
};

const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:4010";
const DEFAULT_CONFIG: &str = "mocks/source.yaml";
const PROJECT_OPENAPI: &str = "source.openapi.yaml";

#[derive(Debug, Subcommand)]
pub enum MockCommand {
    /// Serve schema-valid synthetic responses from OpenAPI or exact edited cases.
    Serve(ServeArgs),
    /// Materialize or extend editable mock cases from OpenAPI.
    Generate(GenerateArgs),
    /// Validate edited configuration and response bodies without writing or binding.
    Check(CheckArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// OpenAPI 3.0 or 3.1 document for an ephemeral, write-free preview.
    #[arg(long, conflicts_with = "config")]
    openapi: Option<PathBuf>,

    /// Materialized mock configuration whose checked body bytes are authoritative.
    #[arg(
        long,
        conflicts_with_all = ["openapi", "project", "operation", "seed", "as_of", "explain"]
    )]
    config: Option<PathBuf>,

    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project: one holding questions/ and
    /// sources/ beside evidence-project.yaml.
    #[arg(long, conflicts_with_all = ["openapi", "config"])]
    project: Option<PathBuf>,

    /// Narrow ephemeral discovery to one `METHOD /path/template` operation.
    #[arg(long)]
    operation: Option<String>,

    /// Numeric loopback listener address. Standalone mode defaults to 127.0.0.1:4010.
    #[arg(long)]
    http_addr: Option<SocketAddr>,

    /// Deterministic unsigned generation seed. Ephemeral mode defaults to zero.
    #[arg(long)]
    seed: Option<u64>,

    /// Calendar date used only by explicit or inferred age generation.
    #[arg(long)]
    as_of: Option<NaiveDate>,

    /// Explain generator choices without printing generated or authored values.
    #[arg(long)]
    explain: bool,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// OpenAPI document for initial standalone materialization.
    #[arg(long, conflicts_with = "config")]
    openapi: Option<PathBuf>,

    /// Existing editable configuration to complete or extend.
    #[arg(
        long,
        conflicts_with_all = [
            "openapi",
            "output",
            "project",
            "seed",
            "as_of"
        ]
    )]
    config: Option<PathBuf>,

    /// Initial configuration path. Defaults to mocks/source.yaml.
    #[arg(long, requires = "openapi", conflicts_with = "config")]
    output: Option<PathBuf>,

    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project: one holding questions/ and
    /// sources/ beside evidence-project.yaml.
    #[arg(long, conflicts_with_all = ["openapi", "config"])]
    project: Option<PathBuf>,

    /// Select one `METHOD /path/template` operation.
    #[arg(long)]
    operation: Option<String>,

    /// Starter or appended case name for the selected operation.
    #[arg(long, requires = "operation")]
    case: Option<String>,

    /// Concrete selected-operation path parameter as NAME=VALUE; repeat as needed.
    #[arg(long = "path-parameter", requires = "operation")]
    path_parameters: Vec<String>,

    /// Deterministic unsigned generation seed for a new plan. Defaults to zero.
    #[arg(long)]
    seed: Option<u64>,

    /// Calendar date used only by explicit or inferred age generation.
    #[arg(long)]
    as_of: Option<NaiveDate>,

    /// Explain generator choices without printing generated or authored values.
    #[arg(long)]
    explain: bool,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Editable mock configuration. Project mode defaults to mocks/source.yaml.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project: one holding questions/ and
    /// sources/ beside evidence-project.yaml.
    #[arg(long, conflicts_with = "config")]
    project: Option<PathBuf>,
}

pub fn run(command: MockCommand) -> Result<ExitCode> {
    match command {
        MockCommand::Serve(args) => serve(args),
        MockCommand::Generate(args) => generate(args),
        MockCommand::Check(args) => check(args),
    }
}

fn serve(args: ServeArgs) -> Result<ExitCode> {
    match (&args.openapi, &args.config) {
        (_, Some(_))
            if args.operation.is_some()
                || args.seed.is_some()
                || args.as_of.is_some()
                || args.explain =>
        {
            bail!("materialized serve rejects generation and operation-selection flags")
        }
        (Some(openapi_path), None) => {
            let root = current_root()?;
            let openapi_relative = normal_relative(openapi_path, "--openapi")?;
            let bytes = files::read_confined(
                &root,
                &openapi_relative,
                registry_evidence_authoring::layout::MAX_OPENAPI_BYTES,
                "OpenAPI document",
            )?;
            let selected = args
                .operation
                .as_deref()
                .map(openapi::parse_operation)
                .transpose()?;
            let prepared = prepare_with_datasets(
                &root,
                &openapi_relative,
                &bytes,
                "OpenAPI document",
                selected.as_ref(),
            )?;
            let address = args
                .http_addr
                .unwrap_or(DEFAULT_HTTP_ADDR.parse().expect("valid default address"));
            serve_ephemeral(prepared, address, None, args.seed, args.as_of, args.explain)
        }
        (None, Some(config_path)) => {
            let root = current_root()?;
            let config = normal_relative(config_path, "--config")?;
            let checked = load_checked_plan(&root, &config, false)?;
            let address = args
                .http_addr
                .unwrap_or(DEFAULT_HTTP_ADDR.parse().expect("valid default address"));
            serve_materialized(checked, address)
        }
        (None, None) => {
            let root = project_root(args.project.as_deref())?;
            let bytes = files::read_confined(
                &root,
                Path::new(PROJECT_OPENAPI),
                registry_evidence_authoring::layout::MAX_OPENAPI_BYTES,
                "project OpenAPI document",
            )
            .context(
                "bare source mock serve needs this project's source.openapi.yaml; use --openapi FILE outside a project",
            )?;
            let selected = args
                .operation
                .as_deref()
                .map(openapi::parse_operation)
                .transpose()?;
            let prepared = prepare_with_datasets(
                &root,
                Path::new(PROJECT_OPENAPI),
                &bytes,
                "project OpenAPI document",
                selected.as_ref(),
            )?;
            let configured = project_source_binding(&root, &prepared)?;
            if args
                .http_addr
                .is_some_and(|requested| requested != configured.address)
            {
                bail!("--http-addr must exactly match the applicable project source origin");
            }
            serve_ephemeral(
                prepared,
                configured.address,
                Some(configured.routes),
                args.seed,
                args.as_of,
                args.explain,
            )
        }
        (Some(_), Some(_)) => unreachable!("clap rejects both explicit modes"),
    }
}

fn serve_ephemeral(
    prepared: openapi::PreparedOpenApi,
    address: SocketAddr,
    route_overrides: Option<BTreeMap<(String, String), String>>,
    seed: Option<u64>,
    as_of: Option<NaiveDate>,
    explain: bool,
) -> Result<ExitCode> {
    server::validate_numeric_loopback_addr(address)?;
    let seed = seed.unwrap_or(openapi::DEFAULT_SEED);
    let as_of = as_of.unwrap_or_else(default_as_of);
    let mut explanations = Vec::new();
    for operation in &prepared.operations {
        let parameters = operation.witness_parameters().with_context(|| {
            format!(
                "preflighting {} {} needs a safe path-parameter witness",
                operation.key.method, operation.key.path
            )
        })?;
        let (document, _) = prepared.generate(operation, &parameters, seed, as_of)?;
        explanations.extend(document.inference);
    }
    let prepared = Arc::new(prepared);
    let mut routes = Vec::new();
    for index in 0..prepared.operations.len() {
        let state = Arc::clone(&prepared);
        let key = &state.operations[index].key;
        let path = route_overrides
            .as_ref()
            .and_then(|routes| routes.get(&(key.method.clone(), key.path.clone())))
            .cloned()
            .unwrap_or_else(|| key.path.clone());
        routes.push(server::RouteSpec::generated(path, move |parameters| {
            if !state.operations[index].accepts_parameters(parameters) {
                return Ok(None);
            }
            state
                .generate(&state.operations[index], parameters, seed, as_of)
                .map(|(_, bytes)| Some(bytes))
        }));
    }
    for skipped in &prepared.skipped {
        if server::can_compile_route_template(&skipped.key.path) {
            routes.push(server::RouteSpec::unsupported_get(skipped.key.path.clone()));
        }
    }
    let snapshot = server::RouteSnapshot::new(routes)?;
    let skipped_count = prepared.skipped.len();
    let digest = hex::encode(prepared.normalized_digest);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting source mock runtime")?;
    runtime.block_on(server::serve_foreground(snapshot, address, move |ready| {
        println!(
            "Source mock ready: mode=ephemeral origin=http://{} contract={} seed={} asOf={} digest=sha256:{} served={} skipped={}",
            ready.local_addr,
            generator::GENERATOR_CONTRACT,
            seed,
            as_of,
            digest,
            ready.route_count.saturating_sub(ready.unsupported_route_count),
            skipped_count,
        );
        if explain {
            println!(
                "Generation registries: faker={} format={} inference={}",
                generator::FAKER_REGISTRY_ID,
                generator::FORMAT_REGISTRY_ID,
                infer::INFERENCE_REGISTRY_ID,
            );
            print_explanations(&explanations);
        }
        for skipped in &prepared.skipped {
            println!(
                "Skipped {} {}: {}",
                skipped.key.method, skipped.key.path, skipped.reason
            );
        }
        println!("Next: evidencectl source mock generate --openapi <file>");
    }))?;
    Ok(ExitCode::SUCCESS)
}

fn serve_materialized(checked: CheckedPlan, address: SocketAddr) -> Result<ExitCode> {
    server::validate_numeric_loopback_addr(address)?;
    let snapshot = server::RouteSnapshot::new(checked.routes)?;
    let route_count = snapshot.route_count();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting source mock runtime")?;
    runtime.block_on(server::serve_foreground(snapshot, address, move |ready| {
        println!(
            "Source mock ready: mode=materialized origin=http://{} served={} skipped=0",
            ready.local_addr, route_count
        );
    }))?;
    Ok(ExitCode::SUCCESS)
}

fn generate(args: GenerateArgs) -> Result<ExitCode> {
    if args.config.is_some() {
        if args.seed.is_some() || args.as_of.is_some() {
            bail!("generate --config uses the stored generation settings");
        }
        if args.operation.is_some() {
            return append_generated_case(args);
        }
        return generate_missing(args);
    }
    generate_initial(args)
}

fn generate_initial(args: GenerateArgs) -> Result<ExitCode> {
    let root = project_root(args.project.as_deref())?;
    let selected = args
        .operation
        .as_deref()
        .map(openapi::parse_operation)
        .transpose()?;
    let openapi_relative = match args.openapi.as_deref() {
        Some(path) => normal_relative(path, "--openapi")?,
        None => PathBuf::from(PROJECT_OPENAPI),
    };
    let output = args
        .output
        .as_deref()
        .map(|path| normal_relative(path, "--output"))
        .transpose()?
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let bytes = files::read_confined(
        &root,
        &openapi_relative,
        registry_evidence_authoring::layout::MAX_OPENAPI_BYTES,
        "OpenAPI document",
    )?;
    let prepared = prepare_with_datasets(
        &root,
        &openapi_relative,
        &bytes,
        "OpenAPI document",
        selected.as_ref(),
    )?;
    let overrides = parse_path_parameters(&args.path_parameters)?;
    let seed = args.seed.unwrap_or(openapi::DEFAULT_SEED);
    let as_of = args.as_of.unwrap_or_else(default_as_of);
    let mut plan_operations = Vec::new();
    let mut publications = Vec::new();
    let mut total_counts = generator::GenerationCounts::default();

    for operation in prepared.operations.iter().filter(|operation| {
        selected.as_ref().is_none_or(|selected| {
            selected.method == operation.key.method && selected.path == operation.key.path
        })
    }) {
        let parameters = if selected.is_some() && !overrides.is_empty() {
            overrides.clone()
        } else {
            operation.witness_parameters().with_context(|| {
                format!(
                    "cannot scaffold {} {}; pass --operation and the required --path-parameter flags",
                    operation.key.method, operation.key.path
                )
            })?
        };
        let request_parameters = operation.plan_parameters(&parameters)?;
        let (generated, body) = prepared.generate(operation, &parameters, seed, as_of)?;
        if args.explain {
            print_explanations(&generated.inference);
        }
        total_counts.explicit += generated.counts.explicit;
        total_counts.inferred += generated.counts.inferred;
        total_counts.format += generated.counts.format;
        total_counts.generic += generated.counts.generic;
        let case_name = args.case.clone().unwrap_or_else(|| {
            if parameters.is_empty() {
                "default".to_owned()
            } else {
                "sample".to_owned()
            }
        });
        let body_path = case_body_path(&operation.key, &case_name);
        publications.push(PublicationFile::new(&body_path, body));
        plan_operations.push(PlanOperation {
            method: operation.key.method.clone(),
            path: operation.key.path.clone(),
            operation_id: operation.operation_id.clone(),
            response: PlanResponse {
                status: 200,
                media_type: "application/json".to_owned(),
            },
            cases: vec![PlanCase {
                name: case_name,
                request: PlanRequest {
                    path_parameters: request_parameters,
                },
                body: body_path.to_string_lossy().into_owned(),
            }],
        });
    }

    let config_name = output
        .file_name()
        .context("--output must name a config inside a mock directory")?;
    let config_reference = relative_reference(
        output.parent().unwrap_or_else(|| Path::new(".")),
        &openapi_relative,
    )?;
    let plan = MockPlan {
        version: plan::PLAN_VERSION,
        openapi: config_reference,
        openapi_digest: Some(Digest::from_bytes(prepared.normalized_digest)),
        generation: Some(GenerationSettings {
            contract: generator::GENERATOR_CONTRACT.to_owned(),
            seed,
            as_of: as_of.to_string(),
            datasets: prepared
                .datasets
                .iter()
                .map(|(identifier, dataset)| {
                    (identifier.clone(), Digest::from_bytes(dataset.digest))
                })
                .collect(),
        }),
        operations: plan_operations,
    };
    publications.push(PublicationFile::new(config_name, plan::render_plan(&plan)?));
    let published = files::publish_initial_tree(&root.join(&output), &publications)?;
    for path in published {
        println!(
            "Created {}",
            output
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
                .display()
        );
    }
    println!(
        "Generated synthetic values: explicit={} inferred={} format={} generic={}",
        total_counts.explicit, total_counts.inferred, total_counts.format, total_counts.generic
    );
    if args.explain {
        println!(
            "Generator contract={} faker={} format={} inference={}",
            generator::GENERATOR_CONTRACT,
            generator::FAKER_REGISTRY_ID,
            generator::FORMAT_REGISTRY_ID,
            infer::INFERENCE_REGISTRY_ID
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn generate_missing(args: GenerateArgs) -> Result<ExitCode> {
    let root = project_root(args.project.as_deref())?;
    let config = normal_relative(
        args.config
            .as_deref()
            .unwrap_or_else(|| Path::new(DEFAULT_CONFIG)),
        "--config",
    )?;
    let mut checked = load_checked_plan(&root, &config, true)?;
    if checked.missing.is_empty() {
        println!("Mock plan is complete; no body was created.");
        return Ok(ExitCode::SUCCESS);
    }
    let generation = restore_generation_inputs(&root, &config, &mut checked)?;
    let as_of = generation.as_of_date()?;
    let config_dir = root.join(config.parent().unwrap_or_else(|| Path::new(".")));
    let mut publications = Vec::new();
    let mut explanations = Vec::new();
    for (operation_index, case_index) in checked.missing {
        let plan_operation = &checked.plan.operations[operation_index];
        let case = &plan_operation.cases[case_index];
        let key = OperationKey {
            method: plan_operation.method.clone(),
            path: plan_operation.path.clone(),
        };
        let operation = checked
            .prepared
            .operation(&key)
            .context("configured operation is no longer compatible")?;
        let raw = operation.authored_parameters(&case.request.path_parameters)?;
        let (generated, body) =
            checked
                .prepared
                .generate(operation, &raw, generation.seed, as_of)?;
        explanations.extend(generated.inference);
        publications.push(PublicationFile::new(&case.body, body));
    }
    let published = files::publish_missing(&config_dir, &publications)?;
    for path in published {
        println!(
            "Created {}",
            config
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
                .display()
        );
    }
    if args.explain {
        println!(
            "Generator contract={} faker={} format={} inference={}",
            generator::GENERATOR_CONTRACT,
            generator::FAKER_REGISTRY_ID,
            generator::FORMAT_REGISTRY_ID,
            infer::INFERENCE_REGISTRY_ID
        );
        print_explanations(&explanations);
    }
    Ok(ExitCode::SUCCESS)
}

fn append_generated_case(args: GenerateArgs) -> Result<ExitCode> {
    let root = current_root()?;
    let config = normal_relative(
        args.config
            .as_deref()
            .expect("append mode requires --config"),
        "--config",
    )?;
    let case_name = args
        .case
        .as_deref()
        .context("generate --config with --operation also needs --case")?;
    let selected = openapi::parse_operation(
        args.operation
            .as_deref()
            .expect("append mode requires --operation"),
    )?;
    let original = files::read_confined(&root, &config, plan::MAX_PLAN_BYTES as u64, "mock plan")?;
    let mut checked = load_checked_plan(&root, &config, false)?;
    let generation = restore_generation_inputs(&root, &config, &mut checked)?;
    let parameters = parse_path_parameters(&args.path_parameters)?;
    let operation = checked
        .prepared
        .operation(&selected)
        .context("selected operation is not present in the materialized plan")?;
    let request_parameters = operation.plan_parameters(&parameters)?;
    let (generated, body) = checked.prepared.generate(
        operation,
        &parameters,
        generation.seed,
        generation.as_of_date()?,
    )?;
    let body_path = case_body_path(&selected, case_name);

    let plan_operation = checked
        .plan
        .operations
        .iter_mut()
        .find(|operation| operation.method == selected.method && operation.path == selected.path)
        .context("selected operation is not present in the materialized plan")?;
    plan_operation.cases.push(PlanCase {
        name: case_name.to_owned(),
        request: PlanRequest {
            path_parameters: request_parameters,
        },
        body: body_path.to_string_lossy().into_owned(),
    });
    let replacement = plan::render_plan(&checked.plan)?;
    let config_directory = root.join(config.parent().unwrap_or_else(|| Path::new(".")));
    files::ensure_confined_absent(&config_directory, &body_path)?;
    let recovery = files::replace_confined(&root, &config, &original, &replacement)?;
    let publication = PublicationFile::new(&body_path, body);
    let published = files::publish_missing(&config_directory, &[publication]).with_context(|| {
        format!(
            "the case was added to the config but its body was not created; the previous config is preserved at {}; rerun generate --config to complete it",
            recovery.display()
        )
    })?;

    println!("Updated {}", config.display());
    println!("Preserved previous config at {}", recovery.display());
    for path in published {
        println!(
            "Created {}",
            config
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(path)
                .display()
        );
    }
    println!(
        "Generated synthetic values: explicit={} inferred={} format={} generic={}",
        generated.counts.explicit,
        generated.counts.inferred,
        generated.counts.format,
        generated.counts.generic
    );
    if args.explain {
        println!(
            "Generator contract={} faker={} format={} inference={}",
            generator::GENERATOR_CONTRACT,
            generator::FAKER_REGISTRY_ID,
            generator::FORMAT_REGISTRY_ID,
            infer::INFERENCE_REGISTRY_ID
        );
        print_explanations(&generated.inference);
    }
    Ok(ExitCode::SUCCESS)
}

fn restore_generation_inputs(
    root: &Path,
    config: &Path,
    checked: &mut CheckedPlan,
) -> Result<GenerationSettings> {
    let generation = checked
        .plan
        .generation
        .clone()
        .context("generate --config needs retained generation metadata")?;
    if checked.plan.openapi_digest.is_none() {
        bail!("generate --config needs a retained openapiDigest");
    }
    let openapi_relative = files::resolve_openapi_reference(root, config, &checked.plan.openapi)?;
    let openapi_bytes = files::read_confined(
        root,
        &openapi_relative,
        registry_evidence_authoring::layout::MAX_OPENAPI_BYTES,
        "configured OpenAPI document",
    )?;
    let (loaded, undeclared) =
        load_referenced_datasets(root, &openapi_relative, &openapi_bytes, &checked.prepared)?;
    if !undeclared.is_empty() {
        bail!("a configured response recipe references an undeclared dataset");
    }
    let actual_digests = loaded
        .iter()
        .map(|(identifier, dataset)| (identifier.clone(), Digest::from_bytes(dataset.digest)))
        .collect::<BTreeMap<_, _>>();
    if actual_digests != generation.datasets {
        bail!("generation.datasets does not match the current referenced dataset bytes");
    }
    checked.prepared.datasets = loaded;
    Ok(generation)
}

fn check(args: CheckArgs) -> Result<ExitCode> {
    let root = project_root(args.project.as_deref())?;
    let config = normal_relative(
        args.config
            .as_deref()
            .unwrap_or_else(|| Path::new(DEFAULT_CONFIG)),
        "--config",
    )?;
    let checked = load_checked_plan(&root, &config, false)?;
    println!(
        "Mock plan valid: operations={} cases={}",
        checked.plan.operations.len(),
        checked.routes.len()
    );
    Ok(ExitCode::SUCCESS)
}

struct CheckedPlan {
    plan: MockPlan,
    prepared: openapi::PreparedOpenApi,
    routes: Vec<server::RouteSpec>,
    missing: Vec<(usize, usize)>,
}

fn load_checked_plan(root: &Path, config: &Path, allow_missing: bool) -> Result<CheckedPlan> {
    let bytes = files::read_confined(root, config, plan::MAX_PLAN_BYTES as u64, "mock plan")?;
    let plan = plan::parse_plan(&bytes)?;
    let openapi_bytes = files::read_openapi_reference(root, config, &plan.openapi)?;
    let mut prepared = openapi::discover(&openapi_bytes, "configured OpenAPI document", None)?;
    let configured_operations = plan
        .operations
        .iter()
        .map(|operation| (operation.method.clone(), operation.path.clone()))
        .collect::<BTreeSet<_>>();
    if let Some(digest) = plan.openapi_digest {
        let actual = prepared.normalized_digest_for(&configured_operations)?;
        if digest.as_bytes() != &actual {
            bail!("openapiDigest does not match the configured operation surface");
        }
    }
    prepared.operations.retain(|operation| {
        configured_operations.contains(&(operation.key.method.clone(), operation.key.path.clone()))
    });
    let config_dir = root.join(config.parent().unwrap_or_else(|| Path::new(".")));
    let mut routes = Vec::new();
    let mut missing = Vec::new();
    for (operation_index, plan_operation) in plan.operations.iter().enumerate() {
        let key = OperationKey {
            method: plan_operation.method.clone(),
            path: plan_operation.path.clone(),
        };
        let operation = prepared.operation(&key).context(
            "configured operation is not a compatible GET 200 application/json operation",
        )?;
        for (case_index, case) in plan_operation.cases.iter().enumerate() {
            operation.authored_parameters(&case.request.path_parameters)?;
            match files::read_confined(
                &config_dir,
                Path::new(&case.body),
                files::MAX_MOCK_BODY_BYTES,
                "mock response body",
            ) {
                Ok(body) => {
                    let value = parse_json_strict(&body)
                        .map_err(|_| anyhow!("mock response body is not strict JSON"))?;
                    if let Err(failure) = generator::validate_value(&operation.schema, &value) {
                        let instance =
                            serde_json::to_string(if failure.instance_pointer.is_empty() {
                                "/"
                            } else {
                                &failure.instance_pointer
                            })
                            .expect("string serialization cannot fail");
                        let schema = serde_json::to_string(if failure.schema_pointer.is_empty() {
                            "/"
                        } else {
                            &failure.schema_pointer
                        })
                        .expect("string serialization cannot fail");
                        bail!(
                            "body `{}` case `{}` for {} {} failed {} at instance {} schema {}",
                            case.body,
                            case.name,
                            plan_operation.method,
                            plan_operation.path,
                            failure.rule,
                            instance,
                            schema,
                        );
                    }
                    let expanded =
                        plan::expand_path(&plan_operation.path, &case.request.path_parameters)
                            .context("configured case path parameters are invalid")?;
                    routes.push(server::RouteSpec::json(expanded, body));
                }
                Err(_error) if allow_missing && path_is_absent(&config_dir.join(&case.body))? => {
                    missing.push((operation_index, case_index));
                }
                Err(error) => return Err(error),
            }
        }
    }
    if !allow_missing && !missing.is_empty() {
        bail!("mock plan has missing response bodies");
    }
    Ok(CheckedPlan {
        plan,
        prepared,
        routes,
        missing,
    })
}

fn path_is_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error).context("inspecting missing mock response body"),
    }
}

fn parse_path_parameters(arguments: &[String]) -> Result<BTreeMap<String, String>> {
    let mut parameters = BTreeMap::new();
    for argument in arguments {
        let (name, value) = argument
            .split_once('=')
            .context("--path-parameter must use NAME=VALUE")?;
        if name.is_empty()
            || value.is_empty()
            || parameters
                .insert(name.to_owned(), value.to_owned())
                .is_some()
        {
            bail!("--path-parameter names must be non-empty and unique");
        }
    }
    Ok(parameters)
}

fn case_body_path(key: &OperationKey, case_name: &str) -> PathBuf {
    use sha2::{Digest as _, Sha256};

    let label = key
        .path
        .split('/')
        .filter(|segment| !segment.is_empty() && !segment.starts_with('{'))
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
        .collect::<Vec<_>>()
        .join("-");
    let identity = Sha256::digest(format!("{}\0{}", key.method, key.path));
    let operation = format!(
        "{}-{}-{}",
        key.method.to_ascii_lowercase(),
        if label.is_empty() { "root" } else { &label },
        &hex::encode(identity)[..8]
    );
    let case_digest = Sha256::digest(case_name.as_bytes());
    PathBuf::from("cases").join(operation).join(format!(
        "{}-{}.json",
        case_name,
        &hex::encode(case_digest)[..8]
    ))
}

fn relative_reference(from_directory: &Path, target: &Path) -> Result<String> {
    let from = normal_components(from_directory)?;
    let target = normal_components(target)?;
    let common = from
        .iter()
        .zip(&target)
        .take_while(|(left, right)| left == right)
        .count();
    let mut output = PathBuf::new();
    for _ in common..from.len() {
        output.push("..");
    }
    for component in &target[common..] {
        output.push(component);
    }
    output
        .to_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .context("OpenAPI path cannot be represented relative to the config")
}

fn normal_components(path: &Path) -> Result<Vec<String>> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => components.push(
                component
                    .to_str()
                    .context("mock paths must be UTF-8")?
                    .to_owned(),
            ),
            _ => bail!("mock paths must stay beneath the selected project root"),
        }
    }
    Ok(components)
}

fn normal_relative(path: &Path, label: &str) -> Result<PathBuf> {
    let components = normal_components(path).with_context(|| format!("validating {label}"))?;
    if components.is_empty() {
        bail!("{label} must name a project-relative file");
    }
    Ok(components.iter().collect())
}

fn current_root() -> Result<PathBuf> {
    std::env::current_dir().context("reading the current directory")
}

fn project_root(project: Option<&Path>) -> Result<PathBuf> {
    match project {
        Some(project) => {
            let metadata = fs::symlink_metadata(project).context("inspecting --project")?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("--project must be a plain directory");
            }
            Ok(project.to_path_buf())
        }
        None => current_root(),
    }
}

fn default_as_of() -> NaiveDate {
    NaiveDate::parse_from_str(openapi::DEFAULT_AS_OF, "%Y-%m-%d").expect("valid default date")
}

fn prepare_with_datasets(
    root: &Path,
    openapi_relative: &Path,
    bytes: &[u8],
    origin: &str,
    selected: Option<&OperationKey>,
) -> Result<openapi::PreparedOpenApi> {
    let mut prepared = openapi::discover(bytes, origin, selected)?;
    let (datasets, undeclared) =
        load_referenced_datasets(root, openapi_relative, bytes, &prepared)?;
    prepared.isolate_undeclared_datasets(&undeclared, selected)?;
    prepared.datasets = datasets;
    Ok(prepared)
}

fn load_referenced_datasets(
    root: &Path,
    openapi_relative: &Path,
    bytes: &[u8],
    prepared: &openapi::PreparedOpenApi,
) -> Result<(
    BTreeMap<String, generator::ReferenceDataset>,
    BTreeSet<String>,
)> {
    use registry_evidence_authoring::{openapi::openapi::Spec, valid_local_identifier};
    use sha2::{Digest as _, Sha256};

    const MAX_DATASET_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_DATASET_ROWS: usize = 10_000;
    const MAX_DATASET_FIELDS: usize = 256;

    let text = std::str::from_utf8(bytes).context("OpenAPI document must be UTF-8")?;
    let spec = Spec::parse(text, "OpenAPI document")?;
    let mut declarations = BTreeMap::new();
    if let Some(hint) = spec.mock_hint() {
        let root_hint = hint
            .as_object()
            .context("root x-evidencectl-mock must be an object")?;
        if root_hint.keys().any(|key| key != "datasets") {
            bail!("root x-evidencectl-mock contains an unknown field");
        }
        let datasets = root_hint
            .get("datasets")
            .map(|datasets| {
                datasets
                    .as_object()
                    .context("x-evidencectl-mock.datasets must be an object")
            })
            .transpose()?
            .cloned()
            .unwrap_or_default();
        if datasets.len() > plan::MAX_DATASETS {
            bail!("x-evidencectl-mock.datasets exceeds its entry limit");
        }
        for (identifier, declaration) in datasets {
            if !valid_local_identifier(&identifier) {
                bail!("a mock dataset has an invalid local identifier");
            }
            let declaration = declaration
                .as_object()
                .context("each mock dataset declaration must be an object")?;
            if declaration.len() != 1 || !declaration.contains_key("path") {
                bail!("each mock dataset declaration must contain only path");
            }
            let path = declaration
                .get("path")
                .and_then(Value::as_str)
                .context("mock dataset path must be a string")?;
            declarations.insert(
                identifier,
                normal_relative(Path::new(path), "dataset path")?,
            );
        }
    }

    let referenced = prepared.referenced_dataset_ids()?;
    let openapi_parent = openapi_relative.parent().unwrap_or_else(|| Path::new("."));
    let mut loaded = BTreeMap::new();
    let mut undeclared = BTreeSet::new();
    for identifier in referenced {
        let Some(declared) = declarations.get(&identifier) else {
            undeclared.insert(identifier);
            continue;
        };
        let relative = openapi_parent.join(declared);
        let raw = files::read_confined(root, &relative, MAX_DATASET_BYTES, "mock dataset")?;
        let value =
            parse_json_strict(&raw).map_err(|_| anyhow!("mock dataset is not strict JSON"))?;
        let rows = value
            .as_array()
            .filter(|rows| !rows.is_empty() && rows.len() <= MAX_DATASET_ROWS)
            .context("mock dataset must be a bounded non-empty array")?
            .iter()
            .map(|row| {
                let row = row
                    .as_object()
                    .filter(|row| row.len() <= MAX_DATASET_FIELDS)
                    .context("every mock dataset row must be a bounded object")?;
                Ok(row.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        loaded.insert(
            identifier,
            generator::ReferenceDataset {
                digest: Sha256::digest(&raw).into(),
                rows,
            },
        );
    }
    Ok((loaded, undeclared))
}

struct ProjectSourceBinding {
    address: SocketAddr,
    routes: BTreeMap<(String, String), String>,
}

fn project_source_binding(
    root: &Path,
    prepared: &openapi::PreparedOpenApi,
) -> Result<ProjectSourceBinding> {
    let sources = root.join("sources");
    let metadata = fs::symlink_metadata(&sources).context(
        "project mock serve needs a compiled source; run source suggest --base-url http://127.0.0.1:4010",
    )?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("sources must be a plain directory");
    }
    let mut files = fs::read_dir(&sources)
        .context("reading project sources")?
        .collect::<std::io::Result<Vec<_>>>()?;
    files.sort_by_key(fs::DirEntry::file_name);
    let operation_keys = prepared
        .operations
        .iter()
        .map(|operation| (operation.key.method.as_str(), operation.key.path.as_str()))
        .collect::<BTreeSet<_>>();
    let mut addresses = BTreeSet::new();
    let mut routes = BTreeMap::new();
    for entry in files {
        let name = entry.file_name();
        let relative = PathBuf::from("sources").join(&name);
        if relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("yaml")
        {
            continue;
        }
        let bytes =
            files::read_confined(root, &relative, plan::MAX_PLAN_BYTES as u64, "source draft")?;
        let value: serde_norway::Value =
            serde_norway::from_slice(&bytes).context("source draft YAML is invalid")?;
        let method = value
            .get("request")
            .and_then(|request| request.get("method"))
            .and_then(serde_norway::Value::as_str);
        let path = value.get("request").and_then(|request| {
            request
                .get("pathTemplate")
                .or_else(|| request.get("path"))
                .and_then(serde_norway::Value::as_str)
        });
        let Some((method, source_path)) = method.zip(path) else {
            continue;
        };
        let Some(operation) = select_project_operation(&operation_keys, method, source_path) else {
            continue;
        };
        let base_url = value
            .get("baseUrl")
            .and_then(serde_norway::Value::as_str)
            .context("applicable project sources need an explicit baseUrl")?;
        addresses.insert(loopback_origin_address(base_url)?);
        let key = (operation.0.to_owned(), operation.1.to_owned());
        if routes
            .insert(key, source_path.to_owned())
            .is_some_and(|existing| existing != source_path)
        {
            bail!("applicable project sources disagree on the served request path");
        }
    }
    if addresses.len() != 1 {
        bail!("applicable project sources must agree on one numeric-loopback origin; rerun source suggest with --base-url")
    }
    let address = addresses
        .into_iter()
        .next()
        .context("project has no applicable compiled source; run source suggest --base-url")?;
    Ok(ProjectSourceBinding { address, routes })
}

fn select_project_operation<'a>(
    operation_keys: &BTreeSet<(&'a str, &'a str)>,
    method: &str,
    source_path: &str,
) -> Option<(&'a str, &'a str)> {
    if let Some(exact) = operation_keys
        .iter()
        .copied()
        .find(|candidate| candidate.0 == method && candidate.1 == source_path)
    {
        return Some(exact);
    }
    operation_keys
        .iter()
        .copied()
        .filter(|candidate| {
            candidate.0 == method
                && source_path
                    .strip_suffix(candidate.1)
                    .is_some_and(|prefix| prefix.starts_with('/') && prefix.len() > 1)
        })
        .max_by_key(|candidate| candidate.1.len())
}

fn loopback_origin_address(origin: &str) -> Result<SocketAddr> {
    let url = url::Url::parse(origin).context("parsing project source baseUrl")?;
    if url.scheme() != "http"
        || url.username() != ""
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("project mock sources must use a plain numeric-loopback HTTP origin");
    }
    let ip = match url.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        _ => bail!("project mock sources must use a numeric-loopback host"),
    };
    let port = url
        .port()
        .context("project mock source origin needs a non-zero port")?;
    let address = SocketAddr::new(ip, port);
    server::validate_numeric_loopback_addr(address)
}

fn print_explanations(explanations: &[generator::ExplainedInference]) {
    for explanation in explanations {
        let pointer = if explanation.schema_pointer.is_empty() {
            "/"
        } else {
            &explanation.schema_pointer
        };
        let decision = &explanation.decision;
        let pointer = serde_json::to_string(pointer).expect("string serialization cannot fail");
        let property = serde_json::to_string(&decision.property_key)
            .expect("string serialization cannot fail");
        if decision.selected() {
            println!(
                "Inference pointer={} property={} rule={} score={} generator={}",
                pointer,
                property,
                decision.rule_id.unwrap_or("none"),
                decision.score.unwrap_or(0),
                decision
                    .recipe
                    .map(infer::InferredRecipe::id)
                    .unwrap_or_else(|| "generic".to_owned())
            );
        } else if let Some(fallback) = decision.fallback {
            println!(
                "Inference pointer={} property={} fallback={}",
                pointer,
                property,
                fallback.label()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_sources_prefer_exact_then_longest_operation_suffix() {
        let operations = BTreeSet::from([
            ("GET", "/people/{id}"),
            ("GET", "/v1/people/{id}"),
            ("POST", "/v1/people/{id}"),
        ]);

        assert_eq!(
            select_project_operation(&operations, "GET", "/v1/people/{id}"),
            Some(("GET", "/v1/people/{id}"))
        );
        assert_eq!(
            select_project_operation(&operations, "GET", "/v1/v1/people/{id}"),
            Some(("GET", "/v1/people/{id}"))
        );
    }
}
