// SPDX-License-Identifier: Apache-2.0

//! Startup loading: read the pinned project, profile and pack and the
//! operator runtime config, run the authoring checks the runtime also
//! stands on, and compile what the facade serves.
//!
//! Loading is all-or-nothing for the artifacts (any refusal stops startup)
//! and per-binding for routes: a binding whose route uses a step kind or
//! token path this runtime does not serve is left unserved with a named
//! refusal, never registered, so nothing it says is silently skipped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use registry_adapter_core::{
    check_project_pins, check_workspace, AdapterPack, AdapterProfile, AdapterProject,
    AdapterRuntimeConfig, AggregationStrategy, ComponentKind, Endpoint, SendComponent, Step,
    ToParameters, Workspace, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
    ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION,
    ADAPTER_PROJECT_KIND, ADAPTER_REMOVED_KEYS, ADAPTER_RUNTIME_API_VERSION, ADAPTER_RUNTIME_KIND,
};
use registry_platform_config::{
    sha256_uri, AuthoredExpressions, RuntimeConfigLoader, RuntimeEnvelope, SecretProvider,
    SecretResolver,
};
use registry_platform_yaml::{
    ApiVersion, Digest, EnvelopeRule, Expect, FormatSpec, Reader, Severity,
};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::auth::{AuthPlan, PlatformAssertionSigner, StaticCredential};
use crate::component::graphql::GraphQlQuery;
use crate::egress::EndpointEgress;
use crate::envelope::CompiledEnvelope;
use crate::read_request::{ReadRequestTemplate, ServedFilter};
use crate::route::{
    check_direct_targets, check_servable, is_served_auth, EndpointRuntime, RouteTable,
};
use crate::scripts::{CodeMaps, ScriptSet};
use registry_adapter_core::{Expression, RouteTemplate};
use serde_json::Value;

/// The ceiling on any upstream reply body a send keeps, and the unit the
/// script bounds scale from; an endpoint declares its own bound beneath it.
pub(crate) const MAXIMUM_RESPONSE_BYTES: usize =
    registry_adapter_core::MAXIMUM_RESPONSE_BYTES as usize;

/// Why one binding is not compiled for serving.
enum BindingRefusal {
    /// The runtime does not serve the binding yet (a path it does not
    /// implement, an unbound endpoint); startup warns and goes on.
    NotServed {
        reason: UnservedReason,
        detail: String,
    },
    /// The binding's own files are faulty (an unreadable, uninventoried,
    /// digest-mismatched or uncompilable script); startup refuses.
    Fault(String),
}

#[derive(Clone, Copy)]
pub(crate) enum UnservedReason {
    ProfileOperationMissing,
    ReservedFacadePath,
    MethodUnsupported,
    WriteAsyncUnsupported,
    RequestBodyUnsupported,
    RequestEnvelopeMissing,
    PaginationDeclarationMissing,
    RecordTypeMissing,
    FilterFieldMissing,
    RouteInstantiationRefused,
    RouteMissing,
    CursorKeyMissing,
    RouteUnsupported,
    WriteIdempotencyMissing,
    DirectRouteMissing,
    SourceAuthenticationUnsupported,
    SourceComponentMismatch,
    SourceUnbound,
    RecordSchemaUnavailable,
    /// A job-only component send sits in a bound route: the authoring
    /// checks raise `adapter.job.send-component-refused`, and the loader
    /// holds the same refusal so a pack assembled without them never
    /// serves.
    JobComponentSend,
}

impl UnservedReason {
    const fn code(self) -> &'static str {
        match self {
            Self::ProfileOperationMissing => "adapter.operation.profile-operation-missing",
            Self::ReservedFacadePath => "adapter.operation.reserved-facade-path",
            Self::MethodUnsupported => "adapter.operation.method-unsupported",
            Self::WriteAsyncUnsupported => "adapter.operation.write-async-unsupported",
            Self::RequestBodyUnsupported => "adapter.operation.request-body-unsupported",
            Self::RequestEnvelopeMissing => "adapter.operation.request-envelope-missing",
            Self::PaginationDeclarationMissing => {
                "adapter.operation.pagination-declaration-missing"
            }
            Self::RecordTypeMissing => "adapter.operation.record-type-missing",
            Self::FilterFieldMissing => "adapter.operation.filter-field-missing",
            Self::RouteInstantiationRefused => "adapter.operation.route-instantiation-refused",
            Self::RouteMissing => "adapter.operation.route-missing",
            Self::CursorKeyMissing => "adapter.operation.cursor-key-missing",
            Self::RouteUnsupported => "adapter.operation.route-unsupported",
            Self::WriteIdempotencyMissing => "adapter.operation.write-idempotency-missing",
            Self::DirectRouteMissing => "adapter.operation.direct-route-missing",
            Self::SourceAuthenticationUnsupported => {
                "adapter.operation.source-authentication-unsupported"
            }
            Self::SourceComponentMismatch => "adapter.operation.source-component-mismatch",
            Self::SourceUnbound => "adapter.operation.source-unbound",
            Self::RecordSchemaUnavailable => "adapter.operation.record-schema-unavailable",
            Self::JobComponentSend => registry_adapter_core::JobCode::SendComponentRefused.code(),
        }
    }
}

fn not_served(reason: UnservedReason, detail: impl Into<String>) -> BindingRefusal {
    BindingRefusal::NotServed {
        reason,
        detail: detail.into(),
    }
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("{path} could not be read")]
    Unreadable { path: String },
    #[error("no {file} beside the project in {directory}; pass {flag} FILE")]
    Absent {
        file: &'static str,
        directory: String,
        flag: &'static str,
    },
    #[error("{path} was refused: {reasons}")]
    Refused { path: String, reasons: String },
    #[error("the workspace check refused the deployment: {0}")]
    Workspace(String),
    #[error("{0}")]
    Runtime(String),
}

/// One facade operation this runtime answers.
pub struct ServedOperation {
    pub operation: String,
    pub method: registry_adapter_core::HttpMethod,
    pub method_path: String,
    /// The compiled request envelope of a read over POST.
    pub request_template: Option<ReadRequestTemplate>,
    /// The largest request body, in bytes, this operation reads.
    pub request_maximum_bytes: usize,
    /// The filters the binding declares, each with its record field's type.
    pub filters: Vec<ServedFilter>,
    pub record_type_parameter: String,
    pub record_id_parameter: Option<String>,
    pub binding: String,
    pub record_type: String,
    pub route_id: String,
    /// The route this operation runs, the one list the deployment's
    /// table holds: a `to: direct:` call into the same route runs these
    /// same steps.
    pub steps: Arc<Vec<Step>>,
    /// The breaker and throttle state of the whole route table, shared
    /// by every served operation so a route and a direct call into it
    /// pace and break on the same nodes, addressed by node for the
    /// process lifetime.
    pub resilience: crate::resilience::ResilienceRuntime,
    pub maximum_upstream_calls: u64,
    pub response_envelope: CompiledEnvelope,
    /// The per-record template filled into the response envelope's
    /// `record` and `records` slots, when the operation declares one.
    pub item_envelope: Option<ServedItem>,
    /// The closed schema of one record this operation may disclose: the
    /// bound record type's declared fields and nothing else.
    pub record_schema: Value,
    /// The cursor and page-size parameters of a search operation.
    pub pagination: Option<ServedPagination>,
}

/// A compiled item envelope and whether it needs the record's identifier.
pub struct ServedItem {
    pub envelope: CompiledEnvelope,
    pub names_record_id: bool,
}

/// The pagination parameters one served search operation declares.
pub struct ServedPagination {
    pub cursor_parameter: String,
    pub page_size_parameter: String,
    pub page_size_minimum: u64,
    pub page_size_maximum: u64,
    /// The page size a call that names none gets, when the profile
    /// declares one.
    pub page_size_default: Option<u64>,
}

/// The request body bound of a read that declares none: 16 KiB.
pub const DEFAULT_REQUEST_MAXIMUM_BYTES: usize = 16 * 1024;

/// Everything startup produced.
pub struct Loaded {
    pub profile: AdapterProfile,
    /// The profile's problem envelope, compiled once.
    pub problem_envelope: CompiledEnvelope,
    pub project: AdapterProject,
    pub runtime: AdapterRuntimeConfig,
    pub scripts: ScriptSet,
    /// The deployment's declared code maps, shared by the conversion
    /// steps and the Rhai `code_map` helper (section 8.6).
    pub code_maps: CodeMaps,
    pub endpoints: BTreeMap<String, EndpointRuntime>,
    /// Every route the deployment declares, pack routes and templated
    /// instantiations alike: what the facade serves and what a
    /// `to: direct:` call resolves against.
    pub routes: RouteTable,
    pub served: Vec<ServedOperation>,
    /// `(binding id, why)` for every binding left unserved.
    pub unserved: Vec<UnservedBinding>,
    pub resolver: SecretResolver,
    /// A digest of the project, profile and pack bytes, so a cursor
    /// minted under other artifacts is refused.
    pub deployment: String,
}

/// One project binding the runtime left unserved, with a stable reason code
/// for machine consumers and a value-free operator detail.
pub struct UnservedBinding {
    pub binding: String,
    pub reason_code: &'static str,
    pub reason: String,
}

/// The source-neutral authored state shared by live serving and offline
/// fixture replay. It contains no runtime config, resolver, listener or
/// database handle.
pub(crate) struct CompiledAuthoring {
    pub(crate) problem_envelope: CompiledEnvelope,
    pub(crate) scripts: ScriptSet,
    pub(crate) code_maps: CodeMaps,
    pub(crate) endpoints: BTreeMap<String, EndpointRuntime>,
    pub(crate) routes: RouteTable,
    pub(crate) served: Vec<ServedOperation>,
    pub(crate) unserved: Vec<UnservedBinding>,
}

/// What an endpoint factory contributes to authored compilation.
pub(crate) enum EndpointCompilation {
    Served(Box<EndpointEgress>),
    Unserved {
        reason: UnservedReason,
        detail: String,
    },
    Absent,
}

impl Loaded {
    /// The problems view the facade answers refusals from.
    #[must_use]
    pub fn problems(&self) -> crate::facade::Problems<'_> {
        crate::facade::Problems {
            profile: &self.profile,
            envelope: &self.problem_envelope,
        }
    }
}

/// Whether a served operation already answers the facade method and path:
/// the router takes one handler per method and path, so a second binding on
/// it would never be reached.
fn serves_path(
    served: &[ServedOperation],
    method: registry_adapter_core::HttpMethod,
    path: &str,
) -> bool {
    served
        .iter()
        .any(|operation| operation.method == method && operation.method_path == path)
}

pub(crate) fn format_spec(kind: &'static str, api_version: &'static str) -> FormatSpec<'static> {
    FormatSpec {
        kind,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: Box::leak(Box::new([ApiVersion::current(api_version)])),
            retired_api_versions: &[],
        },
        removed_keys: &[],
    }
}

pub(crate) fn read<T: DeserializeOwned>(
    path: &Path,
    format: &FormatSpec<'static>,
) -> Result<(T, Vec<u8>), LoadError> {
    let shown = path.display().to_string();
    let bytes = std::fs::read(path).map_err(|_| LoadError::Unreadable {
        path: shown.clone(),
    })?;
    let mut hook = AuthoredExpressions;
    let decoded = Reader::new(shown.clone())
        .with_hook(&mut hook)
        .decode::<T>(&bytes, &Expect::one(format))
        .map_err(|refused| LoadError::Refused {
            path: shown,
            reasons: refused
                .into_diagnostics()
                .iter()
                .map(|diagnostic| format!("{} {}", diagnostic.code, diagnostic.message))
                .collect::<Vec<_>>()
                .join("; "),
        })?;
    Ok((decoded.value, bytes))
}

/// Resolve every secret reference of an endpoint's static credential, so
/// a reference that names no secret refuses startup and not the first send.
/// The resolved values are dropped unread; the sender resolves them again
/// per send.
fn resolve_static_credential(
    endpoint: &str,
    plan: &AuthPlan,
    resolver: &SecretResolver,
) -> Result<(), LoadError> {
    let references: Vec<&str> = match plan.static_credential() {
        Some(StaticCredential::Basic {
            username_ref,
            password_ref,
        }) => vec![username_ref.as_str(), password_ref.as_str()],
        Some(StaticCredential::Authorization { token_ref, .. }) => vec![token_ref.as_str()],
        Some(StaticCredential::ApiKey { value_ref, .. }) => vec![value_ref.as_str()],
        None => Vec::new(),
    };
    for reference in references {
        resolver.resolve(reference).map_err(|_| {
            LoadError::Runtime(format!(
                "endpoint {endpoint} credential reference {reference} did not resolve"
            ))
        })?;
    }
    Ok(())
}

/// Refuse credentials whose local material cannot support the endpoint
/// before the deployment serves callers. Static credentials retain their
/// existing resolution check; private-key JWT additionally resolves and
/// proves the signing key without contacting the token endpoint.
pub(crate) fn preflight_endpoint_credential(
    endpoint: &str,
    plan: &AuthPlan,
    resolver: &SecretResolver,
) -> Result<(), LoadError> {
    resolve_static_credential(endpoint, plan, resolver)?;
    if let Some(token) = plan.token_plan() {
        token
            .preflight_private_key_jwt(resolver, &PlatformAssertionSigner)
            .map_err(|_| {
                LoadError::Runtime(format!(
                    "endpoint {endpoint} private-key JWT credential was refused"
                ))
            })?;
    }
    Ok(())
}

fn digest_of(bytes: &[u8]) -> Digest {
    Digest::new(sha256_uri(bytes)).expect("a computed sha256 uri is a valid digest")
}

/// The profile or pack a deployment loads: the file the flag names, else
/// the file beside the project. A project does not say where its pack
/// lives, so a missing default refuses with the file and the flag to pass.
pub(crate) fn artifact_path(
    given: Option<&Path>,
    project_directory: &Path,
    file: &'static str,
    flag: &'static str,
) -> Result<PathBuf, LoadError> {
    if let Some(path) = given {
        return Ok(path.to_path_buf());
    }
    let beside = project_directory.join(file);
    if beside.exists() {
        return Ok(beside);
    }
    Err(LoadError::Absent {
        file,
        directory: project_directory.display().to_string(),
        flag,
    })
}

/// Load the deployment: `project_directory` holds `project.yaml`;
/// `profile_path` and `pack_path` name the profile and pack files, each
/// defaulting to `profile.yaml` or `pack.yaml` beside the project. The
/// pack's `scripts/` resolve against the pack file's own directory.
/// `runtime_path` is the operator runtime config.
pub fn load(
    project_directory: &Path,
    profile_path: Option<&Path>,
    pack_path: Option<&Path>,
    runtime_path: &Path,
) -> Result<Loaded, LoadError> {
    let (project, project_bytes): (AdapterProject, _) = read(
        &project_directory.join("project.yaml"),
        &format_spec(ADAPTER_PROJECT_KIND, ADAPTER_PROJECT_API_VERSION),
    )?;
    let profile_path = artifact_path(profile_path, project_directory, "profile.yaml", "--profile")?;
    let (profile, profile_bytes): (AdapterProfile, _) = read(
        &profile_path,
        &format_spec(ADAPTER_PROFILE_KIND, ADAPTER_PROFILE_API_VERSION),
    )?;
    let pack_path = artifact_path(pack_path, project_directory, "pack.yaml", "--pack")?;
    let (pack, pack_bytes): (AdapterPack, _) = read(
        &pack_path,
        &format_spec(ADAPTER_PACK_KIND, ADAPTER_PACK_API_VERSION),
    )?;
    let pack_directory = pack_path.parent().unwrap_or_else(|| Path::new("."));
    let absolute = std::fs::canonicalize(runtime_path).map_err(|_| LoadError::Unreadable {
        path: runtime_path.display().to_string(),
    })?;
    let runtime = RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: ADAPTER_RUNTIME_API_VERSION,
        kind: ADAPTER_RUNTIME_KIND,
    })
    .removed_keys(ADAPTER_REMOVED_KEYS)
    .load::<AdapterRuntimeConfig>(&absolute)
    .map_err(|error| LoadError::Runtime(format!("the runtime config was refused: {error}")))?
    .config;

    let mut findings: Vec<String> = Vec::new();
    for diagnostic in check_project_pins(
        &project,
        &profile.version,
        &digest_of(&profile_bytes),
        &pack.version,
        &digest_of(&pack_bytes),
    ) {
        findings.push(format!("{} {}", diagnostic.code, diagnostic.message));
    }
    for diagnostic in check_workspace(&Workspace {
        profile: &profile,
        pack: &pack,
        project: &project,
        runtime: Some(&runtime),
        fixtures: &[],
    }) {
        if diagnostic.severity == Severity::Error {
            findings.push(format!("{} {}", diagnostic.code, diagnostic.message));
        }
    }
    if !findings.is_empty() {
        return Err(LoadError::Workspace(findings.join("; ")));
    }

    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .map_err(|_| LoadError::Runtime("the secret resolver could not start".to_owned()))?;

    let deployment = sha256_uri(
        &[project_bytes.as_slice(), &profile_bytes, &pack_bytes]
            .iter()
            .flat_map(|bytes| {
                let mut framed = (bytes.len() as u64).to_be_bytes().to_vec();
                framed.extend_from_slice(bytes);
                framed
            })
            .collect::<Vec<u8>>(),
    );
    let has_cursor_key = runtime.cursor_key_ref.is_some();
    if runtime.previous_cursor_key_ref.is_some() && !has_cursor_key {
        return Err(LoadError::Runtime(
            "previousCursorKeyRef is set without cursorKeyRef; a previous key only opens cursors the current key sealed"
                .to_owned(),
        ));
    }

    let authored = compile_authored_with(
        &project,
        &profile,
        &pack,
        pack_directory,
        &deployment,
        has_cursor_key,
        |declared| {
            let id = declared.id.as_str();
            let Some(binding) = runtime.endpoints.get(id) else {
                return Ok(EndpointCompilation::Absent);
            };
            let plan = AuthPlan::compile(&declared.authentication, binding).map_err(|fault| {
                LoadError::Runtime(format!(
                    "endpoint {id} authentication was refused: {fault:?}"
                ))
            })?;
            if !is_served_auth(plan.kind()) {
                return Ok(EndpointCompilation::Unserved {
                    reason: UnservedReason::SourceAuthenticationUnsupported,
                    detail: "its authentication is not served by this runtime".to_owned(),
                });
            }
            let egress =
                EndpointEgress::compile(binding, declared, &runtime.endpoint_bindings(), &resolver)
                    .map_err(|fault| {
                        LoadError::Runtime(format!(
                            "endpoint {id} outbound state was refused: {fault}"
                        ))
                    })?;
            preflight_endpoint_credential(id, egress.plan(), &resolver)?;
            Ok(EndpointCompilation::Served(Box::new(egress)))
        },
    )?;
    Ok(Loaded {
        profile,
        problem_envelope: authored.problem_envelope,
        project,
        runtime,
        scripts: authored.scripts,
        code_maps: authored.code_maps,
        endpoints: authored.endpoints,
        routes: authored.routes,
        served: authored.served,
        unserved: authored.unserved,
        resolver,
        deployment,
    })
}

/// Compile the authored runtime state over endpoint egress supplied by the
/// caller. Live startup and offline replay share this exact route, script,
/// GraphQL, code-map and binding compiler; only endpoint transport differs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compile_authored_with<F>(
    project: &AdapterProject,
    profile: &AdapterProfile,
    pack: &AdapterPack,
    pack_directory: &Path,
    _deployment: &str,
    has_cursor_key: bool,
    mut endpoint_factory: F,
) -> Result<CompiledAuthoring, LoadError>
where
    F: FnMut(&Endpoint) -> Result<EndpointCompilation, LoadError>,
{
    let mut scripts = ScriptSet::default();
    let mut endpoints = BTreeMap::new();
    let mut endpoint_refusals: BTreeMap<String, (UnservedReason, String)> = BTreeMap::new();
    for declared in pack.endpoints.iter() {
        let id = declared.id.as_str().to_owned();
        let egress = match endpoint_factory(declared)? {
            EndpointCompilation::Served(egress) => *egress,
            EndpointCompilation::Unserved { reason, detail } => {
                endpoint_refusals.insert(id, (reason, detail));
                continue;
            }
            EndpointCompilation::Absent => continue,
        };
        let base = format!(
            "{}{}",
            egress.origin().origin_url().trim_end_matches('/'),
            egress.origin().base_path()
        );
        let (attempt, maximum_response_bytes) = (egress.attempt(), egress.maximum_response_bytes());
        let graphql = if declared.component == ComponentKind::GraphQl {
            let query = GraphQlQuery::load(pack, pack_directory, declared).map_err(|fault| {
                LoadError::Runtime(format!("endpoint {id} query was refused: {fault}"))
            })?;
            if let Some(Expression::Rhai(script)) = &query.variables {
                scripts
                    .add(pack, pack_directory, &script.file, &script.entrypoint)
                    .map_err(|error| LoadError::Runtime(error.to_string()))?;
            }
            Some(query)
        } else {
            None
        };
        endpoints.insert(
            id,
            EndpointRuntime {
                egress,
                base,
                graphql,
                safe_post_operations: declared
                    .operations
                    .iter()
                    .filter(|operation| operation.safe_upstream)
                    .map(|operation| operation.id.as_str().to_owned())
                    .collect(),
                attempt,
                maximum_response_bytes,
            },
        );
    }

    let mut routes: RouteTable = BTreeMap::new();
    let mut route_refusals: BTreeMap<String, String> = BTreeMap::new();
    for route in &pack.routes {
        routes.insert(route.id.as_str().to_owned(), Arc::new(route.steps.clone()));
    }
    for templated in &project.templated_routes {
        let id = templated.route_id.as_str();
        let built = match pack.route_templates.get(templated.route_template.as_str()) {
            Some(template) => instantiate(template, &templated.parameters)
                .map(|steps| routes.insert(id.to_owned(), Arc::new(steps))),
            None => Err("the templated route names no pack template".to_owned()),
        };
        if let Err(reason) = built {
            routes.remove(id);
            route_refusals.insert(id.to_owned(), reason);
        }
    }
    check_direct_targets(&routes).map_err(LoadError::Runtime)?;

    let mut deployment_resilience = crate::resilience::ResilienceRuntime::empty();
    for steps in routes.values() {
        deployment_resilience.absorb(steps);
    }

    let mut table_script_uses: Vec<(String, String)> = Vec::new();
    let mut table_strategy_uses: Vec<(String, String)> = Vec::new();
    for steps in routes.values() {
        registry_adapter_core::walk_steps(steps, &mut |step, _pointer| {
            for expression in step_expressions(step) {
                if let Expression::Rhai(script) = expression {
                    table_script_uses.push((script.file.clone(), script.entrypoint.clone()));
                }
            }
            for strategy in step_aggregation_strategies(step) {
                if let AggregationStrategy::Rhai { expression: script } = strategy {
                    table_strategy_uses.push((script.file.clone(), script.entrypoint.clone()));
                }
            }
        });
    }
    for (file, entrypoint) in table_script_uses {
        scripts
            .add(pack, pack_directory, &file, &entrypoint)
            .map_err(|error| LoadError::Runtime(error.to_string()))?;
    }
    for (file, entrypoint) in table_strategy_uses {
        scripts
            .add_aggregation(pack, pack_directory, &file, &entrypoint)
            .map_err(|error| LoadError::Runtime(error.to_string()))?;
    }

    let code_maps: CodeMaps = Arc::new(
        pack.code_maps
            .iter()
            .map(|map| (map.id.as_str().to_owned(), map.clone()))
            .collect(),
    );
    let mut unknown_map_ids: Vec<String> = Vec::new();
    for steps in routes.values() {
        registry_adapter_core::walk_steps(steps, &mut |step, _pointer| {
            let convert = match step {
                Step::ConvertBodyTo(convert)
                | Step::ConvertHeaderTo(convert)
                | Step::ConvertPropertyTo(convert) => convert,
                _ => return,
            };
            if let Some(id) = convert.code_map_id() {
                if code_maps.get(id).is_none() {
                    unknown_map_ids.push(id.to_owned());
                }
            }
        });
    }
    if !unknown_map_ids.is_empty() {
        unknown_map_ids.sort();
        unknown_map_ids.dedup();
        return Err(LoadError::Runtime(format!(
            "route conversions name no declared code map: {}",
            unknown_map_ids.join(", ")
        )));
    }

    let mut served = Vec::new();
    let mut unserved = Vec::new();
    for binding in project.bindings.iter() {
        let outcome = compile_binding(
            binding,
            project,
            pack,
            profile,
            pack_directory,
            &endpoints,
            &endpoint_refusals,
            &routes,
            &route_refusals,
            &deployment_resilience,
            has_cursor_key,
            &mut scripts,
        );
        match outcome {
            Ok(operation) => {
                if serves_path(&served, operation.method, &operation.method_path) {
                    return Err(LoadError::Runtime(format!(
                        "binding {} was refused: another binding already serves the facade path {}",
                        binding.id.as_str(),
                        operation.method_path
                    )));
                }
                served.push(operation);
            }
            Err(BindingRefusal::NotServed { reason, detail }) => {
                unserved.push(UnservedBinding {
                    binding: binding.id.as_str().to_owned(),
                    reason_code: reason.code(),
                    reason: detail,
                });
            }
            Err(BindingRefusal::Fault(reason)) => {
                return Err(LoadError::Runtime(format!(
                    "binding {} was refused: {reason}",
                    binding.id.as_str()
                )));
            }
        }
    }
    let problem_envelope =
        CompiledEnvelope::compile(profile.problem_envelope.text(), &BTreeMap::new()).map_err(
            |reason| LoadError::Runtime(format!("the problem envelope is unusable: {reason}")),
        )?;

    Ok(CompiledAuthoring {
        problem_envelope,
        scripts,
        code_maps,
        endpoints,
        routes,
        served,
        unserved,
    })
}

#[allow(clippy::too_many_arguments)]
fn compile_binding(
    binding: &registry_adapter_core::Binding,
    project: &AdapterProject,
    pack: &AdapterPack,
    profile: &AdapterProfile,
    pack_directory: &Path,
    endpoints: &BTreeMap<String, EndpointRuntime>,
    endpoint_refusals: &BTreeMap<String, (UnservedReason, String)>,
    routes: &RouteTable,
    route_refusals: &BTreeMap<String, String>,
    deployment_resilience: &crate::resilience::ResilienceRuntime,
    has_cursor_key: bool,
    scripts: &mut ScriptSet,
) -> Result<ServedOperation, BindingRefusal> {
    let operation = profile
        .operations
        .get(binding.operation.as_str())
        .ok_or_else(|| {
            not_served(
                UnservedReason::ProfileOperationMissing,
                "the binding names no profile operation",
            )
        })?;
    let concrete_method_path = operation.path.replace(
        &format!("{{{}}}", operation.record_type_parameter.as_str()),
        binding.record_type.as_str(),
    );
    if concrete_method_path == crate::effective_contract::WELL_KNOWN_PATH {
        return Err(not_served(
            UnservedReason::ReservedFacadePath,
            "the facade path is reserved for the Adapter effective-contract route",
        ));
    }
    let is_post_read =
        operation.method == registry_adapter_core::HttpMethod::Post && operation.read_only;
    let is_read = operation.is_read();
    if is_read && operation.method != registry_adapter_core::HttpMethod::Get && !is_post_read {
        return Err(not_served(
            UnservedReason::MethodUnsupported,
            "a read facade operation is served only as GET or a readOnly POST",
        ));
    }
    if !is_read
        && !matches!(
            operation.method,
            registry_adapter_core::HttpMethod::Post | registry_adapter_core::HttpMethod::Put
        )
    {
        return Err(not_served(
            UnservedReason::MethodUnsupported,
            "a write facade operation is served only as POST or PUT in this slice",
        ));
    }
    if !is_read && operation.success_status.get() == 202 {
        return Err(not_served(
            UnservedReason::WriteAsyncUnsupported,
            "a write successStatus of 202 is not served before asynchronous completion recovery is implemented",
        ));
    }
    if operation.method == registry_adapter_core::HttpMethod::Get
        && operation.request_envelope.is_some()
    {
        return Err(not_served(
            UnservedReason::RequestBodyUnsupported,
            "a GET read carries no request body, so its request envelope is not served",
        ));
    }
    // A write envelope may name `record`; the facade captures and
    // validates it on the write path. The read template deliberately
    // rejects that slot, so compile it only for read operations.
    let request_template = if is_post_read {
        operation
            .request_envelope
            .as_ref()
            .map(|envelope| ReadRequestTemplate::compile(envelope.text()))
            .transpose()
            .map_err(|reason| {
                BindingRefusal::Fault(format!("the request envelope is unusable: {reason}"))
            })?
    } else {
        None
    };
    if is_post_read && request_template.is_none() {
        return Err(not_served(
            UnservedReason::RequestEnvelopeMissing,
            "a read over POST declares no request envelope",
        ));
    }
    if request_template
        .as_ref()
        .is_some_and(|template| template.names("pageSize") || template.names("cursor"))
        && operation.pagination.is_none()
    {
        return Err(not_served(
            UnservedReason::PaginationDeclarationMissing,
            "the request envelope names a pagination slot on an operation with no pagination",
        ));
    }
    let record_type_declaration = project
        .record_types
        .get(binding.record_type.as_str())
        .ok_or_else(|| {
            not_served(
                UnservedReason::RecordTypeMissing,
                "the binding names no declared record type",
            )
        })?;
    let mut filters = Vec::with_capacity(binding.filters.len());
    for name in binding.filters.iter() {
        let field = record_type_declaration
            .fields
            .iter()
            .find(|field| field.name.as_str() == name.as_str())
            .ok_or_else(|| {
                not_served(
                    UnservedReason::FilterFieldMissing,
                    "the binding declares a filter no record field carries",
                )
            })?;
        filters.push(ServedFilter {
            name: name.as_str().to_owned(),
            field_type: field.r#type,
        });
    }
    let route_id = binding.route.as_str();
    let steps = if let Some(steps) = routes.get(route_id) {
        Arc::clone(steps)
    } else if let Some(reason) = route_refusals.get(route_id) {
        return Err(not_served(
            UnservedReason::RouteInstantiationRefused,
            reason.clone(),
        ));
    } else {
        return Err(not_served(
            UnservedReason::RouteMissing,
            "the binding names no route",
        ));
    };
    if operation.pagination.is_some() && !has_cursor_key {
        return Err(not_served(
            UnservedReason::CursorKeyMissing,
            "a paginated operation needs cursorKeyRef in the runtime config to seal its cursors",
        ));
    }
    check_servable(&steps)
        .map_err(|reason| not_served(UnservedReason::RouteUnsupported, reason))?;
    if !is_read {
        let executable: Vec<&Step> = steps
            .iter()
            .filter(|step| !matches!(step, Step::OnException(_) | Step::ErrorHandler(_)))
            .collect();
        if !matches!(executable.as_slice(), [Step::IdempotentConsumer(_)]) {
            return Err(not_served(
                UnservedReason::WriteIdempotencyMissing,
                "a write operation needs one outer idempotentConsumer around its executable route",
            ));
        }
    }

    let mut refusal: Option<(UnservedReason, String)> = None;
    let mut script_uses: Vec<(String, String)> = Vec::new();
    let mut strategy_uses: Vec<(String, String)> = Vec::new();
    registry_adapter_core::walk_steps(&steps, &mut |step, _pointer| {
        // A direct send resolves against the route table, not the
        // endpoints; every other send goes to a bound endpoint.
        let destination = match step {
            Step::To(to) => Some(&to.uri),
            Step::Enrich(enrich) => Some(&enrich.uri),
            _ => None,
        };
        if let Some(uri) = destination {
            if uri.component == SendComponent::Direct {
                if !routes.contains_key(&uri.id) {
                    refusal.get_or_insert((
                        UnservedReason::DirectRouteMissing,
                        format!(
                            "the direct route {} is declared by no route in the deployment",
                            uri.id
                        ),
                    ));
                }
            } else if matches!(
                uri.component,
                SendComponent::Postgres | SendComponent::File | SendComponent::Sftp
            ) {
                // A job component is never a facade send destination or
                // enrich resource: a file or sftp source is read through
                // the pollEnrich step and a postgres source send is
                // served in a source route only.
                refusal.get_or_insert((UnservedReason::JobComponentSend, String::new()));
            } else if let Some((reason, detail)) = endpoint_refusals.get(&uri.id) {
                refusal.get_or_insert((*reason, format!("endpoint {}: {detail}", uri.id)));
            } else if let Some(endpoint) = endpoints.get(&uri.id) {
                // A send reaches an endpoint of its own component: a
                // graphql send posts the endpoint's pinned query, an
                // http send never does (section 8.8).
                if uri.component == SendComponent::GraphQl && endpoint.graphql.is_none() {
                    refusal.get_or_insert((
                        UnservedReason::SourceComponentMismatch,
                        format!("endpoint {} is not a graphql endpoint", uri.id),
                    ));
                } else if uri.component == SendComponent::Http && endpoint.graphql.is_some() {
                    refusal.get_or_insert((
                        UnservedReason::SourceComponentMismatch,
                        format!("endpoint {} is not an http endpoint", uri.id),
                    ));
                }
            } else {
                refusal.get_or_insert((
                    UnservedReason::SourceUnbound,
                    format!("endpoint {} is not bound by the runtime", uri.id),
                ));
            }
        }
        for expression in step_expressions(step) {
            if let Expression::Rhai(script) = expression {
                script_uses.push((script.file.clone(), script.entrypoint.clone()));
            }
        }
        for strategy in step_aggregation_strategies(step) {
            if let AggregationStrategy::Rhai { expression: script } = strategy {
                strategy_uses.push((script.file.clone(), script.entrypoint.clone()));
            }
        }
    });
    if let Some((reason, detail)) = refusal {
        return Err(not_served(reason, detail));
    }
    for (file, entrypoint) in script_uses {
        scripts
            .add(pack, pack_directory, &file, &entrypoint)
            .map_err(|error| BindingRefusal::Fault(error.to_string()))?;
    }
    // A strategy script answers the old and new bodies, so it compiles as
    // a two-parameter function.
    for (file, entrypoint) in strategy_uses {
        scripts
            .add_aggregation(pack, pack_directory, &file, &entrypoint)
            .map_err(|error| BindingRefusal::Fault(error.to_string()))?;
    }
    Ok(ServedOperation {
        operation: operation.id.as_str().to_owned(),
        method: operation.method,
        method_path: operation.path.clone(),
        request_template,
        request_maximum_bytes: operation
            .request_maximum_bytes
            .map_or(DEFAULT_REQUEST_MAXIMUM_BYTES, |bound| {
                usize::try_from(bound.get()).unwrap_or(DEFAULT_REQUEST_MAXIMUM_BYTES)
            }),
        filters,
        record_type_parameter: operation.record_type_parameter.as_str().to_owned(),
        record_id_parameter: operation
            .record_id_parameter
            .as_ref()
            .map(|name| name.as_str().to_owned()),
        binding: binding.id.as_str().to_owned(),
        record_type: binding.record_type.as_str().to_owned(),
        route_id: route_id.to_owned(),
        steps,
        resilience: deployment_resilience.clone(),
        maximum_upstream_calls: binding.maximum_upstream_calls.get(),
        response_envelope: CompiledEnvelope::compile(
            operation.response_envelope.text(),
            &project.parameterized_parts,
        )
        .map_err(|reason| {
            BindingRefusal::Fault(format!("the response envelope is unusable: {reason}"))
        })?,
        item_envelope: operation
            .item_envelope
            .as_ref()
            .map(|item| {
                CompiledEnvelope::compile(item.text(), &project.parameterized_parts).map(
                    |envelope| ServedItem {
                        envelope,
                        names_record_id: item.mentions("recordId"),
                    },
                )
            })
            .transpose()
            .map_err(|reason| {
                BindingRefusal::Fault(format!("the item envelope is unusable: {reason}"))
            })?,
        record_schema: registry_adapter_core::binding_record_schema(project, binding)
            .map_err(|reason| not_served(UnservedReason::RecordSchemaUnavailable, reason))?,
        pagination: operation
            .pagination
            .as_ref()
            .map(|pagination| ServedPagination {
                cursor_parameter: pagination.cursor_parameter.as_str().to_owned(),
                page_size_parameter: pagination.page_size_parameter.as_str().to_owned(),
                page_size_minimum: pagination.page_size_minimum.get(),
                page_size_maximum: pagination.page_size_maximum.get(),
                page_size_default: pagination.page_size_default.map(|default| default.get()),
            }),
    })
}

/// The template's steps with each parameter's supplied value (or its
/// default) written in. A `{{name}}` that is a whole string takes the
/// value with its type; inside longer text it takes the value's text. A
/// placeholder of a parameter with neither a supplied value nor a
/// default stays for the send to bind per request.
fn instantiate(
    template: &RouteTemplate,
    supplied: &BTreeMap<String, Value>,
) -> Result<Vec<Step>, String> {
    let mut values: BTreeMap<&str, &Value> = BTreeMap::new();
    for parameter in &template.parameters {
        let name = parameter.name.as_str();
        if let Some(value) = supplied.get(name).or(parameter.default_value.as_ref()) {
            values.insert(name, value);
        }
    }
    let mut document = serde_json::to_value(&template.steps)
        .map_err(|error| format!("the template could not be read back: {error}"))?;
    substitute(&mut document, &values);
    serde_json::from_value(document)
        .map_err(|error| format!("the instantiated template is not a route: {error}"))
}

fn substitute(node: &mut Value, values: &BTreeMap<&str, &Value>) {
    match node {
        Value::String(text) => {
            for (name, value) in values {
                for placeholder in [format!("{{{{{name}}}}}"), format!("{{{{?{name}}}}}")] {
                    if *text == placeholder {
                        *node = (*value).clone();
                        return;
                    }
                    if text.contains(&placeholder) {
                        let rendered = match value {
                            Value::String(plain) => plain.clone(),
                            other => other.to_string(),
                        };
                        *text = text.replace(&placeholder, &rendered);
                    }
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| substitute(item, values)),
        Value::Object(members) => members
            .values_mut()
            .for_each(|member| substitute(member, values)),
        _ => {}
    }
}

/// The expressions one step carries directly (the walker visits nested
/// steps itself). Owned, because the inline predicates of `choice` and
/// `filter` decode to a value rather than sitting in a field.
pub(crate) fn step_expressions(step: &Step) -> Vec<Expression> {
    match step {
        Step::SetBody(expression) | Step::Transform(expression) | Step::Script(expression) => {
            vec![expression.clone()]
        }
        Step::SetHeader(header) => vec![header.value.clone()],
        Step::SetProperty(property) => vec![property.value.clone()],
        Step::Validate(validate) => vec![validate.expression.clone()],
        Step::ThrowException(throw) => throw.data.iter().cloned().collect(),
        Step::Choice(choice) => choice
            .when
            .iter()
            .filter_map(|clause| clause.predicate())
            .collect(),
        Step::Filter(filter) => filter.predicate().into_iter().collect(),
        Step::Split(split) => vec![split.expression.clone()],
        Step::Loop(looped) => looped.expression().into_iter().collect(),
        Step::Throttle(throttle) => vec![throttle.limit.clone()],
        Step::To(to) => send_expressions(to.parameters.as_ref()),
        Step::Enrich(enrich) => send_expressions(enrich.parameters.as_ref()),
        Step::OnException(clause) => clause
            .on_when
            .iter()
            .chain(clause.retry_while.iter())
            .cloned()
            .collect(),
        Step::ErrorHandler(handler) => handler
            .default_error_handler
            .as_ref()
            .and_then(|handler| handler.retry_while.as_ref())
            .into_iter()
            .cloned()
            .collect(),
        Step::DoTry(block) => block
            .do_catch
            .iter()
            .filter_map(|catch| catch.on_when.clone())
            .collect(),
        _ => Vec::new(),
    }
}

/// Every expression one send carries, including the dynamic link and
/// request body whose Rhai files must be compiled before the route runs.
fn send_expressions(parameters: Option<&ToParameters>) -> Vec<Expression> {
    let Some(parameters) = parameters else {
        return Vec::new();
    };
    let mut expressions = Vec::new();
    expressions.extend(parameters.http_uri.iter().cloned());
    expressions.extend(parameters.body.iter().cloned());
    expressions.extend(parameters.path_parameters.values().cloned());
    expressions.extend(parameters.query.values().cloned());
    expressions
}

/// The aggregation strategies a step carries directly.
pub(crate) fn step_aggregation_strategies(step: &Step) -> Vec<&AggregationStrategy> {
    match step {
        Step::Split(split) => split.aggregation_strategy.as_ref().into_iter().collect(),
        Step::Enrich(enrich) => enrich.aggregation_strategy.as_ref().into_iter().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PREFLIGHT_KEY: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;

    fn private_key_plan(key_env: &str) -> AuthPlan {
        let binding = registry_adapter_core::EndpointBinding {
            endpoint: registry_platform_yaml::ExternalId::new("private-key-source")
                .expect("endpoint id"),
            base_url: registry_platform_yaml::Url::new("https://source.example.invalid")
                .expect("base url"),
            credential: Some(
                registry_adapter_core::RuntimeCredential::Oauth2PrivateKeyJwt {
                    token_endpoint: registry_platform_yaml::Url::new(
                        "https://tokens.example.invalid/token",
                    )
                    .expect("token endpoint"),
                    client_id_ref: registry_platform_yaml::SecretReference::new(
                        "secret:env/ADAPTER_PREFLIGHT_CLIENT_ID",
                    )
                    .expect("client id reference"),
                    client_assertion_key_ref: registry_platform_yaml::SecretReference::new(
                        format!("secret:env/{key_env}"),
                    )
                    .expect("key reference"),
                    client_assertion_audience: None,
                    scope: None,
                    audience: None,
                    resource: None,
                    maximum_cache_seconds: registry_platform_yaml::BoundedU64::<0, 86_400>::new(
                        3600,
                    )
                    .expect("cache ceiling"),
                    assumed_lifetime_seconds: None,
                },
            ),
            anonymous_https: None,
            tls_trust_profile: None,
            mtls_identity: None,
            attempt_timeout_milliseconds: None,
            maximum_response_bytes: None,
        };
        AuthPlan::compile(
            &registry_adapter_core::EndpointAuthentication::Oauth2PrivateKeyJwt {},
            &binding,
        )
        .expect("plan compiles")
    }

    #[test]
    fn startup_preflights_private_key_jwt_material_value_free() {
        const KEY_ENV: &str = "ADAPTER_PREFLIGHT_PRIVATE_KEY";
        std::env::set_var("ADAPTER_PREFLIGHT_CLIENT_ID", "preflight-client");
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let plan = private_key_plan(KEY_ENV);

        std::env::remove_var(KEY_ENV);
        let missing = preflight_endpoint_credential("private-key-source", &plan, &resolver)
            .expect_err("a missing key refuses startup")
            .to_string();

        let key_canary = "PREFLIGHT-KEY-CANARY-not-a-jwk";
        std::env::set_var(KEY_ENV, key_canary);
        let malformed = preflight_endpoint_credential("private-key-source", &plan, &resolver)
            .expect_err("an unreadable key refuses startup")
            .to_string();

        let unpaired = PREFLIGHT_KEY.replace(
            "1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        std::env::set_var(KEY_ENV, &unpaired);
        let invalid = preflight_endpoint_credential("private-key-source", &plan, &resolver)
            .expect_err("a key whose halves do not pair refuses startup")
            .to_string();

        for refusal in [&missing, &malformed, &invalid] {
            assert!(refusal.contains("private-key-source"), "{refusal}");
            assert!(refusal.contains("credential was refused"), "{refusal}");
            assert!(!refusal.contains(KEY_ENV), "{refusal}");
            assert!(!refusal.contains(key_canary), "{refusal}");
            assert!(!refusal.contains(&unpaired), "{refusal}");
        }

        std::env::set_var(KEY_ENV, PREFLIGHT_KEY);
        preflight_endpoint_credential("private-key-source", &plan, &resolver)
            .expect("a usable key passes startup");
    }

    #[test]
    fn send_expression_inventory_includes_dynamic_uri_body_path_and_query() {
        let parameters: ToParameters = serde_json::from_value(json!({
            "httpUri": {"rhai": {"file": "uri.rhai", "entrypoint": "uri"}},
            "body": {"rhai": {"file": "body.rhai", "entrypoint": "body"}},
            "pathParameters": {"id": {"rhai": {"file": "path.rhai", "entrypoint": "path"}}},
            "query": {"q": {"rhai": {"file": "query.rhai", "entrypoint": "query"}}}
        }))
        .expect("send parameters parse");

        let files: Vec<String> = send_expressions(Some(&parameters))
            .into_iter()
            .filter_map(|expression| match expression {
                Expression::Rhai(script) => Some(script.file),
                _ => None,
            })
            .collect();
        assert_eq!(files.len(), 4, "every send expression is compiled at load");
        for file in ["uri.rhai", "body.rhai", "path.rhai", "query.rhai"] {
            assert!(files.iter().any(|seen| seen == file), "missing {file}");
        }
    }

    #[test]
    fn throw_exception_data_expression_is_in_the_load_inventory() {
        let step = Step::ThrowException(registry_adapter_core::ThrowExceptionStep {
            exception_type: registry_adapter_core::ErrorClass::OutcomeRejected,
            message: None,
            data: Some(Expression::Rhai(registry_adapter_core::RhaiExpression {
                file: "problem.rhai".to_owned(),
                entrypoint: "problem_data".to_owned(),
            })),
        });

        let files: Vec<String> = step_expressions(&step)
            .into_iter()
            .filter_map(|expression| match expression {
                Expression::Rhai(script) => Some(script.file),
                _ => None,
            })
            .collect();
        assert_eq!(files, ["problem.rhai"]);
    }

    fn template() -> RouteTemplate {
        serde_json::from_value(json!({
            "id": "search",
            "parameters": [
                {"name": "program", "type": "string", "required": true},
                {"name": "size", "type": "number", "defaultValue": 25},
                {"name": "id", "type": "string"}
            ],
            "steps": [
                {"setProperty": {"name": "program", "value": {"constant": "{{program}}"}}},
                {"setProperty": {"name": "size", "value": {"constant": "{{size}}"}}},
                {"to": {"uri": "http:tracker", "parameters": {
                    "httpMethod": "GET",
                    "path": "/api/{{program}}/{{id}}",
                    "pathParameters": {"id": {"header": "recordId"}}
                }}}
            ]
        }))
        .expect("the template parses")
    }

    fn supplied(program: &str) -> BTreeMap<String, Value> {
        BTreeMap::from([("program".to_owned(), json!(program))])
    }

    #[test]
    fn a_whole_placeholder_takes_the_typed_value_and_a_default_fills_an_omission() {
        let steps = instantiate(&template(), &supplied("abc")).expect("instantiates");
        let document = serde_json::to_value(&steps).expect("serializes");
        assert_eq!(document[0]["setProperty"]["value"]["constant"], "abc");
        assert_eq!(document[1]["setProperty"]["value"]["constant"], 25);
    }

    #[test]
    fn a_placeholder_inside_text_takes_the_text_and_an_unsupplied_one_stays() {
        let steps = instantiate(&template(), &supplied("abc")).expect("instantiates");
        let document = serde_json::to_value(&steps).expect("serializes");
        assert_eq!(
            document[2]["to"]["parameters"]["path"], "/api/abc/{{id}}",
            "{{id}} is bound per request by pathParameters"
        );
    }

    #[test]
    fn a_second_binding_on_a_served_path_is_found() {
        let operation = ServedOperation {
            operation: "records-get".to_owned(),
            method: registry_adapter_core::HttpMethod::Get,
            request_template: None,
            request_maximum_bytes: DEFAULT_REQUEST_MAXIMUM_BYTES,
            filters: Vec::new(),
            method_path: "/v1/records/{recordType}/{id}".to_owned(),
            record_type_parameter: "recordType".to_owned(),
            record_id_parameter: Some("id".to_owned()),
            binding: "person-get".to_owned(),
            record_type: "person".to_owned(),
            route_id: "route".to_owned(),
            steps: Arc::new(Vec::new()),
            resilience: crate::resilience::ResilienceRuntime::empty(),
            maximum_upstream_calls: 1,
            item_envelope: None,
            response_envelope: CompiledEnvelope::compile("{}", &BTreeMap::new()).unwrap(),
            record_schema: json!({}),
            pagination: None,
        };
        let served = [operation];
        let get = registry_adapter_core::HttpMethod::Get;
        let post = registry_adapter_core::HttpMethod::Post;
        assert!(serves_path(&served, get, "/v1/records/{recordType}/{id}"));
        assert!(!serves_path(&served, post, "/v1/records/{recordType}/{id}"));
        assert!(!serves_path(&served, get, "/v1/records/{recordType}"));
    }

    #[test]
    fn a_missing_pack_beside_the_project_names_the_file_and_the_flag() {
        let directory = tempfile::tempdir().expect("a scratch directory");
        let error = artifact_path(None, directory.path(), "pack.yaml", "--pack")
            .expect_err("no pack sits beside the project");
        let text = error.to_string();
        assert!(
            text.contains("pack.yaml") && text.contains("--pack"),
            "{text}"
        );
    }

    #[test]
    fn a_flag_wins_over_the_file_beside_the_project() {
        let directory = tempfile::tempdir().expect("a scratch directory");
        std::fs::write(directory.path().join("pack.yaml"), "").expect("write a pack");
        let given = Path::new("/elsewhere/pack.yaml");
        assert_eq!(
            artifact_path(Some(given), directory.path(), "pack.yaml", "--pack").unwrap(),
            given
        );
        assert_eq!(
            artifact_path(None, directory.path(), "pack.yaml", "--pack").unwrap(),
            directory.path().join("pack.yaml")
        );
    }

    #[test]
    fn a_map_parameter_instantiates_as_the_whole_object() {
        let template: RouteTemplate = serde_json::from_value(json!({
            "id": "search",
            "parameters": [{"name": "labels", "type": "map", "defaultValue": {}}],
            "steps": [
                {"setProperty": {"name": "labels", "value": {"constant": "{{labels}}"}}}
            ]
        }))
        .expect("the template parses");
        let supplied = BTreeMap::from([("labels".to_owned(), json!({"a": "b"}))]);
        let steps = serde_json::to_value(instantiate(&template, &supplied).expect("instantiates"))
            .expect("steps serialize");
        assert_eq!(
            steps[0]["setProperty"]["value"]["constant"],
            json!({"a": "b"})
        );

        let defaulted = serde_json::to_value(instantiate(&template, &BTreeMap::new()).unwrap())
            .expect("steps serialize");
        assert_eq!(defaulted[0]["setProperty"]["value"]["constant"], json!({}));
    }
}
