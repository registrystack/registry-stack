// SPDX-License-Identifier: Apache-2.0

//! Startup loading: read the pinned project, profile and pack and the
//! operator runtime config, run the authoring checks the runtime also
//! stands on, and compile what the facade serves.
//!
//! Loading is all-or-nothing for the artifacts (any refusal stops startup)
//! and per-binding for routes: a binding whose route uses a step kind or
//! token path this runtime does not serve is left unserved with a named
//! refusal, never registered, so nothing it says is silently skipped.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use registry_adapter_core::{
    check_project_pins, check_workspace, AdapterPack, AdapterProfile, AdapterProject,
    AdapterRuntimeConfig, AggregationStrategy, ComponentKind, Endpoint, SendComponent,
    ServedFilter, Step, ToParameters, Workspace, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
    ADAPTER_PROFILE_API_VERSION, ADAPTER_PROFILE_KIND, ADAPTER_PROJECT_API_VERSION,
    ADAPTER_PROJECT_KIND, ADAPTER_REMOVED_KEYS, ADAPTER_RUNTIME_API_VERSION, ADAPTER_RUNTIME_KIND,
};
use registry_platform_config::{
    sha256_uri, AuthoredExpressions, RuntimeConfigLoader, RuntimeEnvelope, SecretError,
    SecretProvider, SecretResolver,
};
use registry_platform_yaml::{
    ApiVersion, Digest, EnvelopeRule, Expect, FormatSpec, Reader, Severity,
};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::artifacts::{ArtifactSource, PackArtifactBytes};
use crate::async_completion::{
    AcceptedIdSelector, AsyncSourceOperation, ServedAsyncOperation, ServedAsyncStatusRoute,
    ServedAsyncUncertainty,
};
use crate::auth::{AuthPlan, PlatformAssertionSigner, StaticCredential};
use crate::component::graphql::GraphQlQuery;
use crate::egress::EndpointEgress;
use crate::envelope::CompiledEnvelope;
use crate::read_request::ReadRequestTemplate;
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
pub enum UnservedReason {
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
#[derive(Debug)]
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
    /// Optional project-owned transformation applied to each acquired source
    /// item before protocol wrapping and disclosure validation.
    pub project_transform: Option<Arc<crate::project_transform::CompiledProjectTransform>>,
    /// Full project-owned Lookup/Search values schema. The facade validates
    /// the captured input object against it before any source route runs.
    pub project_input_schema: Option<Arc<crate::public_schema::CheckedPublicSchema>>,
    /// Explicit source-neutral read semantics for the selected ordinary or
    /// instantiated route. A Consultation host never infers these guarantees.
    pub read_support: Option<registry_adapter_core::SourceReadSupport>,
    /// The cursor and page-size parameters of a search operation.
    pub pagination: Option<ServedPagination>,
    /// The compiled source-native 202 and status proof contract, absent on
    /// every synchronous operation.
    pub async_completion: Option<ServedAsyncOperation>,
    /// The closed linear multi-effect checkpoint plan, absent on ordinary
    /// single-effect and read operations.
    #[doc(hidden)]
    pub resume: Option<crate::resume::ServedResumeOperation>,
}

impl ServedOperation {
    /// Number of non-safe source steps in the closed linear resume plan.
    /// `None` identifies an ordinary single-effect or read operation.
    #[must_use]
    pub fn resume_step_count(&self) -> Option<u32> {
        self.resume
            .as_ref()
            .and_then(|resume| u32::try_from(resume.step_count()).ok())
    }
}

/// A compiled item envelope and whether it needs the record's identifier.
#[derive(Debug)]
pub struct ServedItem {
    pub envelope: CompiledEnvelope,
    pub names_record_id: bool,
}

/// The pagination parameters one served search operation declares.
#[derive(Debug)]
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
#[derive(Debug)]
pub struct UnservedBinding {
    pub binding: String,
    pub reason_code: &'static str,
    pub reason: String,
}

/// The source-neutral authored state shared by live serving and offline
/// fixture replay. It contains no runtime config, resolver, listener or
/// database handle.
#[derive(Debug)]
pub struct CompiledAuthoring {
    pub problem_envelope: CompiledEnvelope,
    pub scripts: ScriptSet,
    pub code_maps: CodeMaps,
    pub endpoints: BTreeMap<String, EndpointRuntime>,
    pub routes: RouteTable,
    pub served: Vec<ServedOperation>,
    pub unserved: Vec<UnservedBinding>,
}

/// What an endpoint factory contributes to authored compilation.
pub enum EndpointCompilation {
    Served(Box<EndpointEgress>),
    Unserved {
        reason: UnservedReason,
        detail: String,
    },
    Absent,
}

/// Why the facade router cannot take `candidate` beside the operations
/// already served, if it cannot. A templated path serves one concrete path
/// per record type, so a second binding on the same method and concrete
/// path would never be reached. The router also refuses two paths of one
/// shape whose parameters are named differently, whatever their methods.
fn path_conflict(served: &[ServedOperation], candidate: &ServedOperation) -> Option<String> {
    let concrete = path_shape(&concrete_path(candidate));
    let shape = path_shape(&candidate.method_path);
    served.iter().find_map(|operation| {
        if operation.method == candidate.method && path_shape(&concrete_path(operation)) == concrete
        {
            Some(format!(
                "another binding already serves the facade path {}",
                candidate.method_path
            ))
        } else if path_shape(&operation.method_path) == shape
            && operation.method_path != candidate.method_path
        {
            Some(format!(
                "its facade path {} names its path parameters differently from the served path {}",
                candidate.method_path, operation.method_path
            ))
        } else {
            None
        }
    })
}

/// The facade path a served operation answers, with its record type in
/// place of the record-type parameter.
fn concrete_path(operation: &ServedOperation) -> String {
    operation.method_path.replace(
        &format!("{{{}}}", operation.record_type_parameter),
        &operation.record_type,
    )
}

/// A facade path with every parameter unnamed, whether it fills a segment
/// or sits inside one, the form the router matches on.
fn path_shape(path: &str) -> String {
    registry_adapter_core::facade_path_shape(path)
}

pub(crate) fn format_spec(kind: &'static str, api_version: &'static str) -> FormatSpec<'static> {
    FormatSpec {
        kind,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: Box::leak(Box::new([ApiVersion::current(api_version)])),
            retired_api_versions: &[],
        },
        removed_keys: if kind == ADAPTER_PROJECT_KIND {
            registry_adapter_core::ADAPTER_PROJECT_REMOVED_KEYS
        } else {
            &[]
        },
    }
}

/// Read one authored artifact through the shared reader for the format
/// its envelope names: the boundary's public artifact read for hosts
/// that assemble their own documents (`registry-adapter-job`'s status
/// and inspect surfaces), under the same envelope, expression, and
/// unknown-key discipline the compile path reads through.
///
/// # Errors
///
/// An unreadable path or a refused document, the reader's own report
/// rendered value-free.
pub fn read_artifact<T: DeserializeOwned>(
    path: &Path,
    kind: &'static str,
    api_version: &'static str,
) -> Result<(T, Vec<u8>), LoadError> {
    read(path, &format_spec(kind, api_version))
}

pub(crate) fn read<T: DeserializeOwned>(
    path: &Path,
    format: &FormatSpec<'static>,
) -> Result<(T, Vec<u8>), LoadError> {
    read_located(path, format)
        .map(|(value, bytes, _warnings)| (value, bytes))
        .map_err(|refusal| match refusal {
            ReadRefusal::Unreadable(error) => error,
            ReadRefusal::Refused { path, diagnostics } => LoadError::Refused {
                path,
                reasons: diagnostics
                    .iter()
                    .map(located_reason)
                    .collect::<Vec<_>>()
                    .join("; "),
            },
        })
}

/// One reader finding as a sentence an author can act on: the code, the
/// pointer to the faulty member, the reader's message, and its fix.
fn located_reason(diagnostic: &registry_platform_yaml::Diagnostic) -> String {
    let at = if diagnostic.path.is_empty() {
        String::new()
    } else {
        format!(" at {}", diagnostic.path)
    };
    let mut reason = format!("{}{at}: {}", diagnostic.code, diagnostic.message);
    if !diagnostic.suggested_action.is_empty() {
        reason.push_str(". ");
        reason.push_str(&diagnostic.suggested_action);
    }
    reason
}

/// Why [`read_located`] could not decode an artifact.
pub(crate) enum ReadRefusal {
    /// The file could not be read.
    Unreadable(LoadError),
    /// The reader refused the document: its own located findings, each
    /// with the code, pointer, and position an author fixes.
    Refused {
        path: String,
        diagnostics: Vec<registry_platform_yaml::Diagnostic>,
    },
}

/// The same read as [`read`], keeping the reader's located findings
/// instead of folding them into one message, and returning the
/// document's warnings beside the value.
pub(crate) fn read_located<T: DeserializeOwned>(
    path: &Path,
    format: &FormatSpec<'static>,
) -> Result<(T, Vec<u8>, Vec<registry_platform_yaml::Diagnostic>), ReadRefusal> {
    let shown = path.display().to_string();
    let bytes = std::fs::read(path).map_err(|_| {
        ReadRefusal::Unreadable(LoadError::Unreadable {
            path: shown.clone(),
        })
    })?;
    let mut hook = AuthoredExpressions;
    let decoded = Reader::new(shown.clone())
        .with_hook(&mut hook)
        .decode::<T>(&bytes, &Expect::one(format))
        .map_err(|refused| ReadRefusal::Refused {
            path: shown,
            diagnostics: refused.into_diagnostics(),
        })?;
    let warnings = decoded.document.warnings().into_diagnostics();
    Ok((decoded.value, bytes, warnings))
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
        resolve_credential_reference(endpoint, reference, resolver)?;
    }
    Ok(())
}

/// Resolve one credential reference, naming the value-free cause and the
/// fix when it does not resolve.
fn resolve_credential_reference(
    endpoint: &str,
    reference: &str,
    resolver: &SecretResolver,
) -> Result<(), LoadError> {
    resolver.resolve(reference).map(drop).map_err(|error| {
        LoadError::Runtime(format!(
            "endpoint {endpoint} credential reference {reference} did not resolve: {error}; next: {}",
            secret_refusal_fix(&error)
        ))
    })
}

fn secret_refusal_fix(error: &SecretError) -> &'static str {
    match error {
        SecretError::InvalidReference => {
            "write the reference as secret:file/<name> or secret:env/<NAME>"
        }
        SecretError::ProviderDisabled => {
            "enable the reference's provider under secretProviders (file.root or environment: {})"
        }
        SecretError::InvalidProviderConfiguration => {
            "declare at least one provider under secretProviders and give file.root an absolute path"
        }
        SecretError::Unavailable => {
            "create the file under secretProviders.file.root or set the variable; a symlink reads as missing"
        }
        SecretError::UnsafeFile => {
            "make it a regular file owned by the service user, mode 0600 or 0400, with one hard link"
        }
        SecretError::Read => "check that the service user can read the secret file",
        SecretError::InvalidValue => {
            "store a non-empty value with no NUL byte, within the secret size limit"
        }
    }
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
    let (profile, profile_bytes) = match (&project.profile, &project.consultation) {
        (Some(_), None) => {
            let profile_path =
                artifact_path(profile_path, project_directory, "profile.yaml", "--profile")?;
            read::<AdapterProfile>(
                &profile_path,
                &format_spec(ADAPTER_PROFILE_KIND, ADAPTER_PROFILE_API_VERSION),
            )?
        }
        (None, Some(_)) => {
            if profile_path.is_some() {
                return Err(LoadError::Runtime(
                    "a built-in Consultation deployment does not load an authored profile"
                        .to_owned(),
                ));
            }
            let profile = crate::consultation::built_in_profile();
            let mut identity = crate::consultation::PROFILE_ID.as_bytes().to_vec();
            identity.push(0);
            identity.extend_from_slice(crate::consultation::PROFILE_VERSION.as_bytes());
            (profile, identity)
        }
        _ => {
            return Err(LoadError::Workspace(
                "adapter.project.facade-selection exactly one of profile and consultation must be set"
                    .to_owned(),
            ));
        }
    };
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

    let mut authored = compile_authored_with(
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
                LoadError::Runtime(format!("endpoint {id} authentication was refused: {fault}"))
            })?;
            if !is_served_auth(plan.kind()) {
                return Ok(EndpointCompilation::Unserved {
                    reason: UnservedReason::SourceAuthenticationUnsupported,
                    detail: "its authentication is not served by this runtime".to_owned(),
                });
            }
            let recovery_headers: Vec<&str> = declared
                .operations
                .iter()
                .filter_map(|operation| {
                    operation
                        .async_completion
                        .as_ref()
                        .and_then(|completion| completion.uncertainty_recovery.as_ref())
                        .map(|recovery| recovery.request_header.as_str())
                })
                .collect();
            let egress = EndpointEgress::compile_with_recovery_headers(
                binding,
                declared,
                &runtime.endpoint_bindings(),
                &resolver,
                &recovery_headers,
            )
            .map_err(|fault| {
                LoadError::Runtime(format!("endpoint {id} outbound state was refused: {fault}"))
            })?;
            preflight_endpoint_credential(id, egress.plan(), &resolver)?;
            Ok(EndpointCompilation::Served(Box::new(egress)))
        },
    )?;
    if project.consultation.is_some() {
        attach_consultation_project(&project, &pack, project_directory, &mut authored)?;
    }
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

/// Attach the built-in Consultation projection and source semantics to an
/// already compiled authored plan. Live loading and offline fixture replay
/// call the same helper so neither can serve an unprojected source result.
pub fn attach_consultation_project(
    project: &AdapterProject,
    pack: &AdapterPack,
    project_directory: &Path,
    authored: &mut CompiledAuthoring,
) -> Result<(), LoadError> {
    let consultation = project.consultation.as_ref().ok_or_else(|| {
        LoadError::Runtime("the built-in Consultation metadata is unavailable".to_owned())
    })?;
    for operation in &mut authored.served {
        let capability = crate::consultation::ConsultationCapability::from_binding_operation(
            &operation.operation,
        )
        .ok_or_else(|| {
            LoadError::Runtime(format!(
                "binding {} does not name a built-in Consultation capability",
                operation.binding
            ))
        })?;
        let collection = consultation
            .collections
            .get(&operation.record_type)
            .ok_or_else(|| {
                LoadError::Runtime(format!(
                    "binding {} names no Consultation collection",
                    operation.binding
                ))
            })?;
        let binding = project.bindings.get(&operation.binding).ok_or_else(|| {
            LoadError::Runtime("a compiled binding is absent from its project".to_owned())
        })?;
        let templated = project
            .templated_routes
            .get(binding.route.as_str())
            .ok_or_else(|| {
                LoadError::Runtime(format!(
                    "binding {} must select an instantiated route template",
                    operation.binding
                ))
            })?;
        let template = pack
            .route_templates
            .get(templated.route_template.as_str())
            .ok_or_else(|| {
                LoadError::Runtime(format!(
                    "binding {} names no reusable source route template",
                    operation.binding
                ))
            })?;
        let support = template.read_support.clone().ok_or_else(|| {
            LoadError::Runtime(format!(
                "binding {} selects a route template with no declared read support",
                operation.binding
            ))
        })?;
        let source_shape_matches = matches!(
            (capability, &support),
            (
                crate::consultation::ConsultationCapability::Lookup,
                registry_adapter_core::SourceReadSupport::ReadOne { .. }
            ) | (
                crate::consultation::ConsultationCapability::Search,
                registry_adapter_core::SourceReadSupport::ReadPage { .. }
            )
        ) || matches!(
            (capability, &support),
            (
                crate::consultation::ConsultationCapability::Retrieve,
                registry_adapter_core::SourceReadSupport::ReadOne { inputs }
            ) if inputs.len() == 1
        ) || matches!(
            (capability, &support),
            (
                crate::consultation::ConsultationCapability::List,
                registry_adapter_core::SourceReadSupport::ReadPage { inputs, .. }
            ) if inputs.is_empty()
        );
        if !source_shape_matches {
            return Err(LoadError::Runtime(format!(
                "binding {} selects incompatible source read support",
                operation.binding
            )));
        }
        let (selected_input, input_schema) = match capability {
            crate::consultation::ConsultationCapability::Lookup => {
                let lookup = collection.lookup.as_ref().ok_or_else(|| {
                    LoadError::Runtime(format!(
                        "binding {} has no Consultation Lookup metadata",
                        operation.binding
                    ))
                })?;
                (
                    Some(lookup.selector.as_str()),
                    Some(lookup.input_schema.as_str()),
                )
            }
            crate::consultation::ConsultationCapability::Search => {
                let search = collection.search.as_ref().ok_or_else(|| {
                    LoadError::Runtime(format!(
                        "binding {} has no Consultation Search metadata",
                        operation.binding
                    ))
                })?;
                (
                    Some(search.search.as_str()),
                    Some(search.input_schema.as_str()),
                )
            }
            crate::consultation::ConsultationCapability::Retrieve
            | crate::consultation::ConsultationCapability::List => (None, None),
        };
        if let Some(input_schema) = input_schema {
            let (filters, schema) = compile_consultation_input_filters(
                project,
                input_schema,
                capability,
                &support,
                project_directory,
            )
            .map_err(|_| {
                LoadError::Runtime(format!(
                    "binding {} Consultation input schema was refused",
                    operation.binding
                ))
            })?;
            operation.filters = filters;
            operation.project_input_schema = Some(schema);
        }
        operation.request_template =
            crate::consultation::request_envelope(capability, selected_input)
                .map(|template| ReadRequestTemplate::compile(&template))
                .transpose()
                .map_err(|_| {
                    LoadError::Runtime(format!(
                        "binding {} has an unusable Consultation request contract",
                        operation.binding
                    ))
                })?;
        let transform = Arc::new(
            crate::project_transform::CompiledProjectTransform::compile_from_directory(
                project,
                &operation.binding,
                collection.data_schema.as_str(),
                project_directory,
            )
            .map_err(|_| {
                LoadError::Runtime(format!(
                    "binding {} project transformation was refused",
                    operation.binding
                ))
            })?,
        );
        operation.record_schema = transform.schema().as_value().clone();
        operation.project_transform = Some(transform);
        operation.read_support = Some(support);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsultationInputError {
    Schema,
    Shape,
    Scalar,
    SourceSupport,
}

/// Compile one selected Lookup or Search input against the exact scalar
/// capture shape and source support the runtime executes. Authoring commands
/// call this same function before publishing a contract.
pub fn compile_consultation_input_filters(
    project: &AdapterProject,
    schema_id: &str,
    capability: crate::consultation::ConsultationCapability,
    support: &registry_adapter_core::SourceReadSupport,
    project_directory: &Path,
) -> Result<
    (
        Vec<ServedFilter>,
        Arc<crate::public_schema::CheckedPublicSchema>,
    ),
    ConsultationInputError,
> {
    let declared = project
        .artifacts
        .schemas
        .get(schema_id)
        .ok_or(ConsultationInputError::Schema)?;
    let schema = crate::project_transform::compile_project_schema_from_directory(
        declared,
        project_directory,
    )
    .map_err(|_| ConsultationInputError::Schema)?;
    let properties = schema
        .as_value()
        .get("properties")
        .and_then(Value::as_object)
        .filter(|properties| !properties.is_empty())
        .ok_or(ConsultationInputError::Shape)?;
    let required = schema
        .as_value()
        .get("required")
        .and_then(Value::as_array)
        .ok_or(ConsultationInputError::Shape)?
        .iter()
        .map(|name| name.as_str().ok_or(ConsultationInputError::Shape))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if required.len() != properties.len()
        || properties
            .keys()
            .any(|name| !required.contains(name.as_str()))
    {
        return Err(ConsultationInputError::Shape);
    }
    let mut filters = Vec::with_capacity(properties.len());
    for (name, property) in properties {
        let field_type = scalar_filter_type(property)?;
        filters.push(ServedFilter {
            name: name.clone(),
            field_type,
        });
    }
    validate_consultation_filter_support(capability, support, &filters)?;
    Ok((filters, Arc::new(schema)))
}

fn scalar_filter_type(
    property: &Value,
) -> Result<registry_adapter_core::RecordFieldType, ConsultationInputError> {
    match (
        property.get("type").and_then(Value::as_str),
        property.get("format").and_then(Value::as_str),
    ) {
        (Some("string"), Some("date")) => Ok(registry_adapter_core::RecordFieldType::Date),
        (Some("string"), Some("date-time")) => Ok(registry_adapter_core::RecordFieldType::DateTime),
        (Some("string"), None) => Ok(registry_adapter_core::RecordFieldType::String),
        (Some("integer"), None) => Ok(registry_adapter_core::RecordFieldType::Integer),
        (Some("number"), None) => Ok(registry_adapter_core::RecordFieldType::Decimal),
        (Some("boolean"), None) => Ok(registry_adapter_core::RecordFieldType::Boolean),
        _ => Err(ConsultationInputError::Scalar),
    }
}

fn validate_consultation_filter_support(
    capability: crate::consultation::ConsultationCapability,
    support: &registry_adapter_core::SourceReadSupport,
    filters: &[ServedFilter],
) -> Result<(), ConsultationInputError> {
    let filter_names: BTreeSet<&str> = filters.iter().map(|filter| filter.name.as_str()).collect();
    match (capability, support) {
        (
            crate::consultation::ConsultationCapability::Lookup,
            registry_adapter_core::SourceReadSupport::ReadOne { inputs },
        ) => {
            let source_names: BTreeSet<&str> = inputs.iter().map(|input| input.as_str()).collect();
            (source_names == filter_names)
                .then_some(())
                .ok_or(ConsultationInputError::SourceSupport)
        }
        (
            crate::consultation::ConsultationCapability::Search,
            registry_adapter_core::SourceReadSupport::ReadPage { inputs, .. },
        ) => {
            let source_names: BTreeSet<&str> =
                inputs.iter().map(|input| input.name.as_str()).collect();
            (source_names == filter_names
                && filters.iter().all(|filter| {
                    inputs.iter().any(|input| {
                        input.name.as_str() == filter.name
                            && input.comparisons.iter().any(|comparison| {
                                *comparison == registry_adapter_core::SourceComparison::Equality
                            })
                    })
                }))
            .then_some(())
            .ok_or(ConsultationInputError::SourceSupport)
        }
        _ => Err(ConsultationInputError::SourceSupport),
    }
}

/// Compile the authored runtime state over endpoint egress supplied by the
/// caller. Live startup and offline replay share this exact route, script,
/// GraphQL, code-map and binding compiler; only endpoint transport differs.
#[allow(clippy::too_many_arguments)]
pub fn compile_authored_with<F>(
    project: &AdapterProject,
    profile: &AdapterProfile,
    pack: &AdapterPack,
    pack_directory: &Path,
    _deployment: &str,
    has_cursor_key: bool,
    endpoint_factory: F,
) -> Result<CompiledAuthoring, LoadError>
where
    F: FnMut(&Endpoint) -> Result<EndpointCompilation, LoadError>,
{
    compile_authored_from(
        project,
        profile,
        pack,
        pack_directory,
        _deployment,
        has_cursor_key,
        endpoint_factory,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compile_authored_with_artifacts<F>(
    project: &AdapterProject,
    profile: &AdapterProfile,
    pack: &AdapterPack,
    artifacts: &PackArtifactBytes,
    deployment: &str,
    has_cursor_key: bool,
    endpoint_factory: F,
) -> Result<CompiledAuthoring, LoadError>
where
    F: FnMut(&Endpoint) -> Result<EndpointCompilation, LoadError>,
{
    compile_authored_from(
        project,
        profile,
        pack,
        artifacts,
        deployment,
        has_cursor_key,
        endpoint_factory,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compile_authored_from<S, F>(
    project: &AdapterProject,
    profile: &AdapterProfile,
    pack: &AdapterPack,
    artifacts: &S,
    _deployment: &str,
    has_cursor_key: bool,
    mut endpoint_factory: F,
) -> Result<CompiledAuthoring, LoadError>
where
    S: ArtifactSource + ?Sized,
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
            let query = GraphQlQuery::load_from(pack, artifacts, declared).map_err(|fault| {
                LoadError::Runtime(format!("endpoint {id} query was refused: {fault}"))
            })?;
            if let Some(Expression::Rhai(script)) = &query.variables {
                scripts
                    .add_from(pack, artifacts, &script.file, &script.entrypoint)
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
        compile_step_schemas(artifacts, steps, &mut scripts)
            .map_err(|error| LoadError::Runtime(error.to_string()))?;
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
            .add_from(pack, artifacts, &file, &entrypoint)
            .map_err(|error| LoadError::Runtime(error.to_string()))?;
    }
    for (file, entrypoint) in table_strategy_uses {
        scripts
            .add_aggregation_from(pack, artifacts, &file, &entrypoint)
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
            artifacts,
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
                if let Some(conflict) = path_conflict(&served, &operation) {
                    return Err(LoadError::Runtime(format!(
                        "binding {} was refused: {conflict}",
                        binding.id.as_str()
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

pub(crate) fn compile_step_schemas<S: ArtifactSource + ?Sized>(
    artifacts: &S,
    steps: &[Step],
    scripts: &mut ScriptSet,
) -> Result<(), crate::scripts::ScriptLoadError> {
    let mut schemas = Vec::new();
    registry_adapter_core::walk_steps(steps, &mut |step, _| {
        if let Step::ValidateSchema(reference) = step {
            schemas.push(reference.clone());
        }
    });
    for schema in schemas {
        scripts.add_provider_schema_from(artifacts, &schema)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_binding<S: ArtifactSource + ?Sized>(
    binding: &registry_adapter_core::Binding,
    project: &AdapterProject,
    pack: &AdapterPack,
    profile: &AdapterProfile,
    artifacts: &S,
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
    let async_completion = compile_async_operation(operation, binding, &steps, routes, pack)?;
    let resume = crate::resume::compile_resume_operation(&steps, pack)
        .map_err(|reason| not_served(UnservedReason::RouteUnsupported, reason))?;

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
                SendComponent::Postgres
                    | SendComponent::File
                    | SendComponent::RabbitMq
                    | SendComponent::Sftp
                    | SendComponent::SqliteExtract
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
            .add_from(pack, artifacts, &file, &entrypoint)
            .map_err(|error| BindingRefusal::Fault(error.to_string()))?;
    }
    // A strategy script answers the old and new bodies, so it compiles as
    // a two-parameter function.
    for (file, entrypoint) in strategy_uses {
        scripts
            .add_aggregation_from(pack, artifacts, &file, &entrypoint)
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
        project_transform: None,
        project_input_schema: None,
        read_support: None,
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
        async_completion,
        resume,
    })
}

fn compile_async_operation(
    operation: &registry_adapter_core::ProfileOperation,
    binding: &registry_adapter_core::Binding,
    steps: &[Step],
    routes: &RouteTable,
    pack: &AdapterPack,
) -> Result<Option<ServedAsyncOperation>, BindingRefusal> {
    let expects_async = operation.success_status.get() == 202;
    let declarations_match =
        operation.async_completion.is_some() && binding.async_completion.is_some();
    if !expects_async && !declarations_match {
        return Ok(None);
    }
    if !expects_async || !declarations_match {
        return Err(not_served(
            UnservedReason::WriteAsyncUnsupported,
            "the profile and binding do not declare one asynchronous completion contract together",
        ));
    }
    let sources = async_source_candidates(steps, routes, pack);
    let [(initial, source)] = sources.as_slice() else {
        return Err(not_served(
            UnservedReason::WriteAsyncUnsupported,
            "the route does not resolve to exactly one declared asynchronous source operation",
        ));
    };
    let accepted_id =
        AcceptedIdSelector::compile(source.accepted_id.jsonpath()).map_err(|reason| {
            not_served(
                UnservedReason::WriteAsyncUnsupported,
                format!("the asynchronous accepted id selector is unusable: {reason}"),
            )
        })?;
    let status = compile_async_status_route(
        source.status_route.as_str(),
        binding.maximum_upstream_calls.get(),
        routes,
    )?;
    let uncertainty = source
        .uncertainty_recovery
        .as_ref()
        .map(|recovery| {
            compile_async_status_route(
                recovery.status_route.as_str(),
                binding.maximum_upstream_calls.get(),
                routes,
            )
            .map(|status| ServedAsyncUncertainty {
                request_header: recovery.request_header.as_str().to_owned(),
                status,
            })
        })
        .transpose()?;
    Ok(Some(ServedAsyncOperation {
        initial: initial.clone(),
        accepted_id,
        status,
        uncertainty,
    }))
}

fn async_source_candidates(
    steps: &[Step],
    routes: &RouteTable,
    pack: &AdapterPack,
) -> Vec<(
    AsyncSourceOperation,
    registry_adapter_core::EndpointAsyncCompletion,
)> {
    fn visit(
        steps: &[Step],
        routes: &RouteTable,
        pack: &AdapterPack,
        visited: &mut BTreeSet<String>,
        found: &mut Vec<(
            AsyncSourceOperation,
            registry_adapter_core::EndpointAsyncCompletion,
        )>,
    ) {
        let mut direct = Vec::new();
        registry_adapter_core::walk_steps(steps, &mut |step, _| {
            let Step::To(sent) = step else { return };
            if sent.uri.component == SendComponent::Direct {
                direct.push(sent.uri.id.clone());
                return;
            }
            let Some(operation) = sent
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.operation.as_ref())
            else {
                return;
            };
            let Some(endpoint) = pack.endpoints.get(sent.uri.id.as_str()) else {
                return;
            };
            let Some(declared) = endpoint
                .operations
                .iter()
                .find(|declared| declared.id.as_str() == operation.as_str())
            else {
                return;
            };
            let non_safe = match endpoint.component {
                ComponentKind::Http => {
                    let method = sent
                        .parameters
                        .as_ref()
                        .and_then(|parameters| parameters.http_method)
                        .unwrap_or(registry_adapter_core::HttpMethod::Post);
                    !(method.is_safe()
                        || method == registry_adapter_core::HttpMethod::Post
                            && declared.safe_upstream)
                }
                ComponentKind::GraphQl => !matches!(
                    declared.graphql,
                    Some(registry_adapter_core::GraphQlOperationKind::Query)
                ),
                _ => false,
            };
            if non_safe {
                if let Some(completion) = &declared.async_completion {
                    found.push((
                        AsyncSourceOperation {
                            endpoint: sent.uri.id.clone(),
                            operation: operation.as_str().to_owned(),
                        },
                        completion.clone(),
                    ));
                }
            }
        });
        for target in direct {
            if visited.insert(target.clone()) {
                if let Some(target_steps) = routes.get(&target) {
                    visit(target_steps, routes, pack, visited, found);
                }
            }
        }
    }

    let mut found = Vec::new();
    visit(steps, routes, pack, &mut BTreeSet::new(), &mut found);
    found
}

fn compile_async_status_route(
    route_id: &str,
    maximum_upstream_calls: u64,
    routes: &RouteTable,
) -> Result<ServedAsyncStatusRoute, BindingRefusal> {
    let Some(steps) = routes.get(route_id) else {
        return Err(not_served(
            UnservedReason::WriteAsyncUnsupported,
            "an asynchronous status route is absent from the compiled route table",
        ));
    };
    let mut endpoint_ids = BTreeSet::new();
    let mut visited = BTreeSet::new();
    collect_status_endpoints(steps, routes, &mut visited, &mut endpoint_ids);
    if endpoint_ids.is_empty() {
        return Err(not_served(
            UnservedReason::WriteAsyncUnsupported,
            "an asynchronous status route reaches no source endpoint",
        ));
    }
    Ok(ServedAsyncStatusRoute {
        route_id: route_id.to_owned(),
        steps: Arc::clone(steps),
        maximum_upstream_calls,
        endpoint_ids,
    })
}

fn collect_status_endpoints(
    steps: &[Step],
    routes: &RouteTable,
    visited: &mut BTreeSet<String>,
    endpoints: &mut BTreeSet<String>,
) {
    let mut direct = Vec::new();
    registry_adapter_core::walk_steps(steps, &mut |step, _| {
        let uri = match step {
            Step::To(sent) => &sent.uri,
            Step::Enrich(enrich) => &enrich.uri,
            _ => return,
        };
        if uri.component == SendComponent::Direct {
            direct.push(uri.id.clone());
        } else {
            endpoints.insert(uri.id.clone());
        }
    });
    for target in direct {
        if visited.insert(target.clone()) {
            if let Some(target_steps) = routes.get(&target) {
                collect_status_endpoints(target_steps, routes, visited, endpoints);
            }
        }
    }
}

/// The template's steps with each parameter's supplied value (or its
/// default) written in. A `{{name}}` that is a whole string takes the
/// value with its type; inside longer text it takes the value's text. A
/// placeholder of a parameter with neither a supplied value nor a
/// default stays for the send to bind per request.
pub fn instantiate(
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

/// The maintained `breg-records` profile with a one-route pack and a project
/// that binds `records-get` to two record types, `person` then `household`.
#[cfg(test)]
pub(crate) fn two_record_types_inputs() -> (AdapterProfile, AdapterPack, AdapterProject) {
    use serde_json::json;

    let profile_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/adapter/profiles/breg-records/profile.yaml");
    let (profile, _): (AdapterProfile, _) = read(
        &profile_path,
        &format_spec(ADAPTER_PROFILE_KIND, ADAPTER_PROFILE_API_VERSION),
    )
    .expect("the maintained profile reads");
    let pack: AdapterPack = serde_json::from_value(json!({
        "id": "records-pack",
        "version": "1",
        "testedVersions": ["1"],
        "routes": [{"id": "fetch", "from": {"uri": "direct:fetch"}, "steps": [
            {"setBody": {"constant": {"recordIdentifier": "r1", "domainData": {}}}}
        ]}],
    }))
    .expect("the pack parses");
    let project: AdapterProject = serde_json::from_value(json!({
        "project": {"id": "two-types", "version": "1"},
        "profile": {"id": "breg-records", "version": "1", "digest": format!("sha256:{}", "0".repeat(64))},
        "pack": {"id": "records-pack", "version": "1", "digest": format!("sha256:{}", "0".repeat(64))},
        "recordTypes": [
            {"name": "person", "fields": [{"name": "given_name", "type": "string"}]},
            {"name": "household", "fields": [{"name": "size", "type": "integer"}]},
        ],
        "templatedRoutes": [],
        "bindings": [
            {"id": "person-get", "operation": "records-get", "recordType": "person",
             "route": "fetch", "maximumUpstreamCalls": 1},
            {"id": "household-get", "operation": "records-get", "recordType": "household",
             "route": "fetch", "maximumUpstreamCalls": 1},
        ],
        "accessProfiles": [],
    }))
    .expect("the project parses");
    (profile, pack, project)
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
            maximum_concurrency: registry_platform_yaml::BoundedU64::new(8).expect("concurrency"),
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

    #[cfg(unix)]
    #[test]
    fn an_unresolved_credential_reference_names_its_cause_and_the_fix() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("secret root");
        let loose = root.path().join("kobo-password-loose");
        std::fs::write(&loose, "SECRET-CANARY").expect("loose secret");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644))
            .expect("loose mode");
        let resolver = SecretResolver::new([SecretProvider::File], root.path()).expect("resolver");

        let unsafe_file =
            resolve_credential_reference("kobo-api", "secret:file/kobo-password-loose", &resolver)
                .expect_err("a group-readable secret file refuses")
                .to_string();
        let missing =
            resolve_credential_reference("kobo-api", "secret:file/kobo-password-absent", &resolver)
                .expect_err("a missing secret file refuses")
                .to_string();
        let disabled =
            resolve_credential_reference("kobo-api", "secret:env/KOBO_PASSWORD", &resolver)
                .expect_err("a disabled provider refuses")
                .to_string();

        for refusal in [&unsafe_file, &missing, &disabled] {
            assert!(refusal.contains("kobo-api"), "{refusal}");
            assert!(refusal.contains("secret:"), "{refusal}");
            assert!(!refusal.contains("SECRET-CANARY"), "{refusal}");
        }
        assert_ne!(unsafe_file, missing, "the two causes must read differently");
        assert!(unsafe_file.contains("unsafe"), "{unsafe_file}");
        assert!(unsafe_file.contains("0600 or 0400"), "{unsafe_file}");
        assert!(unsafe_file.contains("owned by"), "{unsafe_file}");
        assert!(missing.contains("unavailable"), "{missing}");
        assert!(missing.contains("symlink"), "{missing}");
        assert!(disabled.contains("disabled provider"), "{disabled}");
        assert!(disabled.contains("secretProviders"), "{disabled}");
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

    #[test]
    fn asynchronous_source_contract_compiles_into_closed_served_routes() {
        let operation: registry_adapter_core::ProfileOperation = serde_json::from_value(json!({
            "id": "records-create",
            "method": "POST",
            "path": "/v1/records/{type}",
            "pathParameters": ["type"],
            "recordTypeParameter": "type",
            "successStatus": 202,
            "requestEnvelope": "{\"record\": {{record}}}",
            "responseEnvelope": "{\"record\": {{record}}}",
            "asyncCompletion": {
                "completedStatus": 200,
                "statusPath": "/v1/status/{statusId}",
                "acceptedEnvelope": "{\"statusLink\":\"{{statusLink}}\",\"expiresAt\":\"{{statusExpiresAt}}\",\"requestId\":\"{{requestId}}\"}"
            }
        }))
        .expect("profile operation");
        let binding: registry_adapter_core::Binding = serde_json::from_value(json!({
            "id": "person-create",
            "operation": "records-create",
            "recordType": "person",
            "route": "create",
            "maximumUpstreamCalls": 5,
            "asyncCompletion": {"type": "status-link"}
        }))
        .expect("binding");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "async-pack",
            "version": "1",
            "testedVersions": ["1"],
            "endpoints": [{
                "id": "source",
                "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 4096,
                "operations": [{
                    "id": "create-record",
                    "asyncCompletion": {
                        "acceptedId": {"jsonpath": "$.operationId"},
                        "statusRoute": "status",
                        "uncertaintyRecovery": {
                            "requestHeader": "X-Source-Recovery-Id",
                            "statusRoute": "recovery"
                        }
                    }
                }]
            }],
            "routes": [
                {"id": "create", "from": {"uri": "direct:create"}, "steps": []},
                {"id": "status", "from": {"uri": "direct:status"}, "steps": [
                    {"to": {"uri": "http:source", "parameters": {"httpMethod": "GET", "path": "/status"}}}
                ]},
                {"id": "recovery", "from": {"uri": "direct:recovery"}, "steps": [
                    {"to": {"uri": "http:source", "parameters": {"httpMethod": "GET", "path": "/recovery"}}}
                ]}
            ]
        }))
        .expect("pack");
        let initial: Vec<Step> = serde_json::from_value(json!([{"idempotentConsumer": {
            "expression": {"header": "Idempotency-Key"},
            "steps": [{"to": {"uri": "http:source", "parameters": {
                "httpMethod": "POST", "path": "/records", "body": {"jsonpath": "$"},
                "operation": "create-record"
            }}}]
        }}]))
        .expect("initial route");
        let routes: RouteTable = pack
            .routes
            .iter()
            .map(|route| (route.id.as_str().to_owned(), Arc::new(route.steps.clone())))
            .collect();

        let compiled = match compile_async_operation(&operation, &binding, &initial, &routes, &pack)
        {
            Ok(Some(compiled)) => compiled,
            Ok(None) => panic!("async descriptor is absent"),
            Err(_) => panic!("async contract was refused"),
        };

        assert_eq!(compiled.initial.endpoint, "source");
        assert_eq!(compiled.initial.operation, "create-record");
        assert_eq!(compiled.status.route_id, "status");
        assert_eq!(
            compiled.status.endpoint_ids,
            BTreeSet::from(["source".to_owned()])
        );
        assert_eq!(
            compiled.uncertainty.expect("uncertainty").status.route_id,
            "recovery"
        );
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

    fn served_on(
        method: registry_adapter_core::HttpMethod,
        method_path: &str,
        record_type: &str,
    ) -> ServedOperation {
        ServedOperation {
            operation: "records-get".to_owned(),
            method,
            request_template: None,
            request_maximum_bytes: DEFAULT_REQUEST_MAXIMUM_BYTES,
            filters: Vec::new(),
            method_path: method_path.to_owned(),
            record_type_parameter: "recordType".to_owned(),
            record_id_parameter: Some("id".to_owned()),
            binding: format!("{record_type}-get"),
            record_type: record_type.to_owned(),
            route_id: "route".to_owned(),
            steps: Arc::new(Vec::new()),
            resilience: crate::resilience::ResilienceRuntime::empty(),
            maximum_upstream_calls: 1,
            item_envelope: None,
            response_envelope: CompiledEnvelope::compile("{}", &BTreeMap::new()).unwrap(),
            record_schema: json!({}),
            pagination: None,
            async_completion: None,
            resume: None,
            project_transform: None,
            project_input_schema: None,
            read_support: None,
        }
    }

    #[test]
    fn a_second_binding_on_a_served_path_is_found() {
        let get = registry_adapter_core::HttpMethod::Get;
        let post = registry_adapter_core::HttpMethod::Post;
        let served = [served_on(get, "/v1/records/{recordType}/{id}", "person")];

        let conflict = path_conflict(
            &served,
            &served_on(get, "/v1/records/{recordType}/{id}", "person"),
        );
        assert_eq!(
            conflict.as_deref(),
            Some("another binding already serves the facade path /v1/records/{recordType}/{id}")
        );
        assert!(
            path_conflict(
                &served,
                &served_on(get, "/v1/records/person/{id}", "person")
            )
            .is_some(),
            "a literal path equal to the served concrete path is never reached"
        );
        assert!(path_conflict(
            &served,
            &served_on(post, "/v1/records/{recordType}/{id}", "person")
        )
        .is_none());
        assert!(path_conflict(
            &served,
            &served_on(get, "/v1/records/{recordType}", "person")
        )
        .is_none());
    }

    #[test]
    fn a_second_record_type_on_a_served_path_is_not_a_conflict() {
        let get = registry_adapter_core::HttpMethod::Get;
        let served = [served_on(get, "/v1/records/{recordType}/{id}", "person")];

        assert!(path_conflict(
            &served,
            &served_on(get, "/v1/records/{recordType}/{id}", "household")
        )
        .is_none());
    }

    /// The router refuses two paths of one shape whose parameters are named
    /// differently, whatever their methods, so the load refuses them first.
    #[test]
    fn a_path_of_a_served_shape_with_other_parameter_names_is_a_conflict() {
        let get = registry_adapter_core::HttpMethod::Get;
        let post = registry_adapter_core::HttpMethod::Post;
        let served = [served_on(get, "/v1/records/{recordType}/{id}", "person")];

        for method in [get, post] {
            let conflict = path_conflict(
                &served,
                &served_on(method, "/v1/records/{recordType}/{record_id}", "household"),
            );
            assert_eq!(
                conflict.as_deref(),
                Some(
                    "its facade path /v1/records/{recordType}/{record_id} names its path \
                     parameters differently from the served path /v1/records/{recordType}/{id}"
                )
            );
        }
        assert!(
            path_conflict(
                &served,
                &served_on(get, "/v1/records/{recordType}/search", "household")
            )
            .is_none(),
            "a literal segment is another shape"
        );
    }

    /// A parameter inside a segment is matched by position like a whole
    /// segment one, so its name is normalised the same way.
    #[test]
    fn a_partial_segment_parameter_named_differently_is_a_conflict() {
        let get = registry_adapter_core::HttpMethod::Get;
        let served = [served_on(get, "/v1/records/{recordType}/r-{id}", "person")];

        let conflict = path_conflict(
            &served,
            &served_on(get, "/v1/records/{recordType}/r-{record_id}", "household"),
        );
        assert_eq!(
            conflict.as_deref(),
            Some(
                "its facade path /v1/records/{recordType}/r-{record_id} names its path \
                 parameters differently from the served path /v1/records/{recordType}/r-{id}"
            )
        );
        assert!(
            path_conflict(
                &served,
                &served_on(get, "/v1/records/{recordType}/r-{id}", "household")
            )
            .is_none(),
            "the same spelling for another record type is served beside it"
        );
        assert_eq!(path_shape("/v1/x{type}y/{id}"), "/v1/x{}y/{}");
        assert_eq!(path_shape("/v1/{a}-{b}"), "/v1/{}-{}");
    }

    /// One profile operation bound to two record types compiles two
    /// concrete operations (`products/adapter/CONCEPT.md` section 7), so
    /// the runtime serves both rather than refusing the second binding.
    #[test]
    fn one_operation_bound_to_two_record_types_serves_both() {
        let (profile, pack, project) = two_record_types_inputs();
        let directory = tempfile::tempdir().expect("a scratch directory");

        let authored = compile_authored_with(
            &project,
            &profile,
            &pack,
            directory.path(),
            "deployment",
            true,
            |_| Ok(EndpointCompilation::Absent),
        )
        .unwrap_or_else(|error| panic!("the deployment compiles: {error}"));

        let served: Vec<(&str, &str)> = authored
            .served
            .iter()
            .map(|operation| (operation.operation.as_str(), operation.record_type.as_str()))
            .collect();
        assert_eq!(
            served,
            [("records-get", "person"), ("records-get", "household")]
        );
        assert!(authored.unserved.is_empty());
    }

    /// A refused artifact names where the fault sits and how to fix it,
    /// not only the reader's code and sentence: a 202 on a read names the
    /// operation's pointer, the rule (reads never answer 202), and the fix.
    #[test]
    fn a_refused_profile_names_the_operation_the_rule_and_the_fix() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/adapter/profiles/breg-records/profile.yaml"),
        )
        .expect("the maintained profile reads");
        let refused = source.replacen(
            "  - id: records-search\n    method: GET\n",
            "  - id: records-search\n    method: GET\n    successStatus: 202\n",
            1,
        );
        assert_ne!(refused, source, "the fixture edit applied");
        let directory = tempfile::tempdir().expect("a scratch directory");
        let path = directory.path().join("profile.yaml");
        std::fs::write(&path, refused).expect("write the profile");

        let error = read::<AdapterProfile>(
            &path,
            &format_spec(ADAPTER_PROFILE_KIND, ADAPTER_PROFILE_API_VERSION),
        )
        .expect_err("a 202 read is refused");
        let text = error.to_string();
        assert!(
            text.contains("/operations/0"),
            "names the operation: {text}"
        );
        assert!(
            text.contains("a read never answers 202"),
            "names the rule: {text}"
        );
        assert!(
            text.contains("Declare both on an asynchronous write"),
            "names the fix: {text}"
        );
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
