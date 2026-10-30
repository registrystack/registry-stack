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
use std::path::Path;
use std::time::Duration;

use registry_adapter_core::{
    check_project_pins, check_workspace, AdapterPack, AdapterProfile, AdapterProject,
    AdapterRuntimeConfig, Step, Workspace, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
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

use crate::auth::AuthPlan;
use crate::component::http::header_filter::HeaderFilter;
use crate::component::http::uri::PinnedOrigin;
use crate::interim_loopback::LoopbackSender;
use crate::route::{check_servable, is_served_auth, EndpointRuntime};
use crate::scripts::ScriptSet;
use registry_adapter_core::Expression;

/// One upstream attempt's wall-clock bound.
const ATTEMPT: Duration = Duration::from_secs(10);
/// The largest upstream reply body a send keeps.
const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("{path} could not be read")]
    Unreadable { path: String },
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
    pub method_path: String,
    pub record_type_parameter: String,
    pub record_id_parameter: Option<String>,
    pub binding: String,
    pub record_type: String,
    pub route_id: String,
    pub steps: Vec<Step>,
    pub maximum_upstream_calls: u64,
    pub response_envelope: String,
}

/// Everything startup produced.
pub struct Loaded {
    pub profile: AdapterProfile,
    pub project: AdapterProject,
    pub runtime: AdapterRuntimeConfig,
    pub scripts: ScriptSet,
    pub endpoints: BTreeMap<String, EndpointRuntime>,
    pub served: Vec<ServedOperation>,
    /// `(binding id, why)` for every binding left unserved.
    pub unserved: Vec<(String, String)>,
    pub resolver: SecretResolver,
}

fn format_spec(kind: &'static str, api_version: &'static str) -> FormatSpec<'static> {
    FormatSpec {
        kind,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: Box::leak(Box::new([ApiVersion::current(api_version)])),
            retired_api_versions: &[],
        },
        removed_keys: &[],
    }
}

fn read<T: DeserializeOwned>(
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

fn digest_of(bytes: &[u8]) -> Digest {
    Digest::new(sha256_uri(bytes)).expect("a computed sha256 uri is a valid digest")
}

/// Load the deployment: `project_directory` holds `project.yaml`,
/// `profile.yaml`, `pack.yaml` and `scripts/`; `runtime_path` is the
/// operator runtime config.
pub fn load(project_directory: &Path, runtime_path: &Path) -> Result<Loaded, LoadError> {
    let (project, _): (AdapterProject, _) = read(
        &project_directory.join("project.yaml"),
        &format_spec(ADAPTER_PROJECT_KIND, ADAPTER_PROJECT_API_VERSION),
    )?;
    let (profile, profile_bytes): (AdapterProfile, _) = read(
        &project_directory.join("profile.yaml"),
        &format_spec(ADAPTER_PROFILE_KIND, ADAPTER_PROFILE_API_VERSION),
    )?;
    let (pack, pack_bytes): (AdapterPack, _) = read(
        &project_directory.join("pack.yaml"),
        &format_spec(ADAPTER_PACK_KIND, ADAPTER_PACK_API_VERSION),
    )?;
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

    // Endpoints with a served authentication kind. An endpoint whose plan
    // needs a token endpoint stays out; a route that sends to it is unserved.
    let mut endpoints = BTreeMap::new();
    let mut endpoint_refusals: BTreeMap<String, String> = BTreeMap::new();
    for binding in runtime.endpoints.iter() {
        let id = binding.endpoint.as_str().to_owned();
        let Some(declared) = pack.endpoints.get(&id) else {
            continue;
        };
        let plan = AuthPlan::compile(&declared.authentication, binding).map_err(|fault| {
            LoadError::Runtime(format!(
                "endpoint {id} authentication was refused: {fault:?}"
            ))
        })?;
        if !is_served_auth(plan.kind()) {
            endpoint_refusals.insert(
                id,
                "its authentication needs a token endpoint, which is not served yet".to_owned(),
            );
            continue;
        }
        let origin = PinnedOrigin::new(binding.base_url.as_str())
            .map_err(|_| LoadError::Runtime(format!("endpoint {id} baseUrl was refused")))?;
        let filter = HeaderFilter::for_endpoint(declared).map_err(|_| {
            LoadError::Runtime(format!("endpoint {id} header allowlist was refused"))
        })?;
        let base = format!(
            "{}{}",
            origin.origin_url().trim_end_matches('/'),
            origin.base_path()
        );
        endpoints.insert(
            id,
            EndpointRuntime {
                plan,
                base,
                sender: Box::new(LoopbackSender::new(origin, filter)),
                attempt: ATTEMPT,
                maximum_response_bytes: MAXIMUM_RESPONSE_BYTES,
            },
        );
    }

    let mut scripts = ScriptSet::default();
    let mut served = Vec::new();
    let mut unserved = Vec::new();
    for binding in project.bindings.iter() {
        let outcome = compile_binding(
            binding,
            &project,
            &pack,
            &profile,
            project_directory,
            &endpoints,
            &endpoint_refusals,
            &mut scripts,
        );
        match outcome {
            Ok(operation) => served.push(operation),
            Err(reason) => unserved.push((binding.id.as_str().to_owned(), reason)),
        }
    }
    Ok(Loaded {
        profile,
        project,
        runtime,
        scripts,
        endpoints,
        served,
        unserved,
        resolver,
    })
}

#[allow(clippy::too_many_arguments)]
fn compile_binding(
    binding: &registry_adapter_core::Binding,
    project: &AdapterProject,
    pack: &AdapterPack,
    profile: &AdapterProfile,
    project_directory: &Path,
    endpoints: &BTreeMap<String, EndpointRuntime>,
    endpoint_refusals: &BTreeMap<String, String>,
    scripts: &mut ScriptSet,
) -> Result<ServedOperation, String> {
    let operation = profile
        .operations
        .get(binding.operation.as_str())
        .ok_or("the binding names no profile operation")?;
    let route_id = binding.route.as_str();
    let steps: Vec<Step> = if let Some(templated) = project.templated_routes.get(route_id) {
        let template = pack
            .route_templates
            .get(templated.route_template.as_str())
            .ok_or("the templated route names no pack template")?;
        // Instantiation values are not substituted yet. A template whose
        // parameters are all optional, with no default and no supplied
        // value, keeps its `{{name}}` placeholders, which a send's
        // `pathParameters` bind per request.
        if !templated.parameters.is_empty()
            || template
                .parameters
                .iter()
                .any(|parameter| parameter.required || parameter.default_value.is_some())
        {
            return Err(
                "a route template instantiated with parameter values is not served yet".to_owned(),
            );
        }
        template.steps.clone()
    } else if let Some(route) = pack.routes.get(route_id) {
        route.steps.clone()
    } else {
        return Err("the binding names no route".to_owned());
    };
    check_servable(&steps)?;

    let mut refusal: Option<String> = None;
    let mut script_uses: Vec<(String, String)> = Vec::new();
    registry_adapter_core::walk_steps(&steps, &mut |step, _pointer| {
        if let Step::To(to) = step {
            let id = &to.uri.id;
            if let Some(reason) = endpoint_refusals.get(id) {
                refusal.get_or_insert(format!("endpoint {id}: {reason}"));
            } else if !endpoints.contains_key(id) {
                refusal.get_or_insert(format!("endpoint {id} is not bound by the runtime"));
            }
        }
        for expression in step_expressions(step) {
            if let Expression::Rhai(script) = expression {
                script_uses.push((script.file.clone(), script.entrypoint.clone()));
            }
        }
    });
    if let Some(reason) = refusal {
        return Err(reason);
    }
    for (file, entrypoint) in script_uses {
        scripts
            .add(pack, project_directory, &file, &entrypoint)
            .map_err(|error| error.to_string())?;
    }
    Ok(ServedOperation {
        operation: operation.id.as_str().to_owned(),
        method_path: operation.path.clone(),
        record_type_parameter: operation.record_type_parameter.as_str().to_owned(),
        record_id_parameter: operation
            .record_id_parameter
            .as_ref()
            .map(|name| name.as_str().to_owned()),
        binding: binding.id.as_str().to_owned(),
        record_type: binding.record_type.as_str().to_owned(),
        route_id: route_id.to_owned(),
        steps,
        maximum_upstream_calls: binding.maximum_upstream_calls.get(),
        response_envelope: operation.response_envelope.text().to_owned(),
    })
}

/// The expressions one step carries directly (the walker visits nested
/// steps itself).
fn step_expressions(step: &Step) -> Vec<&Expression> {
    match step {
        Step::SetBody(expression) => vec![expression],
        Step::To(to) => to
            .parameters
            .iter()
            .flat_map(|parameters| parameters.path_parameters.values())
            .collect(),
        Step::OnException(clause) => clause.on_when.iter().collect(),
        _ => Vec::new(),
    }
}
