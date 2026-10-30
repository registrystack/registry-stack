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
use crate::facade::bind_parameterized_parts;
use crate::interim_loopback::LoopbackSender;
use crate::route::{check_servable, is_served_auth, EndpointRuntime};
use crate::scripts::ScriptSet;
use registry_adapter_core::{Expression, RouteTemplate};
use serde_json::Value;

/// One upstream attempt's wall-clock bound.
const ATTEMPT: Duration = Duration::from_secs(10);
/// The largest upstream reply body a send keeps.
const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;

/// Why one binding is not compiled for serving.
enum BindingRefusal {
    /// The runtime does not serve the binding yet (a path it does not
    /// implement, an unbound endpoint); startup warns and goes on.
    NotServed(String),
    /// The binding's own files are faulty (an unreadable, uninventoried,
    /// digest-mismatched or uncompilable script); startup refuses.
    Fault(String),
}

impl From<String> for BindingRefusal {
    fn from(reason: String) -> Self {
        Self::NotServed(reason)
    }
}

impl From<&str> for BindingRefusal {
    fn from(reason: &str) -> Self {
        Self::NotServed(reason.to_owned())
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
    pub method_path: String,
    pub record_type_parameter: String,
    pub record_id_parameter: Option<String>,
    pub binding: String,
    pub record_type: String,
    pub route_id: String,
    pub steps: Vec<Step>,
    pub maximum_upstream_calls: u64,
    pub response_envelope: String,
    /// The closed schema of one record this operation may disclose: the
    /// bound record type's declared fields and nothing else.
    pub record_schema: Value,
    /// The cursor and page-size parameters of a search operation.
    pub pagination: Option<ServedPagination>,
}

/// The pagination parameters one served search operation declares.
pub struct ServedPagination {
    pub cursor_parameter: String,
    pub page_size_parameter: String,
    pub page_size_minimum: u64,
    pub page_size_maximum: u64,
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
    /// A digest of the project, profile and pack bytes, so a cursor
    /// minted under other artifacts is refused.
    pub deployment: String,
}

/// Whether a served operation already answers the facade path: the router
/// takes one handler per path, so a second binding on it would never be
/// reached.
fn serves_path(served: &[ServedOperation], path: &str) -> bool {
    served.iter().any(|operation| operation.method_path == path)
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

/// The profile or pack a deployment loads: the file the flag names, else
/// the file beside the project. A project does not say where its pack
/// lives, so a missing default refuses with the file and the flag to pass.
fn artifact_path(
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

    let mut scripts = ScriptSet::default();
    let mut served = Vec::new();
    let mut unserved = Vec::new();
    for binding in project.bindings.iter() {
        let outcome = compile_binding(
            binding,
            &project,
            &pack,
            &profile,
            pack_directory,
            &endpoints,
            &endpoint_refusals,
            has_cursor_key,
            &mut scripts,
        );
        match outcome {
            Ok(operation) => {
                if serves_path(&served, &operation.method_path) {
                    return Err(LoadError::Runtime(format!(
                        "binding {} was refused: another binding already serves the facade path {}",
                        binding.id.as_str(),
                        operation.method_path
                    )));
                }
                served.push(operation);
            }
            Err(BindingRefusal::NotServed(reason)) => {
                unserved.push((binding.id.as_str().to_owned(), reason));
            }
            Err(BindingRefusal::Fault(reason)) => {
                return Err(LoadError::Runtime(format!(
                    "binding {} was refused: {reason}",
                    binding.id.as_str()
                )));
            }
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
        deployment,
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
    endpoint_refusals: &BTreeMap<String, String>,
    has_cursor_key: bool,
    scripts: &mut ScriptSet,
) -> Result<ServedOperation, BindingRefusal> {
    let operation = profile
        .operations
        .get(binding.operation.as_str())
        .ok_or("the binding names no profile operation")?;
    if operation.method != registry_adapter_core::HttpMethod::Get {
        return Err("a facade method other than GET is not served by this runtime yet".into());
    }
    let route_id = binding.route.as_str();
    let steps: Vec<Step> = if let Some(templated) = project.templated_routes.get(route_id) {
        let template = pack
            .route_templates
            .get(templated.route_template.as_str())
            .ok_or("the templated route names no pack template")?;
        instantiate(template, &templated.parameters)?
    } else if let Some(route) = pack.routes.get(route_id) {
        route.steps.clone()
    } else {
        return Err("the binding names no route".into());
    };
    if operation.pagination.is_some() && !has_cursor_key {
        return Err(
            "a paginated operation needs cursorKeyRef in the runtime config to seal its cursors"
                .into(),
        );
    }
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
        return Err(reason.into());
    }
    for (file, entrypoint) in script_uses {
        scripts
            .add(pack, pack_directory, &file, &entrypoint)
            .map_err(|error| BindingRefusal::Fault(error.to_string()))?;
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
        response_envelope: bind_parameterized_parts(
            operation.response_envelope.text(),
            &project.parameterized_parts,
        ),
        record_schema: registry_adapter_core::binding_record_schema(project, binding)?,
        pagination: operation
            .pagination
            .as_ref()
            .map(|pagination| ServedPagination {
                cursor_parameter: pagination.cursor_parameter.as_str().to_owned(),
                page_size_parameter: pagination.page_size_parameter.as_str().to_owned(),
                page_size_minimum: pagination.page_size_minimum.get(),
                page_size_maximum: pagination.page_size_maximum.get(),
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
/// steps itself).
fn step_expressions(step: &Step) -> Vec<&Expression> {
    match step {
        Step::SetBody(expression) => vec![expression],
        Step::SetProperty(property) => vec![&property.value],
        Step::To(to) => to
            .parameters
            .iter()
            .flat_map(|parameters| {
                parameters
                    .path_parameters
                    .values()
                    .chain(parameters.query.values())
            })
            .collect(),
        Step::OnException(clause) => clause.on_when.iter().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
            method_path: "/v1/records/{recordType}/{id}".to_owned(),
            record_type_parameter: "recordType".to_owned(),
            record_id_parameter: Some("id".to_owned()),
            binding: "person-get".to_owned(),
            record_type: "person".to_owned(),
            route_id: "route".to_owned(),
            steps: Vec::new(),
            maximum_upstream_calls: 1,
            response_envelope: String::new(),
            record_schema: json!({}),
            pagination: None,
        };
        let served = [operation];
        assert!(serves_path(&served, "/v1/records/{recordType}/{id}"));
        assert!(!serves_path(&served, "/v1/records/{recordType}"));
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
}
