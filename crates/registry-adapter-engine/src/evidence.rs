// SPDX-License-Identifier: Apache-2.0

//! Listener-free Evidence acquisition compilation and execution.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, pin::Pin};

use jsonschema::{Draft, JSONSchema, SchemaResolver, SchemaResolverError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use registry_adapter_core::{
    AdapterEndpointBindings, AdapterPack, AggregationStrategy, ComponentKind,
    EndpointAuthentication, EvidenceAuthenticationPolicy, EvidenceClientIdentityPolicy,
    EvidenceConnectionPolicy, Expression, GraphQlOperationKind, HttpMethod, RuntimeCredential,
    SendComponent, SourceRouteDecl, Step,
};
use registry_platform_config::{sha256_uri, SecretResolver};

use crate::artifacts::{ArtifactReadError, ArtifactSource, PackArtifactBytes};
use crate::auth::{AuthPlan, TokenBudget};
use crate::component::graphql::GraphQlQuery;
use crate::exchange::Exchange;
use crate::host_protocol::{
    CompiledHostProtocol, HostAccessAttribution, HostProtocolAttachment, HostProtocolRegistry,
};
use crate::route::{EndpointRuntime, RouteContext, RouteFailure, RouteTable};
use crate::scripts::{CodeMaps, ScriptSet};

/// Default data-operation budget, also enforced by the offline fixture runner.
pub const DEFAULT_MAXIMUM_DATA_OPERATIONS: u64 = 5;
const DEFAULT_ACQUISITION_DEADLINE_MILLISECONDS: u64 = 30_000;
const DEFAULT_MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;
const MAXIMUM_SCHEMA_BYTES: usize = 256 * 1024;
const MAXIMUM_HOST_PROTOCOL_CONFIG_BYTES: usize = 256 * 1024;
const MAXIMUM_SCHEMA_DEPTH: usize = 64;
const MAXIMUM_SCHEMA_NODES: usize = 8_192;
const HOST_PROTOCOL_ATTRIBUTION_HEADERS: [&str; 2] =
    ["registry-access-requester", "registry-access-purpose"];

/// Which side of an Evidence source contract a checked schema describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceSchemaKind {
    /// The reviewed acquisition input object.
    Inputs,
    /// The final facts object returned by a matched lookup.
    Facts,
}

/// Why an Evidence JSON Schema cannot enter the runtime.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum EvidenceSchemaError {
    #[error("the schema exceeds its byte, depth, or node bound")]
    Bound,
    #[error("the schema root must be a closed object")]
    RootNotClosed,
    #[error("every object schema must refuse undeclared properties")]
    ObjectNotClosed,
    #[error("the schema may use local fragment references only")]
    ExternalReference,
    #[error("the schema is not valid JSON Schema 2020-12")]
    Invalid,
}

/// A decoded, bounded, closed JSON Schema compiled with a resolver that
/// refuses every external document. The original value remains available to
/// authoring and host compilers, so nested arrays and objects are not reduced
/// to a product-specific field subset.
pub struct CheckedEvidenceSchema {
    value: Value,
    validator: JSONSchema,
}

impl std::fmt::Debug for CheckedEvidenceSchema {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedEvidenceSchema")
            .field("value", &"<schema>")
            .finish_non_exhaustive()
    }
}

impl CheckedEvidenceSchema {
    /// The exact checked schema value.
    #[must_use]
    pub fn as_value(&self) -> &Value {
        &self.value
    }

    /// Whether one value satisfies this checked schema.
    #[must_use]
    pub fn validate(&self, value: &Value) -> bool {
        self.validator.is_valid(value)
    }
}

#[derive(Debug)]
struct NoExternalSchemaResolver;

impl SchemaResolver for NoExternalSchemaResolver {
    fn resolve(
        &self,
        _root_schema: &Value,
        _url: &Url,
        _original_reference: &str,
    ) -> Result<Arc<Value>, SchemaResolverError> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "external Evidence schema resolution is disabled",
        )
        .into())
    }
}

/// Check and compile one Evidence schema without filesystem or network
/// resolution.
///
/// # Errors
///
/// The schema is refused when it is not a bounded closed object schema, names
/// an external reference or base URI, or does not compile as JSON Schema
/// 2020-12.
pub fn check_schema(
    _kind: EvidenceSchemaKind,
    schema: Value,
) -> Result<CheckedEvidenceSchema, EvidenceSchemaError> {
    check_schema_with_root(schema, SchemaRoot::ClosedObject)
}

/// Check a provider-response schema for the route-level schema validator.
/// Provider envelopes may be arrays or closed objects; nested objects retain
/// the same closure rule, external references remain disabled, and declared
/// formats use the same full validator as Evidence inputs and facts.
pub fn check_provider_schema(schema: Value) -> Result<CheckedEvidenceSchema, EvidenceSchemaError> {
    check_schema_with_root(schema, SchemaRoot::Provider)
}

#[derive(Clone, Copy)]
enum SchemaRoot {
    ClosedObject,
    Provider,
}

fn check_schema_with_root(
    schema: Value,
    root_policy: SchemaRoot,
) -> Result<CheckedEvidenceSchema, EvidenceSchemaError> {
    if serde_json::to_vec(&schema).map_or(true, |encoded| encoded.len() > MAXIMUM_SCHEMA_BYTES) {
        return Err(EvidenceSchemaError::Bound);
    }
    let root_is_closed_object = schema.as_object().is_some_and(|root| {
        root.get("type") == Some(&Value::String("object".to_owned()))
            && root.get("additionalProperties") == Some(&Value::Bool(false))
    });
    let root_is_array = schema
        .as_object()
        .is_some_and(|root| root.get("type") == Some(&Value::String("array".to_owned())));
    let root_is_admitted = match root_policy {
        SchemaRoot::ClosedObject => root_is_closed_object,
        SchemaRoot::Provider => root_is_closed_object || root_is_array,
    };
    if !root_is_admitted {
        return Err(EvidenceSchemaError::RootNotClosed);
    }
    let mut nodes = 0;
    check_schema_value(&schema, 0, &mut nodes)?;

    let mut options = JSONSchema::options();
    options
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_format("uuid", |value| {
            uuid::Uuid::parse_str(value)
                .is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
        })
        .with_resolver(NoExternalSchemaResolver);
    let validator = options
        .compile(&schema)
        .map_err(|_| EvidenceSchemaError::Invalid)?;
    Ok(CheckedEvidenceSchema {
        value: schema,
        validator,
    })
}

fn check_schema_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), EvidenceSchemaError> {
    if depth > MAXIMUM_SCHEMA_DEPTH || *nodes >= MAXIMUM_SCHEMA_NODES {
        return Err(EvidenceSchemaError::Bound);
    }
    *nodes += 1;
    match value {
        Value::Array(items) => {
            for item in items {
                check_schema_value(item, depth + 1, nodes)?;
            }
        }
        Value::Object(object) => {
            if (object.get("type") == Some(&Value::String("object".to_owned()))
                || object.contains_key("properties"))
                && object.get("additionalProperties") != Some(&Value::Bool(false))
            {
                return Err(EvidenceSchemaError::ObjectNotClosed);
            }
            for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
                if let Some(reference) = object.get(keyword) {
                    if !reference
                        .as_str()
                        .is_some_and(|value| value.starts_with('#'))
                    {
                        return Err(EvidenceSchemaError::ExternalReference);
                    }
                }
            }
            if let Some(identifier) = object.get("$id") {
                if !identifier
                    .as_str()
                    .is_some_and(|value| value.starts_with('#'))
                {
                    return Err(EvidenceSchemaError::ExternalReference);
                }
            }
            for member in object.values() {
                check_schema_value(member, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The finite budget shared by every route call in one Evidence acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceLimits {
    maximum_data_operations: u64,
    deadline: Duration,
    maximum_response_bytes: usize,
}

impl EvidenceLimits {
    /// Build a finite acquisition budget.
    ///
    /// # Errors
    ///
    /// Zero is not a meaningful bound for any member.
    pub fn try_new(
        maximum_data_operations: u64,
        deadline_milliseconds: u64,
        maximum_response_bytes: usize,
    ) -> Result<Self, EvidenceLimitError> {
        if maximum_data_operations == 0 || deadline_milliseconds == 0 || maximum_response_bytes == 0
        {
            return Err(EvidenceLimitError);
        }
        Ok(Self {
            maximum_data_operations,
            deadline: Duration::from_millis(deadline_milliseconds),
            maximum_response_bytes,
        })
    }

    #[must_use]
    pub const fn maximum_data_operations(self) -> u64 {
        self.maximum_data_operations
    }

    #[must_use]
    pub const fn deadline(self) -> Duration {
        self.deadline
    }

    #[must_use]
    pub const fn maximum_response_bytes(self) -> usize {
        self.maximum_response_bytes
    }
}

impl Default for EvidenceLimits {
    fn default() -> Self {
        Self {
            maximum_data_operations: DEFAULT_MAXIMUM_DATA_OPERATIONS,
            deadline: Duration::from_millis(DEFAULT_ACQUISITION_DEADLINE_MILLISECONDS),
            maximum_response_bytes: DEFAULT_MAXIMUM_RESPONSE_BYTES,
        }
    }
}

/// A zero acquisition limit is refused rather than interpreted as unlimited.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("Evidence acquisition limits must be finite and nonzero")]
pub struct EvidenceLimitError;

/// The in-memory inputs of listener-free Evidence compilation.
pub struct EvidenceCompileInputs<'a> {
    pub pack: &'a AdapterPack,
    pub route: &'a str,
    pub runtime: &'a EvidenceRuntimeBindings,
    /// The governed connection name. Equal names share transport, token
    /// cache and admission state; different names never share by comparing
    /// URLs or secret references. SQLite-only and no-network programs use
    /// `None`.
    pub connection_id: Option<&'a str>,
    /// The reviewed endpoint policies of the Evidence source's selected
    /// connection. Every reachable HTTP or GraphQL endpoint must match
    /// exactly one member; listener-free and SQLite-only closures pass an
    /// empty slice rather than fabricating a network connection.
    pub connection: &'a [EvidenceConnectionPolicy],
    pub pack_artifacts: &'a PackArtifactBytes,
    pub limits: EvidenceLimits,
}

#[derive(Debug)]
struct EvidenceRuntimeBindingsInner {
    bindings: AdapterEndpointBindings,
    resolver: Arc<SecretResolver>,
    captured_ca_bundles: BTreeMap<String, Arc<[u8]>>,
    endpoint_resources: std::sync::Mutex<BTreeMap<(String, String), EvidenceEndpointResource>>,
    #[cfg(feature = "sqlite-extract")]
    captured_sqlite: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
}

#[derive(Clone, Debug)]
struct EvidenceEndpointResource {
    policy: EvidenceConnectionPolicy,
    physical: Arc<tokio::sync::OnceCell<crate::egress::EndpointSharedResources>>,
}

/// The process-captured endpoint and secret-resolution authority an Evidence
/// program retains. Construction performs no secret, TLS, configuration, or
/// network I/O; the host supplies already-decoded governed bindings and the
/// resolver built from its configured provider policy.
#[derive(Clone, Debug)]
pub struct EvidenceRuntimeBindings {
    inner: Arc<EvidenceRuntimeBindingsInner>,
}

impl EvidenceRuntimeBindings {
    #[must_use]
    pub fn new(bindings: AdapterEndpointBindings, resolver: SecretResolver) -> Self {
        Self::from_parts(
            bindings,
            Arc::new(resolver),
            BTreeMap::new(),
            #[cfg(feature = "sqlite-extract")]
            BTreeMap::new(),
        )
    }

    /// Retain one named HTTP connection's shared resolver and immutable
    /// public CA bytes. Secret and mTLS material is still resolved only after
    /// durable acquisition intent.
    #[must_use]
    pub fn from_shared_http(
        bindings: AdapterEndpointBindings,
        resolver: Arc<SecretResolver>,
        captured_ca_bundles: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self::from_parts(
            bindings,
            resolver,
            captured_ca_bundles,
            #[cfg(feature = "sqlite-extract")]
            BTreeMap::new(),
        )
    }

    /// Capture the immutable SQLite extracts this process is authorized to
    /// use. Capture itself remains a host concern; compilation only retains
    /// these handles and does not open their files.
    #[cfg(feature = "sqlite-extract")]
    #[must_use]
    pub fn with_captured_sqlite(
        bindings: AdapterEndpointBindings,
        resolver: SecretResolver,
        captured_sqlite: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
    ) -> Self {
        Self::from_parts(
            bindings,
            Arc::new(resolver),
            BTreeMap::new(),
            captured_sqlite,
        )
    }

    /// Retain one named connection's shared resolver, immutable public CA
    /// bytes and immutable SQLite snapshots for every compiled Source that
    /// selects that connection.
    #[cfg(feature = "sqlite-extract")]
    #[must_use]
    pub fn from_shared(
        bindings: AdapterEndpointBindings,
        resolver: Arc<SecretResolver>,
        captured_sqlite: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
        captured_ca_bundles: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self::from_parts(bindings, resolver, captured_ca_bundles, captured_sqlite)
    }

    fn from_parts(
        bindings: AdapterEndpointBindings,
        resolver: Arc<SecretResolver>,
        captured_ca_bundles: BTreeMap<String, Vec<u8>>,
        #[cfg(feature = "sqlite-extract")] captured_sqlite: BTreeMap<
            String,
            registry_platform_sqlite::CapturedSnapshot,
        >,
    ) -> Self {
        Self {
            inner: Arc::new(EvidenceRuntimeBindingsInner {
                bindings,
                resolver,
                captured_ca_bundles: captured_ca_bundles
                    .into_iter()
                    .map(|(profile, bytes)| (profile, Arc::from(bytes)))
                    .collect(),
                endpoint_resources: std::sync::Mutex::new(BTreeMap::new()),
                #[cfg(feature = "sqlite-extract")]
                captured_sqlite,
            }),
        }
    }

    fn bindings(&self) -> &AdapterEndpointBindings {
        &self.inner.bindings
    }

    fn resolver(&self) -> &SecretResolver {
        self.inner.resolver.as_ref()
    }

    fn captured_ca(&self, profile: &str) -> Option<&[u8]> {
        self.inner
            .captured_ca_bundles
            .get(profile)
            .map(AsRef::as_ref)
    }

    fn endpoint_resource(
        &self,
        connection_id: &str,
        policy: &EvidenceConnectionPolicy,
    ) -> Result<
        Arc<tokio::sync::OnceCell<crate::egress::EndpointSharedResources>>,
        EvidenceCompileError,
    > {
        let key = (
            connection_id.to_owned(),
            policy.endpoint.as_str().to_owned(),
        );
        let refused = |reason| EvidenceCompileError::ConnectionPolicy {
            endpoint: policy.endpoint.as_str().to_owned(),
            reason,
        };
        let mut resources = self
            .inner
            .endpoint_resources
            .lock()
            .map_err(|_| refused(ConnectionPolicyReason::ResourceUnavailable))?;
        if let Some(resource) = resources.get(&key) {
            if resource.policy != *policy {
                return Err(refused(ConnectionPolicyReason::ResourceConflict));
            }
            return Ok(Arc::clone(&resource.physical));
        }
        let physical = Arc::new(tokio::sync::OnceCell::new());
        resources.insert(
            key,
            EvidenceEndpointResource {
                policy: policy.clone(),
                physical: Arc::clone(&physical),
            },
        );
        Ok(physical)
    }

    #[cfg(feature = "sqlite-extract")]
    fn captured_sqlite(&self) -> &BTreeMap<String, registry_platform_sqlite::CapturedSnapshot> {
        &self.inner.captured_sqlite
    }
}

/// A closed Evidence lookup result. Source dependency failures remain typed
/// execution errors; only a route that explicitly returns `no-match` produces
/// absence.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "lookup", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EvidenceLookup {
    Matched {
        facts: Value,
    },
    NoMatch,
    Ambiguous,
    /// The reviewed source explicitly states that the facts cannot currently
    /// be resolved. Transport, protocol and malformed replies remain errors.
    Unresolved,
}

impl<'de> Deserialize<'de> for EvidenceLookup {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "lookup", rename_all = "kebab-case", deny_unknown_fields)]
        enum ClosedLookup {
            Matched { facts: Value },
            NoMatch {},
            Ambiguous {},
            Unresolved {},
        }
        Ok(match ClosedLookup::deserialize(deserializer)? {
            ClosedLookup::Matched { facts } => Self::Matched { facts },
            ClosedLookup::NoMatch {} => Self::NoMatch,
            ClosedLookup::Ambiguous {} => Self::Ambiguous,
            ClosedLookup::Unresolved {} => Self::Unresolved,
        })
    }
}

#[derive(Debug, Error)]
pub enum EvidenceCompileError {
    #[error("the named Evidence source route is absent")]
    RouteMissing,
    #[error("the named source route has no Evidence contract")]
    ContractMissing,
    #[error("an Evidence schema artifact is unavailable or exceeds its bound")]
    SchemaArtifact,
    #[error("an Evidence schema artifact does not match its digest")]
    SchemaDigest,
    #[error("an Evidence schema artifact is not JSON")]
    SchemaJson,
    #[error("an Evidence schema was refused: {0}")]
    Schema(#[from] EvidenceSchemaError),
    #[error("an Evidence route reaches a write or unsupported destination")]
    ReachableWrite,
    #[error("an Evidence route names an absent direct route")]
    DirectRouteMissing,
    #[error("an Evidence route reaches an endpoint with no runtime binding")]
    EndpointUnbound,
    #[error("an Evidence endpoint could not compile")]
    Endpoint,
    #[cfg(feature = "sqlite-extract")]
    #[error("an Evidence SQLite endpoint could not compile")]
    Sqlite(EvidenceSqliteFault),
    #[error("an Evidence endpoint header policy could not compile: {0}")]
    EndpointHeaders(#[source] crate::component::http::header_filter::AllowlistError),
    #[error(
        "the runtime binding for endpoint `{endpoint}` does not match the reviewed Evidence connection policy: {reason}"
    )]
    ConnectionPolicy {
        endpoint: String,
        reason: ConnectionPolicyReason,
    },
    #[error("an Evidence route artifact could not compile")]
    Artifact,
    #[error(
        "the Evidence route requires {required} data operations, above the configured maximum of {maximum}"
    )]
    StaticOperationBudgetExceeded { required: u64, maximum: u64 },
    #[error("the Evidence route's static data-operation cost is uncountable")]
    StaticOperationBudgetUncountable,
    #[error("an Evidence route shape could not compile: {0}")]
    RouteUnsupported(String),
    #[error("an Evidence host protocol could not compile")]
    HostProtocol,
}

/// The one rule a runtime binding broke against its reviewed Evidence
/// connection policy. Each reason is a fixed sentence that names the member to
/// change and never carries an origin, a secret reference or trust bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ConnectionPolicyReason {
    #[error("the reviewed connection has no policy for this pack endpoint")]
    PolicyMissing,
    #[error("the reviewed connection lists this pack endpoint more than once")]
    PolicyDuplicate,
    #[error("the runtime binding is for a different connection than the source names")]
    ConnectionMismatch,
    #[error("the runtime connection has no entry for this pack endpoint")]
    EndpointUnbound,
    #[error("the runtime `baseUrl` differs from the reviewed `baseUrl`")]
    BaseUrlMismatch,
    #[error("the runtime `tlsTrustProfile` differs from the reviewed `tlsTrustProfile`")]
    TlsTrustProfileMismatch,
    #[error("the reviewed policy requires an `mtlsIdentity` and the runtime binding has none")]
    ClientIdentityRequired,
    #[error("the runtime binding sets an `mtlsIdentity` the reviewed policy forbids")]
    ClientIdentityForbidden,
    #[error(
        "the `tlsTrustProfile` CA bundle is not under `outboundTls.trustProfiles`, or is empty or too large"
    )]
    TrustMaterialUnavailable,
    #[error("the runtime credential does not match the reviewed `authentication`")]
    AuthenticationMismatch,
    #[error("the runtime credential is not admissible for the pack endpoint's authentication")]
    AuthenticationInvalid,
    #[error("another source binds this connection endpoint under a different reviewed policy")]
    ResourceConflict,
    #[error("the shared endpoint resource is unavailable")]
    ResourceUnavailable,
}

#[derive(Debug, Error)]
pub enum EvidenceExecutionError {
    #[error(transparent)]
    Terminal(#[from] EvidenceTerminalError),
    #[error("Evidence inputs do not satisfy the reviewed schema")]
    InputsInvalid,
    #[error("the Evidence route failed")]
    Route(RouteFailure),
    #[cfg(feature = "sqlite-extract")]
    #[error("the Evidence SQLite source failed")]
    Sqlite(EvidenceSqliteFault),
    #[error("the Evidence route did not return a closed lookup result")]
    LookupInvalid,
    #[error("matched Evidence facts do not satisfy the reviewed schema")]
    FactsInvalid,
}

#[derive(Debug, Error)]
pub enum EvidenceBeginError {
    #[error(transparent)]
    Terminal(#[from] EvidenceTerminalError),
    #[error("the captured Evidence endpoint authority could not start")]
    Endpoint,
    #[cfg(feature = "sqlite-extract")]
    #[error("the captured Evidence SQLite source could not start")]
    Sqlite(EvidenceSqliteFault),
}

/// Value-free readiness failures. Readiness may resolve credentials or
/// bootstrap a bounded OAuth token, but it never sends an Evidence data
/// request and never fabricates acquisition inputs.
#[derive(Clone, Debug, Error)]
pub enum EvidenceReadinessError {
    #[error("the captured Evidence endpoint authority could not start")]
    Endpoint,
    #[error("an Evidence source credential is not ready")]
    Credential,
    #[error("the Evidence readiness budget is exhausted")]
    Budget,
    #[cfg(feature = "sqlite-extract")]
    #[error("the captured Evidence SQLite source is not ready")]
    Sqlite(EvidenceSqliteFault),
}

/// Governed SQLite context retained only for an explicit operator diagnostic.
/// Ordinary error rendering remains categorical and carries neither identifier.
#[cfg(feature = "sqlite-extract")]
#[derive(Clone, Eq, PartialEq)]
pub struct EvidenceSqliteFault {
    artifact: String,
    cause: crate::component::sqlite_extract::SqliteExtractError,
}

#[cfg(feature = "sqlite-extract")]
impl EvidenceSqliteFault {
    pub(crate) fn from_statement_artifact(
        artifact: &str,
        cause: crate::component::sqlite_extract::SqliteExtractError,
    ) -> Self {
        Self {
            artifact: artifact.to_owned(),
            cause,
        }
    }

    fn from_plan(
        plan: &crate::component::sqlite_extract::SqliteExtractPlan,
        cause: crate::component::sqlite_extract::SqliteExtractError,
    ) -> Self {
        use crate::component::sqlite_extract::SqliteExtractError;
        use registry_platform_sqlite::ErrorKind;

        let extract_artifact = matches!(
            cause,
            SqliteExtractError::InvalidMetadata
                | SqliteExtractError::Stale
                | SqliteExtractError::Statement(
                    ErrorKind::DatabaseUnavailable
                        | ErrorKind::DatabaseReplaced
                        | ErrorKind::DatabaseWritable
                        | ErrorKind::DatabaseSymlink
                        | ErrorKind::DatabaseNotFile
                        | ErrorKind::DatabaseChanged
                        | ErrorKind::UncheckpointedSidecar
                )
        );
        Self {
            artifact: if extract_artifact {
                plan.extract_profile()
            } else {
                plan.statement_artifact()
            }
            .to_owned(),
            cause,
        }
    }

    /// The reviewed statement artifact or governed extract-profile identifier.
    #[must_use]
    pub fn artifact(&self) -> &str {
        &self.artifact
    }

    /// The closed, value-free adapter cause.
    #[must_use]
    pub const fn cause(&self) -> crate::component::sqlite_extract::SqliteExtractError {
        self.cause
    }

    /// The static adapter diagnosis code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.cause.code()
    }
}

#[cfg(feature = "sqlite-extract")]
impl std::fmt::Debug for EvidenceSqliteFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EvidenceSqliteFault(<governed>)")
    }
}

#[cfg(feature = "sqlite-extract")]
impl std::fmt::Display for EvidenceSqliteFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the governed Evidence SQLite source failed")
    }
}

#[cfg(feature = "sqlite-extract")]
impl std::error::Error for EvidenceSqliteFault {}

#[derive(Clone)]
struct EvidencePackEndpointPlan {
    declared: registry_adapter_core::Endpoint,
    graphql: Option<GraphQlQuery>,
    host_protocol: Option<Arc<dyn CompiledHostProtocol>>,
}

/// A digest-checked, read-only Evidence route compiled entirely from pack
/// bytes. It holds no runtime binding, credential resolver, TLS authority,
/// captured extract or network client.
pub struct EvidencePackProgram {
    pack: String,
    route: String,
    limits: EvidenceLimits,
    steps: Arc<Vec<Step>>,
    input_schema: CheckedEvidenceSchema,
    facts_schema: CheckedEvidenceSchema,
    endpoint_plans: BTreeMap<String, EvidencePackEndpointPlan>,
    #[cfg(feature = "sqlite-extract")]
    sqlite_plans: BTreeMap<String, crate::component::sqlite_extract::SqliteExtractPlan>,
    scripts: ScriptSet,
    resilience: crate::resilience::ResilienceRuntime,
    routes: RouteTable,
    code_maps: CodeMaps,
}

impl EvidencePackProgram {
    /// The checked acquisition-input schema from the pinned pack closure.
    #[must_use]
    pub fn input_schema(&self) -> &CheckedEvidenceSchema {
        &self.input_schema
    }

    /// The checked final-facts schema from the pinned pack closure.
    #[must_use]
    pub fn facts_schema(&self) -> &CheckedEvidenceSchema {
        &self.facts_schema
    }

    /// Logical captured-extract profiles required by this reviewed route.
    /// Reading this set performs no extract, filesystem, credential, or
    /// network I/O.
    #[cfg(feature = "sqlite-extract")]
    #[must_use]
    pub fn required_extract_profiles(&self) -> BTreeSet<String> {
        self.sqlite_plans
            .values()
            .map(|plan| plan.extract_profile().to_owned())
            .collect()
    }

    /// Bind this checked program to one reviewed, process-captured live
    /// connection. This is the first step that accepts credentials, TLS
    /// authority or captured extract handles.
    pub fn bind_live(
        self,
        runtime: &EvidenceRuntimeBindings,
        connection_id: Option<&str>,
        connection: &[EvidenceConnectionPolicy],
    ) -> Result<EvidenceProgram, EvidenceCompileError> {
        #[cfg(feature = "sqlite-extract")]
        for plan in self.sqlite_plans.values() {
            if !runtime
                .captured_sqlite()
                .contains_key(plan.extract_profile())
            {
                return Err(EvidenceCompileError::EndpointUnbound);
            }
        }
        let mut endpoint_plans = BTreeMap::new();
        for (id, plan) in &self.endpoint_plans {
            let refused = |reason| EvidenceCompileError::ConnectionPolicy {
                endpoint: id.clone(),
                reason,
            };
            let mut policies = connection
                .iter()
                .filter(|policy| policy.endpoint.as_str() == id);
            let Some(policy) = policies.next() else {
                return Err(refused(ConnectionPolicyReason::PolicyMissing));
            };
            if policies.next().is_some() {
                return Err(refused(ConnectionPolicyReason::PolicyDuplicate));
            }
            let connection_id = connection_id
                .filter(|connection_id| *connection_id == runtime.bindings().id.as_str())
                .ok_or_else(|| refused(ConnectionPolicyReason::ConnectionMismatch))?;
            validate_connection_policy(runtime, &plan.declared, policy)?;
            let resource = runtime.endpoint_resource(connection_id, policy)?;
            endpoint_plans.insert(
                id.clone(),
                EvidenceEndpointPlan {
                    declared: plan.declared.clone(),
                    graphql: plan.graphql.clone(),
                    host_protocol: plan.host_protocol.clone(),
                    runtime: Arc::new(tokio::sync::OnceCell::new()),
                    resource: Some(resource),
                    replay: None,
                },
            );
        }
        Ok(self.into_program(
            EvidenceProgramRuntime::Live(runtime.clone()),
            endpoint_plans,
        ))
    }

    /// Bind this checked program to a sealed offline transcript. The program
    /// gains no live binding, destination policy, TLS material or secret
    /// provider, and executes through the same route and acquisition budgets.
    pub fn bind_replay(
        self,
        transcript: Arc<crate::replay::ReplayTranscript>,
    ) -> Result<EvidenceProgram, EvidenceCompileError> {
        #[cfg(feature = "sqlite-extract")]
        if !self.sqlite_plans.is_empty() {
            return Err(EvidenceCompileError::Endpoint);
        }
        let mut endpoint_plans = BTreeMap::new();
        for (id, plan) in &self.endpoint_plans {
            let mut endpoint =
                EndpointRuntime::compile_evidence_replay(&plan.declared, Arc::clone(&transcript))
                    .map_err(|_| EvidenceCompileError::Endpoint)?;
            endpoint.graphql = plan.graphql.clone();
            endpoint_plans.insert(
                id.clone(),
                EvidenceEndpointPlan {
                    declared: plan.declared.clone(),
                    graphql: plan.graphql.clone(),
                    host_protocol: plan.host_protocol.clone(),
                    runtime: Arc::new(tokio::sync::OnceCell::new()),
                    resource: None,
                    replay: Some(Arc::new(endpoint)),
                },
            );
        }
        Ok(self.into_program(
            EvidenceProgramRuntime::Replay(SecretResolver::disabled()),
            endpoint_plans,
        ))
    }

    /// Bind a checked mixed HTTP/SQLite program to sealed HTTP exchanges and
    /// explicit captured fixture snapshots, without live credentials, TLS
    /// authority, or network access.
    #[cfg(feature = "sqlite-extract")]
    pub fn bind_fixture(
        self,
        transcript: Arc<crate::replay::ReplayTranscript>,
        captured_sqlite: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
    ) -> Result<EvidenceProgram, EvidenceCompileError> {
        for plan in self.sqlite_plans.values() {
            if !captured_sqlite.contains_key(plan.extract_profile()) {
                return Err(EvidenceCompileError::EndpointUnbound);
            }
        }
        let mut endpoint_plans = BTreeMap::new();
        for (id, plan) in &self.endpoint_plans {
            let mut endpoint =
                EndpointRuntime::compile_evidence_replay(&plan.declared, Arc::clone(&transcript))
                    .map_err(|_| EvidenceCompileError::Endpoint)?;
            endpoint.graphql = plan.graphql.clone();
            endpoint_plans.insert(
                id.clone(),
                EvidenceEndpointPlan {
                    declared: plan.declared.clone(),
                    graphql: plan.graphql.clone(),
                    host_protocol: plan.host_protocol.clone(),
                    runtime: Arc::new(tokio::sync::OnceCell::new()),
                    resource: None,
                    replay: Some(Arc::new(endpoint)),
                },
            );
        }
        Ok(self.into_program(
            EvidenceProgramRuntime::Fixture {
                resolver: SecretResolver::disabled(),
                captured_sqlite,
            },
            endpoint_plans,
        ))
    }

    fn into_program(
        self,
        runtime: EvidenceProgramRuntime,
        endpoint_plans: BTreeMap<String, EvidenceEndpointPlan>,
    ) -> EvidenceProgram {
        EvidenceProgram {
            pack: self.pack,
            route: self.route,
            limits: self.limits,
            steps: self.steps,
            input_schema: self.input_schema,
            facts_schema: self.facts_schema,
            endpoint_plans,
            #[cfg(feature = "sqlite-extract")]
            sqlite_plans: self.sqlite_plans,
            #[cfg(feature = "sqlite-extract")]
            sqlite_sources: Arc::new(SqliteSourceInitialization::default()),
            scripts: self.scripts,
            runtime,
            resilience: self.resilience,
            routes: self.routes,
            code_maps: self.code_maps,
        }
    }
}

enum EvidenceProgramRuntime {
    Live(EvidenceRuntimeBindings),
    Replay(SecretResolver),
    #[cfg(feature = "sqlite-extract")]
    Fixture {
        resolver: SecretResolver,
        captured_sqlite: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
    },
}

impl EvidenceProgramRuntime {
    fn resolver(&self) -> &SecretResolver {
        match self {
            Self::Live(runtime) => runtime.resolver(),
            Self::Replay(resolver) => resolver,
            #[cfg(feature = "sqlite-extract")]
            Self::Fixture { resolver, .. } => resolver,
        }
    }

    fn live(&self) -> Option<&EvidenceRuntimeBindings> {
        match self {
            Self::Live(runtime) => Some(runtime),
            Self::Replay(_) => None,
            #[cfg(feature = "sqlite-extract")]
            Self::Fixture { .. } => None,
        }
    }

    #[cfg(feature = "sqlite-extract")]
    fn captured_sqlite(
        &self,
    ) -> Option<&BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>> {
        match self {
            Self::Live(runtime) => Some(runtime.captured_sqlite()),
            Self::Replay(_) => None,
            Self::Fixture {
                captured_sqlite, ..
            } => Some(captured_sqlite),
        }
    }

    fn is_offline(&self) -> bool {
        match self {
            Self::Live(_) => false,
            Self::Replay(_) => true,
            #[cfg(feature = "sqlite-extract")]
            Self::Fixture { .. } => true,
        }
    }
}

#[derive(Clone)]
struct EvidenceEndpointPlan {
    declared: registry_adapter_core::Endpoint,
    graphql: Option<GraphQlQuery>,
    host_protocol: Option<Arc<dyn CompiledHostProtocol>>,
    runtime: Arc<tokio::sync::OnceCell<Arc<EndpointRuntime>>>,
    resource: Option<Arc<tokio::sync::OnceCell<crate::egress::EndpointSharedResources>>>,
    replay: Option<Arc<EndpointRuntime>>,
}

/// A compiled, listener-free Evidence program. It owns no facade project,
/// inbound router, database, or product client.
pub struct EvidenceProgram {
    pack: String,
    route: String,
    limits: EvidenceLimits,
    steps: Arc<Vec<Step>>,
    input_schema: CheckedEvidenceSchema,
    facts_schema: CheckedEvidenceSchema,
    endpoint_plans: BTreeMap<String, EvidenceEndpointPlan>,
    #[cfg(feature = "sqlite-extract")]
    sqlite_plans: BTreeMap<String, crate::component::sqlite_extract::SqliteExtractPlan>,
    #[cfg(feature = "sqlite-extract")]
    sqlite_sources: Arc<SqliteSourceInitialization>,
    scripts: ScriptSet,
    runtime: EvidenceProgramRuntime,
    resilience: crate::resilience::ResilienceRuntime,
    routes: RouteTable,
    code_maps: CodeMaps,
}

#[cfg(feature = "sqlite-extract")]
type PreparedSqliteSources =
    Arc<BTreeMap<String, crate::component::sqlite_extract::SqliteExtractSource>>;

#[cfg(feature = "sqlite-extract")]
struct SqliteSourceInitialization {
    state: tokio::sync::Mutex<SqliteSourceInitializationState>,
}

#[cfg(feature = "sqlite-extract")]
enum SqliteSourceInitializationState {
    Idle,
    Running {
        result: tokio::sync::watch::Receiver<Option<SqliteSourceInitializationSignal>>,
        task: tokio::task::JoinHandle<()>,
    },
    Ready(PreparedSqliteSources),
}

#[cfg(feature = "sqlite-extract")]
#[derive(Clone)]
enum SqliteSourceInitializationSignal {
    Complete(Result<PreparedSqliteSources, EvidenceReadinessError>),
    RetryAfterDrain,
}

#[cfg(feature = "sqlite-extract")]
impl Default for SqliteSourceInitialization {
    fn default() -> Self {
        Self {
            state: tokio::sync::Mutex::new(SqliteSourceInitializationState::Idle),
        }
    }
}

#[cfg(feature = "sqlite-extract")]
impl SqliteSourceInitialization {
    async fn prepare(
        self: &Arc<Self>,
        plans: BTreeMap<String, crate::component::sqlite_extract::SqliteExtractPlan>,
        captured: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
        deadline: tokio::time::Instant,
    ) -> Result<PreparedSqliteSources, EvidenceReadinessError> {
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(EvidenceReadinessError::Budget);
            }
            let mut receiver = {
                let mut state = self.state.lock().await;
                if tokio::time::Instant::now() >= deadline {
                    return Err(EvidenceReadinessError::Budget);
                }
                match &*state {
                    SqliteSourceInitializationState::Ready(sources) => {
                        return Ok(Arc::clone(sources));
                    }
                    SqliteSourceInitializationState::Running { result, .. } => result.clone(),
                    SqliteSourceInitializationState::Idle => {
                        let (sender, receiver) = tokio::sync::watch::channel(None);
                        let coordinator = Arc::clone(self);
                        let attempt_plans = plans.clone();
                        let attempt_captured = captured.clone();
                        let task = tokio::spawn(async move {
                            coordinator
                                .run_initialization(
                                    attempt_plans,
                                    attempt_captured,
                                    deadline,
                                    sender,
                                )
                                .await;
                        });
                        *state = SqliteSourceInitializationState::Running {
                            result: receiver.clone(),
                            task,
                        };
                        receiver
                    }
                }
            };
            let signal = loop {
                if let Some(signal) = receiver.borrow().clone() {
                    break signal;
                }
                match tokio::time::timeout_at(deadline, receiver.changed()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        self.recover_closed_task().await;
                        return Err(EvidenceReadinessError::Endpoint);
                    }
                    Err(_) => return Err(EvidenceReadinessError::Budget),
                }
            };
            match signal {
                SqliteSourceInitializationSignal::Complete(result) => return result,
                SqliteSourceInitializationSignal::RetryAfterDrain => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(EvidenceReadinessError::Budget);
                    }
                }
            }
        }
    }

    async fn run_initialization(
        self: Arc<Self>,
        plans: BTreeMap<String, crate::component::sqlite_extract::SqliteExtractPlan>,
        captured: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
        deadline: tokio::time::Instant,
        sender: tokio::sync::watch::Sender<Option<SqliteSourceInitializationSignal>>,
    ) {
        let blocking_deadline = deadline.into_std();
        let mut worker = tokio::task::spawn_blocking(move || {
            open_sqlite_sources_before(plans, captured, blocking_deadline)
        });
        let result = match tokio::time::timeout_at(deadline, &mut worker).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(EvidenceReadinessError::Endpoint),
            Err(_) => {
                // The coordinator, not an arbitrary timed-out waiter, owns the
                // worker through completion. Its absolute deadline also stops
                // the worker before a later endpoint or metadata query begins.
                if worker.await.is_err() {
                    tracing::error!(
                        "the SQLite source initialization worker failed while draining"
                    );
                    *self.state.lock().await = SqliteSourceInitializationState::Idle;
                    sender.send_replace(Some(SqliteSourceInitializationSignal::Complete(Err(
                        EvidenceReadinessError::Endpoint,
                    ))));
                    return;
                }
                *self.state.lock().await = SqliteSourceInitializationState::Idle;
                sender.send_replace(Some(SqliteSourceInitializationSignal::RetryAfterDrain));
                return;
            }
        };
        if tokio::time::Instant::now() >= deadline
            || matches!(&result, Err(EvidenceReadinessError::Budget))
        {
            *self.state.lock().await = SqliteSourceInitializationState::Idle;
            sender.send_replace(Some(SqliteSourceInitializationSignal::RetryAfterDrain));
            return;
        }
        match &result {
            Ok(sources) => {
                *self.state.lock().await =
                    SqliteSourceInitializationState::Ready(Arc::clone(sources));
            }
            Err(_) => *self.state.lock().await = SqliteSourceInitializationState::Idle,
        }
        sender.send_replace(Some(SqliteSourceInitializationSignal::Complete(result)));
    }

    async fn recover_closed_task(&self) {
        let task = {
            let mut state = self.state.lock().await;
            match std::mem::replace(&mut *state, SqliteSourceInitializationState::Idle) {
                SqliteSourceInitializationState::Running { task, .. } => Some(task),
                ready @ SqliteSourceInitializationState::Ready(_) => {
                    *state = ready;
                    None
                }
                SqliteSourceInitializationState::Idle => None,
            }
        };
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

#[cfg(feature = "sqlite-extract")]
fn open_sqlite_sources_before(
    plans: BTreeMap<String, crate::component::sqlite_extract::SqliteExtractPlan>,
    captured: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
    deadline: std::time::Instant,
) -> Result<PreparedSqliteSources, EvidenceReadinessError> {
    let mut sources = BTreeMap::new();
    for (id, plan) in plans {
        if std::time::Instant::now() >= deadline {
            return Err(EvidenceReadinessError::Budget);
        }
        let snapshot = captured
            .get(plan.extract_profile())
            .cloned()
            .ok_or_else(|| {
                EvidenceReadinessError::Sqlite(EvidenceSqliteFault::from_plan(
                    &plan,
                    crate::component::sqlite_extract::SqliteExtractError::InvalidMetadata,
                ))
            })?;
        let opened = plan.open_before(snapshot, deadline);
        if std::time::Instant::now() >= deadline {
            return Err(EvidenceReadinessError::Budget);
        }
        let source = opened.map_err(|cause| {
            EvidenceReadinessError::Sqlite(EvidenceSqliteFault::from_plan(&plan, cause))
        })?;
        sources.insert(id, source);
    }
    Ok(Arc::new(sources))
}

impl std::fmt::Debug for EvidenceProgram {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceProgram")
            .field("pack", &self.pack)
            .field("route", &self.route)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl EvidenceProgram {
    /// Whether any reachable selected host protocol requires authorized
    /// requester and purpose attribution for acquisition.
    #[must_use]
    pub fn requires_access_attribution(&self) -> bool {
        self.endpoint_plans.values().any(|plan| {
            plan.host_protocol
                .as_ref()
                .is_some_and(|protocol| protocol.requires_access_attribution())
        })
    }

    #[cfg(feature = "sqlite-extract")]
    fn sqlite_fault(
        &self,
        endpoint: &str,
        cause: crate::component::sqlite_extract::SqliteExtractError,
    ) -> Option<EvidenceSqliteFault> {
        self.sqlite_plans
            .get(endpoint)
            .map(|plan| EvidenceSqliteFault::from_plan(plan, cause))
    }

    #[cfg(feature = "sqlite-extract")]
    async fn prepare_sqlite_sources(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<PreparedSqliteSources, EvidenceReadinessError> {
        if self.sqlite_plans.is_empty() {
            return Ok(Arc::new(BTreeMap::new()));
        }
        let captured_sqlite = self
            .runtime
            .captured_sqlite()
            .ok_or(EvidenceReadinessError::Endpoint)?
            .clone();
        self.sqlite_sources
            .prepare(self.sqlite_plans.clone(), captured_sqlite, deadline)
            .await
    }

    #[cfg(feature = "sqlite-extract")]
    fn prepare_sqlite_sources_for_operator(
        &self,
    ) -> Result<PreparedSqliteSources, EvidenceReadinessError> {
        if self.sqlite_plans.is_empty() {
            return Ok(Arc::new(BTreeMap::new()));
        }
        let captured_sqlite = self
            .runtime
            .captured_sqlite()
            .ok_or(EvidenceReadinessError::Endpoint)?
            .clone();
        let deadline = std::time::Instant::now()
            .checked_add(self.limits.deadline)
            .ok_or(EvidenceReadinessError::Budget)?;
        open_sqlite_sources_before(self.sqlite_plans.clone(), captured_sqlite, deadline)
    }

    async fn initialize_endpoint(
        &self,
        id: &str,
        plan: &EvidenceEndpointPlan,
    ) -> Result<Arc<EndpointRuntime>, EvidenceBeginError> {
        if let Some(replay) = &plan.replay {
            return Ok(Arc::clone(replay));
        }
        let live = self.runtime.live().ok_or(EvidenceBeginError::Endpoint)?;
        plan.runtime
            .get_or_try_init(|| async {
                let binding = live
                    .bindings()
                    .endpoints
                    .get(id)
                    .ok_or(EvidenceBeginError::Endpoint)?;
                let captured_ca = binding
                    .tls_trust_profile
                    .as_ref()
                    .and_then(|profile| live.captured_ca(profile.as_str()));
                let mut endpoint = EndpointRuntime::compile_with_captured_ca(
                    binding,
                    &plan.declared,
                    live.bindings(),
                    live.resolver(),
                    captured_ca,
                )
                .map_err(|_| EvidenceBeginError::Endpoint)?;
                let physical = plan
                    .resource
                    .as_ref()
                    .ok_or(EvidenceBeginError::Endpoint)?
                    .get_or_try_init(|| async {
                        endpoint
                            .egress
                            .shared_resources()
                            .ok_or(EvidenceBeginError::Endpoint)
                    })
                    .await?;
                endpoint
                    .egress
                    .install_shared_resources(physical)
                    .map_err(|_| EvidenceBeginError::Endpoint)?;
                endpoint.graphql = plan.graphql.clone();
                Ok::<_, EvidenceBeginError>(Arc::new(endpoint))
            })
            .await
            .map(Arc::clone)
    }

    /// Record the ordinary acquisition intent and create the shared budget.
    pub async fn begin_acquisition(
        &self,
        hooks: Arc<dyn EvidenceHostHooks>,
    ) -> Result<EvidenceAcquisition, EvidenceBeginError> {
        self.begin_acquisition_inner(hooks, None, chrono::Utc::now(), None)
            .await
    }

    /// Record acquisition intent while retaining immutable, authorized access
    /// attribution for an explicitly opted-in host protocol. The attribution
    /// is never copied into an Exchange or exposed to a script.
    pub async fn begin_acquisition_with_attribution(
        &self,
        hooks: Arc<dyn EvidenceHostHooks>,
        attribution: Arc<HostAccessAttribution>,
    ) -> Result<EvidenceAcquisition, EvidenceBeginError> {
        self.begin_acquisition_inner(hooks, Some(attribution), chrono::Utc::now(), None)
            .await
    }

    /// Begin an acquisition with the host-captured evaluation instant used by
    /// every SQLite statement, host-protocol verification, and freshness check
    /// in this acquisition.
    pub async fn begin_acquisition_at(
        &self,
        hooks: Arc<dyn EvidenceHostHooks>,
        evaluation_instant: chrono::DateTime<chrono::Utc>,
    ) -> Result<EvidenceAcquisition, EvidenceBeginError> {
        self.begin_acquisition_inner(hooks, None, evaluation_instant, None)
            .await
    }

    /// Begin an attributed acquisition at the host-captured evaluation
    /// instant used by SQLite freshness and statement execution and by
    /// host-protocol verification.
    pub async fn begin_acquisition_at_with_attribution(
        &self,
        hooks: Arc<dyn EvidenceHostHooks>,
        attribution: Arc<HostAccessAttribution>,
        evaluation_instant: chrono::DateTime<chrono::Utc>,
    ) -> Result<EvidenceAcquisition, EvidenceBeginError> {
        self.begin_acquisition_inner(hooks, Some(attribution), evaluation_instant, None)
            .await
    }

    pub(crate) async fn begin_acquisition_inner(
        &self,
        hooks: Arc<dyn EvidenceHostHooks>,
        attribution: Option<Arc<HostAccessAttribution>>,
        evaluation_instant: chrono::DateTime<chrono::Utc>,
        maximum_deadline: Option<tokio::time::Instant>,
    ) -> Result<EvidenceAcquisition, EvidenceBeginError> {
        if maximum_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return Err(EvidenceTerminalError::Budget.into());
        }
        let intent = EvidenceAcquisitionIntent {
            pack: self.pack.clone(),
            route: self.route.clone(),
        };
        hooks
            .before_acquisition(intent.clone())
            .await
            .map_err(EvidenceTerminalError::from)?;
        // The complete acquisition budget starts immediately after the
        // durable intent. TLS material reads and extract opening therefore
        // consume the same deadline as subsequent sends and scripts.
        let deadline = tokio::time::Instant::now()
            .checked_add(self.limits.deadline)
            .ok_or(EvidenceTerminalError::Budget)?;
        let deadline = maximum_deadline.map_or(deadline, |maximum| deadline.min(maximum));
        let mut endpoints = BTreeMap::new();
        let mut host_protocols = BTreeMap::new();
        for (id, plan) in &self.endpoint_plans {
            if tokio::time::Instant::now() >= deadline {
                return Err(EvidenceBeginError::Terminal(EvidenceTerminalError::Budget));
            }
            let endpoint = self.initialize_endpoint(id, plan).await?;
            if tokio::time::Instant::now() >= deadline {
                return Err(EvidenceBeginError::Terminal(EvidenceTerminalError::Budget));
            }
            endpoints.insert(id.clone(), endpoint.as_ref().clone());
            if let Some(protocol) = &plan.host_protocol {
                host_protocols.insert(id.clone(), Arc::clone(protocol));
            }
        }
        let endpoints = Arc::new(endpoints);
        #[cfg(feature = "sqlite-extract")]
        let sqlite_sources = self
            .prepare_sqlite_sources(deadline)
            .await
            .map_err(|error| match error {
                EvidenceReadinessError::Budget => {
                    EvidenceBeginError::Terminal(EvidenceTerminalError::Budget)
                }
                EvidenceReadinessError::Sqlite(fault) => EvidenceBeginError::Sqlite(fault),
                EvidenceReadinessError::Endpoint | EvidenceReadinessError::Credential => {
                    EvidenceBeginError::Endpoint
                }
            })?;
        if tokio::time::Instant::now() >= deadline {
            return Err(EvidenceBeginError::Terminal(EvidenceTerminalError::Budget));
        }
        Ok(EvidenceAcquisition::after_intent(
            EvidenceAcquisitionStart {
                limits: self.limits,
                deadline,
                hooks,
                intent,
                endpoints,
                host_protocols: Arc::new(host_protocols),
                attribution,
                #[cfg(feature = "sqlite-extract")]
                sqlite_sources,
                evaluation_instant,
            },
        ))
    }

    /// Resolve and validate every reviewed connection credential without an
    /// Evidence data request. OAuth readiness may perform its bounded token
    /// bootstrap and retains the shared named-connection cache.
    pub async fn credentials_ready(&self) -> Result<(), EvidenceReadinessError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.limits.deadline)
            .ok_or(EvidenceReadinessError::Budget)?;
        #[cfg(feature = "sqlite-extract")]
        {
            self.prepare_sqlite_sources(deadline).await?;
            if tokio::time::Instant::now() >= deadline {
                return Err(EvidenceReadinessError::Budget);
            }
        }
        if self.runtime.is_offline() {
            return Ok(());
        }
        let mut token_budget = TokenBudget::new_exchange();
        for (id, plan) in &self.endpoint_plans {
            let endpoint = tokio::time::timeout_at(deadline, self.initialize_endpoint(id, plan))
                .await
                .map_err(|_| EvidenceReadinessError::Budget)?
                .map_err(|_| EvidenceReadinessError::Endpoint)?;
            let mut events = Vec::new();
            tokio::time::timeout_at(
                deadline,
                endpoint.egress.authorize(
                    &mut token_budget,
                    self.runtime.resolver(),
                    &crate::auth::PlatformAssertionSigner,
                    &mut events,
                ),
            )
            .await
            .map_err(|_| EvidenceReadinessError::Budget)?
            .map_err(|_| EvidenceReadinessError::Credential)?;
        }
        Ok(())
    }

    /// Open every captured extract and report whether any publication age is
    /// outside its reviewed bound. This operator preflight reads only the
    /// reserved publication metadata; it never executes a Source data query.
    #[cfg(feature = "sqlite-extract")]
    pub fn probe_extract_freshness(
        &self,
        evaluation_instant: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, EvidenceReadinessError> {
        match self.diagnose_extract_freshness(evaluation_instant) {
            Ok(()) => Ok(false),
            Err(EvidenceReadinessError::Sqlite(fault))
                if fault.cause() == crate::component::sqlite_extract::SqliteExtractError::Stale =>
            {
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    /// Check every captured extract and retain governed context for an
    /// operator, while ordinary readiness rendering remains categorical.
    #[cfg(feature = "sqlite-extract")]
    pub fn diagnose_extract_freshness(
        &self,
        evaluation_instant: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), EvidenceReadinessError> {
        let sources = self.prepare_sqlite_sources_for_operator()?;
        for (endpoint, source) in sources.iter() {
            source.validate_age(evaluation_instant).map_err(|cause| {
                self.sqlite_fault(endpoint, cause).map_or(
                    EvidenceReadinessError::Endpoint,
                    EvidenceReadinessError::Sqlite,
                )
            })?;
        }
        Ok(())
    }

    /// Execute one route call inside an already-authorized acquisition. The
    /// same acquisition may be reused for bounded pagination or repeated
    /// source lookups; its counters and deadline do not reset.
    pub async fn execute(
        &self,
        acquisition: &EvidenceAcquisition,
        inputs: Value,
    ) -> Result<EvidenceLookup, EvidenceExecutionError> {
        let body = self.execute_raw(acquisition, inputs).await?;
        let lookup: EvidenceLookup =
            serde_json::from_value(body).map_err(|_| EvidenceExecutionError::LookupInvalid)?;
        if let EvidenceLookup::Matched { facts } = &lookup {
            if !self.facts_schema.validate(facts) {
                return Err(EvidenceExecutionError::FactsInvalid);
            }
        }
        Ok(lookup)
    }

    pub(crate) async fn execute_raw(
        &self,
        acquisition: &EvidenceAcquisition,
        inputs: Value,
    ) -> Result<Value, EvidenceExecutionError> {
        if acquisition.pack != self.pack || acquisition.route != self.route {
            return Err(EvidenceExecutionError::Terminal(
                EvidenceTerminalError::Authority,
            ));
        }
        if !self.input_schema.validate(&inputs) {
            return Err(EvidenceExecutionError::InputsInvalid);
        }
        let context = RouteContext {
            endpoints: &acquisition.endpoints,
            scripts: &self.scripts,
            resolver: self.runtime.resolver(),
            resilience: &self.resilience,
            routes: &self.routes,
            code_maps: Arc::clone(&self.code_maps),
            maximum_upstream_calls: self.limits.maximum_data_operations,
            job: crate::job_sources::JobPageState::default(),
        };
        let mut exchange = Exchange::new(format!("evidence:{}", self.route));
        exchange.message.body = inputs;
        let outcome =
            crate::route::run_evidence_route(&context, self.steps.as_ref(), exchange, acquisition)
                .await;
        let exchange = match outcome.result {
            Ok(exchange) => exchange,
            Err(error) => {
                #[cfg(feature = "sqlite-extract")]
                if let Some(diagnostic) = error.evidence_diagnostic.as_ref() {
                    if let Some((endpoint, cause)) = diagnostic.sqlite_parts() {
                        if let Some(fault) = self.sqlite_fault(endpoint, cause) {
                            return Err(EvidenceExecutionError::Sqlite(fault));
                        }
                    }
                }
                return Err(EvidenceExecutionError::Route(error));
            }
        };
        Ok(exchange.message.body)
    }

    #[must_use]
    pub fn input_schema(&self) -> &CheckedEvidenceSchema {
        &self.input_schema
    }

    #[must_use]
    pub fn facts_schema(&self) -> &CheckedEvidenceSchema {
        &self.facts_schema
    }
}

/// Compile a digest-pinned Evidence source route entirely from supplied
/// in-memory artifacts.
pub fn compile_evidence(
    inputs: &EvidenceCompileInputs<'_>,
) -> Result<EvidenceProgram, EvidenceCompileError> {
    compile_evidence_pack(
        inputs.pack,
        inputs.route,
        inputs.pack_artifacts,
        inputs.limits,
    )?
    .bind_live(inputs.runtime, inputs.connection_id, inputs.connection)
}

/// Compile one Evidence pack with the embedding product's closed host
/// protocol registry, then bind it to captured live authority.
pub fn compile_evidence_with_protocols(
    inputs: &EvidenceCompileInputs<'_>,
    protocols: &HostProtocolRegistry,
) -> Result<EvidenceProgram, EvidenceCompileError> {
    compile_evidence_pack_with_protocols(
        inputs.pack,
        inputs.route,
        inputs.pack_artifacts,
        inputs.limits,
        protocols,
    )?
    .bind_live(inputs.runtime, inputs.connection_id, inputs.connection)
}

/// Compile and verify one Evidence pack closure without runtime bindings,
/// secret resolution, TLS material, captured extracts or network I/O.
pub fn compile_evidence_pack(
    pack: &AdapterPack,
    route: &str,
    pack_artifacts: &PackArtifactBytes,
    limits: EvidenceLimits,
) -> Result<EvidencePackProgram, EvidenceCompileError> {
    compile_evidence_pack_with_protocols(
        pack,
        route,
        pack_artifacts,
        limits,
        &HostProtocolRegistry::default(),
    )
}

/// Compile and verify one Evidence pack closure with a closed set of
/// product-supplied host protocols. This remains pure: protocol compilers see
/// only the endpoint declaration and exact digest-pinned public config bytes.
pub fn compile_evidence_pack_with_protocols(
    pack: &AdapterPack,
    route: &str,
    pack_artifacts: &PackArtifactBytes,
    limits: EvidenceLimits,
    protocols: &HostProtocolRegistry,
) -> Result<EvidencePackProgram, EvidenceCompileError> {
    let source = pack
        .source_routes
        .get(route)
        .ok_or(EvidenceCompileError::RouteMissing)?;
    let contract = source
        .evidence
        .as_ref()
        .ok_or(EvidenceCompileError::ContractMissing)?;
    let input_schema = load_schema(
        pack_artifacts,
        &contract.inputs_schema,
        EvidenceSchemaKind::Inputs,
    )?;
    let facts_schema = load_schema(
        pack_artifacts,
        &contract.facts_schema,
        EvidenceSchemaKind::Facts,
    )?;
    compile_read_pack_with_schemas(
        pack,
        source,
        pack_artifacts,
        limits,
        protocols,
        input_schema,
        facts_schema,
    )
}

pub(crate) fn compile_read_pack_with_schemas(
    pack: &AdapterPack,
    source: &SourceRouteDecl,
    pack_artifacts: &PackArtifactBytes,
    limits: EvidenceLimits,
    protocols: &HostProtocolRegistry,
    input_schema: CheckedEvidenceSchema,
    facts_schema: CheckedEvidenceSchema,
) -> Result<EvidencePackProgram, EvidenceCompileError> {
    check_read_only_closure(pack, source)?;
    let worst_case = registry_adapter_core::evidence_route_worst_case(pack, &source.steps);
    if worst_case.uncountable {
        return Err(EvidenceCompileError::StaticOperationBudgetUncountable);
    }
    if worst_case.data_operations > limits.maximum_data_operations() {
        return Err(EvidenceCompileError::StaticOperationBudgetExceeded {
            required: worst_case.data_operations,
            maximum: limits.maximum_data_operations(),
        });
    }

    let mut scripts = ScriptSet::default();
    let mut endpoint_plans = BTreeMap::new();
    #[cfg(feature = "sqlite-extract")]
    let mut sqlite_plans = BTreeMap::new();
    let reachable = reachable_endpoint_ids(pack, source)?;
    for endpoint in pack.endpoints.iter() {
        if authored_endpoint_claims_host_attribution_header(endpoint) {
            return Err(EvidenceCompileError::HostProtocol);
        }
        if !reachable.contains(endpoint.id.as_str()) {
            continue;
        }
        if endpoint.component == ComponentKind::SqliteExtract {
            #[cfg(feature = "sqlite-extract")]
            {
                let plan = crate::component::sqlite_extract::SqliteExtractPlan::compile(
                    endpoint,
                    pack_artifacts,
                )
                .map_err(|cause| {
                    endpoint.sqlite_extract.as_ref().map_or(
                        EvidenceCompileError::Endpoint,
                        |declaration| {
                            EvidenceCompileError::Sqlite(
                                EvidenceSqliteFault::from_statement_artifact(
                                    declaration.statement.path.as_str(),
                                    cause,
                                ),
                            )
                        },
                    )
                })?;
                sqlite_plans.insert(endpoint.id.as_str().to_owned(), plan);
                continue;
            }
            #[cfg(not(feature = "sqlite-extract"))]
            return Err(EvidenceCompileError::Endpoint);
        }
        let graphql = if endpoint.component == ComponentKind::GraphQl {
            let query = GraphQlQuery::load_from(pack, pack_artifacts, endpoint)
                .map_err(|_| EvidenceCompileError::Artifact)?;
            if let Some(Expression::Rhai(script)) = &query.variables {
                scripts
                    .add_from(pack, pack_artifacts, &script.file, &script.entrypoint)
                    .map_err(|_| EvidenceCompileError::Artifact)?;
            }
            Some(query)
        } else {
            None
        };
        let host_protocol = endpoint
            .host_protocol
            .as_ref()
            .map(|declaration| {
                let bytes = pack_artifacts
                    .read_bounded(&declaration.config.path, MAXIMUM_HOST_PROTOCOL_CONFIG_BYTES)
                    .map_err(|_| EvidenceCompileError::HostProtocol)?;
                if sha256_uri(&bytes) != declaration.config.digest.as_str() {
                    return Err(EvidenceCompileError::HostProtocol);
                }
                protocols
                    .compile(declaration, endpoint, &bytes)
                    .map_err(|_| EvidenceCompileError::HostProtocol)
            })
            .transpose()?;
        let mut declared = endpoint.clone();
        if let Some(protocol) = &host_protocol {
            let mut request_headers = declared.request_headers.clone().into_vec();
            for name in protocol.request_header_names() {
                if request_headers
                    .iter()
                    .any(|existing| existing.as_str().eq_ignore_ascii_case(name.as_str()))
                {
                    continue;
                }
                request_headers.push(
                    registry_platform_yaml::ExternalId::new(name.as_str())
                        .map_err(|_| EvidenceCompileError::HostProtocol)?,
                );
            }
            declared.request_headers = registry_platform_yaml::UniqueList::new(request_headers)
                .map_err(|_| EvidenceCompileError::HostProtocol)?;
        }
        crate::component::http::header_filter::HeaderFilter::for_endpoint(&declared)
            .map_err(EvidenceCompileError::EndpointHeaders)?;
        endpoint_plans.insert(
            endpoint.id.as_str().to_owned(),
            EvidencePackEndpointPlan {
                declared,
                graphql,
                host_protocol,
            },
        );
    }
    #[cfg(not(feature = "sqlite-extract"))]
    let bound_endpoints: BTreeSet<String> = endpoint_plans.keys().cloned().collect();
    #[cfg(feature = "sqlite-extract")]
    let bound_endpoints: BTreeSet<String> = endpoint_plans
        .keys()
        .chain(sqlite_plans.keys())
        .cloned()
        .collect();
    ensure_reachable_endpoints_bound(pack, source, &bound_endpoints)?;

    let steps = Arc::new(source.steps.clone());
    let routes: RouteTable = pack
        .routes
        .iter()
        .map(|route| {
            (
                route.from.uri.id.as_str().to_owned(),
                Arc::new(route.steps.clone()),
            )
        })
        .collect();
    crate::route::check_direct_targets(&routes)
        .map_err(|_| EvidenceCompileError::DirectRouteMissing)?;
    compile_step_artifacts(pack, pack_artifacts, steps.as_ref(), &mut scripts)?;
    for steps in routes.values() {
        compile_step_artifacts(pack, pack_artifacts, steps, &mut scripts)?;
    }
    let mut resilience = crate::resilience::ResilienceRuntime::empty();
    resilience.absorb(steps.as_ref());
    for steps in routes.values() {
        resilience.absorb(steps);
    }
    let code_maps = Arc::new(
        pack.code_maps
            .iter()
            .map(|map| (map.id.as_str().to_owned(), map.clone()))
            .collect(),
    );

    Ok(EvidencePackProgram {
        pack: pack.id.as_str().to_owned(),
        route: source.id.as_str().to_owned(),
        limits,
        steps,
        input_schema,
        facts_schema,
        endpoint_plans,
        #[cfg(feature = "sqlite-extract")]
        sqlite_plans,
        scripts,
        resilience,
        routes,
        code_maps,
    })
}

fn authored_endpoint_claims_host_attribution_header(
    endpoint: &registry_adapter_core::Endpoint,
) -> bool {
    let is_host_attribution_header = |candidate: &str| {
        HOST_PROTOCOL_ATTRIBUTION_HEADERS
            .iter()
            .any(|reserved| candidate.eq_ignore_ascii_case(reserved))
    };
    endpoint
        .request_headers
        .iter()
        .any(|name| is_host_attribution_header(name.as_str()))
        || matches!(
            &endpoint.authentication,
            EndpointAuthentication::StaticApiKey { header_name }
                if is_host_attribution_header(header_name)
        )
}

fn validate_connection_policy(
    runtime: &EvidenceRuntimeBindings,
    endpoint: &registry_adapter_core::Endpoint,
    connection: &EvidenceConnectionPolicy,
) -> Result<(), EvidenceCompileError> {
    let refused = |reason| EvidenceCompileError::ConnectionPolicy {
        endpoint: connection.endpoint.as_str().to_owned(),
        reason,
    };
    let binding = runtime
        .bindings()
        .endpoints
        .get(connection.endpoint.as_str())
        .ok_or_else(|| refused(ConnectionPolicyReason::EndpointUnbound))?;
    if binding.base_url != connection.base_url {
        return Err(refused(ConnectionPolicyReason::BaseUrlMismatch));
    }
    if binding.tls_trust_profile != connection.tls_trust_profile {
        return Err(refused(ConnectionPolicyReason::TlsTrustProfileMismatch));
    }
    match connection.client_identity {
        EvidenceClientIdentityPolicy::Forbidden if binding.mtls_identity.is_some() => {
            return Err(refused(ConnectionPolicyReason::ClientIdentityForbidden));
        }
        EvidenceClientIdentityPolicy::Required if binding.mtls_identity.is_none() => {
            return Err(refused(ConnectionPolicyReason::ClientIdentityRequired));
        }
        EvidenceClientIdentityPolicy::Forbidden | EvidenceClientIdentityPolicy::Required => {}
    }
    let trust_material_matches = match &connection.tls_trust_profile {
        None => true,
        Some(profile) => {
            runtime
                .bindings()
                .outbound_tls
                .as_ref()
                .is_some_and(|tls| tls.trust_profiles.contains_key(profile.as_str()))
                && runtime.captured_ca(profile.as_str()).is_some_and(|bytes| {
                    !bytes.is_empty()
                    && bytes.len()
                        <= registry_platform_httputil::destination::MAX_DESTINATION_CA_BUNDLE_BYTES
                })
        }
    };
    if !trust_material_matches {
        return Err(refused(ConnectionPolicyReason::TrustMaterialUnavailable));
    }
    if !authentication_authority_matches(
        &endpoint.authentication,
        binding.credential.as_ref(),
        &connection.authentication,
    ) {
        return Err(refused(ConnectionPolicyReason::AuthenticationMismatch));
    }
    if AuthPlan::compile(&endpoint.authentication, binding).is_err() {
        return Err(refused(ConnectionPolicyReason::AuthenticationInvalid));
    }
    Ok(())
}

fn authentication_authority_matches(
    declared: &EndpointAuthentication,
    runtime: Option<&RuntimeCredential>,
    reviewed: &EvidenceAuthenticationPolicy,
) -> bool {
    match (declared, runtime, reviewed) {
        (
            EndpointAuthentication::None {},
            Some(RuntimeCredential::None {}),
            EvidenceAuthenticationPolicy::None {},
        )
        | (
            EndpointAuthentication::Basic {},
            Some(RuntimeCredential::Basic { .. }),
            EvidenceAuthenticationPolicy::Basic {},
        )
        | (
            EndpointAuthentication::StaticAuthorization { .. },
            Some(RuntimeCredential::StaticAuthorization { .. }),
            EvidenceAuthenticationPolicy::StaticAuthorization {},
        )
        | (
            EndpointAuthentication::StaticApiKey { .. },
            Some(RuntimeCredential::StaticApiKey { .. }),
            EvidenceAuthenticationPolicy::StaticApiKey {},
        ) => true,
        (
            EndpointAuthentication::Oauth2ClientCredentials {},
            Some(RuntimeCredential::Oauth2ClientCredentials {
                token_endpoint,
                scope,
                audience,
                resource,
                credential_placement,
                ..
            }),
            EvidenceAuthenticationPolicy::Oauth2ClientCredentials {
                token_endpoint: reviewed_token_endpoint,
                scope: reviewed_scope,
                audience: reviewed_audience,
                resource: reviewed_resource,
                credential_placement: reviewed_placement,
            },
        ) => {
            token_endpoint == reviewed_token_endpoint
                && scope == reviewed_scope
                && audience == reviewed_audience
                && resource == reviewed_resource
                && credential_placement == reviewed_placement
        }
        (
            EndpointAuthentication::Oauth2PrivateKeyJwt {},
            Some(RuntimeCredential::Oauth2PrivateKeyJwt {
                token_endpoint,
                client_assertion_audience,
                scope,
                audience,
                resource,
                ..
            }),
            EvidenceAuthenticationPolicy::Oauth2PrivateKeyJwt {
                token_endpoint: reviewed_token_endpoint,
                client_assertion_audience: reviewed_assertion_audience,
                scope: reviewed_scope,
                audience: reviewed_audience,
                resource: reviewed_resource,
            },
        ) => {
            token_endpoint == reviewed_token_endpoint
                && client_assertion_audience == reviewed_assertion_audience
                && scope == reviewed_scope
                && audience == reviewed_audience
                && resource == reviewed_resource
        }
        _ => false,
    }
}

pub(crate) fn load_schema(
    artifacts: &PackArtifactBytes,
    reference: &registry_adapter_core::ScriptReference,
    kind: EvidenceSchemaKind,
) -> Result<CheckedEvidenceSchema, EvidenceCompileError> {
    let bytes = artifacts
        .read_bounded(&reference.path, MAXIMUM_SCHEMA_BYTES)
        .map_err(|error| match error {
            ArtifactReadError::Unavailable | ArtifactReadError::TooLarge => {
                EvidenceCompileError::SchemaArtifact
            }
        })?;
    if sha256_uri(&bytes) != reference.digest.as_str() {
        return Err(EvidenceCompileError::SchemaDigest);
    }
    let schema = serde_json::from_slice(&bytes).map_err(|_| EvidenceCompileError::SchemaJson)?;
    check_schema(kind, schema).map_err(EvidenceCompileError::from)
}

fn compile_step_artifacts(
    pack: &AdapterPack,
    artifacts: &PackArtifactBytes,
    steps: &[Step],
    scripts: &mut ScriptSet,
) -> Result<(), EvidenceCompileError> {
    crate::load::compile_step_schemas(artifacts, steps, scripts)
        .map_err(|_| EvidenceCompileError::Artifact)?;
    let mut expressions = Vec::new();
    let mut strategies = Vec::new();
    registry_adapter_core::walk_steps(steps, &mut |step, _| {
        expressions.extend(crate::load::step_expressions(step));
        strategies.extend(
            crate::load::step_aggregation_strategies(step)
                .into_iter()
                .cloned(),
        );
    });
    for expression in expressions {
        if let Expression::Rhai(script) = expression {
            scripts
                .add_from(pack, artifacts, &script.file, &script.entrypoint)
                .map_err(|_| EvidenceCompileError::Artifact)?;
        }
    }
    for strategy in strategies {
        if let AggregationStrategy::Rhai { expression } = strategy {
            scripts
                .add_aggregation_from(pack, artifacts, &expression.file, &expression.entrypoint)
                .map_err(|_| EvidenceCompileError::Artifact)?;
        }
    }
    Ok(())
}

fn check_read_only_closure(
    pack: &AdapterPack,
    source: &SourceRouteDecl,
) -> Result<(), EvidenceCompileError> {
    let routes: BTreeMap<_, _> = pack
        .routes
        .iter()
        .map(|route| (route.from.uri.id.as_str(), route.steps.as_slice()))
        .collect();
    let mut visited = BTreeSet::new();
    check_read_only_steps(pack, &routes, &source.steps, &mut visited)
}

fn check_read_only_steps<'a>(
    pack: &'a AdapterPack,
    routes: &BTreeMap<&'a str, &'a [Step]>,
    steps: &'a [Step],
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), EvidenceCompileError> {
    crate::route::check_evidence_servable(steps).map_err(EvidenceCompileError::RouteUnsupported)?;
    let mut destinations = Vec::new();
    registry_adapter_core::walk_steps(steps, &mut |step, _| match step {
        Step::To(send) => destinations.push((&send.uri, send.parameters.as_ref())),
        Step::Enrich(send) => destinations.push((&send.uri, send.parameters.as_ref())),
        _ => {}
    });
    for (uri, parameters) in destinations {
        if uri.component == SendComponent::Direct {
            let Some(target) = routes.get(uri.id.as_str()).copied() else {
                return Err(EvidenceCompileError::DirectRouteMissing);
            };
            if visited.insert(uri.id.as_str()) {
                check_read_only_steps(pack, routes, target, visited)?;
            }
            continue;
        }
        let endpoint = pack
            .endpoints
            .get(uri.id.as_str())
            .ok_or(EvidenceCompileError::EndpointUnbound)?;
        let operation = parameters.and_then(|parameters| parameters.operation.as_ref());
        let safe = match uri.component {
            SendComponent::Http if endpoint.component == ComponentKind::Http => {
                let method = parameters
                    .and_then(|parameters| parameters.http_method)
                    .unwrap_or(HttpMethod::Post);
                method == HttpMethod::Get
                    || method == HttpMethod::Post
                        && operation.is_some_and(|operation| {
                            endpoint.operations.iter().any(|declared| {
                                declared.id.as_str() == operation.as_str() && declared.safe_upstream
                            })
                        })
            }
            SendComponent::GraphQl if endpoint.component == ComponentKind::GraphQl => operation
                .is_some_and(|operation| {
                    endpoint.operations.iter().any(|declared| {
                        declared.id.as_str() == operation.as_str()
                            && declared.graphql == Some(GraphQlOperationKind::Query)
                    })
                }),
            SendComponent::SqliteExtract if endpoint.component == ComponentKind::SqliteExtract => {
                endpoint.sqlite_extract.is_some()
            }
            _ => false,
        };
        if !safe {
            return Err(EvidenceCompileError::ReachableWrite);
        }
    }
    Ok(())
}

fn ensure_reachable_endpoints_bound(
    pack: &AdapterPack,
    source: &SourceRouteDecl,
    endpoints: &BTreeSet<String>,
) -> Result<(), EvidenceCompileError> {
    for endpoint in reachable_endpoint_ids(pack, source)? {
        if !endpoints.contains(&endpoint) {
            return Err(EvidenceCompileError::EndpointUnbound);
        }
    }
    Ok(())
}

pub(crate) fn reachable_endpoint_ids(
    pack: &AdapterPack,
    source: &SourceRouteDecl,
) -> Result<BTreeSet<String>, EvidenceCompileError> {
    let routes: BTreeMap<_, _> = pack
        .routes
        .iter()
        .map(|route| (route.from.uri.id.as_str(), route.steps.as_slice()))
        .collect();
    let mut pending = vec![source.steps.as_slice()];
    let mut visited = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    while let Some(steps) = pending.pop() {
        let mut destinations = Vec::new();
        registry_adapter_core::walk_steps(steps, &mut |step, _| match step {
            Step::To(send) => destinations.push(&send.uri),
            Step::Enrich(send) => destinations.push(&send.uri),
            _ => {}
        });
        for uri in destinations {
            if uri.component == SendComponent::Direct {
                if visited.insert(uri.id.as_str()) {
                    pending.push(
                        routes
                            .get(uri.id.as_str())
                            .copied()
                            .ok_or(EvidenceCompileError::DirectRouteMissing)?,
                    );
                }
            } else {
                endpoints.insert(uri.id.as_str().to_owned());
            }
        }
    }
    Ok(endpoints)
}

/// The value-free acquisition intent a host must authorize and journal before
/// the first route invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceAcquisitionIntent {
    pub pack: String,
    pub route: String,
}

/// The transport shape of one reviewed Evidence data operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceSendMethod {
    Get,
    ReadOnlyPost,
    GraphQlQuery,
    HostProtocol,
    #[cfg(feature = "sqlite-extract")]
    SqliteExtract,
}

/// The value-free intent emitted immediately before credential acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceSendIntent {
    pub endpoint: String,
    pub operation: Option<String>,
    pub method: EvidenceSendMethod,
}

/// Why a host hook refused an acquisition or send.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EvidenceHookError {
    #[error("the Evidence acquisition is not authorized")]
    Authority,
    #[error("the Evidence acquisition intent could not be audited")]
    Audit,
}

pub type EvidenceHookFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), EvidenceHookError>> + Send + 'a>>;

/// Host-owned authority and audit hooks. The acquisition hook is mandatory;
/// the per-send hook is optional but, when supplied, runs before credentials
/// are read or produced.
pub trait EvidenceHostHooks: Send + Sync {
    fn before_acquisition<'a>(
        &'a self,
        intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a>;

    fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

/// Terminal acquisition failures. These are raised outside the route's
/// catchable hierarchy, so pack `onException` and `doCatch` clauses cannot
/// convert them into successful evidence.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EvidenceTerminalError {
    #[error("Evidence acquisition authority refused the operation")]
    Authority,
    #[error("Evidence acquisition audit recording failed")]
    Audit,
    #[error("the shared Evidence acquisition budget is exhausted")]
    Budget,
    #[error("the selected Evidence host protocol refused the response")]
    Protocol,
}

impl From<EvidenceHookError> for EvidenceTerminalError {
    fn from(error: EvidenceHookError) -> Self {
        match error {
            EvidenceHookError::Authority => Self::Authority,
            EvidenceHookError::Audit => Self::Audit,
        }
    }
}

#[derive(Debug, Default)]
struct EvidenceBudgetState {
    data_operations: u64,
    response_bytes: usize,
}

/// Trusted validity metadata retained outside the route Exchange after a host
/// protocol verifies an exact wire response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTrustedProtocolMetadata {
    pub endpoint: String,
    pub valid_until: String,
}

/// State shared by every route invocation that contributes to one Evidence
/// lookup. Hosts create it only through the compiled program's begin path.
pub struct EvidenceAcquisition {
    pack: String,
    route: String,
    limits: EvidenceLimits,
    deadline: tokio::time::Instant,
    hooks: Arc<dyn EvidenceHostHooks>,
    endpoints: Arc<BTreeMap<String, EndpointRuntime>>,
    host_protocols: Arc<BTreeMap<String, Arc<dyn CompiledHostProtocol>>>,
    attribution: Option<Arc<HostAccessAttribution>>,
    #[cfg(feature = "sqlite-extract")]
    sqlite_sources: Arc<BTreeMap<String, crate::component::sqlite_extract::SqliteExtractSource>>,
    evaluation_instant: chrono::DateTime<chrono::Utc>,
    state: tokio::sync::Mutex<EvidenceBudgetState>,
    trusted_protocol_metadata: tokio::sync::Mutex<Vec<EvidenceTrustedProtocolMetadata>>,
    trusted_protocol_attachment: tokio::sync::Mutex<Option<HostProtocolAttachment>>,
    pub(crate) token_budget: tokio::sync::Mutex<TokenBudget>,
    pub(crate) projection_http: Option<crate::projection::ProjectionHttpState>,
}

struct EvidenceAcquisitionStart {
    limits: EvidenceLimits,
    deadline: tokio::time::Instant,
    hooks: Arc<dyn EvidenceHostHooks>,
    intent: EvidenceAcquisitionIntent,
    endpoints: Arc<BTreeMap<String, EndpointRuntime>>,
    host_protocols: Arc<BTreeMap<String, Arc<dyn CompiledHostProtocol>>>,
    attribution: Option<Arc<HostAccessAttribution>>,
    #[cfg(feature = "sqlite-extract")]
    sqlite_sources: Arc<BTreeMap<String, crate::component::sqlite_extract::SqliteExtractSource>>,
    evaluation_instant: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for EvidenceAcquisition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceAcquisition")
            .field("limits", &self.limits)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl EvidenceAcquisition {
    #[cfg(test)]
    pub(crate) async fn begin(
        limits: EvidenceLimits,
        hooks: Arc<dyn EvidenceHostHooks>,
        intent: EvidenceAcquisitionIntent,
    ) -> Result<Self, EvidenceTerminalError> {
        let pack = intent.pack.clone();
        let route = intent.route.clone();
        hooks.before_acquisition(intent).await?;
        let deadline = tokio::time::Instant::now()
            .checked_add(limits.deadline)
            .ok_or(EvidenceTerminalError::Budget)?;
        Ok(Self {
            pack,
            route,
            limits,
            deadline,
            hooks,
            endpoints: Arc::new(BTreeMap::new()),
            host_protocols: Arc::new(BTreeMap::new()),
            attribution: None,
            #[cfg(feature = "sqlite-extract")]
            sqlite_sources: Arc::new(BTreeMap::new()),
            evaluation_instant: chrono::Utc::now(),
            state: tokio::sync::Mutex::new(EvidenceBudgetState::default()),
            trusted_protocol_metadata: tokio::sync::Mutex::new(Vec::new()),
            trusted_protocol_attachment: tokio::sync::Mutex::new(None),
            token_budget: tokio::sync::Mutex::new(TokenBudget::new_exchange()),
            projection_http: None,
        })
    }

    fn after_intent(start: EvidenceAcquisitionStart) -> Self {
        Self {
            pack: start.intent.pack,
            route: start.intent.route,
            limits: start.limits,
            deadline: start.deadline,
            hooks: start.hooks,
            endpoints: start.endpoints,
            host_protocols: start.host_protocols,
            attribution: start.attribution,
            #[cfg(feature = "sqlite-extract")]
            sqlite_sources: start.sqlite_sources,
            evaluation_instant: start.evaluation_instant,
            state: tokio::sync::Mutex::new(EvidenceBudgetState::default()),
            trusted_protocol_metadata: tokio::sync::Mutex::new(Vec::new()),
            trusted_protocol_attachment: tokio::sync::Mutex::new(None),
            token_budget: tokio::sync::Mutex::new(TokenBudget::new_exchange()),
            projection_http: None,
        }
    }

    /// The absolute deadline shared by every route call in this acquisition.
    /// Embedding hosts retain it through their terminal release gate; they do
    /// not use it to cancel a durable append that has already begun.
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    pub(crate) fn maximum_response_bytes(&self) -> usize {
        self.limits.maximum_response_bytes
    }

    pub(crate) fn host_protocol(&self, endpoint: &str) -> Option<&Arc<dyn CompiledHostProtocol>> {
        self.host_protocols.get(endpoint)
    }

    pub(crate) fn attribution(&self) -> Option<&HostAccessAttribution> {
        self.attribution.as_deref()
    }

    pub(crate) async fn record_protocol_validity(&self, endpoint: &str, valid_until: String) {
        self.trusted_protocol_metadata
            .lock()
            .await
            .push(EvidenceTrustedProtocolMetadata {
                endpoint: endpoint.to_owned(),
                valid_until,
            });
    }

    /// Retain the one opaque attachment a verified host-protocol response
    /// carried. A second attachment in the same acquisition is refused rather
    /// than merged or replaced.
    pub(crate) async fn record_protocol_attachment(
        &self,
        attachment: HostProtocolAttachment,
    ) -> Result<(), EvidenceTerminalError> {
        let mut slot = self.trusted_protocol_attachment.lock().await;
        if slot.is_some() {
            return Err(EvidenceTerminalError::Protocol);
        }
        *slot = Some(attachment);
        Ok(())
    }

    /// The opaque attachment a host protocol verifier returned for this
    /// acquisition, if any. The engine never reads it; the embedding host
    /// downcasts it to the type its protocol produces. It never enters the
    /// Exchange processed by routes.
    pub async fn trusted_protocol_attachment(&self) -> Option<HostProtocolAttachment> {
        self.trusted_protocol_attachment.lock().await.clone()
    }

    /// Trusted validity metadata returned only after host-protocol
    /// verification. Values never enter the Exchange processed by routes.
    pub async fn trusted_protocol_metadata(&self) -> Vec<EvidenceTrustedProtocolMetadata> {
        self.trusted_protocol_metadata.lock().await.clone()
    }

    #[cfg(feature = "sqlite-extract")]
    pub(crate) fn sqlite_source(
        &self,
        id: &str,
    ) -> Option<&crate::component::sqlite_extract::SqliteExtractSource> {
        self.sqlite_sources.get(id)
    }

    pub(crate) fn evaluation_instant(&self) -> chrono::DateTime<chrono::Utc> {
        self.evaluation_instant
    }

    pub(crate) async fn before_data_send(
        &self,
        intent: EvidenceSendIntent,
    ) -> Result<(), EvidenceTerminalError> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(EvidenceTerminalError::Budget);
        }
        {
            let mut state = self.state.lock().await;
            if state.data_operations >= self.limits.maximum_data_operations
                || (self.projection_http.is_some()
                    && state.response_bytes >= self.limits.maximum_response_bytes)
            {
                return Err(EvidenceTerminalError::Budget);
            }
            state.data_operations += 1;
        }
        self.hooks.before_credentials(intent).await?;
        Ok(())
    }

    pub(crate) async fn remaining_response_bytes(&self) -> usize {
        let state = self.state.lock().await;
        self.limits
            .maximum_response_bytes
            .saturating_sub(state.response_bytes)
    }

    pub(crate) async fn record_response_bytes(
        &self,
        bytes: usize,
    ) -> Result<(), EvidenceTerminalError> {
        let mut state = self.state.lock().await;
        let Some(total) = state.response_bytes.checked_add(bytes) else {
            return Err(EvidenceTerminalError::Budget);
        };
        if total > self.limits.maximum_response_bytes {
            return Err(EvidenceTerminalError::Budget);
        }
        state.response_bytes = total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use registry_platform_config::SecretProvider;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[test]
    fn checked_schema_keeps_nested_values_and_declared_optionality() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "parents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "name": {"type": "string"},
                            "holdings": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["name"]
                    }
                },
                "spouse": {"$ref": "#/$defs/person"}
            },
            "$defs": {
                "person": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"]
                }
            },
            "required": ["parents"]
        });

        let checked =
            check_schema(EvidenceSchemaKind::Facts, schema.clone()).expect("nested closed schema");
        assert_eq!(checked.as_value(), &schema);
        assert!(checked.validate(&json!({"parents": [{"name": "A", "holdings": ["H1"]}]})));
        assert!(checked.validate(&json!({
            "parents": [{"name": "A"}],
            "spouse": {"name": "B"}
        })));
    }

    #[test]
    fn checked_schema_refuses_external_resolution_and_unbounded_shapes() {
        for schema in [
            json!({"type": "object", "additionalProperties": false, "$ref": "https://example.test/schema"}),
            json!({"type": "object", "additionalProperties": false, "$dynamicRef": "other.json#person"}),
            json!({"$id": "file:///tmp/facts.json", "type": "object", "additionalProperties": false}),
            json!({"type": "object", "properties": {"name": {"type": "string"}}}),
        ] {
            assert!(
                check_schema(EvidenceSchemaKind::Facts, schema).is_err(),
                "unsafe schema is refused"
            );
        }
    }

    #[test]
    fn checked_schema_enforces_declared_calendar_datetime_and_uuid_formats() {
        let checked = check_schema(
            EvidenceSchemaKind::Facts,
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "effectiveDate": {"type": "string", "format": "date"},
                    "observedAt": {"type": "string", "format": "date-time"},
                    "recordId": {"type": "string", "format": "uuid"}
                },
                "required": ["effectiveDate", "observedAt", "recordId"]
            }),
        )
        .expect("closed schema with standard formats");

        assert!(checked.validate(&json!({
            "effectiveDate": "2024-02-29",
            "observedAt": "2026-10-31T12:30:00Z",
            "recordId": "018f1f47-a922-7e31-8000-000000000001"
        })));
        for (format, invalid) in [
            (
                "date",
                json!({
                    "effectiveDate": "2026-02-29",
                    "observedAt": "2026-10-31T12:30:00Z",
                    "recordId": "018f1f47-a922-7e31-8000-000000000001"
                }),
            ),
            (
                "date-time",
                json!({
                    "effectiveDate": "2026-10-31",
                    "observedAt": "not-a-date-time",
                    "recordId": "018f1f47-a922-7e31-8000-000000000001"
                }),
            ),
            (
                "uuid",
                json!({
                    "effectiveDate": "2026-10-31",
                    "observedAt": "2026-10-31T12:30:00Z",
                    "recordId": "not-a-uuid"
                }),
            ),
            (
                "canonical uuid",
                json!({
                    "effectiveDate": "2026-10-31",
                    "observedAt": "2026-10-31T12:30:00Z",
                    "recordId": "018f1f47a9227e318000000000000001"
                }),
            ),
            (
                "canonical uuid",
                json!({
                    "effectiveDate": "2026-10-31",
                    "observedAt": "2026-10-31T12:30:00Z",
                    "recordId": "018F1F47-A922-7E31-8000-000000000001"
                }),
            ),
        ] {
            assert!(
                !checked.validate(&invalid),
                "a value violating the declared {format} format must be refused"
            );
        }
    }

    #[test]
    fn evidence_limits_default_to_one_finite_acquisition_budget() {
        let limits = EvidenceLimits::default();
        assert_eq!(limits.maximum_data_operations(), 5);
        assert_eq!(limits.deadline(), std::time::Duration::from_secs(30));
        assert!(limits.maximum_response_bytes() > 0);
        assert!(EvidenceLimits::try_new(0, 30_000, 1).is_err());
        assert!(EvidenceLimits::try_new(5, 0, 1).is_err());
        assert!(EvidenceLimits::try_new(5, 30_000, 0).is_err());
    }

    #[test]
    fn unresolved_is_a_closed_lookup_outcome_distinct_from_absence_and_failure() {
        assert_eq!(
            serde_json::from_value::<EvidenceLookup>(json!({"lookup": "unresolved"}))
                .expect("declared unresolved lookup"),
            EvidenceLookup::Unresolved
        );
        assert!(serde_json::from_value::<EvidenceLookup>(json!({
            "lookup": "unresolved",
            "facts": {}
        }))
        .is_err());
        assert_ne!(EvidenceLookup::Unresolved, EvidenceLookup::NoMatch);
    }

    #[derive(Default)]
    struct RecordingHooks {
        acquisitions: Mutex<Vec<EvidenceAcquisitionIntent>>,
        sends: Mutex<Vec<EvidenceSendIntent>>,
    }

    impl EvidenceHostHooks for RecordingHooks {
        fn before_acquisition<'a>(
            &'a self,
            intent: EvidenceAcquisitionIntent,
        ) -> EvidenceHookFuture<'a> {
            self.acquisitions.lock().expect("lock").push(intent);
            Box::pin(async { Ok(()) })
        }

        fn before_credentials<'a>(&'a self, intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
            self.sends.lock().expect("lock").push(intent);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn one_acquisition_shares_operations_bytes_and_hooks_across_calls() {
        let hooks = Arc::new(RecordingHooks::default());
        let limits = EvidenceLimits::try_new(2, 30_000, 7).expect("limits");
        let acquisition = EvidenceAcquisition::begin(
            limits,
            hooks.clone(),
            EvidenceAcquisitionIntent {
                pack: "civil-register".to_owned(),
                route: "person-evidence".to_owned(),
            },
        )
        .await
        .expect("intent recorded");

        for index in 0..2 {
            acquisition
                .before_data_send(EvidenceSendIntent {
                    endpoint: "register".to_owned(),
                    operation: Some(format!("lookup-{index}")),
                    method: EvidenceSendMethod::Get,
                })
                .await
                .expect("within operation budget");
        }
        acquisition
            .record_response_bytes(3)
            .await
            .expect("first response");
        acquisition
            .record_response_bytes(4)
            .await
            .expect("shared exact byte ceiling");
        assert_eq!(
            acquisition
                .before_data_send(EvidenceSendIntent {
                    endpoint: "register".to_owned(),
                    operation: None,
                    method: EvidenceSendMethod::Get,
                })
                .await,
            Err(EvidenceTerminalError::Budget)
        );
        assert_eq!(
            acquisition.record_response_bytes(1).await,
            Err(EvidenceTerminalError::Budget)
        );
        assert_eq!(hooks.acquisitions.lock().expect("lock").len(), 1);
        assert_eq!(hooks.sends.lock().expect("lock").len(), 2);
    }

    fn in_memory_program() -> EvidenceProgram {
        let inputs_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"nationalId": {"type": "string"}},
            "required": ["nationalId"]
        });
        let facts_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "parents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"]
                    }
                },
                "spouse": {"type": "string"}
            },
            "required": ["parents"]
        });
        let inputs_bytes = serde_json::to_vec(&inputs_schema).expect("schema");
        let facts_bytes = serde_json::to_vec(&facts_schema).expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "civil-register",
            "version": "1",
            "testedVersions": [],
            "sourceRoutes": [{
                "id": "person-evidence",
                "evidence": {
                    "inputsSchema": {
                        "path": "schemas/inputs.json",
                        "digest": sha256_uri(&inputs_bytes)
                    },
                    "factsSchema": {
                        "path": "schemas/facts.json",
                        "digest": sha256_uri(&facts_bytes)
                    }
                },
                "steps": [{
                    "setBody": {"constant": {
                        "lookup": "matched",
                        "facts": {"parents": [{"name": "Ada"}]}
                    }}
                }]
            }]
        }))
        .expect("pack");
        let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
            "id": "evidence-runtime",
            "endpoints": [],
            "allowedPrivateCidrs": ["192.168.0.0/16"]
        }))
        .expect("bindings");
        let runtime = EvidenceRuntimeBindings::new(
            bindings,
            SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
        );
        let artifacts = PackArtifactBytes::new([
            ("schemas/inputs.json".to_owned(), inputs_bytes),
            ("schemas/facts.json".to_owned(), facts_bytes),
        ]);
        compile_evidence(&EvidenceCompileInputs {
            pack: &pack,
            route: "person-evidence",
            runtime: &runtime,
            connection_id: None,
            connection: &[],
            pack_artifacts: &artifacts,
            limits: EvidenceLimits::default(),
        })
        .expect("program compiles from supplied bytes")
    }

    #[test]
    fn pure_pack_compile_requires_exact_artifacts_without_runtime_bindings() {
        let schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "offline-pack",
            "version": "1",
            "testedVersions": [],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "inputs.json", "digest": sha256_uri(&schema)},
                    "factsSchema": {"path": "facts.json", "digest": sha256_uri(&schema)}
                },
                "steps": [{"setBody": {"constant": {"lookup": "no-match"}}}]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([
            ("inputs.json".to_owned(), schema.clone()),
            ("facts.json".to_owned(), schema.clone()),
        ]);

        let checked =
            compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default())
                .expect("pure compile needs no runtime authority");
        assert_eq!(checked.input_schema().as_value()["type"], "object");

        let missing = PackArtifactBytes::new([("inputs.json".to_owned(), schema.clone())]);
        assert!(matches!(
            compile_evidence_pack(&pack, "evidence", &missing, EvidenceLimits::default()),
            Err(EvidenceCompileError::SchemaArtifact)
        ));
        let tampered = PackArtifactBytes::new([
            ("inputs.json".to_owned(), schema),
            (
                "facts.json".to_owned(),
                br#"{\"type\":\"object\"}"#.to_vec(),
            ),
        ]);
        assert!(matches!(
            compile_evidence_pack(&pack, "evidence", &tampered, EvidenceLimits::default()),
            Err(EvidenceCompileError::SchemaDigest)
        ));
    }

    /// The selected Evidence source route is admitted before any runtime
    /// authority is bound. A path placeholder without its matching binding
    /// is therefore a compile refusal, not a first-request route failure.
    #[test]
    fn pure_pack_compile_refuses_a_mismatched_source_path_binding() {
        let schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "offline-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "provider",
                "component": "http",
                "authentication": {"type": "none"},
                "maximumResponseBytes": 4096,
                "operations": [{"id": "lookup", "safeUpstream": true}]
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "inputs.json", "digest": sha256_uri(&schema)},
                    "factsSchema": {"path": "facts.json", "digest": sha256_uri(&schema)}
                },
                "steps": [{"to": {"uri": "http:provider", "parameters": {
                    "httpMethod": "GET",
                    "path": "/v1/facts/{{given_name}}",
                    "operation": "lookup"
                }}}]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([
            ("inputs.json".to_owned(), schema.clone()),
            ("facts.json".to_owned(), schema),
        ]);

        assert!(matches!(
            compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default()),
            Err(EvidenceCompileError::RouteUnsupported(_))
        ));
    }

    struct InertHostProtocol;

    impl crate::host_protocol::CompiledHostProtocol for InertHostProtocol {
        fn response_header_names(&self) -> &[http::HeaderName] {
            &[]
        }

        fn prepare_attempt(
            &self,
            _request: crate::host_protocol::HostProtocolRequestContext<'_>,
            _attribution: Option<&crate::host_protocol::HostAccessAttribution>,
            _maximum_request_bytes: usize,
        ) -> Result<
            crate::host_protocol::PreparedHostProtocolRequest,
            crate::host_protocol::HostProtocolError,
        > {
            Err(crate::host_protocol::HostProtocolError)
        }
    }

    struct RecordingHostProtocolCompiler {
        configs: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl crate::host_protocol::HostProtocolCompiler for RecordingHostProtocolCompiler {
        fn id(&self) -> &str {
            "signed-evidence-v1"
        }

        fn compile(
            &self,
            _endpoint: &registry_adapter_core::Endpoint,
            config: &[u8],
        ) -> Result<
            Arc<dyn crate::host_protocol::CompiledHostProtocol>,
            crate::host_protocol::HostProtocolError,
        > {
            self.configs.lock().expect("configs").push(config.to_vec());
            Ok(Arc::new(InertHostProtocol))
        }
    }

    struct CountingHostProtocolCompiler {
        id: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl crate::host_protocol::HostProtocolCompiler for CountingHostProtocolCompiler {
        fn id(&self) -> &str {
            self.id
        }

        fn compile(
            &self,
            _endpoint: &registry_adapter_core::Endpoint,
            _config: &[u8],
        ) -> Result<
            Arc<dyn crate::host_protocol::CompiledHostProtocol>,
            crate::host_protocol::HostProtocolError,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(InertHostProtocol))
        }
    }

    fn pack_with_attribution_header_collision(
        request_header: Option<&str>,
        api_key_header: Option<&str>,
        protocol: Option<(&str, Value)>,
    ) -> (AdapterPack, PackArtifactBytes) {
        let schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let authentication = api_key_header.map_or_else(
            || json!({"type": "none"}),
            |header| json!({"type": "static-api-key", "headerName": header}),
        );
        let mut endpoint = json!({
            "id": "register",
            "component": "http",
            "authentication": authentication,
            "attemptTimeoutMilliseconds": 1000,
            "maximumResponseBytes": 4096,
            "requestHeaders": request_header.map_or_else(Vec::<&str>::new, |header| vec![header]),
            "responseHeaders": [],
            "operations": [{"id": "read-evidence", "safeUpstream": true}],
            "testedVersions": []
        });
        let mut artifacts = vec![
            ("inputs.json".to_owned(), schema.clone()),
            ("facts.json".to_owned(), schema.clone()),
        ];
        if let Some((id, config)) = protocol {
            let config = serde_json::to_vec(&config).expect("protocol config");
            endpoint["hostProtocol"] = json!({
                "id": id,
                "config": {"path": "protocol.json", "digest": sha256_uri(&config)}
            });
            artifacts.push(("protocol.json".to_owned(), config));
        }
        let pack = serde_json::from_value(json!({
            "id": "reserved-attribution-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [endpoint],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "inputs.json", "digest": sha256_uri(&schema)},
                    "factsSchema": {"path": "facts.json", "digest": sha256_uri(&schema)}
                },
                "steps": [{"to": {
                    "uri": "http:register",
                    "parameters": {
                        "httpMethod": "POST",
                        "operation": "read-evidence",
                        "path": "/v1/evidence",
                        "body": {"constant": {"subjects": []}}
                    }
                }}]
            }]
        }))
        .expect("pack");
        (pack, PackArtifactBytes::new(artifacts))
    }

    #[test]
    fn authored_endpoints_cannot_claim_protocol_owned_attribution_headers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = HostProtocolRegistry::try_new([
            Arc::new(CountingHostProtocolCompiler {
                id: "access-attribution-v1",
                calls: Arc::clone(&calls),
            }) as Arc<dyn crate::host_protocol::HostProtocolCompiler>,
            Arc::new(CountingHostProtocolCompiler {
                id: "registry-lookup-v1",
                calls: Arc::clone(&calls),
            }) as Arc<dyn crate::host_protocol::HostProtocolCompiler>,
        ])
        .expect("registry");
        let contexts = [
            ("none", None),
            (
                "access-attribution-v1",
                Some(("access-attribution-v1", json!({}))),
            ),
            (
                "registry-lookup-v1 false",
                Some((
                    "registry-lookup-v1",
                    json!({"forwardAccessAttribution": false}),
                )),
            ),
            (
                "registry-lookup-v1 true",
                Some((
                    "registry-lookup-v1",
                    json!({"forwardAccessAttribution": true}),
                )),
            ),
        ];
        for (context, protocol) in contexts {
            for header in ["Registry-Access-Requester", "REGISTRY-ACCESS-PURPOSE"] {
                let (pack, artifacts) =
                    pack_with_attribution_header_collision(Some(header), None, protocol.clone());
                assert!(
                    matches!(
                        compile_evidence_pack_with_protocols(
                            &pack,
                            "evidence",
                            &artifacts,
                            EvidenceLimits::default(),
                            &registry,
                        ),
                        Err(EvidenceCompileError::HostProtocol)
                    ),
                    "{context} must refuse authored {header}"
                );
            }
        }
        for header in ["Registry-Access-Requester", "REGISTRY-ACCESS-PURPOSE"] {
            let (pack, artifacts) =
                pack_with_attribution_header_collision(None, Some(header), None);
            assert!(matches!(
                compile_evidence_pack_with_protocols(
                    &pack,
                    "evidence",
                    &artifacts,
                    EvidenceLimits::default(),
                    &registry,
                ),
                Err(EvidenceCompileError::HostProtocol)
            ));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pure_compile_requires_a_known_host_protocol_and_exact_config_bytes() {
        let schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let config = br#"{"contract":"reviewed"}"#.to_vec();
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "protocol-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "register",
                "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 4096,
                "responseHeaders": [],
                "requestHeaders": [],
                "operations": [{"id": "read-evidence", "safeUpstream": true}],
                "testedVersions": [],
                "hostProtocol": {
                    "id": "signed-evidence-v1",
                    "config": {"path": "protocol.json", "digest": sha256_uri(&config)}
                }
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "inputs.json", "digest": sha256_uri(&schema)},
                    "factsSchema": {"path": "facts.json", "digest": sha256_uri(&schema)}
                },
                "steps": [{"to": {
                    "uri": "http:register",
                    "parameters": {
                        "httpMethod": "POST",
                        "operation": "read-evidence",
                        "path": "/v1/evidence",
                        "body": {"constant": {"subjects": []}}
                    }
                }}]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([
            ("inputs.json".to_owned(), schema.clone()),
            ("facts.json".to_owned(), schema),
            ("protocol.json".to_owned(), config.clone()),
        ]);

        assert!(matches!(
            compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default()),
            Err(EvidenceCompileError::HostProtocol)
        ));

        let configs = Arc::new(Mutex::new(Vec::new()));
        let registry = HostProtocolRegistry::try_new([Arc::new(RecordingHostProtocolCompiler {
            configs: Arc::clone(&configs),
        })
            as Arc<dyn crate::host_protocol::HostProtocolCompiler>])
        .expect("closed protocol registry");
        compile_evidence_pack_with_protocols(
            &pack,
            "evidence",
            &artifacts,
            EvidenceLimits::default(),
            &registry,
        )
        .expect("known protocol compiles from exact bytes");

        assert_eq!(*configs.lock().expect("configs"), vec![config]);
    }

    struct WireHostProtocolCompiler {
        expected_config: Vec<u8>,
        expected_response: Vec<u8>,
        attempts: Arc<AtomicUsize>,
    }

    impl crate::host_protocol::HostProtocolCompiler for WireHostProtocolCompiler {
        fn id(&self) -> &str {
            "signed-evidence-v1"
        }

        fn compile(
            &self,
            endpoint: &registry_adapter_core::Endpoint,
            config: &[u8],
        ) -> Result<
            Arc<dyn crate::host_protocol::CompiledHostProtocol>,
            crate::host_protocol::HostProtocolError,
        > {
            if endpoint.component != ComponentKind::Http || config != self.expected_config {
                return Err(crate::host_protocol::HostProtocolError);
            }
            Ok(Arc::new(WireHostProtocol {
                expected_response: self.expected_response.clone(),
                attempts: Arc::clone(&self.attempts),
                request_headers: vec![http::HeaderName::from_static("x-evidence-requester")],
                response_headers: vec![
                    http::header::CONTENT_TYPE,
                    http::HeaderName::from_static("traceparent"),
                ],
            }))
        }
    }

    struct WireHostProtocol {
        expected_response: Vec<u8>,
        attempts: Arc<AtomicUsize>,
        request_headers: Vec<http::HeaderName>,
        response_headers: Vec<http::HeaderName>,
    }

    impl crate::host_protocol::CompiledHostProtocol for WireHostProtocol {
        fn request_header_names(&self) -> &[http::HeaderName] {
            &self.request_headers
        }

        fn response_header_names(&self) -> &[http::HeaderName] {
            &self.response_headers
        }

        fn requires_access_attribution(&self) -> bool {
            true
        }

        fn prepare_attempt(
            &self,
            request: crate::host_protocol::HostProtocolRequestContext<'_>,
            attribution: Option<&crate::host_protocol::HostAccessAttribution>,
            maximum_request_bytes: usize,
        ) -> Result<
            crate::host_protocol::PreparedHostProtocolRequest,
            crate::host_protocol::HostProtocolError,
        > {
            let attribution = attribution.ok_or(crate::host_protocol::HostProtocolError)?;
            if request.method() != crate::host_protocol::HostProtocolMethod::Post
                || request.path() != "/v1/evidence"
                || request.has_query()
                || !request.body().is_some_and(Value::is_object)
            {
                return Err(crate::host_protocol::HostProtocolError);
            }
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            let body = serde_json::to_vec(&json!({"requestNonce": attempt}))
                .map_err(|_| crate::host_protocol::HostProtocolError)?;
            if body.len() > maximum_request_bytes {
                return Err(crate::host_protocol::HostProtocolError);
            }
            let header = http::HeaderValue::from_str(attribution.requester())
                .map_err(|_| crate::host_protocol::HostProtocolError)?;
            Ok(crate::host_protocol::PreparedHostProtocolRequest::new(
                zeroize::Zeroizing::new(body),
                vec![(
                    http::HeaderName::from_static("x-evidence-requester"),
                    header,
                )],
                Box::new(WireHostProtocolVerifier {
                    attempt,
                    expected_response: self.expected_response.clone(),
                }),
            ))
        }
    }

    struct WireHostProtocolVerifier {
        attempt: usize,
        expected_response: Vec<u8>,
    }

    impl crate::host_protocol::HostProtocolResponseVerifier for WireHostProtocolVerifier {
        fn verify(
            self: Box<Self>,
            response: crate::host_protocol::HostProtocolWireResponse,
        ) -> Result<
            crate::host_protocol::VerifiedHostProtocolResponse,
            crate::host_protocol::HostProtocolResponseRefusal,
        > {
            let content_type = response
                .headers()
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>();
            let traceparent = response
                .headers()
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("traceparent"))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>();
            if response.status() != 200
                || content_type != ["application/jose+json"]
                || traceparent != ["00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"]
                || response.into_body().as_slice() != self.expected_response.as_slice()
            {
                return Err(crate::host_protocol::HostProtocolResponseRefusal::Protocol);
            }
            Ok(crate::host_protocol::VerifiedHostProtocolResponse::new(
                json!({"lookup": "matched", "facts": {"nonce": self.attempt}}),
                Some("2026-11-01T12:35:00Z".to_owned()),
            ))
        }
    }

    struct RetryHostProtocolCompiler {
        allow_refresh_retry: bool,
        attempts: Arc<AtomicUsize>,
    }

    impl crate::host_protocol::HostProtocolCompiler for RetryHostProtocolCompiler {
        fn id(&self) -> &str {
            "retry-protocol"
        }

        fn compile(
            &self,
            endpoint: &registry_adapter_core::Endpoint,
            config: &[u8],
        ) -> Result<
            Arc<dyn crate::host_protocol::CompiledHostProtocol>,
            crate::host_protocol::HostProtocolError,
        > {
            if endpoint.component != ComponentKind::Http || config != br#"{"contract":"retry"}"# {
                return Err(crate::host_protocol::HostProtocolError);
            }
            Ok(Arc::new(RetryHostProtocol {
                allow_refresh_retry: self.allow_refresh_retry,
                attempts: Arc::clone(&self.attempts),
            }))
        }
    }

    struct RetryHostProtocol {
        allow_refresh_retry: bool,
        attempts: Arc<AtomicUsize>,
    }

    impl crate::host_protocol::CompiledHostProtocol for RetryHostProtocol {
        fn response_header_names(&self) -> &[http::HeaderName] {
            &[]
        }

        fn allows_credential_refresh_retry(&self) -> bool {
            self.allow_refresh_retry
        }

        fn prepare_attempt(
            &self,
            request: crate::host_protocol::HostProtocolRequestContext<'_>,
            _attribution: Option<&crate::host_protocol::HostAccessAttribution>,
            maximum_request_bytes: usize,
        ) -> Result<
            crate::host_protocol::PreparedHostProtocolRequest,
            crate::host_protocol::HostProtocolError,
        > {
            if request.method() != crate::host_protocol::HostProtocolMethod::Post
                || request.path() != "/v1/evidence"
                || request.has_query()
                || !request.body().is_some_and(Value::is_object)
            {
                return Err(crate::host_protocol::HostProtocolError);
            }
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            let body = serde_json::to_vec(&json!({"requestNonce": attempt}))
                .map_err(|_| crate::host_protocol::HostProtocolError)?;
            if body.len() > maximum_request_bytes {
                return Err(crate::host_protocol::HostProtocolError);
            }
            Ok(crate::host_protocol::PreparedHostProtocolRequest::new(
                zeroize::Zeroizing::new(body),
                Vec::new(),
                Box::new(RetryHostProtocolVerifier),
            ))
        }
    }

    struct RetryHostProtocolVerifier;

    impl crate::host_protocol::HostProtocolResponseVerifier for RetryHostProtocolVerifier {
        fn verify(
            self: Box<Self>,
            response: crate::host_protocol::HostProtocolWireResponse,
        ) -> Result<
            crate::host_protocol::VerifiedHostProtocolResponse,
            crate::host_protocol::HostProtocolResponseRefusal,
        > {
            if response.status() != 200 || response.into_body().as_slice() != b"signed-answer" {
                return Err(crate::host_protocol::HostProtocolResponseRefusal::Protocol);
            }
            Ok(crate::host_protocol::VerifiedHostProtocolResponse::new(
                json!({"lookup": "no-match"}),
                None,
            ))
        }
    }

    async fn execute_oauth_protocol_replay(
        allow_refresh_retry: bool,
    ) -> (
        Result<EvidenceLookup, EvidenceExecutionError>,
        usize,
        Result<(), crate::replay::ReplayFailure>,
    ) {
        let schema = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false, "properties": {}
        }))
        .expect("schema");
        let config = br#"{"contract":"retry"}"#.to_vec();
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "retry-protocol-pack", "version": "1", "testedVersions": [],
            "endpoints": [{
                "id": "register", "component": "http",
                "authentication": {"type": "oauth2-client-credentials"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 4096,
                "requestHeaders": [], "responseHeaders": [],
                "operations": [{"id": "read-evidence", "safeUpstream": true}],
                "testedVersions": [],
                "hostProtocol": {
                    "id": "retry-protocol",
                    "config": {"path": "protocol.json", "digest": sha256_uri(&config)}
                }
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)},
                    "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)}
                },
                "steps": [{"to": {"uri": "http:register", "parameters": {
                    "httpMethod": "POST", "operation": "read-evidence",
                    "path": "/v1/evidence", "body": {"constant": {"subjects": []}}
                }}}]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([
            ("schema.json".to_owned(), schema),
            ("protocol.json".to_owned(), config),
        ]);
        let attempts = Arc::new(AtomicUsize::new(0));
        let registry = HostProtocolRegistry::try_new([Arc::new(RetryHostProtocolCompiler {
            allow_refresh_retry,
            attempts: Arc::clone(&attempts),
        })
            as Arc<dyn crate::host_protocol::HostProtocolCompiler>])
        .expect("registry");
        let checked = compile_evidence_pack_with_protocols(
            &pack,
            "evidence",
            &artifacts,
            EvidenceLimits::default(),
            &registry,
        )
        .expect("checked program");

        let mut exchanges = vec![
            json!({
                "request": {"endpoint": "register", "tokenRequest": true,
                    "method": "POST", "path": "/oauth/token"},
                "response": {"status": 200, "body": {
                    "access_token": "first-token", "token_type": "Bearer", "expires_in": 300
                }}
            }),
            json!({
                "request": {"endpoint": "register", "method": "POST",
                    "path": "/v1/evidence", "body": {"requestNonce": 1}},
                "response": {"status": 401,
                    "rawBodyBase64": base64::engine::general_purpose::STANDARD.encode(b"refused")}
            }),
        ];
        if allow_refresh_retry {
            exchanges.extend([
                json!({
                    "request": {"endpoint": "register", "tokenRequest": true,
                        "method": "POST", "path": "/oauth/token"},
                    "response": {"status": 200, "body": {
                        "access_token": "second-token", "token_type": "Bearer", "expires_in": 300
                    }}
                }),
                json!({
                    "request": {"endpoint": "register", "method": "POST",
                        "path": "/v1/evidence", "body": {"requestNonce": 2}},
                    "response": {"status": 200,
                        "rawBodyBase64": base64::engine::general_purpose::STANDARD.encode(b"signed-answer")}
                }),
            ]);
        }
        let transcript = Arc::new(crate::replay::ReplayTranscript::from_exchanges(
            serde_json::from_value(json!([
                {"type": "endpoint", "endpoint": "register"},
                {"type": "token-endpoint", "endpoint": "register"}
            ]))
            .expect("intercepts"),
            serde_json::from_value(Value::Array(exchanges)).expect("exchanges"),
        ));
        let program = checked
            .bind_replay(Arc::clone(&transcript))
            .expect("replay binding");
        let acquisition = program
            .begin_acquisition(Arc::new(RecordingHooks::default()))
            .await
            .expect("acquisition");
        let result = program.execute(&acquisition, json!({})).await;
        (result, attempts.load(Ordering::SeqCst), transcript.finish())
    }

    #[tokio::test]
    async fn host_protocol_oauth_refresh_requires_review_and_prepares_every_physical_read() {
        let (refused, attempts, transcript) = execute_oauth_protocol_replay(false).await;
        assert!(refused.is_err(), "the default protocol refuses the resend");
        assert_eq!(attempts, 1, "the refused resend prepares no second request");
        assert_eq!(transcript, Ok(()), "only the admitted sends were consumed");

        let (accepted, attempts, transcript) = execute_oauth_protocol_replay(true).await;
        assert!(
            matches!(accepted, Ok(EvidenceLookup::NoMatch)),
            "the reviewed refresh completes the lookup"
        );
        assert_eq!(attempts, 2, "the reviewed resend draws a fresh request");
        assert_eq!(transcript, Ok(()), "both physical reads were consumed");
    }

    #[cfg(feature = "sqlite-extract")]
    #[tokio::test]
    async fn fixture_binding_executes_mixed_http_replay_and_captured_sqlite_without_live_authority()
    {
        use chrono::{DateTime, Utc};
        use registry_platform_sqlite::{materialize_fixture, CapturedSnapshot};

        let directory = tempfile::tempdir().expect("extract directory");
        let extract_path = directory.path().join("extract.sqlite");
        materialize_fixture(
            &extract_path,
            "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); \
             INSERT INTO evidence_extract VALUES('2026-10-31T12:00:00Z', 'fixture', 'extract-a'); \
             CREATE TABLE people(id TEXT, active INTEGER); \
             INSERT INTO people VALUES('0007', 1);",
        )
        .expect("fixture extract");
        let captured = CapturedSnapshot::capture(&extract_path).expect("captured extract");

        let sql = b"SELECT id, active FROM people WHERE id = :id";
        let script = br#"fn facts(exchange) {
            let rows = exchange.body.rows;
            if rows.len() == 0 { return #{lookup: "no-match"}; }
            #{lookup: "matched", facts: #{id: rows[0].id, active: rows[0].active}}
        }"#;
        let inputs = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false, "properties": {}
        }))
        .expect("input schema");
        let facts = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false,
            "properties": {"id": {"type": "string"}, "active": {"type": "boolean"}},
            "required": ["id", "active"]
        }))
        .expect("facts schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "mixed-fixture-pack", "version": "1", "testedVersions": [],
            "endpoints": [
                {
                    "id": "register", "component": "http",
                    "authentication": {"type": "none"},
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 4096,
                    "requestHeaders": [], "responseHeaders": [],
                    "operations": [], "testedVersions": []
                },
                {
                    "id": "people", "component": "sqlite-extract",
                    "authentication": {"type": "none"},
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 8192,
                    "sqliteExtract": {
                        "extractProfile": "people",
                        "statement": {"path": "queries/people.sql", "digest": sha256_uri(sql)},
                        "columns": [
                            {"name": "id", "type": "string"},
                            {"name": "active", "type": "boolean"}
                        ],
                        "parameters": [{"name": "id", "required": true}],
                        "maximumExtractAgeSeconds": 3600,
                        "maximumRows": 2, "maximumCellBytes": 1024,
                        "maximumStatementSteps": 100000, "concurrency": 2
                    }
                },
                {
                    "id": "unreachable-extract", "component": "sqlite-extract",
                    "authentication": {"type": "none"},
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 8192,
                    "sqliteExtract": {
                        "extractProfile": "unreachable",
                        "statement": {"path": "queries/people.sql", "digest": sha256_uri(sql)},
                        "columns": [
                            {"name": "id", "type": "string"},
                            {"name": "active", "type": "boolean"}
                        ],
                        "parameters": [{"name": "id", "required": true}],
                        "maximumExtractAgeSeconds": 3600,
                        "maximumRows": 2, "maximumCellBytes": 1024,
                        "maximumStatementSteps": 100000, "concurrency": 2
                    }
                }
            ],
            "scripts": [{"path": "scripts/facts.rhai", "digest": sha256_uri(script)}],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "inputs.json", "digest": sha256_uri(&inputs)},
                    "factsSchema": {"path": "facts.json", "digest": sha256_uri(&facts)}
                },
                "steps": [
                    {"to": {"uri": "http:register", "parameters": {
                        "httpMethod": "GET", "path": "/person"
                    }}},
                    {"to": {"uri": "sqlite-extract:people", "parameters": {
                        "queryParameters": {"id": {"jsonpath": "$.id"}}
                    }}},
                    {"setBody": {"rhai": {
                        "file": "scripts/facts.rhai", "entrypoint": "facts"
                    }}}
                ]
            }]
        }))
        .expect("mixed pack");
        let artifacts = PackArtifactBytes::new([
            ("queries/people.sql".to_owned(), sql.to_vec()),
            ("scripts/facts.rhai".to_owned(), script.to_vec()),
            ("inputs.json".to_owned(), inputs),
            ("facts.json".to_owned(), facts),
        ]);
        let transcript = Arc::new(crate::replay::ReplayTranscript::from_exchanges(
            serde_json::from_value(json!([
                {"type": "endpoint", "endpoint": "register"}
            ]))
            .expect("intercepts"),
            serde_json::from_value(json!([{
                "request": {"endpoint": "register", "method": "GET", "path": "/person"},
                "response": {"status": 200, "body": {"id": "0007"}}
            }]))
            .expect("exchange"),
        ));
        let checked = compile_evidence_pack(
            &pack,
            "evidence",
            &artifacts,
            EvidenceLimits::try_new(2, 30_000, 16_384).expect("limits"),
        )
        .expect("pure mixed compile");
        assert_eq!(
            checked.required_extract_profiles(),
            std::collections::BTreeSet::from(["people".to_owned()]),
            "an unselected pack endpoint does not create a runtime binding obligation"
        );
        assert!(matches!(
            checked.bind_fixture(Arc::clone(&transcript), BTreeMap::new()),
            Err(EvidenceCompileError::EndpointUnbound)
        ));
        let program = compile_evidence_pack(
            &pack,
            "evidence",
            &artifacts,
            EvidenceLimits::try_new(2, 30_000, 16_384).expect("limits"),
        )
        .expect("pure mixed compile")
        .bind_fixture(
            Arc::clone(&transcript),
            BTreeMap::from([("people".to_owned(), captured)]),
        )
        .expect("fixture binding");
        let hooks = Arc::new(RecordingHooks::default());
        let evaluation_instant = DateTime::parse_from_rfc3339("2026-10-31T12:30:00Z")
            .expect("instant")
            .with_timezone(&Utc);
        let acquisition = program
            .begin_acquisition_at(hooks.clone(), evaluation_instant)
            .await
            .expect("one acquisition");

        assert_eq!(
            program
                .execute(&acquisition, json!({}))
                .await
                .expect("mixed lookup"),
            EvidenceLookup::Matched {
                facts: json!({"id": "0007", "active": true})
            }
        );
        assert_eq!(hooks.acquisitions.lock().expect("lock").len(), 1);
        assert_eq!(hooks.sends.lock().expect("lock").len(), 2);
        assert_eq!(transcript.finish(), Ok(()));
    }

    #[cfg(feature = "sqlite-extract")]
    fn sqlite_initialization_fixture() -> (
        tempfile::TempDir,
        BTreeMap<String, crate::component::sqlite_extract::SqliteExtractPlan>,
        BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
    ) {
        use registry_platform_sqlite::{materialize_fixture, CapturedSnapshot};

        let directory = tempfile::tempdir().expect("extract directory");
        let extract_path = directory.path().join("extract.sqlite");
        materialize_fixture(
            &extract_path,
            "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); \
             INSERT INTO evidence_extract VALUES('2026-10-31T12:00:00Z', 'fixture', 'extract-a'); \
             CREATE TABLE people(id TEXT); INSERT INTO people VALUES('0007');",
        )
        .expect("fixture extract");
        let captured = CapturedSnapshot::capture(&extract_path).expect("captured extract");
        let sql = b"SELECT id FROM people";
        let endpoint: registry_adapter_core::Endpoint = serde_json::from_value(json!({
            "id": "people", "component": "sqlite-extract",
            "authentication": {"type": "none"},
            "attemptTimeoutMilliseconds": 1000,
            "maximumResponseBytes": 8192,
            "sqliteExtract": {
                "extractProfile": "people",
                "statement": {"path": "queries/people.sql", "digest": sha256_uri(sql)},
                "columns": [{"name": "id", "type": "string"}],
                "parameters": [], "maximumExtractAgeSeconds": 86400,
                "maximumRows": 2, "maximumCellBytes": 1024,
                "maximumStatementSteps": 100000, "concurrency": 1
            }
        }))
        .expect("SQLite endpoint");
        let plan = crate::component::sqlite_extract::SqliteExtractPlan::compile(
            &endpoint,
            &PackArtifactBytes::new([("queries/people.sql".to_owned(), sql.to_vec())]),
        )
        .expect("SQLite plan");
        let plans = BTreeMap::from([("people".to_owned(), plan)]);
        let captured = BTreeMap::from([("people".to_owned(), captured)]);
        (directory, plans, captured)
    }

    #[cfg(feature = "sqlite-extract")]
    #[tokio::test]
    async fn a_later_live_deadline_waits_through_an_expired_initializers_drain_and_retries() {
        let (_directory, plans, captured) = sqlite_initialization_fixture();
        let initialization = Arc::new(SqliteSourceInitialization::default());

        // Model the interval after an earlier caller's deadline fired but
        // before its owned blocking worker finished draining. The sender is
        // retained until that drain completes, so later callers must wait
        // without inheriting the earlier caller's Budget result.
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let draining = Arc::clone(&initialization);
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            *draining.state.lock().await = SqliteSourceInitializationState::Idle;
            sender.send_replace(Some(SqliteSourceInitializationSignal::RetryAfterDrain));
        });
        *initialization.state.lock().await = SqliteSourceInitializationState::Running {
            result: receiver,
            task,
        };

        let expired = initialization
            .prepare(
                plans.clone(),
                captured.clone(),
                tokio::time::Instant::now() + Duration::from_millis(1),
            )
            .await;
        assert!(matches!(expired, Err(EvidenceReadinessError::Budget)));
        assert!(matches!(
            &*initialization.state.lock().await,
            SqliteSourceInitializationState::Running { .. }
        ));

        let prepared = initialization
            .prepare(
                plans,
                captured,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .expect("the later caller retries after the earlier worker drains");
        assert!(prepared.contains_key("people"));
        assert!(matches!(
            &*initialization.state.lock().await,
            SqliteSourceInitializationState::Ready(_)
        ));
    }

    #[cfg(feature = "sqlite-extract")]
    #[tokio::test]
    async fn a_live_deadline_survives_two_earlier_draining_cohorts_and_succeeds_on_the_third() {
        let (_directory, plans, captured) = sqlite_initialization_fixture();
        let initialization = Arc::new(SqliteSourceInitialization::default());

        // T first joins cohort one. Before T can rejoin after its drain, a
        // second earlier-deadline cohort has claimed the one Running slot.
        // T must observe both completed drains and then initialize under its
        // own still-live deadline, never inherit either cohort's Budget.
        let (first_sender, first_receiver) = tokio::sync::watch::channel(None);
        let first_draining = Arc::clone(&initialization);
        let first_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let (second_sender, second_receiver) = tokio::sync::watch::channel(None);
            let second_draining = Arc::clone(&first_draining);
            let second_task = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                *second_draining.state.lock().await = SqliteSourceInitializationState::Idle;
                second_sender.send_replace(Some(SqliteSourceInitializationSignal::RetryAfterDrain));
            });
            *first_draining.state.lock().await = SqliteSourceInitializationState::Running {
                result: second_receiver,
                task: second_task,
            };
            first_sender.send_replace(Some(SqliteSourceInitializationSignal::RetryAfterDrain));
        });
        *initialization.state.lock().await = SqliteSourceInitializationState::Running {
            result: first_receiver,
            task: first_task,
        };

        let prepared = initialization
            .prepare(
                plans,
                captured,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .expect("T retries after both earlier cohorts drain");
        assert!(prepared.contains_key("people"));
        assert!(matches!(
            &*initialization.state.lock().await,
            SqliteSourceInitializationState::Ready(_)
        ));
    }

    #[cfg(feature = "sqlite-extract")]
    #[tokio::test]
    async fn concurrent_acquisitions_keep_the_refused_statement_bound_to_its_reached_endpoint() {
        use registry_platform_sqlite::{materialize_fixture, CapturedSnapshot};

        let directory = tempfile::tempdir().expect("extract directory");
        let extract_path = directory.path().join("extract.sqlite");
        materialize_fixture(
            &extract_path,
            "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); \
             INSERT INTO evidence_extract VALUES('2026-10-31T12:00:00Z', 'fixture', 'extract-a'); \
             CREATE TABLE people(id TEXT); INSERT INTO people VALUES('0007');",
        )
        .expect("fixture extract");
        let captured = CapturedSnapshot::capture(&extract_path).expect("captured extract");
        let first_sql = b"SELECT id FROM people WHERE id = :id";
        let second_sql = b"SELECT id FROM people WHERE id = :id";
        let inputs = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false,
            "properties": {"second": {"type": "boolean"}}, "required": ["second"]
        }))
        .expect("input schema");
        let facts = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false, "properties": {}
        }))
        .expect("facts schema");
        let endpoint = |id: &str, profile: &str, statement: &str, digest: String| {
            json!({
                "id": id, "component": "sqlite-extract",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 8192,
                "sqliteExtract": {
                    "extractProfile": profile,
                    "statement": {"path": statement, "digest": digest},
                    "columns": [{"name": "id", "type": "string"}],
                    "parameters": [{"name": "id", "required": true}],
                    "maximumExtractAgeSeconds": 86400,
                    "maximumRows": 2, "maximumCellBytes": 1024,
                    "maximumStatementSteps": 100000, "concurrency": 2
                }
            })
        };
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "two-extract-pack", "version": "1", "testedVersions": [],
            "endpoints": [
                endpoint("first", "first-profile", "queries/first.sql", sha256_uri(first_sql)),
                endpoint("second", "second-profile", "queries/second.sql", sha256_uri(second_sql))
            ],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "inputs.json", "digest": sha256_uri(&inputs)},
                    "factsSchema": {"path": "facts.json", "digest": sha256_uri(&facts)}
                },
                "steps": [{"choice": {
                    "when": [{
                        "jsonpath": "$.second",
                        "steps": [{"to": {"uri": "sqlite-extract:second", "parameters": {
                            "queryParameters": {}
                        }}}]
                    }],
                    "otherwise": {"steps": [{"to": {
                        "uri": "sqlite-extract:first", "parameters": {"queryParameters": {}}
                    }}]}
                }}]
            }]
        }))
        .expect("two-endpoint pack");
        let artifacts = PackArtifactBytes::new([
            ("queries/first.sql".to_owned(), first_sql.to_vec()),
            ("queries/second.sql".to_owned(), second_sql.to_vec()),
            ("inputs.json".to_owned(), inputs),
            ("facts.json".to_owned(), facts),
        ]);
        let program =
            compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default())
                .expect("pure compile")
                .bind_fixture(
                    Arc::new(crate::replay::ReplayTranscript::from_exchanges(
                        Vec::new(),
                        Vec::new(),
                    )),
                    BTreeMap::from([
                        ("first-profile".to_owned(), captured.clone()),
                        ("second-profile".to_owned(), captured),
                    ]),
                )
                .expect("fixture binding");
        let evaluation_instant = chrono::DateTime::parse_from_rfc3339("2026-10-31T12:30:00Z")
            .expect("instant")
            .with_timezone(&chrono::Utc);
        let first = program
            .begin_acquisition_at(Arc::new(RecordingHooks::default()), evaluation_instant)
            .await
            .expect("first acquisition");
        let second = program
            .begin_acquisition_at(Arc::new(RecordingHooks::default()), evaluation_instant)
            .await
            .expect("second acquisition");

        let (first_failure, second_failure) = tokio::join!(
            program.execute(&first, json!({"second": false})),
            program.execute(&second, json!({"second": true}))
        );
        let sqlite_fault = |failure: Result<EvidenceLookup, EvidenceExecutionError>| match failure {
            Err(EvidenceExecutionError::Sqlite(fault)) => fault,
            other => panic!("expected a typed SQLite fault, got {other:?}"),
        };
        let first_fault = sqlite_fault(first_failure);
        let second_fault = sqlite_fault(second_failure);
        assert_eq!(first_fault.artifact(), "queries/first.sql");
        assert_eq!(second_fault.artifact(), "queries/second.sql");
        assert_eq!(first_fault.code(), "adapter.sqlite.statement-parameter");
        assert_eq!(second_fault.code(), "adapter.sqlite.statement-parameter");
        assert!(!format!("{first_fault:?} {first_fault}").contains("queries/first.sql"));
        assert!(!format!("{second_fault:?} {second_fault}").contains("queries/second.sql"));
    }

    #[tokio::test]
    async fn selected_host_protocol_verifies_exact_wire_bytes_outside_the_exchange() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        let request = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&request);
        let response = b" \n {\"signed\" : true} \n ".to_vec();
        let server_response = response.clone();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection");
            let mut wire = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !wire.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).expect("request head");
                assert!(read > 0, "request head completes");
                wire.extend_from_slice(&chunk[..read]);
            }
            let head_end = wire
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("head end")
                + 4;
            let head = String::from_utf8_lossy(&wire[..head_end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map_or(0, |value| value.trim().parse::<usize>().expect("length"));
            while wire.len() < head_end + length {
                let read = stream.read(&mut chunk).expect("request body");
                assert!(read > 0, "request body completes");
                wire.extend_from_slice(&chunk[..read]);
            }
            *observed.lock().expect("request") = wire;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/jose+json\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                server_response.len()
            )
            .expect("response head");
            stream.write_all(&server_response).expect("response body");
        });

        let schema = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false,
            "properties": {"nonce": {"type": "integer"}}
        }))
        .expect("schema");
        let config = br#"{"contract":"wire-test"}"#.to_vec();
        let finish = br#"fn finish(exchange) {
    if exchange.headers["content-type"] != () || exchange.headers["traceparent"] != () {
        throw "trusted protocol headers escaped into the exchange";
    }
    exchange.body
}"#
        .to_vec();
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "wire-protocol-pack", "version": "1", "testedVersions": [],
            "scripts": [{"path": "scripts/finish.rhai", "digest": sha256_uri(&finish)}],
            "endpoints": [{
                "id": "register", "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 4096,
                "requestHeaders": ["x-evidence-requester"],
                "responseHeaders": [],
                "operations": [{"id": "read-evidence", "safeUpstream": true}],
                "testedVersions": [],
                "hostProtocol": {
                    "id": "signed-evidence-v1",
                    "config": {"path": "protocol.json", "digest": sha256_uri(&config)}
                }
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)},
                    "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)}
                },
                "steps": [
                    {"to": {"uri": "http:register", "parameters": {
                        "httpMethod": "POST", "operation": "read-evidence",
                        "path": "/v1/evidence", "body": {"constant": {"subjects": []}}
                    }}},
                    {"setBody": {"rhai": {"file": "scripts/finish.rhai", "entrypoint": "finish"}}}
                ]
            }]
        }))
        .expect("pack");
        let base_url = format!("http://127.0.0.1:{port}");
        let runtime = EvidenceRuntimeBindings::new(
            serde_json::from_value(json!({
                "id": "wire-runtime",
                "endpoints": [{
                    "endpoint": "register", "baseUrl": base_url.clone(),
                    "credential": {"type": "none"}
                }],
                "allowedPrivateCidrs": []
            }))
            .expect("runtime"),
            SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
        );
        let connection: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint": "register", "baseUrl": base_url,
            "clientIdentity": "forbidden", "authentication": {"type": "none"}
        }))
        .expect("policy");
        let artifacts = PackArtifactBytes::new([
            ("schema.json".to_owned(), schema),
            ("protocol.json".to_owned(), config.clone()),
            ("scripts/finish.rhai".to_owned(), finish),
        ]);
        let attempts = Arc::new(AtomicUsize::new(0));
        let registry = HostProtocolRegistry::try_new([Arc::new(WireHostProtocolCompiler {
            expected_config: config,
            expected_response: response,
            attempts: Arc::clone(&attempts),
        })
            as Arc<dyn crate::host_protocol::HostProtocolCompiler>])
        .expect("registry");
        let program = compile_evidence_with_protocols(
            &EvidenceCompileInputs {
                pack: &pack,
                route: "evidence",
                runtime: &runtime,
                connection_id: Some("wire-runtime"),
                connection: std::slice::from_ref(&connection),
                pack_artifacts: &artifacts,
                limits: EvidenceLimits::default(),
            },
            &registry,
        )
        .expect("program");
        let acquisition = program
            .begin_acquisition_with_attribution(
                Arc::new(RecordingHooks::default()),
                Arc::new(
                    crate::host_protocol::HostAccessAttribution::try_new(
                        "requester@example.test",
                        "eligibility",
                    )
                    .expect("attribution"),
                ),
            )
            .await
            .expect("acquisition");

        assert!(program.requires_access_attribution());

        assert_eq!(
            program
                .execute(&acquisition, json!({}))
                .await
                .expect("lookup"),
            EvidenceLookup::Matched {
                facts: json!({"nonce": 1})
            }
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            acquisition.trusted_protocol_metadata().await,
            vec![EvidenceTrustedProtocolMetadata {
                endpoint: "register".to_owned(),
                valid_until: "2026-11-01T12:35:00Z".to_owned()
            }]
        );
        let request = request.lock().expect("request");
        let request_text = String::from_utf8_lossy(&request);
        assert!(request_text
            .to_ascii_lowercase()
            .contains("x-evidence-requester: requester@example.test"));
        assert!(!request_text.contains("eligibility"));
    }

    /// Observations a replay-bound attachment protocol makes while verifying.
    #[derive(Default)]
    struct AttachmentProbe {
        instants: Mutex<Vec<chrono::DateTime<chrono::Utc>>>,
    }

    struct AttachmentProtocolCompiler {
        attachment: Option<HostProtocolAttachment>,
        probe: Arc<AttachmentProbe>,
    }

    impl crate::host_protocol::HostProtocolCompiler for AttachmentProtocolCompiler {
        fn id(&self) -> &str {
            "attachment-protocol"
        }

        fn compile(
            &self,
            _endpoint: &registry_adapter_core::Endpoint,
            _config: &[u8],
        ) -> Result<
            Arc<dyn crate::host_protocol::CompiledHostProtocol>,
            crate::host_protocol::HostProtocolError,
        > {
            Ok(Arc::new(AttachmentProtocol {
                attachment: self.attachment.clone(),
                probe: Arc::clone(&self.probe),
            }))
        }
    }

    struct AttachmentProtocol {
        attachment: Option<HostProtocolAttachment>,
        probe: Arc<AttachmentProbe>,
    }

    impl crate::host_protocol::CompiledHostProtocol for AttachmentProtocol {
        fn response_header_names(&self) -> &[http::HeaderName] {
            &[]
        }

        fn prepare_attempt(
            &self,
            _request: crate::host_protocol::HostProtocolRequestContext<'_>,
            _attribution: Option<&crate::host_protocol::HostAccessAttribution>,
            _maximum_request_bytes: usize,
        ) -> Result<
            crate::host_protocol::PreparedHostProtocolRequest,
            crate::host_protocol::HostProtocolError,
        > {
            Ok(crate::host_protocol::PreparedHostProtocolRequest::new(
                zeroize::Zeroizing::new(b"{}".to_vec()),
                Vec::new(),
                Box::new(AttachmentVerifier {
                    attachment: self.attachment.clone(),
                    probe: Arc::clone(&self.probe),
                }),
            ))
        }
    }

    struct AttachmentVerifier {
        attachment: Option<HostProtocolAttachment>,
        probe: Arc<AttachmentProbe>,
    }

    impl crate::host_protocol::HostProtocolResponseVerifier for AttachmentVerifier {
        fn verify(
            self: Box<Self>,
            response: crate::host_protocol::HostProtocolWireResponse,
        ) -> Result<
            crate::host_protocol::VerifiedHostProtocolResponse,
            crate::host_protocol::HostProtocolResponseRefusal,
        > {
            self.probe
                .instants
                .lock()
                .expect("probe")
                .push(response.evaluation_instant());
            let verified = crate::host_protocol::VerifiedHostProtocolResponse::new(
                json!({"lookup": "no-match"}),
                None,
            );
            Ok(match self.attachment {
                Some(attachment) => verified.with_attachment(attachment),
                None => verified,
            })
        }
    }

    /// Run `sends` consecutive protocol reads against a replay transcript and
    /// return the acquisition with the lookup result.
    async fn execute_attachment_protocol(
        attachment: Option<HostProtocolAttachment>,
        probe: &Arc<AttachmentProbe>,
        sends: usize,
        evaluation_instant: chrono::DateTime<chrono::Utc>,
    ) -> (
        EvidenceAcquisition,
        Result<EvidenceLookup, EvidenceExecutionError>,
    ) {
        let schema = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false, "properties": {}
        }))
        .expect("schema");
        let config = br#"{}"#.to_vec();
        let step = json!({"to": {"uri": "http:register", "parameters": {
            "httpMethod": "POST", "operation": "read-evidence",
            "path": "/v1/evidence", "body": {"constant": {}}
        }}});
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "attachment-protocol-pack", "version": "1", "testedVersions": [],
            "endpoints": [{
                "id": "register", "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 4096,
                "requestHeaders": [], "responseHeaders": [],
                "operations": [{"id": "read-evidence", "safeUpstream": true}],
                "testedVersions": [],
                "hostProtocol": {
                    "id": "attachment-protocol",
                    "config": {"path": "protocol.json", "digest": sha256_uri(&config)}
                }
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)},
                    "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)}
                },
                "steps": vec![step; sends]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([
            ("schema.json".to_owned(), schema),
            ("protocol.json".to_owned(), config),
        ]);
        let registry = HostProtocolRegistry::try_new([Arc::new(AttachmentProtocolCompiler {
            attachment,
            probe: Arc::clone(probe),
        })
            as Arc<dyn crate::host_protocol::HostProtocolCompiler>])
        .expect("registry");
        let checked = compile_evidence_pack_with_protocols(
            &pack,
            "evidence",
            &artifacts,
            EvidenceLimits::default(),
            &registry,
        )
        .expect("checked program");
        let exchanges = (0..sends)
            .map(|_| {
                json!({
                    "request": {"endpoint": "register", "method": "POST",
                        "path": "/v1/evidence", "body": {}},
                    "response": {"status": 200,
                        "rawBodyBase64": base64::engine::general_purpose::STANDARD.encode(b"signed")}
                })
            })
            .collect::<Vec<_>>();
        let transcript = Arc::new(crate::replay::ReplayTranscript::from_exchanges(
            serde_json::from_value(json!([{"type": "endpoint", "endpoint": "register"}]))
                .expect("intercepts"),
            serde_json::from_value(Value::Array(exchanges)).expect("exchanges"),
        ));
        let program = checked.bind_replay(transcript).expect("replay binding");
        let acquisition = program
            .begin_acquisition_at(Arc::new(RecordingHooks::default()), evaluation_instant)
            .await
            .expect("acquisition");
        let result = program.execute(&acquisition, json!({})).await;
        (acquisition, result)
    }

    fn attachment_test_instant() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-11-06T09:30:00Z")
            .expect("instant")
            .with_timezone(&chrono::Utc)
    }

    #[tokio::test]
    async fn host_protocol_attachment_round_trips_untouched_and_verifier_sees_the_injected_instant()
    {
        let probe = Arc::new(AttachmentProbe::default());
        let attachment: HostProtocolAttachment = Arc::new(String::from("opaque-facts"));
        let (acquisition, result) = execute_attachment_protocol(
            Some(Arc::clone(&attachment)),
            &probe,
            1,
            attachment_test_instant(),
        )
        .await;

        assert!(matches!(result, Ok(EvidenceLookup::NoMatch)));
        let carried = acquisition
            .trusted_protocol_attachment()
            .await
            .expect("attachment");
        assert!(Arc::ptr_eq(&carried, &attachment));
        assert_eq!(
            carried.downcast_ref::<String>().map(String::as_str),
            Some("opaque-facts")
        );
        assert_eq!(
            *probe.instants.lock().expect("probe"),
            vec![attachment_test_instant()],
            "the verifier is handed the acquisition's instant, not the wall clock"
        );
    }

    #[tokio::test]
    async fn host_protocol_attachment_a_host_does_not_read_has_no_effect() {
        let probe = Arc::new(AttachmentProbe::default());
        let (with_attachment, with_result) = execute_attachment_protocol(
            Some(Arc::new(7_u32)),
            &probe,
            1,
            attachment_test_instant(),
        )
        .await;
        let (without_attachment, without_result) =
            execute_attachment_protocol(None, &probe, 1, attachment_test_instant()).await;

        assert!(matches!(with_result, Ok(EvidenceLookup::NoMatch)));
        assert!(matches!(without_result, Ok(EvidenceLookup::NoMatch)));
        assert!(without_attachment
            .trusted_protocol_attachment()
            .await
            .is_none());
        assert_eq!(
            with_attachment.trusted_protocol_metadata().await,
            without_attachment.trusted_protocol_metadata().await,
            "the attachment adds nothing to the validity metadata"
        );
    }

    #[tokio::test]
    async fn two_host_protocol_attachments_in_one_lookup_refuse() {
        let probe = Arc::new(AttachmentProbe::default());
        let (acquisition, result) =
            execute_attachment_protocol(Some(Arc::new(1_u8)), &probe, 2, attachment_test_instant())
                .await;

        let Err(EvidenceExecutionError::Route(failure)) = result else {
            panic!("a second attachment is a protocol refusal, got {result:?}");
        };
        assert_eq!(failure.code, Some("evidence.protocol-failed"));
        assert_eq!(probe.instants.lock().expect("probe").len(), 2);
        assert!(
            acquisition.trusted_protocol_attachment().await.is_some(),
            "the first attachment is not replaced by the refused second"
        );
    }

    #[tokio::test]
    async fn pure_pack_program_binds_to_sealed_replay_without_live_authority() {
        let input_schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let facts_schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"id": {"type": "string"}},
            "required": ["id"]
        }))
        .expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "replay-source-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "register",
                "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 4096,
                "responseHeaders": [],
                "requestHeaders": [],
                "operations": [],
                "testedVersions": []
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "inputs.json", "digest": sha256_uri(&input_schema)},
                    "factsSchema": {"path": "facts.json", "digest": sha256_uri(&facts_schema)}
                },
                "steps": [{"to": {
                    "uri": "http:register",
                    "parameters": {"httpMethod": "GET", "path": "/people/P-1"}
                }}]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([
            ("inputs.json".to_owned(), input_schema),
            ("facts.json".to_owned(), facts_schema),
        ]);
        let checked =
            compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default())
                .expect("pure compile");
        let intercepts = serde_json::from_value(json!([
            {"type": "endpoint", "endpoint": "register"}
        ]))
        .expect("intercepts");
        let exchanges = serde_json::from_value(json!([{
            "request": {
                "endpoint": "register",
                "method": "GET",
                "path": "/people/P-1"
            },
            "response": {
                "status": 200,
                "body": {"lookup": "matched", "facts": {"id": "P-1"}}
            }
        }]))
        .expect("recorded exchanges");
        let transcript = Arc::new(crate::replay::ReplayTranscript::from_exchanges(
            intercepts, exchanges,
        ));
        let program = checked
            .bind_replay(Arc::clone(&transcript))
            .expect("sealed replay binding");
        let acquisition = program
            .begin_acquisition(Arc::new(RecordingHooks::default()))
            .await
            .expect("replay acquisition");

        assert_eq!(
            program
                .execute(&acquisition, json!({}))
                .await
                .expect("replayed lookup"),
            EvidenceLookup::Matched {
                facts: json!({"id": "P-1"})
            }
        );
        transcript.finish().expect("complete transcript");
    }

    #[tokio::test]
    async fn direct_routes_resolve_by_from_uri_for_read_only_reachability_and_execution() {
        let input_schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let facts_schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"id": {"type": "string"}},
            "required": ["id"]
        }))
        .expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "direct-name-contract",
            "version": "1",
            "testedVersions": [],
            "endpoints": [
                {
                    "id": "register",
                    "component": "http",
                    "authentication": {"type": "none"},
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 4096,
                    "operations": [],
                    "testedVersions": []
                },
                {
                    "id": "forbidden-write",
                    "component": "http",
                    "authentication": {
                        "type": "static-api-key",
                        "headerName": "x-private-key"
                    },
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 4096,
                    "operations": [{"id": "update", "idempotentUpstream": true}],
                    "testedVersions": []
                }
            ],
            "routes": [
                {
                    "id": "shared-read-route",
                    "from": {"uri": "direct:read-records"},
                    "steps": [{"to": {
                        "uri": "http:register",
                        "parameters": {"httpMethod": "GET", "path": "/people/P-1"}
                    }}]
                },
                {
                    "id": "read-records",
                    "from": {"uri": "direct:decoy-write"},
                    "steps": [{"to": {
                        "uri": "http:forbidden-write",
                        "parameters": {
                            "httpMethod": "POST",
                            "path": "/people/P-1",
                            "operation": "update",
                            "body": {"constant": {"private": true}}
                        }
                    }}]
                }
            ],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {
                        "path": "inputs.json",
                        "digest": sha256_uri(&input_schema)
                    },
                    "factsSchema": {
                        "path": "facts.json",
                        "digest": sha256_uri(&facts_schema)
                    }
                },
                "steps": [{"to": {"uri": "direct:read-records"}}]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([
            ("inputs.json".to_owned(), input_schema),
            ("facts.json".to_owned(), facts_schema),
        ]);
        let checked =
            compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default())
                .expect("the source reaches the read route by its from URI");
        let transcript = Arc::new(crate::replay::ReplayTranscript::from_exchanges(
            serde_json::from_value(json!([
                {"type": "endpoint", "endpoint": "register"}
            ]))
            .expect("intercepts"),
            serde_json::from_value(json!([{
                "request": {
                    "endpoint": "register",
                    "method": "GET",
                    "path": "/people/P-1"
                },
                "response": {
                    "status": 200,
                    "body": {"lookup": "matched", "facts": {"id": "P-1"}}
                }
            }]))
            .expect("recorded exchanges"),
        ));
        let program = checked
            .bind_replay(Arc::clone(&transcript))
            .expect("the unreachable credentialed decoy needs no binding");
        let acquisition = program
            .begin_acquisition(Arc::new(RecordingHooks::default()))
            .await
            .expect("replay acquisition");
        assert_eq!(
            program.execute(&acquisition, json!({})).await.unwrap(),
            EvidenceLookup::Matched {
                facts: json!({"id":"P-1"})
            }
        );
        transcript.finish().expect("only the read route executed");
    }

    #[tokio::test]
    async fn compiled_program_executes_without_a_facade_or_filesystem() {
        let program = in_memory_program();
        let hooks = Arc::new(RecordingHooks::default());
        let acquisition = program
            .begin_acquisition(hooks.clone())
            .await
            .expect("authorized intent");
        let outcome = program
            .execute(&acquisition, json!({"nationalId": "P-1"}))
            .await
            .expect("lookup");
        assert_eq!(
            outcome,
            EvidenceLookup::Matched {
                facts: json!({"parents": [{"name": "Ada"}]})
            }
        );
        assert_eq!(hooks.acquisitions.lock().expect("lock").len(), 1);
        assert!(hooks.sends.lock().expect("lock").is_empty());
        assert_eq!(
            program
                .execute(&acquisition, json!({"unknown": "P-1"}))
                .await
                .expect_err("unknown input refused")
                .to_string(),
            "Evidence inputs do not satisfy the reviewed schema"
        );
    }

    /// Each connection-policy refusal names the pack endpoint and one closed
    /// rule, so an operator fixes the binding without diffing it by hand. The
    /// message never carries the origin, a secret reference or trust bytes.
    #[test]
    fn every_connection_policy_refusal_names_its_endpoint_and_rule() {
        use ConnectionPolicyReason as Reason;
        let schema_bytes = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let pack_with = |authentication: Value| -> AdapterPack {
            serde_json::from_value(json!({
                "id": "policy-pack",
                "version": "1",
                "testedVersions": [],
                "endpoints": [{
                    "id": "register",
                    "component": "http",
                    "authentication": authentication,
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 1024,
                    "responseHeaders": [],
                    "requestHeaders": [],
                    "operations": [],
                    "testedVersions": []
                }],
                "sourceRoutes": [{
                    "id": "evidence",
                    "evidence": {
                        "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema_bytes)},
                        "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema_bytes)}
                    },
                    "steps": [
                        {"to": {"uri": "http:register", "parameters": {"httpMethod": "GET", "path": "/r"}}}
                    ]
                }]
            }))
            .expect("pack")
        };
        let artifacts = PackArtifactBytes::new([("schema.json".to_owned(), schema_bytes.clone())]);
        let reviewed = || {
            json!({
                "endpoint": "register",
                "baseUrl": "http://127.0.0.1:8101",
                "clientIdentity": "forbidden",
                "authentication": {"type": "none"}
            })
        };
        let bound = || {
            json!({
                "endpoint": "register",
                "baseUrl": "http://127.0.0.1:8101",
                "credential": {"type": "none"}
            })
        };
        let refusal = |authentication: Value,
                       binding: Value,
                       connection_id: Option<&str>,
                       policies: Vec<Value>| {
            let pack = pack_with(authentication);
            let runtime = EvidenceRuntimeBindings::new(
                serde_json::from_value(json!({
                    "id": "shared",
                    "endpoints": [binding],
                    "allowedPrivateCidrs": ["192.168.0.0/16"]
                }))
                .expect("bindings"),
                SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
            );
            let policies: Vec<EvidenceConnectionPolicy> =
                serde_json::from_value(Value::Array(policies)).expect("policies");
            match compile_evidence(&EvidenceCompileInputs {
                pack: &pack,
                route: "evidence",
                runtime: &runtime,
                connection_id,
                connection: &policies,
                pack_artifacts: &artifacts,
                limits: EvidenceLimits::default(),
            }) {
                Err(error @ EvidenceCompileError::ConnectionPolicy { .. }) => {
                    let message = error.to_string();
                    for forbidden in ["127.0.0.1", "8101", "8199", "secret:", "env/"] {
                        assert!(!message.contains(forbidden), "{message}");
                    }
                    let EvidenceCompileError::ConnectionPolicy { endpoint, reason } = error else {
                        unreachable!()
                    };
                    assert_eq!(endpoint, "register", "{message}");
                    assert!(message.contains("endpoint `register`"), "{message}");
                    assert!(message.contains(&reason.to_string()), "{message}");
                    reason
                }
                Err(other) => panic!("expected a connection-policy refusal, got {other}"),
                Ok(_) => panic!("expected a connection-policy refusal, got a program"),
            }
        };
        let none = || json!({"type": "none"});
        let with = |mut value: Value, key: &str, member: Value| {
            value[key] = member;
            value
        };

        assert_eq!(
            refusal(none(), bound(), Some("shared"), vec![]),
            Reason::PolicyMissing
        );
        assert_eq!(
            refusal(
                none(),
                bound(),
                Some("shared"),
                vec![reviewed(), reviewed()]
            ),
            Reason::PolicyDuplicate
        );
        assert_eq!(
            refusal(none(), bound(), None, vec![reviewed()]),
            Reason::ConnectionMismatch
        );
        assert_eq!(
            refusal(none(), bound(), Some("independent"), vec![reviewed()]),
            Reason::ConnectionMismatch
        );
        assert_eq!(
            refusal(
                none(),
                with(bound(), "endpoint", json!("other")),
                Some("shared"),
                vec![reviewed()]
            ),
            Reason::EndpointUnbound
        );
        assert_eq!(
            refusal(
                none(),
                with(bound(), "baseUrl", json!("http://127.0.0.1:8199")),
                Some("shared"),
                vec![reviewed()]
            ),
            Reason::BaseUrlMismatch
        );
        assert_eq!(
            refusal(
                none(),
                bound(),
                Some("shared"),
                vec![with(reviewed(), "tlsTrustProfile", json!("pki"))]
            ),
            Reason::TlsTrustProfileMismatch
        );
        assert_eq!(
            refusal(
                none(),
                bound(),
                Some("shared"),
                vec![with(reviewed(), "clientIdentity", json!("required"))]
            ),
            Reason::ClientIdentityRequired
        );
        assert_eq!(
            refusal(
                none(),
                with(
                    bound(),
                    "mtlsIdentity",
                    json!({"certificateRef": "secret:env/CERT", "keyRef": "secret:env/KEY"})
                ),
                Some("shared"),
                vec![reviewed()]
            ),
            Reason::ClientIdentityForbidden
        );
        assert_eq!(
            refusal(
                none(),
                with(bound(), "tlsTrustProfile", json!("pki")),
                Some("shared"),
                vec![with(reviewed(), "tlsTrustProfile", json!("pki"))]
            ),
            Reason::TrustMaterialUnavailable
        );
        assert_eq!(
            refusal(
                none(),
                bound(),
                Some("shared"),
                vec![with(reviewed(), "authentication", json!({"type": "basic"}))]
            ),
            Reason::AuthenticationMismatch
        );
        assert_eq!(
            refusal(
                none(),
                with(bound(), "anonymousHttps", json!("operator-approved")),
                Some("shared"),
                vec![reviewed()]
            ),
            Reason::AuthenticationInvalid
        );

        // Two programs that share one named endpoint resource must agree on
        // its reviewed policy; the second disagreeing one is refused.
        let runtime = EvidenceRuntimeBindings::new(
            serde_json::from_value(json!({
                "id": "shared",
                "endpoints": [bound()],
                "allowedPrivateCidrs": ["192.168.0.0/16"]
            }))
            .expect("bindings"),
            SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
        );
        let first: EvidenceConnectionPolicy = serde_json::from_value(reviewed()).expect("policy");
        let second: EvidenceConnectionPolicy =
            serde_json::from_value(with(reviewed(), "baseUrl", json!("http://127.0.0.1:8199")))
                .expect("policy");
        runtime
            .endpoint_resource("shared", &first)
            .expect("the first policy claims the resource");
        match runtime.endpoint_resource("shared", &second) {
            Err(EvidenceCompileError::ConnectionPolicy { endpoint, reason }) => {
                assert_eq!(endpoint, "register");
                assert_eq!(reason, Reason::ResourceConflict);
            }
            Err(other) => panic!("expected a resource conflict, got {other}"),
            Ok(_) => panic!("expected a resource conflict"),
        }
    }

    #[test]
    fn compile_admits_two_reviewed_endpoints_and_refuses_second_origin_drift() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        });
        let schema_bytes = serde_json::to_vec(&schema).expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "two-source-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [
                {
                    "id": "first",
                    "component": "http",
                    "authentication": {"type": "none"},
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 1024,
                    "responseHeaders": [],
                    "requestHeaders": [],
                    "operations": [],
                    "testedVersions": []
                },
                {
                    "id": "second",
                    "component": "http",
                    "authentication": {"type": "none"},
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 1024,
                    "responseHeaders": [],
                    "requestHeaders": [],
                    "operations": [],
                    "testedVersions": []
                }
            ],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema_bytes)},
                    "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema_bytes)}
                },
                "steps": [
                    {"to": {"uri": "http:first", "parameters": {"httpMethod": "GET", "path": "/first"}}},
                    {"to": {"uri": "http:second", "parameters": {"httpMethod": "GET", "path": "/second"}}}
                ]
            }]
        }))
        .expect("pack");
        let artifacts = PackArtifactBytes::new([("schema.json".to_owned(), schema_bytes.clone())]);
        let policies: Vec<EvidenceConnectionPolicy> = serde_json::from_value(json!([
            {
                "endpoint": "first",
                "baseUrl": "http://127.0.0.1:8101",
                "clientIdentity": "forbidden",
                "authentication": {"type": "none"}
            },
            {
                "endpoint": "second",
                "baseUrl": "http://127.0.0.1:8102",
                "clientIdentity": "forbidden",
                "authentication": {"type": "none"}
            }
        ]))
        .expect("policies");
        let make_runtime = |id: &str, second_url: &str| {
            EvidenceRuntimeBindings::new(
                serde_json::from_value(json!({
                    "id": id,
                    "endpoints": [
                        {"endpoint": "first", "baseUrl": "http://127.0.0.1:8101", "credential": {"type": "none"}},
                        {"endpoint": "second", "baseUrl": second_url, "credential": {"type": "none"}}
                    ],
                    "allowedPrivateCidrs": ["192.168.0.0/16"]
                }))
                .expect("bindings"),
                SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
            )
        };

        let runtime = make_runtime("shared", "http://127.0.0.1:8102");
        let first_program = compile_evidence(&EvidenceCompileInputs {
            pack: &pack,
            route: "evidence",
            runtime: &runtime,
            connection_id: Some("shared"),
            connection: &policies,
            pack_artifacts: &artifacts,
            limits: EvidenceLimits::default(),
        })
        .expect("both reviewed endpoints compile");
        let same_name = compile_evidence(&EvidenceCompileInputs {
            pack: &pack,
            route: "evidence",
            runtime: &runtime,
            connection_id: Some("shared"),
            connection: &policies,
            pack_artifacts: &artifacts,
            limits: EvidenceLimits::default(),
        })
        .expect("same named connection compiles");
        assert!(Arc::ptr_eq(
            first_program.endpoint_plans["first"]
                .resource
                .as_ref()
                .expect("live resource"),
            same_name.endpoint_plans["first"]
                .resource
                .as_ref()
                .expect("live resource")
        ));
        assert!(matches!(
            compile_evidence(&EvidenceCompileInputs {
                pack: &pack,
                route: "evidence",
                runtime: &runtime,
                connection_id: Some("independent"),
                connection: &policies,
                pack_artifacts: &artifacts,
                limits: EvidenceLimits::default(),
            }),
            Err(EvidenceCompileError::ConnectionPolicy {
                reason: ConnectionPolicyReason::ConnectionMismatch,
                ..
            })
        ));

        let drifted = make_runtime("drifted", "http://127.0.0.1:8199");
        assert!(matches!(
            compile_evidence(&EvidenceCompileInputs {
                pack: &pack,
                route: "evidence",
                runtime: &drifted,
                connection_id: Some("drifted"),
                connection: &policies,
                pack_artifacts: &artifacts,
                limits: EvidenceLimits::default(),
            }),
            Err(EvidenceCompileError::ConnectionPolicy {
                reason: ConnectionPolicyReason::BaseUrlMismatch,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn named_connection_cache_never_reuses_another_packs_graphql_plan() {
        let schema = serde_json::to_vec(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .expect("schema");
        let first_query = b"query FirstRecord { firstRecord { id } }\n";
        let second_query = b"query SecondRecord { secondRecord { id } }\n";
        let make_pack = |id: &str,
                         path: &str,
                         operation: &str,
                         header: &str,
                         authentication: Value,
                         query: &[u8]| {
            serde_json::from_value::<AdapterPack>(json!({
                "id": id,
                "version": "1",
                "testedVersions": [],
                "endpoints": [{
                    "id": "register",
                    "component": "graphql",
                    "authentication": authentication,
                    "attemptTimeoutMilliseconds": 1000,
                    "maximumResponseBytes": 1024,
                    "queryFile": path,
                    "operationName": operation,
                    "operations": [{"id": "lookup", "graphql": "query"}],
                    "responseHeaders": [],
                    "requestHeaders": [header],
                    "testedVersions": []
                }],
                "queryFiles": [{"path": path, "digest": sha256_uri(query)}],
                "sourceRoutes": [{
                    "id": "evidence",
                    "evidence": {
                        "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)},
                        "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)}
                    },
                    "steps": [{"to": {
                        "uri": "graphql:register",
                        "parameters": {"operation": "lookup"}
                    }}]
                }]
            }))
            .expect("pack")
        };
        let first_pack = make_pack(
            "first-pack",
            "queries/first.graphql",
            "FirstRecord",
            "x-first-pack",
            json!({"type": "oauth2-client-credentials"}),
            first_query,
        );
        let second_pack = make_pack(
            "second-pack",
            "queries/second.graphql",
            "SecondRecord",
            "x-second-pack",
            json!({"type": "oauth2-client-credentials"}),
            second_query,
        );
        let runtime = EvidenceRuntimeBindings::new(
            serde_json::from_value(json!({
                "id": "shared-connection",
                "endpoints": [{
                    "endpoint": "register",
                    "baseUrl": "https://register.example.invalid/graphql",
                    "credential": {
                        "type": "oauth2-client-credentials",
                        "tokenEndpoint": "https://issuer.example.invalid/token",
                        "clientIdRef": "secret:env/CLIENT_ID",
                        "clientSecretRef": "secret:env/CLIENT_SECRET",
                        "credentialPlacement": "basic-header",
                        "maximumCacheSeconds": 300
                    }
                    ,"maximumConcurrency": 1
                }],
                "allowedPrivateCidrs": []
            }))
            .expect("bindings"),
            SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
        );
        let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint": "register",
            "baseUrl": "https://register.example.invalid/graphql",
            "clientIdentity": "forbidden",
            "authentication": {
                "type": "oauth2-client-credentials",
                "tokenEndpoint": "https://issuer.example.invalid/token",
                "credentialPlacement": "basic-header"
            }
        }))
        .expect("reviewed policy");
        let compile = |pack: &AdapterPack,
                       path: &str,
                       query: &[u8],
                       runtime: &EvidenceRuntimeBindings,
                       policy: &EvidenceConnectionPolicy,
                       connection_id: &str| {
            let artifacts = PackArtifactBytes::new([
                ("schema.json".to_owned(), schema.clone()),
                (path.to_owned(), query.to_vec()),
            ]);
            compile_evidence(&EvidenceCompileInputs {
                pack,
                route: "evidence",
                runtime,
                connection_id: Some(connection_id),
                connection: std::slice::from_ref(policy),
                pack_artifacts: &artifacts,
                limits: EvidenceLimits::default(),
            })
            .expect("program")
        };
        let first = compile(
            &first_pack,
            "queries/first.graphql",
            first_query,
            &runtime,
            &policy,
            "shared-connection",
        );
        let second = compile(
            &second_pack,
            "queries/second.graphql",
            second_query,
            &runtime,
            &policy,
            "shared-connection",
        );

        let first_endpoint = first
            .initialize_endpoint("register", &first.endpoint_plans["register"])
            .await
            .expect("first runtime");
        let second_endpoint = second
            .initialize_endpoint("register", &second.endpoint_plans["register"])
            .await
            .expect("second runtime");

        assert!(!Arc::ptr_eq(&first_endpoint, &second_endpoint));
        assert_eq!(
            first_endpoint
                .graphql
                .as_ref()
                .expect("first query")
                .text
                .as_bytes(),
            first_query
        );
        assert_eq!(
            second_endpoint
                .graphql
                .as_ref()
                .expect("second query")
                .text
                .as_bytes(),
            second_query
        );
        assert_eq!(first_endpoint.egress.request_allowlist(), ["x-first-pack"]);
        assert_eq!(
            second_endpoint.egress.request_allowlist(),
            ["x-second-pack"]
        );
        assert!(
            first_endpoint
                .egress
                .shares_token_cache_with(&second_endpoint.egress),
            "the named connection must share its OAuth cache without sharing logical pack plans"
        );
        assert!(
            first_endpoint
                .egress
                .shares_data_admission_with(&second_endpoint.egress),
            "the named connection shares its physical data admission without sharing logical plans"
        );
        let held = first_endpoint.egress.acquire_data_permit().await;
        let waiting_egress = second_endpoint.egress.clone();
        let waiting = tokio::spawn(async move { waiting_egress.acquire_data_permit().await });
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "the second program waits on the named connection's single physical permit"
        );
        waiting.abort();
        assert!(
            waiting
                .await
                .expect_err("waiting acquisition is cancelled")
                .is_cancelled(),
            "cancelling a waiter is visible"
        );
        drop(held);
        let _released = tokio::time::timeout(
            Duration::from_secs(1),
            second_endpoint.egress.acquire_data_permit(),
        )
        .await
        .expect("the cancelled waiter retained no permit");

        let bearer_pack = make_pack(
            "bearer-pack",
            "queries/bearer.graphql",
            "FirstRecord",
            "x-bearer-pack",
            json!({"type": "static-authorization", "scheme": "Bearer"}),
            first_query,
        );
        let token_pack = make_pack(
            "token-pack",
            "queries/token.graphql",
            "SecondRecord",
            "x-token-pack",
            json!({"type": "static-authorization", "scheme": "Token"}),
            second_query,
        );
        let static_runtime = EvidenceRuntimeBindings::new(
            serde_json::from_value(json!({
                "id": "static-connection",
                "endpoints": [{
                    "endpoint": "register",
                    "baseUrl": "https://register.example.invalid/graphql",
                    "credential": {
                        "type": "static-authorization",
                        "tokenRef": "secret:env/STATIC_TOKEN"
                    }
                }],
                "allowedPrivateCidrs": []
            }))
            .expect("static bindings"),
            SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
        );
        let static_policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint": "register",
            "baseUrl": "https://register.example.invalid/graphql",
            "clientIdentity": "forbidden",
            "authentication": {"type": "static-authorization"}
        }))
        .expect("static policy");
        let bearer = compile(
            &bearer_pack,
            "queries/bearer.graphql",
            first_query,
            &static_runtime,
            &static_policy,
            "static-connection",
        );
        let token = compile(
            &token_pack,
            "queries/token.graphql",
            second_query,
            &static_runtime,
            &static_policy,
            "static-connection",
        );
        let bearer_endpoint = bearer
            .initialize_endpoint("register", &bearer.endpoint_plans["register"])
            .await
            .expect("bearer runtime");
        let token_endpoint = token
            .initialize_endpoint("register", &token.endpoint_plans["register"])
            .await
            .expect("token runtime");
        assert_eq!(
            bearer_endpoint.egress.declared_authorization_scheme(),
            Some("Bearer")
        );
        assert_eq!(
            token_endpoint.egress.declared_authorization_scheme(),
            Some("Token")
        );
    }

    #[test]
    fn reviewed_oauth_token_endpoint_drift_is_refused_before_execution() {
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "oauth-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "register",
                "component": "http",
                "authentication": {"type": "oauth2-client-credentials"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 1024,
                "responseHeaders": [],
                "requestHeaders": [],
                "operations": [],
                "testedVersions": []
            }]
        }))
        .expect("pack");
        let runtime = EvidenceRuntimeBindings::new(
            serde_json::from_value(json!({
                "id": "runtime",
                "endpoints": [{
                    "endpoint": "register",
                    "baseUrl": "https://register.example.invalid/api",
                    "credential": {
                        "type": "oauth2-client-credentials",
                        "tokenEndpoint": "https://issuer.example.invalid/token",
                        "clientIdRef": "secret:env/CLIENT_ID",
                        "clientSecretRef": "secret:env/CLIENT_SECRET",
                        "scope": "records.read",
                        "audience": "records",
                        "resource": "https://register.example.invalid/",
                        "credentialPlacement": "basic-header",
                        "maximumCacheSeconds": 300
                    }
                }],
                "allowedPrivateCidrs": ["192.168.0.0/16"]
            }))
            .expect("binding"),
            SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
        );
        let reviewed: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint": "register",
            "baseUrl": "https://register.example.invalid/api",
            "clientIdentity": "forbidden",
            "authentication": {
                "type": "oauth2-client-credentials",
                "tokenEndpoint": "https://other-issuer.example.invalid/token",
                "scope": "records.read",
                "audience": "records",
                "resource": "https://register.example.invalid/",
                "credentialPlacement": "basic-header"
            }
        }))
        .expect("reviewed connection");
        let endpoint = pack.endpoints.get("register").expect("endpoint");
        assert!(matches!(
            validate_connection_policy(&runtime, endpoint, &reviewed),
            Err(EvidenceCompileError::ConnectionPolicy {
                reason: ConnectionPolicyReason::AuthenticationMismatch,
                ..
            })
        ));
    }

    #[test]
    fn reachable_writes_are_refused_even_through_direct_routes() {
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "write-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "register",
                "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 1024,
                "responseHeaders": [],
                "requestHeaders": [],
                "operations": [{"id": "update", "idempotentUpstream": true}],
                "testedVersions": []
            }],
            "routes": [{
                "id": "hidden-write",
                "from": {"uri": "direct:hidden-write"},
                "steps": [{"to": {
                    "uri": "http:register",
                    "parameters": {
                        "httpMethod": "POST",
                        "operation": "update",
                        "path": "/records",
                        "body": {"constant": {"changed": true}}
                    }
                }}]
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "steps": [{"to": {"uri": "direct:hidden-write"}}]
            }]
        }))
        .expect("pack");
        let source = pack.source_routes.get("evidence").expect("source");
        assert!(matches!(
            check_read_only_closure(&pack, source),
            Err(EvidenceCompileError::ReachableWrite)
        ));
    }

    #[test]
    fn reviewed_get_and_safe_post_are_admitted() {
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "read-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "register",
                "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 1024,
                "responseHeaders": [],
                "requestHeaders": [],
                "operations": [{
                    "id": "search",
                    "safeUpstream": true
                }],
                "testedVersions": []
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "steps": [
                    {"to": {"uri": "http:register", "parameters": {
                        "httpMethod": "GET", "path": "/records/1"
                    }}},
                    {"to": {"uri": "http:register", "parameters": {
                        "httpMethod": "POST",
                        "operation": "search",
                        "path": "/records/_search",
                        "body": {"constant": {"name": "Ada"}}
                    }}}
                ]
            }]
        }))
        .expect("pack");
        let source = pack.source_routes.get("evidence").expect("source");
        check_read_only_closure(&pack, source).expect("reviewed reads admitted");
    }

    struct RefuseIntent;

    impl EvidenceHostHooks for RefuseIntent {
        fn before_acquisition<'a>(
            &'a self,
            _intent: EvidenceAcquisitionIntent,
        ) -> EvidenceHookFuture<'a> {
            Box::pin(async { Err(EvidenceHookError::Audit) })
        }
    }

    #[tokio::test]
    async fn tls_material_is_unread_until_after_durable_acquisition_intent() {
        let inputs_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        });
        let facts_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        });
        let inputs_bytes = serde_json::to_vec(&inputs_schema).expect("schema");
        let facts_bytes = serde_json::to_vec(&facts_schema).expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "tls-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "register",
                "component": "http",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 1024,
                "responseHeaders": [],
                "requestHeaders": [],
                "operations": [],
                "testedVersions": []
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {
                        "path": "schemas/inputs.json",
                        "digest": sha256_uri(&inputs_bytes)
                    },
                    "factsSchema": {
                        "path": "schemas/facts.json",
                        "digest": sha256_uri(&facts_bytes)
                    }
                },
                "steps": [{"to": {"uri": "http:register", "parameters": {
                    "httpMethod": "GET", "path": "/lookup"
                }}}]
            }]
        }))
        .expect("pack");
        let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
            "id": "tls-runtime",
            "endpoints": [{
                "endpoint": "register",
                "baseUrl": "https://register.example.invalid",
                "credential": {"type": "none"},
                "anonymousHttps": "operator-approved",
                "tlsTrustProfile": "private-ca"
            }],
            "outboundTls": {"trustProfiles": {
                "private-ca": {"caBundleFile": "/definitely/not/read-before-evidence-intent.pem"}
            }},
            "allowedPrivateCidrs": ["192.168.0.0/16"]
        }))
        .expect("bindings");
        let runtime = EvidenceRuntimeBindings::from_shared_http(
            bindings,
            Arc::new(SecretResolver::new([SecretProvider::Environment], "").expect("resolver")),
            BTreeMap::from([("private-ca".to_owned(), b"not-a-certificate".to_vec())]),
        );
        let connection: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint": "register",
            "baseUrl": "https://register.example.invalid",
            "tlsTrustProfile": "private-ca",
            "clientIdentity": "forbidden",
            "authentication": {"type": "none"}
        }))
        .expect("reviewed connection");
        let artifacts = PackArtifactBytes::new([
            ("schemas/inputs.json".to_owned(), inputs_bytes),
            ("schemas/facts.json".to_owned(), facts_bytes),
        ]);

        let program = compile_evidence(&EvidenceCompileInputs {
            pack: &pack,
            route: "evidence",
            runtime: &runtime,
            connection_id: Some("tls-runtime"),
            connection: std::slice::from_ref(&connection),
            pack_artifacts: &artifacts,
            limits: EvidenceLimits::default(),
        })
        .expect("compile captures references without reading TLS material");
        assert!(matches!(
            program.begin_acquisition(Arc::new(RefuseIntent)).await,
            Err(EvidenceBeginError::Terminal(EvidenceTerminalError::Audit))
        ));
        assert!(matches!(
            program
                .begin_acquisition(Arc::new(RecordingHooks::default()))
                .await,
            Err(EvidenceBeginError::Endpoint)
        ));
    }

    struct InstallFileSecret {
        path: PathBuf,
    }

    impl EvidenceHostHooks for InstallFileSecret {
        fn before_acquisition<'a>(
            &'a self,
            _intent: EvidenceAcquisitionIntent,
        ) -> EvidenceHookFuture<'a> {
            Box::pin(async { Ok(()) })
        }

        fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
            std::fs::write(&self.path, "test-only-key").expect("write fixture secret");
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))
                .expect("protect fixture secret");
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn captured_file_provider_resolves_only_after_the_precredential_hook() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        let connected = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&connected);
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2048];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).expect("request");
                assert!(read > 0, "request head completes");
                request.extend_from_slice(&chunk[..read]);
            }
            let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
            observed.store(head.contains("x-api-key: test-only-key"), Ordering::SeqCst);
            let body = r#"{"lookup":"matched","facts":{}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("response");
        });

        let inputs_schema = json!({
            "type": "object", "additionalProperties": false, "properties": {}
        });
        let facts_schema = json!({
            "type": "object", "additionalProperties": false, "properties": {}
        });
        let inputs_bytes = serde_json::to_vec(&inputs_schema).expect("schema");
        let facts_bytes = serde_json::to_vec(&facts_schema).expect("schema");
        let pack: AdapterPack = serde_json::from_value(json!({
            "id": "file-secret-pack",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "register",
                "component": "http",
                "authentication": {"type": "static-api-key", "headerName": "x-api-key"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 1024,
                "responseHeaders": [],
                "requestHeaders": [],
                "operations": [],
                "testedVersions": []
            }],
            "sourceRoutes": [{
                "id": "evidence",
                "evidence": {
                    "inputsSchema": {"path": "schemas/inputs.json", "digest": sha256_uri(&inputs_bytes)},
                    "factsSchema": {"path": "schemas/facts.json", "digest": sha256_uri(&facts_bytes)}
                },
                "steps": [{"to": {"uri": "http:register", "parameters": {
                    "httpMethod": "GET", "path": "/lookup"
                }}}]
            }]
        }))
        .expect("pack");
        let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
            "id": "file-secret-runtime",
            "endpoints": [{
                "endpoint": "register",
                "baseUrl": format!("http://127.0.0.1:{port}"),
                "credential": {"type": "static-api-key", "valueRef": "secret:file/api-key"}
            }],
            "allowedPrivateCidrs": ["192.168.0.0/16"]
        }))
        .expect("bindings");
        let secret_root = tempfile::tempdir().expect("secret root");
        let secret_path = secret_root.path().join("api-key");
        let runtime = EvidenceRuntimeBindings::new(
            bindings,
            SecretResolver::new(
                [SecretProvider::File, SecretProvider::Environment],
                secret_root.path(),
            )
            .expect("configured resolver"),
        );
        let connection: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint": "register",
            "baseUrl": format!("http://127.0.0.1:{port}"),
            "clientIdentity": "forbidden",
            "authentication": {"type": "static-api-key"}
        }))
        .expect("reviewed connection");
        let artifacts = PackArtifactBytes::new([
            ("schemas/inputs.json".to_owned(), inputs_bytes),
            ("schemas/facts.json".to_owned(), facts_bytes),
        ]);
        let program = compile_evidence(&EvidenceCompileInputs {
            pack: &pack,
            route: "evidence",
            runtime: &runtime,
            connection_id: Some("file-secret-runtime"),
            connection: std::slice::from_ref(&connection),
            pack_artifacts: &artifacts,
            limits: EvidenceLimits::default(),
        })
        .expect("pure compile");
        assert!(!secret_path.exists(), "compile performs no secret read");
        assert!(
            !connected.load(Ordering::SeqCst),
            "compile performs no send"
        );
        assert!(matches!(
            program.credentials_ready().await,
            Err(EvidenceReadinessError::Credential)
        ));
        std::fs::write(&secret_path, "readiness-key").expect("write readiness fixture");
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect readiness fixture");
        program
            .credentials_ready()
            .await
            .expect("static credential is ready without a data send");
        assert!(
            !connected.load(Ordering::SeqCst),
            "credential readiness performs no data request"
        );
        std::fs::remove_file(&secret_path).expect("reset readiness fixture");
        let acquisition = program
            .begin_acquisition(Arc::new(InstallFileSecret {
                path: secret_path.clone(),
            }))
            .await
            .expect("captured authority starts after intent");
        assert!(
            !secret_path.exists(),
            "begin does not resolve a data credential"
        );

        assert_eq!(
            program
                .execute(&acquisition, json!({}))
                .await
                .expect("lookup"),
            EvidenceLookup::Matched { facts: json!({}) }
        );
        assert!(connected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn evidence_replay_retains_default_and_declared_attempt_timeouts() {
        let schema = serde_json::to_vec(&json!({
            "type": "object", "additionalProperties": false, "properties": {}
        }))
        .expect("schema");
        for attempt in [None, Some(30_000), Some(45_000)] {
            let mut endpoint = json!({
                "id": "register", "component": "http",
                "authentication": {"type": "none"}, "maximumResponseBytes": 1024
            });
            if let Some(attempt) = attempt {
                endpoint["attemptTimeoutMilliseconds"] = json!(attempt);
            }
            let pack: AdapterPack = serde_json::from_value(json!({
                "id": "replay-evidence", "version": "1", "testedVersions": [],
                "endpoints": [endpoint],
                "sourceRoutes": [{
                    "id": "evidence",
                    "evidence": {
                        "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)},
                        "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema)}
                    },
                    "steps": [{"to": {"uri": "http:register", "parameters": {
                        "httpMethod": "GET", "path": "/lookup"
                    }}}]
                }]
            }))
            .expect("pack");
            let artifacts = PackArtifactBytes::new([("schema.json".to_owned(), schema.clone())]);
            let make_transcript = || {
                Arc::new(crate::replay::ReplayTranscript::from_exchanges(
                    serde_json::from_value(json!([{"type": "endpoint", "endpoint": "register"}]))
                        .expect("intercepts"),
                    serde_json::from_value(json!([{
                        "request": {"endpoint": "register", "method": "GET", "path": "/lookup"},
                        "response": {"status": 200, "body": {"lookup": "matched", "facts": {}}}
                    }]))
                    .expect("exchanges"),
                ))
            };
            let transcript = make_transcript();
            let program =
                compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default())
                    .expect("Evidence timeout profile compiles")
                    .bind_replay(Arc::clone(&transcript))
                    .expect("Evidence timeout profile binds to replay");
            let expected_attempt = Duration::from_millis(attempt.unwrap_or(30_000));
            assert_eq!(
                program.endpoint_plans["register"]
                    .replay
                    .as_ref()
                    .expect("replay endpoint")
                    .attempt,
                expected_attempt,
                "replay retains the Evidence attempt default and declared override"
            );
            let acquisition = program
                .begin_acquisition(Arc::new(RecordingHooks::default()))
                .await
                .expect("acquisition");
            assert_eq!(
                program
                    .execute(&acquisition, json!({}))
                    .await
                    .expect("Evidence replay executes above the ordinary timeout ceiling"),
                EvidenceLookup::Matched { facts: json!({}) }
            );
            assert_eq!(transcript.finish(), Ok(()));
            #[cfg(feature = "sqlite-extract")]
            {
                let transcript = make_transcript();
                let program =
                    compile_evidence_pack(&pack, "evidence", &artifacts, EvidenceLimits::default())
                        .expect("Evidence fixture profile compiles")
                        .bind_fixture(Arc::clone(&transcript), BTreeMap::new())
                        .expect("Evidence fixture profile binds");
                assert_eq!(
                    program.endpoint_plans["register"]
                        .replay
                        .as_ref()
                        .expect("fixture endpoint")
                        .attempt,
                    expected_attempt,
                    "fixture binding retains the same Evidence attempt policy"
                );
                let acquisition = program
                    .begin_acquisition(Arc::new(RecordingHooks::default()))
                    .await
                    .expect("fixture acquisition");
                assert_eq!(
                    program
                        .execute(&acquisition, json!({}))
                        .await
                        .expect("fixture executes"),
                    EvidenceLookup::Matched { facts: json!({}) }
                );
                assert_eq!(transcript.finish(), Ok(()));
            }
        }
    }

    #[tokio::test]
    async fn explicit_evidence_deadline_is_not_clamped_to_ten_seconds() {
        let limits = EvidenceLimits::try_new(5, 12_500, 1024).expect("limits");
        let acquisition = EvidenceAcquisition::begin(
            limits,
            Arc::new(RecordingHooks::default()),
            EvidenceAcquisitionIntent {
                pack: "deadline-pack".to_owned(),
                route: "deadline-route".to_owned(),
            },
        )
        .await
        .expect("acquisition");
        assert!(
            acquisition
                .deadline()
                .saturating_duration_since(tokio::time::Instant::now())
                > Duration::from_secs(10)
        );
    }

    #[tokio::test]
    async fn evidence_attempt_defaults_and_overrides_complete_after_ten_seconds() {
        use tokio::io::AsyncReadExt;

        let request_arrived = Arc::new(tokio::sync::Notify::new());
        let release_response = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("delayed Evidence listener");
        let port = listener.local_addr().expect("listener address").port();
        let server_request_arrived = Arc::clone(&request_arrived);
        let server_release_response = Arc::clone(&release_response);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("Evidence connection");
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut chunk = [0_u8; 512];
                let read = stream.read(&mut chunk).await.expect("request head");
                assert!(read > 0, "the request head completes");
                request.extend_from_slice(&chunk[..read]);
            }
            server_request_arrived.notify_one();
            server_release_response.notified().await;
            // The response leaves from a plain thread after a real delay,
            // as a slow upstream's would, so the lookup waits on the socket
            // with no timer due before its attempt timeout.
            let mut stream = stream.into_std().expect("std Evidence stream");
            stream
                .set_nonblocking(false)
                .expect("blocking Evidence stream");
            std::thread::spawn(move || {
                use std::io::Write;
                std::thread::sleep(Duration::from_millis(50));
                let body = br#"{"lookup":"matched","facts":{}}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).expect("response head");
                stream.write_all(body).expect("response body");
            })
        });

        let schema = json!({
            "type": "object", "additionalProperties": false, "properties": {}
        });
        let schema_bytes = serde_json::to_vec(&schema).expect("schema");
        let make_pack = |attempt: Option<u64>| {
            let mut endpoint = json!({
                "id": "register",
                "component": "http",
                "authentication": {"type": "none"},
                "maximumResponseBytes": 1024
            });
            if let Some(attempt) = attempt {
                endpoint["attemptTimeoutMilliseconds"] = json!(attempt);
            }
            serde_json::from_value::<AdapterPack>(json!({
                "id": "delayed-evidence",
                "version": "1",
                "testedVersions": [],
                "endpoints": [endpoint],
                "sourceRoutes": [{
                    "id": "evidence",
                    "evidence": {
                        "inputsSchema": {"path": "schema.json", "digest": sha256_uri(&schema_bytes)},
                        "factsSchema": {"path": "schema.json", "digest": sha256_uri(&schema_bytes)}
                    },
                    "steps": [{"to": {"uri": "http:register", "parameters": {
                        "httpMethod": "GET", "path": "/lookup"
                    }}}]
                }]
            }))
            .expect("Evidence pack")
        };
        let artifacts = PackArtifactBytes::new([("schema.json".to_owned(), schema_bytes.clone())]);
        let base_url = format!("http://127.0.0.1:{port}");
        let connection: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint": "register",
            "baseUrl": base_url,
            "clientIdentity": "forbidden",
            "authentication": {"type": "none"}
        }))
        .expect("reviewed connection");
        let limits = EvidenceLimits::try_new(5, 60_000, 4096).expect("limits");
        let compile_program = |pack: &AdapterPack, id: &str, override_ms: Option<u64>| {
            let mut binding = json!({
                "endpoint": "register",
                "baseUrl": base_url,
                "credential": {"type": "none"}
            });
            if let Some(override_ms) = override_ms {
                binding["attemptTimeoutMilliseconds"] = json!(override_ms);
            }
            let runtime = EvidenceRuntimeBindings::new(
                serde_json::from_value(json!({
                    "id": id,
                    "endpoints": [binding],
                    "allowedPrivateCidrs": []
                }))
                .expect("runtime bindings"),
                SecretResolver::new([SecretProvider::Environment], "").expect("resolver"),
            );
            compile_evidence(&EvidenceCompileInputs {
                pack,
                route: "evidence",
                runtime: &runtime,
                connection_id: Some(id),
                connection: std::slice::from_ref(&connection),
                pack_artifacts: &artifacts,
                limits,
            })
            .expect("Evidence program")
        };

        let omitted = make_pack(None);
        let default_program = compile_program(&omitted, "default-attempt", None);
        let default_acquisition = default_program
            .begin_acquisition(Arc::new(RecordingHooks::default()))
            .await
            .expect("default acquisition");
        assert_eq!(
            default_acquisition.endpoints["register"].attempt,
            Duration::from_secs(30)
        );

        let explicit = make_pack(Some(15_000));
        let explicit_program = compile_program(&explicit, "pack-attempt", None);
        let explicit_acquisition = explicit_program
            .begin_acquisition(Arc::new(RecordingHooks::default()))
            .await
            .expect("pack acquisition");
        assert_eq!(
            explicit_acquisition.endpoints["register"].attempt,
            Duration::from_secs(15)
        );

        let override_program = compile_program(&omitted, "runtime-attempt", Some(45_000));
        let override_acquisition = override_program
            .begin_acquisition(Arc::new(RecordingHooks::default()))
            .await
            .expect("override acquisition");
        assert_eq!(
            override_acquisition.endpoints["register"].attempt,
            Duration::from_secs(45)
        );
        let execute = tokio::spawn(async move {
            override_program
                .execute(&override_acquisition, json!({}))
                .await
        });
        request_arrived.notified().await;
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_secs(11)).await;
        // A paused clock jumps to the next timer whenever the runtime is
        // idle, which is the attempt timeout while the lookup waits on
        // the socket. Resume real time so the response decides the lookup.
        tokio::time::resume();
        release_response.notify_one();
        assert_eq!(
            execute
                .await
                .expect("delayed Evidence task completes")
                .expect("delayed Evidence lookup"),
            EvidenceLookup::Matched { facts: json!({}) }
        );
        assert!(started.elapsed() >= Duration::from_secs(11));
        server
            .await
            .expect("delayed server task completed")
            .join()
            .expect("delayed response sent");
    }
}
