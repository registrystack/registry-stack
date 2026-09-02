// SPDX-License-Identifier: Apache-2.0
//! Strict project journeys and candidate-bound, non-authorizing test receipts.
//!
//! Journey source is reviewed project input, not HTTP authority. The validator
//! therefore resolves every logical entity, operation, profile, and field
//! against the compiled Registry before the executor may perform I/O. The
//! executor receives only requests derived by this module and already-verified
//! synthetic claims. It cannot accept a caller URL, SQL fragment, physical
//! identifier, credential, or arbitrary header.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ETAG, IF_MATCH};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use axum::Router;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_httpsec::{response_trace_id, TraceId};
use registry_platform_oidc::{JwksFetcher, TokenVerifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tower::Service as _;
use zeroize::Zeroizing;

use crate::api::{HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture};
use crate::api::{VerifiedClaimValue, VerifiedRequestClaims};
use crate::auth::RegistryAuthenticator;
use crate::compiler::{compile_project_with_assets, module_digest_with_assets, CompileProfile};
use crate::contract::{
    parse_module_yaml, parse_project_yaml, redact_authored_values, ModuleAssetSource,
};
use crate::contract::{AccessProfileSource, LookupValueOrigin, Operation};
use crate::data::{validate_field_value, FieldValue};
use crate::derived_sql::MAX_DERIVED_SQL_BYTES;
use crate::model::CompiledRoute;
use crate::model::{ActionRouteKind, CompiledAction, CompiledActionGrant, CompiledActionRoute};
use crate::model::{CompiledQueryKind, CompiledQueryOperation, CompiledRegistry, HttpMethod};
#[cfg(any(test, feature = "postgres-test"))]
use crate::package::{canonical_signed_bytes as package_canonical_signed_bytes, VerifiedPackage};
use crate::package::{
    PackageCompileProfile, PackageFileRole, PreparedPackage, FIXTURE_JOURNEYS_PATH,
};
use crate::postgres::{
    PostgresRecordMutationService, PostgresRecordReadService, PostgresRevisionReadService,
    PreparedSchemaTestCatalogVerifier, PreparedSchemaTestDatabase, RuntimePool,
};
use crate::runtime_config::RuntimeConfig;
#[cfg(feature = "postgres-test")]
use crate::startup::PreparedServer;

const JOURNEY_API_VERSION: &str = "registry.registrystack.org/server-journeys/v1";
const RECEIPT_API_VERSION: &str = "registry.registrystack.org/server-schema-test-receipt/v1";
const RECEIPT_KIND: &str = "SchemaTestReceipt";
const MAX_JOURNEY_FILE_BYTES: usize = 1024 * 1024;
const MAX_JOURNEYS: usize = 128;
const MAX_STEPS_PER_JOURNEY: usize = 128;
const MAX_TOTAL_STEPS: usize = 512;
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_BINDING_BYTES: usize = 256;
const MAX_BEARER_TOKEN_BYTES: usize = 32 * 1024;
const MIN_SUPPORTED_POSTGRES_MAJOR: u16 = 15;
const MAX_SUPPORTED_POSTGRES_MAJOR: u16 = 18;

type CredentialMap = BTreeMap<(String, String), Option<Zeroizing<String>>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureError {
    JourneyTooLarge,
    JourneyShapeRefused,
    JourneyVersionRefused,
    JourneyBoundsRefused,
    DuplicateIdentifier,
    LogicalReferenceRefused,
    AuthorityWideningRefused,
    RequestConstructionRefused,
    ResponseTooLarge,
    ResponseShapeRefused,
    ExpectationMismatch,
    ExecutionRefused,
    CandidateBindingRefused,
    ReceiptShapeRefused,
    ReceiptBindingRefused,
    ResponseStatusMismatch {
        expected: u16,
        actual: u16,
    },
    /// A journeys document that stops matching the grammar, reported with the
    /// path it stops at. The member, the alternatives the grammar accepts, and
    /// the source location are carried; authored values are not.
    JourneyShapeInvalid {
        path: String,
        message: String,
    },
    /// A refusal that belongs to one journey rather than to one of its steps.
    JourneyRefused {
        journey_index: usize,
        journey_id: String,
        message: String,
    },
    StepFailed {
        journey_index: usize,
        step_index: usize,
        error: Box<Self>,
    },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::StepFailed {
            journey_index,
            step_index,
            error,
        } = self
        {
            return write!(
                formatter,
                "journeys[{journey_index}].steps[{step_index}]: {error}"
            );
        }
        if let Self::ResponseStatusMismatch { expected, actual } = self {
            return write!(
                formatter,
                "expected HTTP {expected}, received HTTP {actual}"
            );
        }
        if let Self::JourneyShapeInvalid { path, message } = self {
            return write!(formatter, "`{path}`: {message}");
        }
        if let Self::JourneyRefused {
            journey_index,
            journey_id,
            message,
        } = self
        {
            return write!(
                formatter,
                "journeys[{journey_index}] `{journey_id}`: {message}"
            );
        }
        if let Self::JourneyVersionRefused = self {
            return write!(
                formatter,
                "the fixture journeys document must set `apiVersion: {JOURNEY_API_VERSION}`"
            );
        }
        formatter.write_str(match self {
            Self::JourneyTooLarge => "the fixture journey exceeded a fixed bound",
            Self::JourneyShapeRefused => "the fixture journey shape was refused",
            Self::JourneyBoundsRefused => "the fixture journey inventory was refused",
            Self::DuplicateIdentifier => "the fixture journey contains a duplicate identifier",
            Self::LogicalReferenceRefused => "the fixture logical reference was refused",
            Self::AuthorityWideningRefused => "the fixture authority reference was refused",
            Self::RequestConstructionRefused => "the fixture request could not be constructed",
            Self::ResponseTooLarge => "the fixture response exceeded a fixed bound",
            Self::ResponseShapeRefused => "the fixture response shape was refused",
            Self::ExpectationMismatch => "the fixture expectation did not match",
            Self::ExecutionRefused => "the fixture request execution was refused",
            Self::CandidateBindingRefused => "the schema test candidate binding was refused",
            Self::ReceiptShapeRefused => "the schema test receipt shape was refused",
            Self::ReceiptBindingRefused => "the schema test receipt binding was refused",
            Self::ResponseStatusMismatch { .. }
            | Self::StepFailed { .. }
            | Self::JourneyShapeInvalid { .. }
            | Self::JourneyRefused { .. }
            | Self::JourneyVersionRefused => {
                unreachable!("handled above")
            }
        })
    }
}

impl std::error::Error for FixtureError {}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JourneyDocument {
    api_version: String,
    journeys: Vec<JourneySource>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JourneySource {
    id: String,
    steps: Vec<StepSource>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StepSource {
    id: String,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    entity: String,
    access_profile: String,
    #[serde(default)]
    claims: ClaimsSource,
    request: ActionSource,
    expect: ExpectationSource,
    #[serde(default)]
    capture: Option<String>,
    #[serde(default)]
    capture_results: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    tag = "operation"
)]
enum ActionSource {
    Create {
        data: Map<String, Value>,
    },
    Get {
        record_ref: String,
    },
    List {},
    Query {
        #[serde(default)]
        select: BTreeSet<String>,
        #[serde(default)]
        top: Option<u16>,
        #[serde(default)]
        count: bool,
        #[serde(default)]
        bbox: Option<BboxSource>,
    },
    Lookup {
        selector: String,
        #[serde(default)]
        values: Map<String, Value>,
    },
    ReadPath {
        path: String,
        record_ref: String,
        #[serde(default)]
        select: BTreeSet<String>,
        #[serde(default)]
        top: Option<u16>,
        #[serde(default)]
        count: bool,
    },
    Patch {
        record_ref: String,
        etag_ref: String,
        changes: Vec<FieldChangeSource>,
    },
    Batch {
        items: Vec<BatchItemSource>,
    },
    TargetConditions {
        #[serde(default)]
        input: Map<String, Value>,
    },
    Invoke {
        #[serde(default)]
        input: Map<String, Value>,
        #[serde(default)]
        preconditions: BTreeMap<String, ImmediateActionPreconditionSource>,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    SubmitRequest {
        record_ref: String,
        etag_ref: String,
    },
    ApproveRequest {
        stage: String,
        record_ref: String,
        etag_ref: String,
        #[serde(default)]
        proposal_version: Option<u32>,
        #[serde(default)]
        proposal_version_ref: Option<String>,
        #[serde(default)]
        effect_digest: Option<String>,
        #[serde(default)]
        effect_digest_ref: Option<String>,
    },
    RejectRequest {
        stage: String,
        record_ref: String,
        etag_ref: String,
        #[serde(default)]
        proposal_version: Option<u32>,
        #[serde(default)]
        proposal_version_ref: Option<String>,
        #[serde(default)]
        effect_digest: Option<String>,
        #[serde(default)]
        effect_digest_ref: Option<String>,
    },
    RequestRevision {
        stage: String,
        record_ref: String,
        etag_ref: String,
        #[serde(default)]
        proposal_version: Option<u32>,
        #[serde(default)]
        proposal_version_ref: Option<String>,
        #[serde(default)]
        effect_digest: Option<String>,
        #[serde(default)]
        effect_digest_ref: Option<String>,
    },
    ReviseRequest {
        record_ref: String,
        etag_ref: String,
        rebase: bool,
    },
    CancelRequest {
        record_ref: String,
        etag_ref: String,
    },
    ApplyRequest {
        record_ref: String,
        etag_ref: String,
        #[serde(default)]
        proposal_version: Option<u32>,
        #[serde(default)]
        proposal_version_ref: Option<String>,
        #[serde(default)]
        effect_digest: Option<String>,
        #[serde(default)]
        effect_digest_ref: Option<String>,
    },
}

impl ActionSource {
    fn operation(&self) -> Operation {
        match self {
            Self::Create { .. } => Operation::Create,
            Self::Get { .. } => Operation::Get,
            Self::List { .. } | Self::Query { .. } | Self::ReadPath { .. } => Operation::List,
            Self::Lookup { .. } => Operation::Lookup,
            Self::Patch { .. } => Operation::Patch,
            Self::Batch { .. } => Operation::Batch,
            Self::TargetConditions { .. } | Self::Invoke { .. } => Operation::Invoke,
            Self::SubmitRequest { .. } => Operation::SubmitRequest,
            Self::ApproveRequest { .. } => Operation::ApproveRequest,
            Self::RejectRequest { .. } => Operation::RejectRequest,
            Self::RequestRevision { .. } => Operation::RequestRevision,
            Self::ReviseRequest { .. } => Operation::ReviseRequest,
            Self::CancelRequest { .. } => Operation::CancelRequest,
            Self::ApplyRequest { .. } => Operation::ApplyRequest,
        }
    }

    fn route_id(&self, entity_id: &str) -> String {
        let suffix = match self {
            Self::Create { .. } => "create".to_owned(),
            Self::Get { .. } => "get".to_owned(),
            Self::List { .. } | Self::Query { .. } => "list".to_owned(),
            Self::Lookup { .. } => "lookup".to_owned(),
            Self::ReadPath { path, .. } => format!("path.{path}"),
            Self::Patch { .. } => "patch".to_owned(),
            Self::Batch { .. } => "batch".to_owned(),
            Self::TargetConditions { .. } => "target_conditions".to_owned(),
            Self::Invoke { .. } => "invoke".to_owned(),
            Self::SubmitRequest { .. } => "request.submit".to_owned(),
            Self::ApproveRequest { stage, .. } => format!("request.stages.{stage}.approve"),
            Self::RejectRequest { stage, .. } => format!("request.stages.{stage}.reject"),
            Self::RequestRevision { stage, .. } => {
                format!("request.stages.{stage}.request_revision")
            }
            Self::ReviseRequest { .. } => "request.revise".to_owned(),
            Self::CancelRequest { .. } => "request.cancel".to_owned(),
            Self::ApplyRequest { .. } => "request.apply".to_owned(),
        };
        format!("records.{entity_id}.{suffix}")
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ImmediateActionPreconditionSource {
    #[serde(default)]
    if_match: Option<String>,
    #[serde(default)]
    condition_ref: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FieldChangeSource {
    field: String,
    value: Value,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BboxSource {
    west: String,
    south: String,
    east: String,
    north: String,
}

impl BboxSource {
    fn query_value(&self) -> String {
        format!("{},{},{},{}", self.west, self.south, self.east, self.north)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "operation")]
enum BatchItemSource {
    Create { data: Map<String, Value> },
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClaimsSource {
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    scopes: BTreeSet<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    direct_claims: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    Success,
    Refusal,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExpectationSource {
    outcome: ExpectedOutcome,
    status: u16,
    #[serde(default)]
    fields: Map<String, Value>,
    #[serde(default)]
    count: Option<usize>,
    #[serde(default)]
    problem_code: Option<String>,
}

/// A complete journey suite that has been resolved against one exact compiled
/// Registry. Its internals are private so execution cannot substitute paths or
/// authority material after structural preflight.
#[derive(Clone)]
pub struct ValidatedFixtureJourneys {
    registry_revision: String,
    file_sha256: String,
    file_bytes: Vec<u8>,
    journeys: Vec<ValidatedJourney>,
}

impl fmt::Debug for ValidatedFixtureJourneys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedFixtureJourneys")
            .field("journey_count", &self.journeys.len())
            .field(
                "step_count",
                &self
                    .journeys
                    .iter()
                    .map(|journey| journey.steps.len())
                    .sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

impl ValidatedFixtureJourneys {
    pub fn journey_ids(&self) -> Vec<&str> {
        self.journeys
            .iter()
            .map(|journey| journey.id.as_str())
            .collect()
    }

    pub fn file_sha256(&self) -> &str {
        &self.file_sha256
    }
}

#[derive(Clone)]
struct ValidatedJourney {
    id: String,
    steps: Vec<ValidatedStep>,
}

#[derive(Clone)]
struct ValidatedStep {
    id: String,
    entity: Option<String>,
    action_id: Option<String>,
    access_profile: String,
    claims: ClaimsSource,
    route: FixtureRoute,
    profile: AccessProfileSource,
    response_readable_fields: BTreeSet<String>,
    action: ActionSource,
    expect: ExpectationSource,
    capture: Option<String>,
    capture_results: BTreeMap<String, String>,
}

#[derive(Clone)]
enum FixtureRoute {
    Entity(CompiledRoute),
    Action(CompiledActionRoute),
}

impl FixtureRoute {
    fn path(&self) -> &str {
        match self {
            Self::Entity(route) => &route.path,
            Self::Action(route) => &route.path,
        }
    }
}

#[derive(Clone)]
struct CaptureSource {
    entity: Option<String>,
    operation: Operation,
    has_etag: bool,
    condition_map: bool,
}

/// Parse and resolve all journey references before any request executor is
/// called. YAML errors are deliberately collapsed into a value-free refusal.
pub fn validate_fixture_journeys(
    bytes: &[u8],
    registry: &CompiledRegistry,
) -> Result<ValidatedFixtureJourneys, FixtureError> {
    if bytes.is_empty() || bytes.len() > MAX_JOURNEY_FILE_BYTES {
        return Err(FixtureError::JourneyTooLarge);
    }
    let deserializer = serde_norway::Deserializer::from_slice(bytes);
    let document: JourneyDocument =
        serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let path = error.path().to_string();
            FixtureError::JourneyShapeInvalid {
                path: if path.is_empty() {
                    "the journeys document".to_owned()
                } else {
                    path
                },
                message: redact_authored_values(&error.inner().to_string()),
            }
        })?;
    if document.api_version != JOURNEY_API_VERSION {
        return Err(FixtureError::JourneyVersionRefused);
    }
    if document.journeys.is_empty() || document.journeys.len() > MAX_JOURNEYS {
        return Err(FixtureError::JourneyBoundsRefused);
    }

    let mut journey_ids = BTreeSet::new();
    let mut total_steps = 0usize;
    let mut journeys = Vec::with_capacity(document.journeys.len());
    for (journey_index, journey) in document.journeys.into_iter().enumerate() {
        let mut step_ids = BTreeSet::new();
        let mut capture_ids = BTreeSet::new();
        let mut capture_sources = BTreeMap::new();
        let journey_refusal = |message: String| FixtureError::JourneyRefused {
            journey_index,
            journey_id: journey.id.clone(),
            message,
        };
        if !valid_stable_id(&journey.id) {
            return Err(journey_refusal(format!(
                "the journey id is not a stable identifier: it starts with a lower-case letter and holds only lower-case letters, digits, and hyphens, in at most {MAX_IDENTIFIER_BYTES} bytes"
            )));
        }
        if !journey_ids.insert(journey.id.clone()) {
            return Err(journey_refusal(
                "an earlier journey already declares this id: journey ids are unique in one document".to_owned(),
            ));
        }
        if journey.steps.is_empty() || journey.steps.len() > MAX_STEPS_PER_JOURNEY {
            return Err(journey_refusal(format!(
                "the journey declares {} steps: a journey declares at least one step and at most {MAX_STEPS_PER_JOURNEY}",
                journey.steps.len()
            )));
        }
        total_steps = total_steps
            .checked_add(journey.steps.len())
            .ok_or_else(|| {
                journey_refusal(format!(
                    "the document declares more than {MAX_TOTAL_STEPS} steps in total"
                ))
            })?;
        if total_steps > MAX_TOTAL_STEPS {
            return Err(journey_refusal(format!(
                "the document declares {total_steps} steps in total: a document declares at most {MAX_TOTAL_STEPS}"
            )));
        }
        let mut steps = Vec::with_capacity(journey.steps.len());
        for (step_index, step) in journey.steps.into_iter().enumerate() {
            let step_failure = |error| FixtureError::StepFailed {
                journey_index,
                step_index,
                error: Box::new(error),
            };
            let validated_step = (|| -> Result<ValidatedStep, FixtureError> {
                if !valid_stable_id(&step.id) || !step_ids.insert(step.id.clone()) {
                    return Err(if valid_stable_id(&step.id) {
                        FixtureError::DuplicateIdentifier
                    } else {
                        FixtureError::LogicalReferenceRefused
                    });
                }
                let step_entity = (!step.entity.is_empty()).then_some(step.entity.as_str());
                let step_action = step.action.as_deref();
                if step_entity.is_some() == step_action.is_some() {
                    return Err(FixtureError::LogicalReferenceRefused);
                }
                validate_action_references(&step.request, &capture_sources, step_entity)?;
                let capture = step.capture.clone();
                if let Some(identifier) = capture.as_deref() {
                    if !valid_stable_id(identifier) || !capture_ids.insert(identifier.to_owned()) {
                        return Err(if valid_stable_id(identifier) {
                            FixtureError::DuplicateIdentifier
                        } else {
                            FixtureError::LogicalReferenceRefused
                        });
                    }
                }
                for identifier in step.capture_results.values() {
                    if !valid_stable_id(identifier) || !capture_ids.insert(identifier.to_owned()) {
                        return Err(if valid_stable_id(identifier) {
                            FixtureError::DuplicateIdentifier
                        } else {
                            FixtureError::LogicalReferenceRefused
                        });
                    }
                }
                let operation = step.request.operation();
                let (
                    entity_id,
                    action_id,
                    route,
                    profile,
                    response_readable_fields,
                    action,
                    expect,
                    capture_result_entities,
                ) = if let Some(action_id) = step_action {
                    let action = registry
                        .actions()
                        .actions
                        .iter()
                        .find(|action| action.id == action_id)
                        .ok_or(FixtureError::LogicalReferenceRefused)?;
                    let route_kind = immediate_action_route_kind(&step.request)?;
                    let route = registry
                        .actions()
                        .routes
                        .iter()
                        .find(|route| {
                            route.action_id == action.id
                                && route.kind == route_kind
                                && route.operation == Operation::Invoke
                                && route.method == HttpMethod::Post
                                && route.access_profiles.contains(&step.access_profile)
                        })
                        .cloned()
                        .ok_or(FixtureError::LogicalReferenceRefused)?;
                    let grant = action
                        .grants
                        .iter()
                        .find(|grant| grant.profile_id == step.access_profile)
                        .ok_or(FixtureError::LogicalReferenceRefused)?;
                    let profile = action_profile_from_grant(grant);
                    validate_claims(&step.claims, &profile, step.expect.outcome)?;
                    validate_immediate_action_fields(&step.request, action, &capture_sources)?;
                    validate_expectation(
                        &step.expect,
                        operation,
                        &profile,
                        capture.is_some(),
                        !step.capture_results.is_empty(),
                    )?;
                    let capture_result_entities = validate_capture_results(
                        &step.request,
                        action,
                        grant,
                        &step.capture_results,
                    )?;
                    (
                        None,
                        Some(action.id.clone()),
                        FixtureRoute::Action(route),
                        profile,
                        BTreeSet::new(),
                        step.request,
                        step.expect,
                        capture_result_entities,
                    )
                } else {
                    let entity_id = step.entity.clone();
                    let entity = registry
                        .entities()
                        .get(&entity_id)
                        .ok_or(FixtureError::LogicalReferenceRefused)?;
                    let request = internalize_entity_action(&step.request, registry, entity)?;
                    let profile = entity
                        .access_profiles
                        .get(&step.access_profile)
                        .ok_or(FixtureError::LogicalReferenceRefused)?;
                    if !matches!(request, ActionSource::ReadPath { .. })
                        && !profile.operations.contains(&operation)
                    {
                        return Err(FixtureError::LogicalReferenceRefused);
                    }
                    let expected_route_id = request.route_id(&entity_id);
                    let route = registry
                        .routes()
                        .routes
                        .iter()
                        .find(|route| {
                            route.entity_id == entity_id
                                && route.id == expected_route_id
                                && route.operation == operation
                                && route.method == operation_method(operation)
                                && route.access_profiles.contains(&step.access_profile)
                        })
                        .cloned()
                        .ok_or(FixtureError::LogicalReferenceRefused)?;
                    validate_claims(&step.claims, profile, step.expect.outcome)?;
                    validate_action_fields(
                        &request,
                        registry,
                        entity,
                        profile,
                        step.expect.outcome,
                    )?;
                    let response_entity = match &request {
                        ActionSource::ReadPath { path, .. } => entity
                            .read_paths
                            .get(path)
                            .and_then(|read_path| registry.entities().get(&read_path.to))
                            .ok_or(FixtureError::LogicalReferenceRefused)?,
                        _ => entity,
                    };
                    let expect = internalize_expectation(&step.expect, response_entity)?;
                    validate_expectation(
                        &expect,
                        operation,
                        profile,
                        capture.is_some(),
                        !step.capture_results.is_empty(),
                    )?;
                    let response_readable_field_ids = match &request {
                        ActionSource::ReadPath { path, .. } => profile
                            .read_paths
                            .iter()
                            .find(|grant| grant.path == *path)
                            .map(|grant| grant.readable_fields.clone())
                            .ok_or(FixtureError::LogicalReferenceRefused)?,
                        _ => profile.readable_fields.clone(),
                    };
                    let response_readable_fields =
                        externalize_field_set(response_entity, &response_readable_field_ids)?;
                    let action = externalize_action(&request, registry, entity)?;
                    let expect = externalize_expectation(&expect, response_entity)?;
                    (
                        Some(entity_id),
                        None,
                        FixtureRoute::Entity(route),
                        profile.clone(),
                        response_readable_fields,
                        action,
                        expect,
                        BTreeMap::new(),
                    )
                };
                if let Some(identifier) = capture.as_deref() {
                    capture_sources.insert(
                        identifier.to_owned(),
                        CaptureSource {
                            entity: entity_id.clone(),
                            operation,
                            has_etag: !matches!(
                                action,
                                ActionSource::TargetConditions { .. } | ActionSource::Invoke { .. }
                            ),
                            condition_map: matches!(action, ActionSource::TargetConditions { .. }),
                        },
                    );
                }
                for (identifier, entity) in capture_result_entities {
                    capture_sources.insert(
                        identifier.to_owned(),
                        CaptureSource {
                            entity: Some(entity),
                            operation: Operation::Invoke,
                            has_etag: false,
                            condition_map: false,
                        },
                    );
                }
                Ok(ValidatedStep {
                    id: step.id,
                    entity: entity_id,
                    action_id,
                    access_profile: step.access_profile,
                    claims: step.claims,
                    route,
                    profile: profile.clone(),
                    response_readable_fields,
                    action,
                    expect,
                    capture,
                    capture_results: step.capture_results,
                })
            })()
            .map_err(step_failure)?;
            steps.push(validated_step);
        }
        journeys.push(ValidatedJourney {
            id: journey.id,
            steps,
        });
    }
    Ok(ValidatedFixtureJourneys {
        registry_revision: registry.revision().to_owned(),
        file_sha256: sha256(bytes),
        file_bytes: bytes.to_vec(),
        journeys,
    })
}

fn validate_action_references(
    action: &ActionSource,
    captures: &BTreeMap<String, CaptureSource>,
    step_entity: Option<&str>,
) -> Result<(), FixtureError> {
    let references: &[&str] = match action {
        ActionSource::Get { record_ref } => &[record_ref],
        ActionSource::ReadPath { record_ref, .. } => &[record_ref],
        ActionSource::Patch {
            record_ref,
            etag_ref,
            ..
        } => &[record_ref, etag_ref],
        ActionSource::SubmitRequest {
            record_ref,
            etag_ref,
        }
        | ActionSource::ReviseRequest {
            record_ref,
            etag_ref,
            ..
        }
        | ActionSource::CancelRequest {
            record_ref,
            etag_ref,
        }
        | ActionSource::ApplyRequest {
            record_ref,
            etag_ref,
            ..
        } => &[record_ref, etag_ref],
        ActionSource::ApproveRequest {
            record_ref,
            etag_ref,
            ..
        }
        | ActionSource::RejectRequest {
            record_ref,
            etag_ref,
            ..
        }
        | ActionSource::RequestRevision {
            record_ref,
            etag_ref,
            ..
        } => &[record_ref, etag_ref],
        ActionSource::Create { .. }
        | ActionSource::List { .. }
        | ActionSource::Query { .. }
        | ActionSource::Lookup { .. }
        | ActionSource::Batch { .. }
        | ActionSource::TargetConditions { .. }
        | ActionSource::Invoke { .. } => &[],
    };
    if references
        .iter()
        .any(|identifier| !valid_stable_id(identifier) || !captures.contains_key(*identifier))
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    for reference in etag_references(action) {
        let Some(source) = captures.get(reference) else {
            return Err(FixtureError::LogicalReferenceRefused);
        };
        if !source.has_etag {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    }
    let mut value_record_refs = Vec::new();
    collect_action_value_record_refs(action, &mut value_record_refs)?;
    if value_record_refs
        .iter()
        .any(|identifier| !valid_stable_id(identifier) || !captures.contains_key(*identifier))
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    if is_request_action(action.operation()) {
        let step_entity = step_entity.ok_or(FixtureError::LogicalReferenceRefused)?;
        for reference in references {
            let source = captures
                .get(*reference)
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            if source.entity.as_deref() != Some(step_entity) || source.operation != Operation::Get {
                return Err(FixtureError::LogicalReferenceRefused);
            }
        }
    }
    if let ActionSource::Invoke { preconditions, .. } = action {
        for condition in preconditions.values() {
            let Some(reference) = condition.condition_ref.as_deref() else {
                continue;
            };
            let Some(source) = captures.get(reference) else {
                return Err(FixtureError::LogicalReferenceRefused);
            };
            if !valid_stable_id(reference) || !source.condition_map {
                return Err(FixtureError::LogicalReferenceRefused);
            }
        }
    }
    for reference in request_action_proposal_refs(action) {
        let Some(source) = captures.get(reference) else {
            return Err(FixtureError::LogicalReferenceRefused);
        };
        if !valid_stable_id(reference) {
            return Err(FixtureError::LogicalReferenceRefused);
        }
        if source.entity.as_deref() != step_entity || source.operation != Operation::Get {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    }
    Ok(())
}

fn etag_references(action: &ActionSource) -> Vec<&str> {
    match action {
        ActionSource::Patch { etag_ref, .. }
        | ActionSource::SubmitRequest { etag_ref, .. }
        | ActionSource::ReviseRequest { etag_ref, .. }
        | ActionSource::CancelRequest { etag_ref, .. }
        | ActionSource::ApplyRequest { etag_ref, .. }
        | ActionSource::ApproveRequest { etag_ref, .. }
        | ActionSource::RejectRequest { etag_ref, .. }
        | ActionSource::RequestRevision { etag_ref, .. } => vec![etag_ref],
        _ => Vec::new(),
    }
}

fn collect_action_value_record_refs<'a>(
    action: &'a ActionSource,
    references: &mut Vec<&'a str>,
) -> Result<(), FixtureError> {
    match action {
        ActionSource::Create { data } | ActionSource::Lookup { values: data, .. } => {
            collect_map_value_record_refs(data, references)
        }
        ActionSource::Patch { changes, .. } => {
            for change in changes {
                collect_value_record_refs(&change.value, references)?;
            }
            Ok(())
        }
        ActionSource::Batch { items } => {
            for item in items {
                match item {
                    BatchItemSource::Create { data } => {
                        collect_map_value_record_refs(data, references)?;
                    }
                }
            }
            Ok(())
        }
        ActionSource::TargetConditions { input } | ActionSource::Invoke { input, .. } => {
            collect_map_value_record_refs(input, references)
        }
        ActionSource::Get { .. }
        | ActionSource::List { .. }
        | ActionSource::Query { .. }
        | ActionSource::ReadPath { .. }
        | ActionSource::SubmitRequest { .. }
        | ActionSource::ApproveRequest { .. }
        | ActionSource::RejectRequest { .. }
        | ActionSource::RequestRevision { .. }
        | ActionSource::ReviseRequest { .. }
        | ActionSource::CancelRequest { .. }
        | ActionSource::ApplyRequest { .. } => Ok(()),
    }
}

fn collect_map_value_record_refs<'a>(
    values: &'a Map<String, Value>,
    references: &mut Vec<&'a str>,
) -> Result<(), FixtureError> {
    for value in values.values() {
        collect_value_record_refs(value, references)?;
    }
    Ok(())
}

fn collect_value_record_refs<'a>(
    value: &'a Value,
    references: &mut Vec<&'a str>,
) -> Result<(), FixtureError> {
    match value {
        Value::Object(object) => {
            if let Some(record_ref) = object.get("recordRef") {
                if object.len() != 1 {
                    return Err(FixtureError::LogicalReferenceRefused);
                }
                references.push(
                    record_ref
                        .as_str()
                        .ok_or(FixtureError::LogicalReferenceRefused)?,
                );
                Ok(())
            } else {
                for nested in object.values() {
                    collect_value_record_refs(nested, references)?;
                }
                Ok(())
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_value_record_refs(item, references)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn request_action_proposal_refs(action: &ActionSource) -> Vec<&str> {
    match action {
        ActionSource::ApproveRequest {
            proposal_version_ref,
            effect_digest_ref,
            ..
        }
        | ActionSource::RejectRequest {
            proposal_version_ref,
            effect_digest_ref,
            ..
        }
        | ActionSource::RequestRevision {
            proposal_version_ref,
            effect_digest_ref,
            ..
        }
        | ActionSource::ApplyRequest {
            proposal_version_ref,
            effect_digest_ref,
            ..
        } => proposal_version_ref
            .iter()
            .chain(effect_digest_ref.iter())
            .map(String::as_str)
            .collect(),
        _ => Vec::new(),
    }
}

fn validate_claims(
    claims: &ClaimsSource,
    profile: &AccessProfileSource,
    outcome: ExpectedOutcome,
) -> Result<(), FixtureError> {
    if profile.anonymous {
        if claims.principal.is_some()
            || !claims.scopes.is_empty()
            || claims.purpose.is_some()
            || !claims.direct_claims.is_empty()
        {
            return Err(FixtureError::AuthorityWideningRefused);
        }
        return Ok(());
    }
    if profile.principal_claim.is_none()
        || claims
            .principal
            .as_deref()
            .is_none_or(|value| value.is_empty() || value.len() > MAX_BINDING_BYTES)
        || !claims.scopes.is_subset(&profile.required_scopes)
    {
        return Err(FixtureError::AuthorityWideningRefused);
    }
    let boundary_claims = profile
        .row_boundaries
        .iter()
        .map(|boundary| boundary.claim.as_str())
        .collect::<BTreeSet<_>>();
    if claims.direct_claims.iter().any(|(name, value)| {
        !boundary_claims.contains(name.as_str())
            || value.is_empty()
            || value.len() > MAX_BINDING_BYTES
    }) {
        return Err(FixtureError::AuthorityWideningRefused);
    }
    if let Some(purpose) = claims.purpose.as_deref() {
        if purpose.len() > MAX_BINDING_BYTES || !profile.required_purposes.contains(purpose) {
            return Err(FixtureError::AuthorityWideningRefused);
        }
    }
    if outcome == ExpectedOutcome::Success
        && (claims.principal.is_none()
            || claims.scopes != profile.required_scopes
            || (!profile.required_purposes.is_empty() && claims.purpose.is_none())
            || boundary_claims
                .iter()
                .any(|name| !claims.direct_claims.contains_key(*name)))
    {
        return Err(FixtureError::AuthorityWideningRefused);
    }
    Ok(())
}

fn immediate_action_route_kind(action: &ActionSource) -> Result<ActionRouteKind, FixtureError> {
    match action {
        ActionSource::Invoke { .. } => Ok(ActionRouteKind::Invoke),
        ActionSource::TargetConditions { .. } => Ok(ActionRouteKind::TargetConditions),
        _ => Err(FixtureError::LogicalReferenceRefused),
    }
}

fn action_profile_from_grant(grant: &CompiledActionGrant) -> AccessProfileSource {
    AccessProfileSource {
        id: grant.profile_id.clone(),
        default: grant.default,
        anonymous: grant.anonymous,
        principal_claim: grant.principal_claim.clone(),
        required_scopes: grant.required_scopes.clone(),
        required_purposes: grant.required_purposes.clone(),
        operations: grant.operations.clone(),
        readable_fields: BTreeSet::new(),
        writable_fields: BTreeSet::new(),
        filterable_fields: BTreeSet::new(),
        sortable_fields: BTreeSet::new(),
        spatial_queries: None,
        row_boundaries: grant
            .targets
            .iter()
            .flat_map(|target| target.row_boundaries.iter().cloned())
            .collect(),
        lookups: Vec::new(),
        read_paths: Vec::new(),
        review_stages: Vec::new(),
        apply_targets: Vec::new(),
        request_presence: Vec::new(),
        allow_count: false,
        revision_access: false,
        provenance_fields: Vec::new(),
        allow_data_export: false,
    }
}

fn validate_immediate_action_fields(
    request: &ActionSource,
    action: &CompiledAction,
    captures: &BTreeMap<String, CaptureSource>,
) -> Result<(), FixtureError> {
    match request {
        ActionSource::TargetConditions { input } => {
            let required = condition_input_api_names(action);
            validate_action_input_map(input, action, captures, Some(&required))?;
            if input.keys().collect::<BTreeSet<_>>() != required.iter().collect::<BTreeSet<_>>() {
                return Err(FixtureError::LogicalReferenceRefused);
            }
        }
        ActionSource::Invoke {
            input,
            preconditions,
            idempotency_key,
        } => {
            validate_action_input_map(input, action, captures, None)?;
            let condition_inputs = condition_input_api_names(action);
            for (name, condition) in preconditions {
                if !condition_inputs.contains(name) {
                    return Err(FixtureError::LogicalReferenceRefused);
                }
                if condition.if_match.is_some() == condition.condition_ref.is_some() {
                    return Err(FixtureError::LogicalReferenceRefused);
                }
                if let Some(tag) = condition.if_match.as_deref() {
                    validate_action_if_match(tag)?;
                }
                if let Some(reference) = condition.condition_ref.as_deref() {
                    if !valid_stable_id(reference) {
                        return Err(FixtureError::LogicalReferenceRefused);
                    }
                }
            }
            if condition_inputs
                .iter()
                .any(|name| !preconditions.contains_key(name.as_str()))
            {
                return Err(FixtureError::LogicalReferenceRefused);
            }
            if let Some(key) = idempotency_key {
                validate_idempotency_key_source(key)?;
            }
        }
        _ => return Err(FixtureError::LogicalReferenceRefused),
    }
    Ok(())
}

fn validate_action_input_map(
    input: &Map<String, Value>,
    action: &CompiledAction,
    captures: &BTreeMap<String, CaptureSource>,
    accepted_names: Option<&BTreeSet<String>>,
) -> Result<(), FixtureError> {
    let inputs_by_api_name = action
        .inputs
        .iter()
        .map(|input| (input.api_name.as_str(), input))
        .collect::<BTreeMap<_, _>>();
    for (name, value) in input {
        if name.len() > MAX_IDENTIFIER_BYTES {
            return Err(FixtureError::LogicalReferenceRefused);
        }
        if accepted_names.is_some_and(|accepted| !accepted.contains(name)) {
            return Err(FixtureError::LogicalReferenceRefused);
        }
        let declared = inputs_by_api_name
            .get(name.as_str())
            .ok_or(FixtureError::LogicalReferenceRefused)?;
        if !fixture_action_input_value_is_valid(value, declared, captures) {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    }
    for declared in &action.inputs {
        if declared.required
            && accepted_names.is_none_or(|accepted| accepted.contains(&declared.api_name))
            && !input.contains_key(&declared.api_name)
        {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    }
    if canonical_size(&Value::Object(input.clone()))? > MAX_BODY_BYTES {
        return Err(FixtureError::JourneyTooLarge);
    }
    Ok(())
}

fn fixture_action_input_value_is_valid(
    value: &Value,
    declared: &crate::model::CompiledActionInput,
    captures: &BTreeMap<String, CaptureSource>,
) -> bool {
    if let crate::contract::FieldTypeSource::Reference { target, .. } = &declared.field_type {
        if let Some(reference) = value.as_object().and_then(|object| {
            (object.len() == 1)
                .then(|| object.get("recordRef"))
                .flatten()
                .and_then(Value::as_str)
        }) {
            return captures
                .get(reference)
                .is_some_and(|source| source.entity.as_deref() == Some(target.as_str()));
        }
    }
    validate_field_value(FieldValue::Json(value), &declared.field_type)
}

fn condition_input_api_names(action: &CompiledAction) -> BTreeSet<String> {
    let logical_ids = action
        .effects
        .iter()
        .filter_map(|effect| match &effect.target.binding {
            crate::model::CompiledActionTargetBinding::Existing { input } => Some(input.as_str()),
            crate::model::CompiledActionTargetBinding::Create => None,
        })
        .collect::<BTreeSet<_>>();
    action
        .inputs
        .iter()
        .filter(|input| logical_ids.contains(input.id.as_str()))
        .map(|input| input.api_name.clone())
        .collect()
}

fn validate_capture_results(
    request: &ActionSource,
    action: &CompiledAction,
    grant: &CompiledActionGrant,
    capture_results: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, FixtureError> {
    let mut captures = BTreeMap::new();
    if capture_results.is_empty() {
        return Ok(captures);
    }
    if !matches!(request, ActionSource::Invoke { .. }) {
        return Err(FixtureError::JourneyShapeRefused);
    }
    for (effect, capture) in capture_results {
        if !grant.results.contains(effect) {
            return Err(FixtureError::LogicalReferenceRefused);
        }
        let target_entity_id = action
            .effects
            .iter()
            .find(|compiled| compiled.id == *effect)
            .map(|compiled| compiled.target.entity_id.clone())
            .ok_or(FixtureError::LogicalReferenceRefused)?;
        captures.insert(capture.clone(), target_entity_id);
    }
    Ok(captures)
}

fn validate_action_if_match(value: &str) -> Result<(), FixtureError> {
    if !value.is_empty()
        && value.len() <= MAX_BINDING_BYTES
        && value.starts_with("\"rs-")
        && value.ends_with('"')
    {
        Ok(())
    } else {
        Err(FixtureError::LogicalReferenceRefused)
    }
}

fn validate_idempotency_key_source(value: &str) -> Result<(), FixtureError> {
    if valid_stable_id(value) {
        Ok(())
    } else {
        Err(FixtureError::LogicalReferenceRefused)
    }
}

fn validate_action_fields(
    action: &ActionSource,
    registry: &CompiledRegistry,
    entity: &crate::model::CompiledEntity,
    profile: &AccessProfileSource,
    outcome: ExpectedOutcome,
) -> Result<(), FixtureError> {
    let validate_data = |data: &Map<String, Value>| {
        if data.is_empty()
            || data.keys().any(|field| {
                !entity.fields.contains_key(field) || !profile.writable_fields.contains(field)
            })
            || canonical_size(&Value::Object(data.clone()))? > MAX_BODY_BYTES
        {
            return Err(FixtureError::LogicalReferenceRefused);
        }
        Ok(())
    };
    match action {
        ActionSource::Create { data } => validate_data(data),
        ActionSource::Get { .. } | ActionSource::List { .. } => Ok(()),
        ActionSource::Query { .. } | ActionSource::ReadPath { .. } => {
            validate_structured_query(registry, entity, profile, action, outcome)
        }
        ActionSource::Lookup { selector, values } => {
            let selector_profile = entity
                .selector_profiles
                .get(selector)
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            let lookup = profile
                .lookups
                .iter()
                .find(|lookup| lookup.selector == *selector)
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            let exact_fields = selector_profile.fields.iter().collect::<BTreeSet<_>>();
            let supplied_fields = values.keys().collect::<BTreeSet<_>>();
            let origin_shape_is_valid = match lookup.value_origin {
                LookupValueOrigin::Request => supplied_fields == exact_fields,
                LookupValueOrigin::VerifiedClaim => values.is_empty(),
            };
            if selector.is_empty()
                || selector.len() > MAX_IDENTIFIER_BYTES
                || !origin_shape_is_valid
                || canonical_size(&Value::Object(values.clone()))? > MAX_BODY_BYTES
            {
                return Err(FixtureError::LogicalReferenceRefused);
            }
            Ok(())
        }
        ActionSource::Patch { changes, .. } => {
            if changes.is_empty() || changes.len() > entity.fields.len() {
                return Err(FixtureError::JourneyBoundsRefused);
            }
            let mut fields = BTreeSet::new();
            for change in changes {
                if !fields.insert(change.field.as_str())
                    || !entity.fields.contains_key(&change.field)
                    || !profile.writable_fields.contains(&change.field)
                {
                    return Err(FixtureError::LogicalReferenceRefused);
                }
            }
            let document = Value::Array(
                changes
                    .iter()
                    .map(|change| {
                        json!({"op":"replace","path":format!("/data/{}", change.field),"value":change.value})
                    })
                    .collect(),
            );
            if canonical_size(&document)? > MAX_BODY_BYTES {
                return Err(FixtureError::JourneyTooLarge);
            }
            Ok(())
        }
        ActionSource::Batch { items } => {
            let maximum_items = entity
                .batch
                .as_ref()
                .map(|batch| usize::from(batch.maximum_items))
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            if items.is_empty() || items.len() > maximum_items {
                return Err(FixtureError::JourneyBoundsRefused);
            }
            for item in items {
                match item {
                    BatchItemSource::Create { data } => validate_data(data)?,
                }
            }
            let body_bytes = canonical_size(&batch_body(items))?;
            let compiled_maximum = usize::try_from(
                entity
                    .batch
                    .as_ref()
                    .expect("batch inventory was checked")
                    .maximum_bytes,
            )
            .map_err(|_| FixtureError::JourneyBoundsRefused)?;
            if body_bytes > MAX_BODY_BYTES || body_bytes > compiled_maximum {
                return Err(FixtureError::JourneyTooLarge);
            }
            Ok(())
        }
        ActionSource::SubmitRequest { .. }
        | ActionSource::ReviseRequest { .. }
        | ActionSource::CancelRequest { .. } => {
            validate_request_action_plan(action, entity)?;
            if canonical_size(&request_action_body(action, &BTreeMap::new())?)? > MAX_BODY_BYTES {
                return Err(FixtureError::JourneyTooLarge);
            }
            Ok(())
        }
        ActionSource::ApproveRequest { .. }
        | ActionSource::RejectRequest { .. }
        | ActionSource::RequestRevision { .. }
        | ActionSource::ApplyRequest { .. } => {
            validate_request_action_plan(action, entity)?;
            validate_request_action_proposal_binding(action)?;
            Ok(())
        }
        ActionSource::TargetConditions { .. } | ActionSource::Invoke { .. } => {
            Err(FixtureError::LogicalReferenceRefused)
        }
    }
}

fn validate_request_action_plan(
    action: &ActionSource,
    entity: &crate::model::CompiledEntity,
) -> Result<(), FixtureError> {
    let request = entity
        .change_request
        .as_ref()
        .ok_or(FixtureError::LogicalReferenceRefused)?;
    let operation = action.operation();
    let stage = request_action_stage(action)?;
    if request.actions.iter().any(|candidate| {
        candidate.operation.access_operation() == operation
            && candidate.review_stage.as_deref() == stage
    }) {
        Ok(())
    } else {
        Err(FixtureError::LogicalReferenceRefused)
    }
}

fn request_action_stage(action: &ActionSource) -> Result<Option<&str>, FixtureError> {
    match action {
        ActionSource::ApproveRequest { stage, .. }
        | ActionSource::RejectRequest { stage, .. }
        | ActionSource::RequestRevision { stage, .. } => {
            if valid_stable_id(stage) {
                Ok(Some(stage.as_str()))
            } else {
                Err(FixtureError::LogicalReferenceRefused)
            }
        }
        _ => Ok(None),
    }
}

fn validate_request_action_proposal_binding(action: &ActionSource) -> Result<(), FixtureError> {
    let binding = request_action_binding(action)?;
    if binding.proposal_version.is_some() == binding.proposal_version_ref.is_some()
        || binding.effect_digest.is_some() == binding.effect_digest_ref.is_some()
        || binding.proposal_version == Some(0)
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    if let Some(digest) = binding.effect_digest {
        validate_digest(digest)?;
    }
    Ok(())
}

struct RequestActionBinding<'a> {
    proposal_version: Option<u32>,
    proposal_version_ref: Option<&'a str>,
    effect_digest: Option<&'a str>,
    effect_digest_ref: Option<&'a str>,
}

fn request_action_binding(action: &ActionSource) -> Result<RequestActionBinding<'_>, FixtureError> {
    match action {
        ActionSource::ApproveRequest {
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
            ..
        }
        | ActionSource::RejectRequest {
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
            ..
        }
        | ActionSource::RequestRevision {
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
            ..
        }
        | ActionSource::ApplyRequest {
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
            ..
        } => Ok(RequestActionBinding {
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.as_deref(),
            effect_digest: effect_digest.as_deref(),
            effect_digest_ref: effect_digest_ref.as_deref(),
        }),
        _ => Err(FixtureError::LogicalReferenceRefused),
    }
}

fn validate_digest(value: &str) -> Result<(), FixtureError> {
    if value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[7..].bytes().all(|byte| !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(FixtureError::LogicalReferenceRefused)
    }
}

fn validate_structured_query(
    registry: &CompiledRegistry,
    entity: &crate::model::CompiledEntity,
    profile: &AccessProfileSource,
    action: &ActionSource,
    outcome: ExpectedOutcome,
) -> Result<(), FixtureError> {
    let (read_path, select, top, count, bbox) = match action {
        ActionSource::Query {
            select,
            top,
            count,
            bbox,
        } => (None, select, *top, *count, bbox.as_ref()),
        ActionSource::ReadPath {
            path,
            select,
            top,
            count,
            ..
        } => (Some(path.as_str()), select, *top, *count, None),
        _ => return Err(FixtureError::LogicalReferenceRefused),
    };
    if top.is_some_and(|top| top == 0 || top > 100) {
        return Err(FixtureError::JourneyBoundsRefused);
    }
    let parsed_bbox = bbox.map(parse_fixture_bbox).transpose()?;
    if let Some(path) = read_path {
        if bbox.is_some() {
            return Err(FixtureError::LogicalReferenceRefused);
        }
        let compiled_path = entity
            .read_paths
            .get(path)
            .ok_or(FixtureError::LogicalReferenceRefused)?;
        let grant = profile
            .read_paths
            .iter()
            .find(|grant| grant.path == path)
            .ok_or(FixtureError::LogicalReferenceRefused)?;
        let target = registry
            .entities()
            .get(&compiled_path.to)
            .ok_or(FixtureError::LogicalReferenceRefused)?;
        if path.is_empty()
            || path.len() > MAX_IDENTIFIER_BYTES
            || (count && !grant.allow_count)
            || !select.is_subset(&grant.readable_fields)
            || select
                .iter()
                .any(|field| !compiled_field_exists(target, field))
        {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    } else if (count && !profile.allow_count)
        || select.iter().any(|field| {
            field != "id"
                && field != "revision"
                && (!profile.readable_fields.contains(field)
                    || !compiled_field_exists(entity, field))
        })
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    if let Some(bbox) = parsed_bbox.as_ref() {
        validate_query_bbox(registry, entity, profile, bbox, outcome)?;
    }
    Ok(())
}

fn parse_fixture_bbox(source: &BboxSource) -> Result<crate::query::BboxClause, FixtureError> {
    let value = source.query_value();
    let parsed = crate::query::parse_read_query([("bbox", value.as_str())])
        .map_err(|_| FixtureError::LogicalReferenceRefused)?;
    let crate::query::ParsedReadQueryMode::Query(options) = parsed.mode else {
        return Err(FixtureError::LogicalReferenceRefused);
    };
    options.bbox.ok_or(FixtureError::LogicalReferenceRefused)
}

fn validate_query_bbox(
    registry: &CompiledRegistry,
    entity: &crate::model::CompiledEntity,
    profile: &AccessProfileSource,
    bbox: &crate::query::BboxClause,
    outcome: ExpectedOutcome,
) -> Result<(), FixtureError> {
    let operation = compiled_query_operation(registry, &entity.id, &profile.id)?;
    let Some(capability) = operation
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
    else {
        return if outcome == ExpectedOutcome::Refusal {
            Ok(())
        } else {
            Err(FixtureError::LogicalReferenceRefused)
        };
    };
    if operation.kind != CompiledQueryKind::List
        || operation.read_path.is_some()
        || !profile.readable_fields.contains(&capability.geometry_field)
        || entity
            .geojson
            .as_ref()
            .is_none_or(|geojson| geojson.geometry_field != capability.geometry_field)
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    let maximum_longitude_span = capability
        .maximum_longitude_span_degrees
        .as_f64()
        .filter(|value| value.is_finite() && *value > 0.0 && *value <= 360.0)
        .ok_or(FixtureError::LogicalReferenceRefused)?;
    let maximum_latitude_span = capability
        .maximum_latitude_span_degrees
        .as_f64()
        .filter(|value| value.is_finite() && *value > 0.0 && *value <= 180.0)
        .ok_or(FixtureError::LogicalReferenceRefused)?;
    if bbox
        .longitude_span()
        .map_err(|_| FixtureError::LogicalReferenceRefused)?
        > maximum_longitude_span
        || bbox
            .latitude_span()
            .map_err(|_| FixtureError::LogicalReferenceRefused)?
            > maximum_latitude_span
    {
        return if outcome == ExpectedOutcome::Refusal {
            Ok(())
        } else {
            Err(FixtureError::LogicalReferenceRefused)
        };
    }
    Ok(())
}

fn compiled_query_operation<'a>(
    registry: &'a CompiledRegistry,
    entity_id: &str,
    profile_id: &str,
) -> Result<&'a CompiledQueryOperation, FixtureError> {
    registry
        .queries()
        .operations
        .iter()
        .find(|operation| {
            operation.entity_id == entity_id
                && operation.profile_id == profile_id
                && operation.kind == CompiledQueryKind::List
                && operation.read_path.is_none()
        })
        .ok_or(FixtureError::LogicalReferenceRefused)
}

fn compiled_field_exists(entity: &crate::model::CompiledEntity, field: &str) -> bool {
    entity.fields.contains_key(field) || entity.derived_fields.contains_key(field)
}

fn source_field_id(
    entity: &crate::model::CompiledEntity,
    field_name: &str,
) -> Result<String, FixtureError> {
    if field_name == "id" || field_name == "revision" || compiled_field_exists(entity, field_name) {
        return Ok(field_name.to_owned());
    }
    entity
        .stored_fields
        .iter()
        .map(|field| &field.logical)
        .chain(entity.derived_fields.values().map(|field| &field.logical))
        .find(|field| field.api_name == field_name)
        .map(|field| field.id.clone())
        .ok_or(FixtureError::LogicalReferenceRefused)
}

fn internalize_field_set(
    entity: &crate::model::CompiledEntity,
    fields: &BTreeSet<String>,
) -> Result<BTreeSet<String>, FixtureError> {
    let mut normalized = BTreeSet::new();
    for field in fields {
        if !normalized.insert(source_field_id(entity, field)?) {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    }
    Ok(normalized)
}

fn internalize_data(
    entity: &crate::model::CompiledEntity,
    data: &Map<String, Value>,
) -> Result<Map<String, Value>, FixtureError> {
    let mut normalized = Map::new();
    for (field, value) in data {
        let field = source_field_id(entity, field)?;
        if normalized.insert(field, value.clone()).is_some() {
            return Err(FixtureError::LogicalReferenceRefused);
        }
    }
    Ok(normalized)
}

fn internalize_entity_action(
    action: &ActionSource,
    registry: &CompiledRegistry,
    entity: &crate::model::CompiledEntity,
) -> Result<ActionSource, FixtureError> {
    Ok(match action {
        ActionSource::Create { data } => ActionSource::Create {
            data: internalize_data(entity, data)?,
        },
        ActionSource::Get { record_ref } => ActionSource::Get {
            record_ref: record_ref.clone(),
        },
        ActionSource::List { .. } => ActionSource::List {},
        ActionSource::Query {
            select,
            top,
            count,
            bbox,
        } => ActionSource::Query {
            select: internalize_field_set(entity, select)?,
            top: *top,
            count: *count,
            bbox: bbox.clone(),
        },
        ActionSource::Lookup { selector, values } => ActionSource::Lookup {
            selector: selector.clone(),
            values: internalize_data(entity, values)?,
        },
        ActionSource::ReadPath {
            path,
            record_ref,
            select,
            top,
            count,
        } => {
            let target = entity
                .read_paths
                .get(path)
                .and_then(|read_path| registry.entities().get(&read_path.to))
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            ActionSource::ReadPath {
                path: path.clone(),
                record_ref: record_ref.clone(),
                select: internalize_field_set(target, select)?,
                top: *top,
                count: *count,
            }
        }
        ActionSource::Patch {
            record_ref,
            etag_ref,
            changes,
        } => ActionSource::Patch {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            changes: changes
                .iter()
                .map(|change| {
                    source_field_id(entity, &change.field).map(|field| FieldChangeSource {
                        field,
                        value: change.value.clone(),
                    })
                })
                .collect::<Result<Vec<_>, FixtureError>>()?,
        },
        ActionSource::Batch { items } => ActionSource::Batch {
            items: items
                .iter()
                .map(|item| match item {
                    BatchItemSource::Create { data } => {
                        internalize_data(entity, data).map(|data| BatchItemSource::Create { data })
                    }
                })
                .collect::<Result<Vec<_>, FixtureError>>()?,
        },
        ActionSource::SubmitRequest {
            record_ref,
            etag_ref,
        } => ActionSource::SubmitRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
        },
        ActionSource::ApproveRequest {
            stage,
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::ApproveRequest {
            stage: stage.clone(),
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
        ActionSource::RejectRequest {
            stage,
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::RejectRequest {
            stage: stage.clone(),
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
        ActionSource::RequestRevision {
            stage,
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::RequestRevision {
            stage: stage.clone(),
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
        ActionSource::ReviseRequest {
            record_ref,
            etag_ref,
            rebase,
        } => ActionSource::ReviseRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            rebase: *rebase,
        },
        ActionSource::CancelRequest {
            record_ref,
            etag_ref,
        } => ActionSource::CancelRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
        },
        ActionSource::ApplyRequest {
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::ApplyRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
        ActionSource::TargetConditions { .. } | ActionSource::Invoke { .. } => {
            return Err(FixtureError::LogicalReferenceRefused)
        }
    })
}

fn internalize_expectation(
    expectation: &ExpectationSource,
    response_entity: &crate::model::CompiledEntity,
) -> Result<ExpectationSource, FixtureError> {
    Ok(ExpectationSource {
        outcome: expectation.outcome,
        status: expectation.status,
        fields: internalize_data(response_entity, &expectation.fields)?,
        count: expectation.count,
        problem_code: expectation.problem_code.clone(),
    })
}

fn field_api_name<'a>(entity: &'a crate::model::CompiledEntity, field_id: &str) -> Option<&'a str> {
    if field_id == "id" {
        return Some("id");
    }
    if field_id == "revision" {
        return Some("revision");
    }
    entity
        .stored_fields
        .iter()
        .map(|field| &field.logical)
        .chain(entity.derived_fields.values().map(|field| &field.logical))
        .find(|field| field.id == field_id)
        .map(|field| field.api_name.as_str())
}

fn externalize_field_set(
    entity: &crate::model::CompiledEntity,
    fields: &BTreeSet<String>,
) -> Result<BTreeSet<String>, FixtureError> {
    fields
        .iter()
        .map(|field| {
            field_api_name(entity, field)
                .map(str::to_owned)
                .ok_or(FixtureError::LogicalReferenceRefused)
        })
        .collect()
}

fn externalize_data(
    entity: &crate::model::CompiledEntity,
    data: &Map<String, Value>,
) -> Result<Map<String, Value>, FixtureError> {
    data.iter()
        .map(|(field, value)| {
            field_api_name(entity, field)
                .map(|api_name| (api_name.to_owned(), value.clone()))
                .ok_or(FixtureError::LogicalReferenceRefused)
        })
        .collect()
}

fn externalize_action(
    action: &ActionSource,
    registry: &CompiledRegistry,
    entity: &crate::model::CompiledEntity,
) -> Result<ActionSource, FixtureError> {
    Ok(match action {
        ActionSource::Create { data } => ActionSource::Create {
            data: externalize_data(entity, data)?,
        },
        ActionSource::Get { record_ref } => ActionSource::Get {
            record_ref: record_ref.clone(),
        },
        ActionSource::List { .. } => ActionSource::List {},
        ActionSource::Query {
            select,
            top,
            count,
            bbox,
        } => ActionSource::Query {
            select: externalize_field_set(entity, select)?,
            top: *top,
            count: *count,
            bbox: bbox.clone(),
        },
        ActionSource::Lookup { selector, values } => ActionSource::Lookup {
            selector: selector.clone(),
            values: externalize_data(entity, values)?,
        },
        ActionSource::ReadPath {
            path,
            record_ref,
            select,
            top,
            count,
        } => {
            let target = entity
                .read_paths
                .get(path)
                .and_then(|read_path| registry.entities().get(&read_path.to))
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            ActionSource::ReadPath {
                path: path.clone(),
                record_ref: record_ref.clone(),
                select: externalize_field_set(target, select)?,
                top: *top,
                count: *count,
            }
        }
        ActionSource::Patch {
            record_ref,
            etag_ref,
            changes,
        } => ActionSource::Patch {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            changes: changes
                .iter()
                .map(|change| {
                    Ok(FieldChangeSource {
                        field: field_api_name(entity, &change.field)
                            .ok_or(FixtureError::LogicalReferenceRefused)?
                            .to_owned(),
                        value: change.value.clone(),
                    })
                })
                .collect::<Result<Vec<_>, FixtureError>>()?,
        },
        ActionSource::Batch { items } => ActionSource::Batch {
            items: items
                .iter()
                .map(|item| match item {
                    BatchItemSource::Create { data } => {
                        externalize_data(entity, data).map(|data| BatchItemSource::Create { data })
                    }
                })
                .collect::<Result<Vec<_>, FixtureError>>()?,
        },
        ActionSource::TargetConditions { input } => ActionSource::TargetConditions {
            input: input.clone(),
        },
        ActionSource::Invoke {
            input,
            preconditions,
            idempotency_key,
        } => ActionSource::Invoke {
            input: input.clone(),
            preconditions: preconditions.clone(),
            idempotency_key: idempotency_key.clone(),
        },
        ActionSource::SubmitRequest {
            record_ref,
            etag_ref,
        } => ActionSource::SubmitRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
        },
        ActionSource::ApproveRequest {
            stage,
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::ApproveRequest {
            stage: stage.clone(),
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
        ActionSource::RejectRequest {
            stage,
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::RejectRequest {
            stage: stage.clone(),
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
        ActionSource::RequestRevision {
            stage,
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::RequestRevision {
            stage: stage.clone(),
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
        ActionSource::ReviseRequest {
            record_ref,
            etag_ref,
            rebase,
        } => ActionSource::ReviseRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            rebase: *rebase,
        },
        ActionSource::CancelRequest {
            record_ref,
            etag_ref,
        } => ActionSource::CancelRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
        },
        ActionSource::ApplyRequest {
            record_ref,
            etag_ref,
            proposal_version,
            proposal_version_ref,
            effect_digest,
            effect_digest_ref,
        } => ActionSource::ApplyRequest {
            record_ref: record_ref.clone(),
            etag_ref: etag_ref.clone(),
            proposal_version: *proposal_version,
            proposal_version_ref: proposal_version_ref.clone(),
            effect_digest: effect_digest.clone(),
            effect_digest_ref: effect_digest_ref.clone(),
        },
    })
}

fn externalize_expectation(
    expectation: &ExpectationSource,
    response_entity: &crate::model::CompiledEntity,
) -> Result<ExpectationSource, FixtureError> {
    Ok(ExpectationSource {
        outcome: expectation.outcome,
        status: expectation.status,
        fields: externalize_data(response_entity, &expectation.fields)?,
        count: expectation.count,
        problem_code: expectation.problem_code.clone(),
    })
}

fn validate_expectation(
    expectation: &ExpectationSource,
    operation: Operation,
    profile: &AccessProfileSource,
    captures: bool,
    captures_results: bool,
) -> Result<(), FixtureError> {
    if captures_results && operation != Operation::Invoke {
        return Err(FixtureError::JourneyShapeRefused);
    }
    if is_request_action(operation) || operation == Operation::Invoke {
        if !expectation.fields.is_empty() || expectation.count.is_some() {
            return Err(FixtureError::JourneyShapeRefused);
        }
    } else if expectation
        .fields
        .keys()
        .any(|field| !profile.readable_fields.contains(field) || field.len() > MAX_IDENTIFIER_BYTES)
        || canonical_size(&Value::Object(expectation.fields.clone()))? > MAX_RESPONSE_BYTES
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    match expectation.outcome {
        ExpectedOutcome::Success => {
            let expected = match operation {
                Operation::Create => 201,
                Operation::Get
                | Operation::List
                | Operation::Lookup
                | Operation::Patch
                | Operation::Batch
                | Operation::Invoke
                | Operation::Snapshot => 200,
                Operation::SubmitRequest
                | Operation::ApproveRequest
                | Operation::RejectRequest
                | Operation::RequestRevision
                | Operation::ReviseRequest
                | Operation::CancelRequest
                | Operation::ApplyRequest => 200,
                Operation::Tombstone | Operation::Revisions => {
                    return Err(FixtureError::LogicalReferenceRefused)
                }
            };
            if expectation.status != expected || expectation.problem_code.is_some() {
                return Err(FixtureError::JourneyShapeRefused);
            }
            if matches!(operation, Operation::List | Operation::Batch) {
                if expectation.count.is_none() || !expectation.fields.is_empty() || captures {
                    return Err(FixtureError::JourneyShapeRefused);
                }
            } else if is_request_action(operation) {
                if expectation.count.is_some() || captures || captures_results {
                    return Err(FixtureError::JourneyShapeRefused);
                }
            } else if operation == Operation::Invoke {
                if expectation.count.is_some() {
                    return Err(FixtureError::JourneyShapeRefused);
                }
            } else if expectation.count.is_some() {
                return Err(FixtureError::JourneyShapeRefused);
            }
        }
        ExpectedOutcome::Refusal => {
            if expectation.status < 400
                || expectation.problem_code.as_deref().is_none_or(|code| {
                    code.is_empty()
                        || code.len() > MAX_IDENTIFIER_BYTES
                        || !code.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'.' | b'_')
                        })
                })
                || !expectation.fields.is_empty()
                || expectation.count.is_some()
                || captures
                || problem_contract(expectation.status, expectation.problem_code.as_deref())
                    .is_none()
            {
                return Err(FixtureError::JourneyShapeRefused);
            }
        }
    }
    Ok(())
}

fn canonical_size(value: &Value) -> Result<usize, FixtureError> {
    canonicalize_json(value)
        .map(|bytes| bytes.len())
        .map_err(|_| FixtureError::JourneyShapeRefused)
}

/// Success token produced only after every selected journey and step has
/// matched. It has no serialization or public constructor.
struct SuccessfulFixtureJourneys {
    registry_revision: String,
    file_sha256: String,
    journey_ids: Vec<String>,
    candidate_binding_sha256: String,
}

impl fmt::Debug for SuccessfulFixtureJourneys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuccessfulFixtureJourneys")
            .field("journey_count", &self.journey_ids.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Observation {
    kind: ObservationKind,
    document: Value,
}

#[derive(Clone)]
enum ObservationKind {
    Record {
        record_id: String,
        etag: String,
    },
    ActionConditions {
        if_match_by_input: BTreeMap<String, String>,
    },
    ActionApplication,
}

#[derive(Clone)]
struct ActionResultReference {
    entity: String,
    record_id: String,
    revision: u64,
}

fn observed_record_id<'a>(
    observations: &'a BTreeMap<String, Observation>,
    reference: &str,
) -> Result<&'a str, FixtureError> {
    match &observations
        .get(reference)
        .ok_or(FixtureError::RequestConstructionRefused)?
        .kind
    {
        ObservationKind::Record { record_id, .. } => Ok(record_id),
        _ => Err(FixtureError::RequestConstructionRefused),
    }
}

fn observed_etag<'a>(
    observations: &'a BTreeMap<String, Observation>,
    reference: &str,
) -> Result<&'a str, FixtureError> {
    match &observations
        .get(reference)
        .ok_or(FixtureError::RequestConstructionRefused)?
        .kind
    {
        ObservationKind::Record { etag, .. } => Ok(etag),
        _ => Err(FixtureError::RequestConstructionRefused),
    }
}

fn observed_condition_if_match(
    observations: &BTreeMap<String, Observation>,
    reference: &str,
    input_api_name: &str,
) -> Result<String, FixtureError> {
    match &observations
        .get(reference)
        .ok_or(FixtureError::RequestConstructionRefused)?
        .kind
    {
        ObservationKind::ActionConditions { if_match_by_input } => if_match_by_input
            .get(input_api_name)
            .cloned()
            .ok_or(FixtureError::RequestConstructionRefused),
        _ => Err(FixtureError::RequestConstructionRefused),
    }
}

/// Concrete state machine used only by the real-PostgreSQL integration gate.
///
/// The runner derives its identity from `registry_state` through the same
/// runtime pool used by the HTTP services, captures the prepared server's
/// router, and owns dispatch through receipt completion. It never exposes a
/// request or accepts a caller-created response. Otherwise a `postgres-test`
/// dependency could feed canned success documents into the state machine and
/// mint a receipt without exercising the Registry router or PostgreSQL. This
/// feature-gated seam is not available to ordinary tooling or runtime builds.
/// The production command path must receive equivalent dispatch and pool
/// identity directly from startup rather than accept an implementable executor.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub struct PostgresFixtureTestRunner {
    pool: RuntimePool,
    app: Router,
    bearer_tokens: Vec<String>,
    bearer_index: usize,
    suite: ValidatedFixtureJourneys,
    candidate: ValidatedSchemaTestCandidate,
    execution_facts: SchemaTestExecutionFacts,
    journey_index: usize,
    step_index: usize,
    observations: BTreeMap<String, Observation>,
}

#[cfg(feature = "postgres-test")]
impl PostgresFixtureTestRunner {
    pub async fn prepare(
        package: &VerifiedPackage,
        sources: &SchemaTestSources<'_>,
        suite: &ValidatedFixtureJourneys,
        prepared: &PreparedServer,
        bearer_tokens: Vec<String>,
    ) -> Result<Self, FixtureError> {
        let (app, pool) = prepared
            .fixture_runtime()
            .ok_or(FixtureError::ExecutionRefused)?;
        let step_count = suite
            .journeys
            .iter()
            .try_fold(0_usize, |count, journey| {
                count.checked_add(journey.steps.len())
            })
            .ok_or(FixtureError::JourneyBoundsRefused)?;
        if bearer_tokens.len() != step_count
            || bearer_tokens.iter().any(|token| {
                token.is_empty()
                    || token.len() > MAX_BEARER_TOKEN_BYTES
                    || token.bytes().any(|byte| {
                        !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
                    })
            })
        {
            return Err(FixtureError::RequestConstructionRefused);
        }
        let execution_facts = database_execution_facts(&pool).await?;
        let candidate = validate_schema_test_candidate(package, sources, &execution_facts, suite)?;
        Ok(Self {
            pool,
            app,
            bearer_tokens,
            bearer_index: 0,
            suite: suite.clone(),
            candidate,
            execution_facts,
            journey_index: 0,
            step_index: 0,
            observations: BTreeMap::new(),
        })
    }

    fn current_step_failure(&self, error: FixtureError) -> FixtureError {
        match error {
            FixtureError::StepFailed { .. } => error,
            other => FixtureError::StepFailed {
                journey_index: self.journey_index,
                step_index: self.step_index,
                error: Box::new(other),
            },
        }
    }

    fn next_request(&self) -> Result<Option<Request<Body>>, FixtureError> {
        let Some(journey) = self.suite.journeys.get(self.journey_index) else {
            return Ok(None);
        };
        let step = journey
            .steps
            .get(self.step_index)
            .ok_or(FixtureError::ExecutionRefused)?;
        let bearer = self
            .bearer_tokens
            .get(self.bearer_index)
            .ok_or(FixtureError::ExecutionRefused)?;
        fixture_request(&journey.id, step, &self.observations, Some(bearer)).map(Some)
    }

    /// Execute every validated journey through the captured Registry router.
    /// A failure consumes the runner and therefore cannot be converted into a
    /// completed result or receipt by skipping the remaining steps.
    pub async fn run_all(mut self) -> Result<CompletedPostgresFixtureTest, FixtureError> {
        while let Some(request) = self
            .next_request()
            .map_err(|error| self.current_step_failure(error))?
        {
            let response = self
                .app
                .call(request)
                .await
                .map_err(|error| match error {})?;
            self.accept_current_response(response).await?;
        }
        self.finish().await
    }

    async fn accept_current_response(
        &mut self,
        response: Response<Body>,
    ) -> Result<(), FixtureError> {
        let step = self
            .suite
            .journeys
            .get(self.journey_index)
            .and_then(|journey| journey.steps.get(self.step_index))
            .cloned()
            .ok_or(FixtureError::ExecutionRefused)?;
        let actual = response.status().as_u16();
        if actual != step.expect.status {
            return Err(
                self.current_step_failure(FixtureError::ResponseStatusMismatch {
                    expected: step.expect.status,
                    actual,
                }),
            );
        }
        accept_response(&step, response, &mut self.observations)
            .await
            .map_err(|error| self.current_step_failure(error))?;
        self.bearer_index += 1;
        self.step_index += 1;
        let journey = self
            .suite
            .journeys
            .get(self.journey_index)
            .ok_or(FixtureError::ExecutionRefused)?;
        if self.step_index == journey.steps.len() {
            self.journey_index += 1;
            self.step_index = 0;
            self.observations.clear();
        }
        Ok(())
    }

    async fn finish(self) -> Result<CompletedPostgresFixtureTest, FixtureError> {
        if self.journey_index != self.suite.journeys.len()
            || self.step_index != 0
            || self.bearer_index != self.bearer_tokens.len()
        {
            return Err(FixtureError::ExecutionRefused);
        }
        let final_facts = database_execution_facts(&self.pool).await?;
        if final_facts != self.execution_facts {
            return Err(FixtureError::CandidateBindingRefused);
        }
        Ok(CompletedPostgresFixtureTest {
            successful: SuccessfulFixtureJourneys {
                registry_revision: self.suite.registry_revision.clone(),
                file_sha256: self.suite.file_sha256.clone(),
                journey_ids: sorted_journey_ids(&self.suite),
                candidate_binding_sha256: candidate_binding_sha256(&self.candidate),
            },
            candidate: self.candidate,
        })
    }
}

/// Completed result from the concrete real-PostgreSQL test runner. It exposes
/// receipt operations, never the candidate or a success-token constructor.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub struct CompletedPostgresFixtureTest {
    candidate: ValidatedSchemaTestCandidate,
    successful: SuccessfulFixtureJourneys,
}

#[cfg(feature = "postgres-test")]
impl CompletedPostgresFixtureTest {
    pub fn build_receipt(
        &self,
        suite: &ValidatedFixtureJourneys,
    ) -> Result<SchemaTestReceipt, FixtureError> {
        build_schema_test_receipt(&self.candidate, suite, &self.successful)
    }

    pub fn revalidate_receipt(
        &self,
        bytes: &[u8],
        suite: &ValidatedFixtureJourneys,
    ) -> Result<SchemaTestReceipt, FixtureError> {
        revalidate_schema_test_receipt(bytes, &self.candidate, suite)
    }
}

/// One private bearer credential bound to a validated journey step.
pub struct SchemaTestCredentialBinding {
    journey_id: String,
    step_id: String,
    bearer_token: Option<Zeroizing<String>>,
}

impl SchemaTestCredentialBinding {
    pub fn bearer(
        journey_id: impl Into<String>,
        step_id: impl Into<String>,
        bearer_token: Zeroizing<String>,
    ) -> Self {
        Self {
            journey_id: journey_id.into(),
            step_id: step_id.into(),
            bearer_token: Some(bearer_token),
        }
    }

    pub fn anonymous(journey_id: impl Into<String>, step_id: impl Into<String>) -> Self {
        Self {
            journey_id: journey_id.into(),
            step_id: step_id.into(),
            bearer_token: None,
        }
    }
}

impl fmt::Debug for SchemaTestCredentialBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaTestCredentialBinding")
            .field("journey_id", &self.journey_id)
            .field("step_id", &self.step_id)
            .field("has_bearer_token", &self.bearer_token.is_some())
            .finish()
    }
}

/// Closed credential inventory consumed by the schema-test executor.
pub struct SchemaTestCredentialBindings {
    bindings: Vec<SchemaTestCredentialBinding>,
}

impl SchemaTestCredentialBindings {
    /// Close the credential inventory against one exact validated suite before
    /// any database preparation is necessary. Protected steps require one
    /// bearer value and anonymous steps require an explicit anonymous binding.
    pub fn new(
        suite: &ValidatedFixtureJourneys,
        bindings: Vec<SchemaTestCredentialBinding>,
    ) -> Result<Self, FixtureError> {
        let result = Self { bindings };
        result.validate(suite)?;
        Ok(result)
    }

    fn validate(&self, suite: &ValidatedFixtureJourneys) -> Result<(), FixtureError> {
        let expected = suite.journeys.iter().flat_map(|journey| {
            journey.steps.iter().map(move |step| {
                (
                    (journey.id.as_str(), step.id.as_str()),
                    step.profile.anonymous,
                )
            })
        });
        if self.bindings.len() > MAX_TOTAL_STEPS {
            return Err(FixtureError::JourneyBoundsRefused);
        }
        if self.bindings.len() != expected.clone().count() {
            return Err(FixtureError::RequestConstructionRefused);
        }
        let expected = expected.collect::<BTreeMap<_, _>>();
        let mut actual = BTreeSet::new();
        for binding in &self.bindings {
            if !valid_stable_id(&binding.journey_id) || !valid_stable_id(&binding.step_id) {
                return Err(FixtureError::RequestConstructionRefused);
            }
            let key = (binding.journey_id.as_str(), binding.step_id.as_str());
            let Some(anonymous) = expected.get(&key) else {
                return Err(FixtureError::RequestConstructionRefused);
            };
            if !actual.insert(key)
                || match (*anonymous, binding.bearer_token.as_ref()) {
                    (true, None) => false,
                    (false, Some(token)) => !valid_bearer_token(token),
                    (true, Some(_)) | (false, None) => true,
                }
            {
                return Err(FixtureError::RequestConstructionRefused);
            }
        }
        Ok(())
    }

    fn into_map(self, suite: &ValidatedFixtureJourneys) -> Result<CredentialMap, FixtureError> {
        self.validate(suite)?;
        let mut actual = BTreeMap::new();
        for binding in self.bindings {
            let key = (binding.journey_id, binding.step_id);
            if actual.insert(key, binding.bearer_token).is_some() {
                return Err(FixtureError::RequestConstructionRefused);
            }
        }
        Ok(actual)
    }
}

fn valid_bearer_token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_BEARER_TOKEN_BYTES {
        return false;
    }
    let mut segments = token.split('.');
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    };
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ),
        (Some(header), Some(claims), Some(signature), None)
            if valid_segment(header) && valid_segment(claims) && valid_segment(signature)
    )
}

impl fmt::Debug for SchemaTestCredentialBindings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaTestCredentialBindings")
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

/// Execute a pre-sign schema test through the production database and HTTP
/// services. The returned receipt is deterministic and non-authorizing.
pub async fn execute_schema_test(
    database: PreparedSchemaTestDatabase,
    config: &RuntimeConfig,
    package: &PreparedPackage,
    suite: &ValidatedFixtureJourneys,
    credentials: SchemaTestCredentialBindings,
) -> Result<SchemaTestReceipt, FixtureError> {
    let key_source = config
        .oidc_key_source()
        .await
        .map_err(|_| FixtureError::ExecutionRefused)?;
    execute_schema_test_with_key_source(database, config, package, suite, credentials, key_source)
        .await
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn execute_schema_test_with_key_source_for_test(
    database: PreparedSchemaTestDatabase,
    config: &RuntimeConfig,
    package: &PreparedPackage,
    suite: &ValidatedFixtureJourneys,
    credentials: SchemaTestCredentialBindings,
    key_source: Arc<JwksFetcher>,
) -> Result<SchemaTestReceipt, FixtureError> {
    execute_schema_test_with_key_source(database, config, package, suite, credentials, key_source)
        .await
}

async fn execute_schema_test_with_key_source(
    database: PreparedSchemaTestDatabase,
    config: &RuntimeConfig,
    package: &PreparedPackage,
    suite: &ValidatedFixtureJourneys,
    credentials: SchemaTestCredentialBindings,
    key_source: Arc<JwksFetcher>,
) -> Result<SchemaTestReceipt, FixtureError> {
    // Credential coverage and mode are pure preflight. Keep this before even
    // reading candidate database facts so malformed inputs cannot trigger I/O.
    let credential_map = credentials.into_map(suite)?;
    let pool = database.pool();
    let initial_facts = database_execution_facts(&pool).await?;
    let (candidate, compiled) =
        validate_prepared_schema_test_candidate(package, &initial_facts, suite)?;
    let mut runtime = SchemaTestRuntime::new(
        database,
        config,
        compiled,
        key_source,
        initial_facts.clone(),
    )
    .await?;

    let mut bearer_index = 0usize;
    let mut observations = BTreeMap::new();
    for (journey_index, journey) in suite.journeys.iter().enumerate() {
        for (step_index, step) in journey.steps.iter().enumerate() {
            let step_failure = |error| FixtureError::StepFailed {
                journey_index,
                step_index,
                error: Box::new(error),
            };
            let bearer = credential_map
                .get(&(journey.id.clone(), step.id.clone()))
                .ok_or_else(|| step_failure(FixtureError::RequestConstructionRefused))?;
            match (step.profile.anonymous, bearer.as_ref()) {
                (true, None) => {}
                (true, Some(_)) | (false, None) => {
                    return Err(step_failure(FixtureError::RequestConstructionRefused));
                }
                (false, Some(token)) => {
                    runtime
                        .authenticate_exact(step, token.as_str())
                        .await
                        .map_err(&step_failure)?;
                }
            }
            let bearer_token = bearer.as_ref().map(|token| token.as_str());
            let request = fixture_request(&journey.id, step, &observations, bearer_token)
                .map_err(&step_failure)?;
            let response = runtime
                .app
                .call(request)
                .await
                .map_err(|error| match error {})?;
            let actual = response.status().as_u16();
            if actual != step.expect.status {
                return Err(step_failure(FixtureError::ResponseStatusMismatch {
                    expected: step.expect.status,
                    actual,
                }));
            }
            accept_response(step, response, &mut observations)
                .await
                .map_err(step_failure)?;
            bearer_index += 1;
        }
        observations.clear();
    }
    if bearer_index != credential_map.len() {
        return Err(FixtureError::ExecutionRefused);
    }
    let final_facts = database_execution_facts(&runtime.pool).await?;
    if final_facts != runtime.initial_facts || !runtime.readiness.is_ready().await {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let successful = SuccessfulFixtureJourneys {
        registry_revision: suite.registry_revision.clone(),
        file_sha256: suite.file_sha256.clone(),
        journey_ids: sorted_journey_ids(suite),
        candidate_binding_sha256: candidate_binding_sha256(&candidate),
    };
    build_schema_test_receipt(&candidate, suite, &successful)
}

struct SchemaTestRuntime {
    app: Router,
    pool: RuntimePool,
    initial_facts: SchemaTestExecutionFacts,
    authenticator: Arc<RegistryAuthenticator>,
    verifier: TokenVerifier,
    readiness: Arc<SchemaTestReadiness>,
}

impl SchemaTestRuntime {
    async fn new(
        database: PreparedSchemaTestDatabase,
        config: &RuntimeConfig,
        compiled: CompiledRegistry,
        key_source: Arc<JwksFetcher>,
        initial_facts: SchemaTestExecutionFacts,
    ) -> Result<Self, FixtureError> {
        key_source
            .ensure_key_set()
            .await
            .map_err(|_| FixtureError::ExecutionRefused)?;
        let pool = database.pool();
        let registry = Arc::new(compiled);
        let audit_profile = config
            .audit_profile()
            .map_err(|_| FixtureError::ExecutionRefused)?;
        let cursor_codec = Arc::new(
            config
                .cursor_codec()
                .map_err(|_| FixtureError::ExecutionRefused)?,
        );
        let event_destinations = Arc::new(
            config
                .activate_event_destinations(&registry)
                .map_err(|_| FixtureError::ExecutionRefused)?,
        );
        let authenticator = Arc::new(
            RegistryAuthenticator::new(
                &registry,
                config.authentication().oidc().token_verifier_config(),
                Arc::clone(&key_source),
                config.authentication().authority_claim_config(),
            )
            .map_err(|_| FixtureError::ExecutionRefused)?,
        );
        let verifier = TokenVerifier::new(
            config.authentication().oidc().token_verifier_config(),
            Arc::clone(&key_source),
        );
        let readiness = Arc::new(SchemaTestReadiness {
            pool: pool.clone(),
            catalog_verifier: database.catalog_verifier(),
            key_source,
        });
        if !readiness.is_ready().await {
            return Err(FixtureError::CandidateBindingRefused);
        }
        let expected = database.expected().clone();
        let read_identity = ReadRuntimeIdentity {
            package_revision: expected.package_revision.clone(),
            schema_fingerprint: expected.schema_fingerprint.clone(),
        };
        let records = Arc::new(PostgresRecordReadService::new(
            pool.clone(),
            Arc::clone(&registry),
            expected.clone(),
            database.lock_key(),
            config.operational_timeouts().record_lock,
            audit_profile.clone(),
            Arc::clone(&cursor_codec),
        ));
        let revisions = Arc::new(PostgresRevisionReadService::new(
            pool.clone(),
            Arc::clone(&registry),
            expected.clone(),
            database.lock_key(),
            config.operational_timeouts().record_lock,
            audit_profile.clone(),
        ));
        let mutations = Arc::new(PostgresRecordMutationService::new_with_event_destinations(
            pool.clone(),
            Arc::clone(&registry),
            expected,
            database.lock_key(),
            config.operational_timeouts().record_lock,
            audit_profile,
            Some(event_destinations),
        ));
        let service = Arc::new(
            HttpService::new(
                registry,
                read_identity,
                records,
                Arc::clone(&readiness) as Arc<dyn ReadinessProbe>,
                cursor_codec,
            )
            .with_postgres_revisions(revisions)
            .with_postgres_mutations(mutations),
        );
        let app = crate::startup::with_request_timeout_for_test(
            crate::api::authenticated_router(service, Arc::clone(&authenticator)),
            config.operational_timeouts().http_request,
        );
        Ok(Self {
            app,
            pool,
            initial_facts,
            authenticator,
            verifier,
            readiness,
        })
    }

    async fn authenticate_exact(
        &self,
        step: &ValidatedStep,
        token: &str,
    ) -> Result<(), FixtureError> {
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|_| FixtureError::RequestConstructionRefused)?;
        let mapped = self
            .authenticator
            .authenticate(token)
            .await
            .map_err(|_| FixtureError::RequestConstructionRefused)?;
        let scopes = verified.scopes.into_iter().collect::<BTreeSet<_>>();
        if scopes != step.claims.scopes
            || mapped.principal_claim() != step.profile.principal_claim.as_deref()
            || mapped.principal() != step.claims.principal.as_deref()
            || mapped.purpose() != step.claims.purpose.as_deref()
        {
            return Err(FixtureError::AuthorityWideningRefused);
        }
        for (name, expected) in &step.claims.direct_claims {
            if mapped
                .direct_claim(name)
                .map(VerifiedClaimValue::values)
                .as_ref()
                != Some(&BTreeSet::from([expected.clone()]))
            {
                return Err(FixtureError::AuthorityWideningRefused);
            }
        }
        let actual_names = step
            .profile
            .row_boundaries
            .iter()
            .filter(|boundary| mapped.direct_claim(&boundary.claim).is_some())
            .map(|boundary| boundary.claim.clone())
            .collect::<BTreeSet<_>>();
        if actual_names != step.claims.direct_claims.keys().cloned().collect() {
            return Err(FixtureError::AuthorityWideningRefused);
        }
        Ok(())
    }
}

struct SchemaTestReadiness {
    pool: RuntimePool,
    catalog_verifier: PreparedSchemaTestCatalogVerifier,
    key_source: Arc<JwksFetcher>,
}

impl SchemaTestReadiness {
    async fn check(&self) -> Result<(), FixtureError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| FixtureError::ExecutionRefused)?;
        let maintenance = client
            .query_opt(
                "SELECT maintenance_status
                   FROM registry_internal.registry_state
                  WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| FixtureError::ExecutionRefused)?
            .ok_or(FixtureError::CandidateBindingRefused)?
            .get::<_, String>(0);
        if maintenance != "ready" {
            return Err(FixtureError::CandidateBindingRefused);
        }
        self.catalog_verifier
            .verify()
            .await
            .map_err(|_| FixtureError::CandidateBindingRefused)?;
        self.key_source
            .ensure_key_set()
            .await
            .map_err(|_| FixtureError::ExecutionRefused)?;
        Ok(())
    }
}

impl ReadinessProbe for SchemaTestReadiness {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async move { self.check().await.is_ok() })
    }
}

async fn database_execution_facts(
    pool: &RuntimePool,
) -> Result<SchemaTestExecutionFacts, FixtureError> {
    let client = pool
        .get()
        .await
        .map_err(|_| FixtureError::ExecutionRefused)?;
    let row = client
        .query_one(
            "SELECT current_database(), current_setting('server_version_num'),
                    package_id, environment, instance_id, database_id,
                    active_package_revision, package_sequence,
                    schema_fingerprint, maintenance_status
               FROM registry_internal.registry_state
              WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| FixtureError::ExecutionRefused)?;
    let version = row
        .get::<_, String>(1)
        .parse::<u32>()
        .map_err(|_| FixtureError::ExecutionRefused)?;
    let sequence =
        u64::try_from(row.get::<_, i64>(7)).map_err(|_| FixtureError::CandidateBindingRefused)?;
    let postgres_major =
        u16::try_from(version / 10_000).map_err(|_| FixtureError::CandidateBindingRefused)?;
    Ok(SchemaTestExecutionFacts::from_database_snapshot(
        DatabaseExecutionSnapshot {
            current_database: row.get(0),
            package_id: row.get(2),
            environment: row.get(3),
            instance_id: row.get(4),
            database_id: row.get(5),
            package_revision: row.get(6),
            sequence,
            schema_fingerprint: row.get(8),
            postgres_major,
            maintenance_status: row.get(9),
        },
    ))
}

fn fixture_request(
    journey_id: &str,
    step: &ValidatedStep,
    observations: &BTreeMap<String, Observation>,
    bearer_token: Option<&str>,
) -> Result<Request<Body>, FixtureError> {
    let mut path = step.route.path().to_owned();
    let mut method = Method::GET;
    let mut body = Body::empty();
    let mut content_type = None;
    let mut if_match: Option<String> = None;
    let mut extra_query_options = Vec::new();
    match &step.action {
        ActionSource::Create { data } => {
            method = Method::POST;
            body = json_body(&json!({"data": resolve_fixture_value_refs(
                &Value::Object(data.clone()),
                observations
            )?}))?;
            content_type = Some("application/json");
        }
        ActionSource::Get { record_ref } => {
            let record_id = observed_record_id(observations, record_ref)?;
            path = path.replace("{record_id}", record_id);
        }
        ActionSource::List { .. } => {}
        ActionSource::Query {
            select,
            top,
            count,
            bbox,
        } => {
            extra_query_options =
                fixture_query_options(step, None, select, *top, *count, bbox.as_ref())?;
        }
        ActionSource::Lookup { selector, values } => {
            method = Method::POST;
            let document = if values.is_empty() {
                json!({"selector": selector})
            } else {
                json!({"selector": selector, "values": values})
            };
            body = json_body(&document)?;
            content_type = Some("application/json");
        }
        ActionSource::ReadPath {
            path: read_path,
            record_ref,
            select,
            top,
            count,
        } => {
            let record_id = observed_record_id(observations, record_ref)?;
            path = path.replace("{record_id}", record_id);
            extra_query_options =
                fixture_query_options(step, Some(read_path), select, *top, *count, None)?;
        }
        ActionSource::Patch {
            record_ref,
            etag_ref,
            changes,
        } => {
            let record_id = observed_record_id(observations, record_ref)?;
            let etag = observed_etag(observations, etag_ref)?;
            path = path.replace("{record_id}", record_id);
            method = Method::PATCH;
            body = json_body(&Value::Array(
                changes
                    .iter()
                    .map(|change| {
                        Ok(json!({
                            "op": "replace",
                            "path": format!("/data/{}", change.field),
                            "value": resolve_fixture_value_refs(&change.value, observations)?
                        }))
                    })
                    .collect::<Result<Vec<_>, FixtureError>>()?,
            ))?;
            content_type = Some("application/json-patch+json");
            if_match = Some(etag.to_owned());
        }
        ActionSource::Batch { items } => {
            method = Method::POST;
            body = json_body(&resolve_fixture_value_refs(
                &batch_body(items),
                observations,
            )?)?;
            content_type = Some("application/json");
        }
        ActionSource::SubmitRequest {
            record_ref,
            etag_ref,
        }
        | ActionSource::ReviseRequest {
            record_ref,
            etag_ref,
            ..
        }
        | ActionSource::CancelRequest {
            record_ref,
            etag_ref,
        }
        | ActionSource::ApproveRequest {
            record_ref,
            etag_ref,
            ..
        }
        | ActionSource::RejectRequest {
            record_ref,
            etag_ref,
            ..
        }
        | ActionSource::RequestRevision {
            record_ref,
            etag_ref,
            ..
        }
        | ActionSource::ApplyRequest {
            record_ref,
            etag_ref,
            ..
        } => {
            let record_id = observed_record_id(observations, record_ref)?;
            let action_if_match =
                captured_request_action_if_match(observations, etag_ref, &step.action)?;
            path = path.replace("{record_id}", record_id);
            method = Method::POST;
            body = json_body(&request_action_body(&step.action, observations)?)?;
            content_type = Some("application/json");
            if_match = Some(action_if_match);
        }
        ActionSource::TargetConditions { input } => {
            method = Method::POST;
            body = json_body(&json!({"input": resolve_fixture_value_refs(
                &Value::Object(input.clone()),
                observations
            )?}))?;
            content_type = Some("application/json");
        }
        ActionSource::Invoke {
            input,
            preconditions,
            ..
        } => {
            method = Method::POST;
            let mut envelope = Map::new();
            envelope.insert(
                "input".to_owned(),
                resolve_fixture_value_refs(&Value::Object(input.clone()), observations)?,
            );
            if !preconditions.is_empty() {
                envelope.insert(
                    "preconditions".to_owned(),
                    immediate_action_preconditions_body(preconditions, observations)?,
                );
            }
            body = json_body(&Value::Object(envelope))?;
            content_type = Some("application/json");
        }
    }
    if !path.starts_with('/') || path.contains(['?', '#']) || path.contains('{') {
        return Err(FixtureError::RequestConstructionRefused);
    }
    path.push_str("?accessProfile=");
    percent_encode_query_value(&step.access_profile, &mut path);
    for (name, value) in extra_query_options {
        path.push('&');
        path.push_str(name);
        path.push('=');
        percent_encode_query_value(&value, &mut path);
    }
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .body(body)
        .map_err(|_| FixtureError::RequestConstructionRefused)?;
    if let Some(value) = content_type {
        request.headers_mut().insert(
            CONTENT_TYPE,
            value
                .parse()
                .map_err(|_| FixtureError::RequestConstructionRefused)?,
        );
    }
    if matches!(
        step.action,
        ActionSource::Create { .. }
            | ActionSource::Patch { .. }
            | ActionSource::Batch { .. }
            | ActionSource::Invoke { .. }
            | ActionSource::SubmitRequest { .. }
            | ActionSource::ApproveRequest { .. }
            | ActionSource::RejectRequest { .. }
            | ActionSource::RequestRevision { .. }
            | ActionSource::ReviseRequest { .. }
            | ActionSource::CancelRequest { .. }
            | ActionSource::ApplyRequest { .. }
    ) {
        let key_id = match &step.action {
            ActionSource::Invoke {
                idempotency_key: Some(key),
                ..
            } => key.as_str(),
            _ => step.id.as_str(),
        };
        let target_id = step
            .action_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .or(step.entity.as_deref())
            .ok_or(FixtureError::RequestConstructionRefused)?;
        let key = format!("fixture-{journey_id}-{target_id}-{key_id}");
        request.headers_mut().insert(
            "idempotency-key",
            key.parse()
                .map_err(|_| FixtureError::RequestConstructionRefused)?,
        );
    }
    if let Some(value) = if_match {
        request.headers_mut().insert(
            IF_MATCH,
            value
                .as_str()
                .parse()
                .map_err(|_| FixtureError::RequestConstructionRefused)?,
        );
    }
    if let Some(token) = bearer_token {
        request.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {token}")
                .parse()
                .map_err(|_| FixtureError::RequestConstructionRefused)?,
        );
    } else {
        request.extensions_mut().insert(verified_claims(step)?);
    }
    Ok(request)
}

fn fixture_query_options(
    step: &ValidatedStep,
    _read_path: Option<&str>,
    select: &BTreeSet<String>,
    top: Option<u16>,
    count: bool,
    bbox: Option<&BboxSource>,
) -> Result<Vec<(&'static str, String)>, FixtureError> {
    let mut parameters = Vec::new();
    if !select.is_empty() {
        parameters.push((
            "$select",
            select.iter().cloned().collect::<Vec<_>>().join(","),
        ));
    }
    if let Some(top) = top {
        parameters.push(("$top", top.to_string()));
    }
    if count {
        parameters.push(("$count", "true".to_owned()));
    }
    if let Some(bbox) = bbox {
        parameters.push(("bbox", parse_fixture_bbox(bbox)?.canonical_bbox_value()));
    }
    if step.access_profile.is_empty() {
        return Err(FixtureError::RequestConstructionRefused);
    }
    Ok(parameters)
}

trait FixtureBboxCanonical {
    fn canonical_bbox_value(&self) -> String;
}

impl FixtureBboxCanonical for crate::query::BboxClause {
    fn canonical_bbox_value(&self) -> String {
        format!(
            "{},{},{},{}",
            self.west(),
            self.south(),
            self.east(),
            self.north()
        )
    }
}

fn percent_encode_query_value(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn json_body(value: &Value) -> Result<Body, FixtureError> {
    let bytes = canonicalize_json(value).map_err(|_| FixtureError::RequestConstructionRefused)?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(FixtureError::JourneyTooLarge);
    }
    Ok(Body::from(bytes))
}

fn batch_body(items: &[BatchItemSource]) -> Value {
    json!({
        "items": items.iter().map(|item| match item {
            BatchItemSource::Create { data } => json!({"operation":"create","data":data}),
        }).collect::<Vec<_>>()
    })
}

fn resolve_fixture_value_refs(
    value: &Value,
    observations: &BTreeMap<String, Observation>,
) -> Result<Value, FixtureError> {
    match value {
        Value::Object(object) => {
            if let Some(record_ref) = object.get("recordRef") {
                if object.len() != 1 {
                    return Err(FixtureError::RequestConstructionRefused);
                }
                let reference = record_ref
                    .as_str()
                    .filter(|reference| valid_stable_id(reference))
                    .ok_or(FixtureError::RequestConstructionRefused)?;
                let observation = observations
                    .get(reference)
                    .ok_or(FixtureError::RequestConstructionRefused)?;
                match &observation.kind {
                    ObservationKind::Record { record_id, .. } => {
                        Ok(Value::String(record_id.clone()))
                    }
                    _ => Err(FixtureError::RequestConstructionRefused),
                }
            } else {
                object
                    .iter()
                    .map(|(key, nested)| {
                        resolve_fixture_value_refs(nested, observations)
                            .map(|resolved| (key.clone(), resolved))
                    })
                    .collect::<Result<Map<String, Value>, FixtureError>>()
                    .map(Value::Object)
            }
        }
        Value::Array(items) => items
            .iter()
            .map(|item| resolve_fixture_value_refs(item, observations))
            .collect::<Result<Vec<_>, FixtureError>>()
            .map(Value::Array),
        _ => Ok(value.clone()),
    }
}

fn request_action_body(
    action: &ActionSource,
    observations: &BTreeMap<String, Observation>,
) -> Result<Value, FixtureError> {
    match action {
        ActionSource::SubmitRequest { .. } | ActionSource::CancelRequest { .. } => Ok(json!({})),
        ActionSource::ReviseRequest { rebase, .. } => Ok(json!({"rebase": *rebase})),
        ActionSource::ApproveRequest { .. }
        | ActionSource::RejectRequest { .. }
        | ActionSource::RequestRevision { .. }
        | ActionSource::ApplyRequest { .. } => {
            let binding = request_action_binding(action)?;
            let version = match (binding.proposal_version, binding.proposal_version_ref) {
                (Some(version), None) => version,
                (None, Some(reference)) => captured_proposal_version(observations, reference)?,
                _ => return Err(FixtureError::RequestConstructionRefused),
            };
            let digest = match (binding.effect_digest, binding.effect_digest_ref) {
                (Some(digest), None) => digest.to_owned(),
                (None, Some(reference)) => captured_effect_digest(observations, reference)?,
                _ => return Err(FixtureError::RequestConstructionRefused),
            };
            validate_digest(&digest)?;
            Ok(json!({
                "proposalVersion": version,
                "effectDigest": digest,
            }))
        }
        _ => Err(FixtureError::RequestConstructionRefused),
    }
}

fn immediate_action_preconditions_body(
    preconditions: &BTreeMap<String, ImmediateActionPreconditionSource>,
    observations: &BTreeMap<String, Observation>,
) -> Result<Value, FixtureError> {
    preconditions
        .iter()
        .map(|(input_api_name, condition)| {
            let if_match = match (
                condition.if_match.as_deref(),
                condition.condition_ref.as_deref(),
            ) {
                (Some(value), None) => {
                    validate_action_if_match(value)?;
                    value.to_owned()
                }
                (None, Some(reference)) => {
                    observed_condition_if_match(observations, reference, input_api_name)?
                }
                _ => return Err(FixtureError::RequestConstructionRefused),
            };
            Ok((input_api_name.clone(), json!({"ifMatch": if_match})))
        })
        .collect::<Result<Map<String, Value>, FixtureError>>()
        .map(Value::Object)
}

fn captured_request_action_if_match(
    observations: &BTreeMap<String, Observation>,
    reference: &str,
    action: &ActionSource,
) -> Result<String, FixtureError> {
    let observation = observations
        .get(reference)
        .ok_or(FixtureError::RequestConstructionRefused)?;
    let actions = observation
        .document
        .pointer("/data/request/actions")
        .and_then(Value::as_array)
        .ok_or(FixtureError::RequestConstructionRefused)?;
    let expected_operation = request_action_name(action)?;
    let expected_stage = request_action_stage(action)?;
    let mut matches = actions.iter().filter(|candidate| {
        candidate
            .get("operation")
            .and_then(Value::as_str)
            .is_some_and(|operation| operation == expected_operation)
            && match (expected_stage, candidate.get("stage")) {
                (Some(expected), Some(value)) => value.as_str() == Some(expected),
                (None, Some(value)) => value.is_null(),
                (None, None) => true,
                (Some(_), None) => false,
            }
    });
    let entry = matches
        .next()
        .filter(|_| matches.next().is_none())
        .ok_or(FixtureError::RequestConstructionRefused)?;
    let if_match = entry
        .get("ifMatch")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_BINDING_BYTES
                && value.starts_with("\"rs-")
                && value.ends_with('"')
        })
        .ok_or(FixtureError::RequestConstructionRefused)?;
    Ok(if_match.to_owned())
}

fn request_action_name(action: &ActionSource) -> Result<&'static str, FixtureError> {
    match action {
        ActionSource::SubmitRequest { .. } => Ok("submit_request"),
        ActionSource::ApproveRequest { .. } => Ok("approve_request"),
        ActionSource::RejectRequest { .. } => Ok("reject_request"),
        ActionSource::RequestRevision { .. } => Ok("request_revision"),
        ActionSource::ReviseRequest { .. } => Ok("revise_request"),
        ActionSource::CancelRequest { .. } => Ok("cancel_request"),
        ActionSource::ApplyRequest { .. } => Ok("apply_request"),
        _ => Err(FixtureError::RequestConstructionRefused),
    }
}

fn captured_proposal_version(
    observations: &BTreeMap<String, Observation>,
    reference: &str,
) -> Result<u32, FixtureError> {
    observations
        .get(reference)
        .and_then(|observation| {
            observation
                .document
                .pointer("/data/request/proposalVersion")
                .and_then(Value::as_u64)
        })
        .filter(|version| *version > 0 && *version <= u64::from(u32::MAX))
        .map(|version| version as u32)
        .ok_or(FixtureError::RequestConstructionRefused)
}

fn captured_effect_digest(
    observations: &BTreeMap<String, Observation>,
    reference: &str,
) -> Result<String, FixtureError> {
    let digest = observations
        .get(reference)
        .and_then(|observation| {
            observation
                .document
                .pointer("/data/request/effectDigest")
                .and_then(Value::as_str)
        })
        .ok_or(FixtureError::RequestConstructionRefused)?;
    validate_digest(digest)?;
    Ok(digest.to_owned())
}

fn verified_claims(step: &ValidatedStep) -> Result<VerifiedRequestClaims, FixtureError> {
    if step.profile.anonymous {
        return Ok(VerifiedRequestClaims::anonymous());
    }
    let principal_claim = step
        .profile
        .principal_claim
        .as_deref()
        .ok_or(FixtureError::RequestConstructionRefused)?;
    let principal = step
        .claims
        .principal
        .as_deref()
        .ok_or(FixtureError::RequestConstructionRefused)?;
    let direct_claims = step
        .claims
        .direct_claims
        .iter()
        .map(|(name, value)| {
            VerifiedClaimValue::direct_string(value.clone())
                .map(|value| (name.clone(), value))
                .map_err(|_| FixtureError::RequestConstructionRefused)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    VerifiedRequestClaims::authenticated(
        principal_claim,
        principal,
        step.claims.scopes.clone(),
        step.claims.purpose.clone(),
        direct_claims,
    )
    .map_err(|_| FixtureError::RequestConstructionRefused)
}

async fn accept_response(
    step: &ValidatedStep,
    response: Response<Body>,
    observations: &mut BTreeMap<String, Observation>,
) -> Result<(), FixtureError> {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
        .await
        .map_err(|_| FixtureError::ResponseTooLarge)?;
    let document = parse_json_strict(&bytes).map_err(|_| FixtureError::ResponseShapeRefused)?;
    assert_response(step, status, &document)?;
    if matches!(step.expect.outcome, ExpectedOutcome::Refusal) {
        let header_trace =
            response_trace_id(&headers).map_err(|_| FixtureError::ResponseShapeRefused)?;
        if document.get("traceId").and_then(Value::as_str) != Some(header_trace.as_str()) {
            return Err(FixtureError::ResponseShapeRefused);
        }
    }
    if !step.capture_results.is_empty() {
        capture_immediate_action_results(step, &document, observations)?;
    }
    if let Some(capture) = step.capture.as_ref() {
        let kind = capture_observation_kind(step, &headers, &document)?;
        observations.insert(capture.clone(), Observation { kind, document });
    }
    Ok(())
}

fn capture_observation_kind(
    step: &ValidatedStep,
    headers: &HeaderMap,
    document: &Value,
) -> Result<ObservationKind, FixtureError> {
    match step.action {
        ActionSource::TargetConditions { .. } => Ok(ObservationKind::ActionConditions {
            if_match_by_input: parse_target_conditions(document)?,
        }),
        ActionSource::Invoke { .. } => {
            let application_id = document
                .get("applicationId")
                .and_then(Value::as_str)
                .filter(|value| {
                    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == *value)
                })
                .ok_or(FixtureError::ResponseShapeRefused)?;
            let _ = application_id;
            parse_immediate_action_results(document)?;
            Ok(ObservationKind::ActionApplication)
        }
        _ => {
            let record_id = document
                .pointer("/data/recordIdentifier")
                .and_then(Value::as_str)
                .filter(|value| {
                    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == *value)
                })
                .ok_or(FixtureError::ResponseShapeRefused)?;
            let etag = headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty() && value.len() <= MAX_BINDING_BYTES)
                .ok_or(FixtureError::ResponseShapeRefused)?;
            Ok(ObservationKind::Record {
                record_id: record_id.to_owned(),
                etag: etag.to_owned(),
            })
        }
    }
}

fn capture_immediate_action_results(
    step: &ValidatedStep,
    document: &Value,
    observations: &mut BTreeMap<String, Observation>,
) -> Result<(), FixtureError> {
    let results = parse_immediate_action_results(document)?;
    for (effect, capture) in &step.capture_results {
        let result = results
            .get(effect)
            .ok_or(FixtureError::ResponseShapeRefused)?;
        observations.insert(
            capture.clone(),
            Observation {
                kind: ObservationKind::Record {
                    record_id: result.record_id.clone(),
                    etag: format!("\"rs-action-result-{}\"", result.revision),
                },
                document: json!({
                    "id": result.record_id,
                    "entity": result.entity,
                    "revision": result.revision,
                    "data": {}
                }),
            },
        );
    }
    Ok(())
}

fn assert_response(
    step: &ValidatedStep,
    status: StatusCode,
    document: &Value,
) -> Result<(), FixtureError> {
    if status.as_u16() != step.expect.status {
        return Err(FixtureError::ExpectationMismatch);
    }
    match step.expect.outcome {
        ExpectedOutcome::Refusal => {
            let (title, detail) =
                problem_contract(step.expect.status, step.expect.problem_code.as_deref())
                    .ok_or(FixtureError::ResponseShapeRefused)?;
            let code = step
                .expect
                .problem_code
                .as_deref()
                .ok_or(FixtureError::ResponseShapeRefused)?;
            let object = exact_object(
                document,
                &["type", "title", "status", "detail", "code", "traceId"],
            )?;
            let trace_id = object
                .get("traceId")
                .and_then(Value::as_str)
                .ok_or(FixtureError::ResponseShapeRefused)?;
            TraceId::parse(trace_id).map_err(|_| FixtureError::ResponseShapeRefused)?;
            let expected_type = format!("urn:registry-server:problem:{code}");
            if object.get("type").and_then(Value::as_str) != Some(expected_type.as_str())
                || object.get("title").and_then(Value::as_str) != Some(title)
                || object.get("status").and_then(Value::as_u64)
                    != Some(u64::from(step.expect.status))
                || object.get("detail").and_then(Value::as_str) != Some(detail)
                || object.get("code").and_then(Value::as_str) != Some(code)
            {
                return Err(FixtureError::ExpectationMismatch);
            }
        }
        ExpectedOutcome::Success => match step.action {
            ActionSource::List { .. }
            | ActionSource::Query { .. }
            | ActionSource::ReadPath { .. } => {
                let include_count = matches!(
                    step.action,
                    ActionSource::Query { count: true, .. }
                        | ActionSource::ReadPath { count: true, .. }
                );
                let expected_keys: &[&str] = if include_count {
                    &["items", "pageInfo", "meta", "count"]
                } else {
                    &["items", "pageInfo", "meta"]
                };
                let object = exact_object(document, expected_keys)?;
                assert_record_meta(object)?;
                let items = object
                    .get("items")
                    .and_then(Value::as_array)
                    .ok_or(FixtureError::ResponseShapeRefused)?;
                let page_info = object
                    .get("pageInfo")
                    .and_then(Value::as_object)
                    .ok_or(FixtureError::ResponseShapeRefused)?;
                if page_info.len() != 1
                    || !page_info.get("nextCursor").is_some_and(|cursor| {
                        cursor.is_null()
                            || cursor.as_str().is_some_and(|value| {
                                !value.is_empty() && value.len() <= MAX_BINDING_BYTES
                            })
                    })
                    || Some(items.len()) != step.expect.count
                    || (include_count
                        && object.get("count").and_then(Value::as_u64)
                            != step
                                .expect
                                .count
                                .and_then(|count| u64::try_from(count).ok()))
                {
                    return Err(FixtureError::ExpectationMismatch);
                }
                for item in items {
                    assert_record_shape(item, &step.response_readable_fields, &Map::new())?;
                }
            }
            ActionSource::Batch { .. } => {
                let object = exact_object(document, &["results", "snapshot"])?;
                assert_snapshot_reference(object)?;
                let results = object
                    .get("results")
                    .and_then(Value::as_array)
                    .ok_or(FixtureError::ResponseShapeRefused)?;
                if Some(results.len()) != step.expect.count {
                    return Err(FixtureError::ExpectationMismatch);
                }
                for result in results {
                    let object =
                        exact_object(result, &["operation", "id", "revision", "etag", "data"])?;
                    if object.get("operation").and_then(Value::as_str) != Some("create")
                        || object
                            .get("etag")
                            .and_then(Value::as_str)
                            .is_none_or(|etag| {
                                etag.len() > MAX_BINDING_BYTES
                                    || !etag.starts_with("\"rs-")
                                    || !etag.ends_with('"')
                            })
                    {
                        return Err(FixtureError::ResponseShapeRefused);
                    }
                    assert_batch_record_members(
                        object,
                        &step.response_readable_fields,
                        &Map::new(),
                    )?;
                }
            }
            ActionSource::Create { .. } | ActionSource::Patch { .. } => {
                let object = assert_single_record_envelope(document)?;
                let member = object
                    .get("data")
                    .ok_or(FixtureError::ResponseShapeRefused)?;
                let member = exact_object(
                    member,
                    &[
                        "recordIdentifier",
                        "revisionIdentifier",
                        "domainData",
                        "snapshot",
                    ],
                )?;
                assert_snapshot_reference(member)?;
                assert_record_members(member, &step.response_readable_fields, &step.expect.fields)?;
            }
            ActionSource::Get { .. } | ActionSource::Lookup { .. } => {
                let object = assert_single_record_envelope(document)?;
                assert_record_shape(
                    object
                        .get("data")
                        .ok_or(FixtureError::ResponseShapeRefused)?,
                    &step.response_readable_fields,
                    &step.expect.fields,
                )?;
            }
            ActionSource::SubmitRequest { .. }
            | ActionSource::ApproveRequest { .. }
            | ActionSource::RejectRequest { .. }
            | ActionSource::RequestRevision { .. }
            | ActionSource::ReviseRequest { .. }
            | ActionSource::CancelRequest { .. }
            | ActionSource::ApplyRequest { .. } => {
                assert_request_action_shape(document)?;
            }
            ActionSource::TargetConditions { .. } => {
                parse_target_conditions(document)?;
            }
            ActionSource::Invoke { .. } => {
                assert_immediate_action_shape(
                    document,
                    step.action_id
                        .as_deref()
                        .ok_or(FixtureError::ResponseShapeRefused)?,
                )?;
            }
        },
    }
    Ok(())
}

fn parse_target_conditions(value: &Value) -> Result<BTreeMap<String, String>, FixtureError> {
    let object = exact_object(value, &["preconditions"])?;
    let preconditions = object
        .get("preconditions")
        .and_then(Value::as_object)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    let mut result = BTreeMap::new();
    for (input, condition) in preconditions {
        if input.is_empty() || input.len() > MAX_IDENTIFIER_BYTES {
            return Err(FixtureError::ResponseShapeRefused);
        }
        let condition = exact_object(condition, &["ifMatch"])?;
        let if_match = condition
            .get("ifMatch")
            .and_then(Value::as_str)
            .ok_or(FixtureError::ResponseShapeRefused)?;
        validate_action_if_match(if_match).map_err(|_| FixtureError::ResponseShapeRefused)?;
        result.insert(input.clone(), if_match.to_owned());
    }
    Ok(result)
}

fn assert_immediate_action_shape(value: &Value, action_id: &str) -> Result<(), FixtureError> {
    let object = exact_object(value, &["applicationId", "action", "results"])?;
    let application_id = object
        .get("applicationId")
        .and_then(Value::as_str)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if !uuid::Uuid::parse_str(application_id)
        .is_ok_and(|parsed| parsed.to_string() == application_id)
        || object.get("action").and_then(Value::as_str) != Some(action_id)
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    parse_immediate_action_results(value)?;
    Ok(())
}

fn parse_immediate_action_results(
    value: &Value,
) -> Result<BTreeMap<String, ActionResultReference>, FixtureError> {
    let results = value
        .get("results")
        .and_then(Value::as_object)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    let mut parsed = BTreeMap::new();
    for (effect, result) in results {
        if !valid_stable_id(effect) {
            return Err(FixtureError::ResponseShapeRefused);
        }
        let result = exact_object(result, &["entity", "recordId", "revision"])?;
        let entity = result
            .get("entity")
            .and_then(Value::as_str)
            .filter(|value| valid_stable_id(value))
            .ok_or(FixtureError::ResponseShapeRefused)?;
        let record_id = result
            .get("recordId")
            .and_then(Value::as_str)
            .filter(|value| uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == *value))
            .ok_or(FixtureError::ResponseShapeRefused)?;
        let revision = result
            .get("revision")
            .and_then(Value::as_u64)
            .filter(|revision| *revision > 0)
            .ok_or(FixtureError::ResponseShapeRefused)?;
        parsed.insert(
            effect.clone(),
            ActionResultReference {
                entity: entity.to_owned(),
                record_id: record_id.to_owned(),
                revision,
            },
        );
    }
    Ok(parsed)
}

fn assert_request_action_shape(value: &Value) -> Result<(), FixtureError> {
    let object = exact_object(value, &["id", "revision", "snapshot", "request"])?;
    let identifier = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if object
        .get("revision")
        .and_then(Value::as_u64)
        .is_none_or(|revision| revision == 0)
        || !uuid::Uuid::parse_str(identifier).is_ok_and(|parsed| parsed.to_string() == identifier)
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    assert_snapshot_reference(object)?;
    let request = object
        .get("request")
        .and_then(Value::as_object)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if request.keys().any(|key| {
        !matches!(
            key.as_str(),
            "serverState" | "proposalVersion" | "effectDigest" | "application"
        )
    }) || !["serverState", "proposalVersion", "effectDigest"]
        .iter()
        .all(|key| request.contains_key(*key))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    assert_request_state(request)?;
    assert_optional_proposal_version(request.get("proposalVersion"))?;
    assert_optional_effect_digest(
        request
            .get("effectDigest")
            .ok_or(FixtureError::ResponseShapeRefused)?,
    )?;
    if let Some(application) = request.get("application") {
        if !application.is_null() {
            assert_request_application_shape(application)?;
        }
    }
    Ok(())
}

fn exact_object<'a>(
    value: &'a Value,
    expected_keys: &[&str],
) -> Result<&'a Map<String, Value>, FixtureError> {
    let object = value
        .as_object()
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if object.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !object.contains_key(*key))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    Ok(object)
}

fn assert_record_shape(
    value: &Value,
    readable_fields: &BTreeSet<String>,
    expected_fields: &Map<String, Value>,
) -> Result<(), FixtureError> {
    let object = value
        .as_object()
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "recordIdentifier"
                | "revisionIdentifier"
                | "domainData"
                | "request"
                | "requestPresence"
        )
    }) || !["recordIdentifier", "revisionIdentifier", "domainData"]
        .iter()
        .all(|key| object.contains_key(*key))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    assert_record_members(object, readable_fields, expected_fields)?;
    if let Some(request) = object.get("request") {
        assert_request_record_metadata_shape(request)?;
    }
    Ok(())
}

fn assert_snapshot_reference(object: &Map<String, Value>) -> Result<(), FixtureError> {
    let reference = object
        .get("snapshot")
        .and_then(Value::as_str)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    crate::history_reference::SnapshotReference::parse(reference)
        .map_err(|_| FixtureError::ResponseShapeRefused)?;
    Ok(())
}

fn assert_record_members(
    object: &Map<String, Value>,
    readable_fields: &BTreeSet<String>,
    expected_fields: &Map<String, Value>,
) -> Result<(), FixtureError> {
    let identifier = object
        .get("recordIdentifier")
        .and_then(Value::as_str)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    let revision = object
        .get("revisionIdentifier")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(FixtureError::ResponseShapeRefused)?;
    let data = object
        .get("domainData")
        .and_then(Value::as_object)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if revision == 0
        || !uuid::Uuid::parse_str(identifier).is_ok_and(|parsed| parsed.to_string() == identifier)
        || !data
            .keys()
            .all(|field| readable_fields.contains(field.as_str()))
        || expected_fields
            .iter()
            .any(|(field, expected)| data.get(field) != Some(expected))
    {
        return Err(FixtureError::ExpectationMismatch);
    }
    Ok(())
}

fn assert_batch_record_members(
    object: &Map<String, Value>,
    readable_fields: &BTreeSet<String>,
    expected_fields: &Map<String, Value>,
) -> Result<(), FixtureError> {
    let identifier = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    let revision = object
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    let data = object
        .get("data")
        .and_then(Value::as_object)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if revision == 0
        || !uuid::Uuid::parse_str(identifier).is_ok_and(|parsed| parsed.to_string() == identifier)
        || !data
            .keys()
            .all(|field| readable_fields.contains(field.as_str()))
        || expected_fields
            .iter()
            .any(|(field, expected)| data.get(field) != Some(expected))
    {
        return Err(FixtureError::ExpectationMismatch);
    }
    Ok(())
}

fn assert_single_record_envelope(value: &Value) -> Result<&Map<String, Value>, FixtureError> {
    let object = exact_object(value, &["data", "meta"])?;
    assert_record_meta(object)?;
    Ok(object)
}

fn assert_record_meta(object: &Map<String, Value>) -> Result<(), FixtureError> {
    let meta = object
        .get("meta")
        .and_then(Value::as_object)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if meta.len() != 3
        || [
            "registryIdentifier",
            "datasetIdentifier",
            "entityTypeIdentifier",
        ]
        .iter()
        .any(|key| {
            meta.get(*key)
                .and_then(Value::as_str)
                .is_none_or(|value| value.is_empty() || value.len() > MAX_BINDING_BYTES)
        })
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    Ok(())
}

fn assert_request_record_metadata_shape(value: &Value) -> Result<(), FixtureError> {
    let request = value
        .as_object()
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if request.keys().any(|key| {
        !matches!(
            key.as_str(),
            "serverState"
                | "proposalVersion"
                | "effectDigest"
                | "editable"
                | "actions"
                | "history"
                | "application"
        )
    }) || !["serverState", "proposalVersion"]
        .iter()
        .all(|key| request.contains_key(*key))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    assert_request_state(request)?;
    assert_optional_proposal_version(request.get("proposalVersion"))?;
    if let Some(digest) = request.get("effectDigest") {
        assert_optional_effect_digest(digest)?;
    }
    if let Some(editable) = request.get("editable") {
        if !editable.is_boolean() {
            return Err(FixtureError::ResponseShapeRefused);
        }
    }
    if let Some(actions) = request.get("actions") {
        let actions = actions
            .as_array()
            .ok_or(FixtureError::ResponseShapeRefused)?;
        for action in actions {
            assert_request_action_link_shape(action)?;
        }
    }
    if let Some(history) = request.get("history") {
        assert_request_history_shape(history)?;
    }
    if let Some(application) = request.get("application") {
        assert_request_application_shape(application)?;
    }
    Ok(())
}

fn assert_request_state(request: &Map<String, Value>) -> Result<(), FixtureError> {
    let allowed_states = BTreeSet::from([
        "draft",
        "submitted",
        "approved",
        "needs_changes",
        "rejected",
        "canceled",
        "applied",
    ]);
    if request
        .get("serverState")
        .and_then(Value::as_str)
        .is_none_or(|state| !allowed_states.contains(state))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    Ok(())
}

fn assert_optional_proposal_version(value: Option<&Value>) -> Result<(), FixtureError> {
    let value = value.ok_or(FixtureError::ResponseShapeRefused)?;
    if !value.is_null()
        && value
            .as_u64()
            .is_none_or(|version| version == 0 || version > u64::from(u32::MAX))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    Ok(())
}

fn assert_optional_effect_digest(value: &Value) -> Result<(), FixtureError> {
    if !value.is_null() {
        validate_digest(value.as_str().ok_or(FixtureError::ResponseShapeRefused)?)?;
    }
    Ok(())
}

fn assert_request_action_link_shape(value: &Value) -> Result<(), FixtureError> {
    let action = value
        .as_object()
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if action.keys().any(|key| {
        !matches!(
            key.as_str(),
            "operation"
                | "method"
                | "href"
                | "ifMatch"
                | "stage"
                | "rebase"
                | "proposalVersion"
                | "effectDigest"
                | "decision"
                | "review"
        )
    }) || !["operation", "method", "href", "ifMatch"]
        .iter()
        .all(|key| action.contains_key(*key))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    if action
        .get("operation")
        .and_then(Value::as_str)
        .is_none_or(|operation| operation.len() > MAX_IDENTIFIER_BYTES)
        || action.get("method").and_then(Value::as_str) != Some("POST")
        || action
            .get("href")
            .and_then(Value::as_str)
            .is_none_or(|href| !href.starts_with('/') || href.len() > MAX_BINDING_BYTES)
        || action
            .get("ifMatch")
            .and_then(Value::as_str)
            .is_none_or(|etag| {
                etag.is_empty()
                    || etag.len() > MAX_BINDING_BYTES
                    || !etag.starts_with("\"rs-")
                    || !etag.ends_with('"')
            })
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    if let Some(stage) = action.get("stage") {
        if stage.as_str().is_none_or(|stage| !valid_stable_id(stage)) {
            return Err(FixtureError::ResponseShapeRefused);
        }
    }
    if let Some(rebase) = action.get("rebase") {
        if !rebase.is_boolean() {
            return Err(FixtureError::ResponseShapeRefused);
        }
    }
    if action.contains_key("proposalVersion") {
        assert_optional_proposal_version(action.get("proposalVersion"))?;
    }
    if let Some(digest) = action.get("effectDigest") {
        assert_optional_effect_digest(digest)?;
    }
    Ok(())
}

fn assert_request_history_shape(value: &Value) -> Result<(), FixtureError> {
    let history = exact_object(value, &["proposals", "nextAfterProposalVersion"])?;
    let proposals = history
        .get("proposals")
        .and_then(Value::as_array)
        .ok_or(FixtureError::ResponseShapeRefused)?;
    for proposal in proposals {
        let proposal = proposal
            .as_object()
            .ok_or(FixtureError::ResponseShapeRefused)?;
        if !proposal.contains_key("proposalVersion")
            || !proposal.contains_key("serverState")
            || proposal
                .get("proposalVersion")
                .and_then(Value::as_u64)
                .is_none_or(|version| version == 0 || version > u64::from(u32::MAX))
        {
            return Err(FixtureError::ResponseShapeRefused);
        }
    }
    let cursor = history
        .get("nextAfterProposalVersion")
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if !cursor.is_null()
        && cursor
            .as_u64()
            .is_none_or(|version| version == 0 || version > u64::from(u32::MAX))
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    Ok(())
}

fn assert_request_application_shape(value: &Value) -> Result<(), FixtureError> {
    let application = value
        .as_object()
        .ok_or(FixtureError::ResponseShapeRefused)?;
    if application.keys().any(|key| {
        !matches!(
            key.as_str(),
            "id" | "applicationId" | "proposalVersion" | "effectDigest" | "appliedAt"
        )
    }) || !application.contains_key("proposalVersion")
    {
        return Err(FixtureError::ResponseShapeRefused);
    }
    if let Some(identifier) = application
        .get("id")
        .or_else(|| application.get("applicationId"))
    {
        let identifier = identifier
            .as_str()
            .ok_or(FixtureError::ResponseShapeRefused)?;
        if !uuid::Uuid::parse_str(identifier).is_ok_and(|parsed| parsed.to_string() == identifier) {
            return Err(FixtureError::ResponseShapeRefused);
        }
    }
    assert_optional_proposal_version(application.get("proposalVersion"))?;
    if let Some(digest) = application.get("effectDigest") {
        assert_optional_effect_digest(digest)?;
    }
    Ok(())
}

fn problem_contract(status: u16, code: Option<&str>) -> Option<(&'static str, &'static str)> {
    match (status, code?) {
        (400, "query.invalid") => Some(("Bad Request", "The query request is invalid.")),
        (400, "request.invalid") => Some(("Bad Request", "The request is invalid.")),
        (404, "resource.not_found") => Some(("Not Found", "The requested resource was not found.")),
        (409, "mutation.conflict") => {
            Some(("Conflict", "The mutation conflicts with current state."))
        }
        (409, "idempotency.conflict") => Some((
            "Conflict",
            "The idempotency key is bound to another request.",
        )),
        (412, "precondition.failed") => {
            Some(("Precondition Failed", "The mutation precondition failed."))
        }
        (415, "unsupported.media_type") => Some((
            "Unsupported Media Type",
            "The request media type is not supported.",
        )),
        (428, "precondition.required") => Some((
            "Precondition Required",
            "The mutation precondition is required.",
        )),
        (503, "source.unavailable") => Some((
            "Service Unavailable",
            "The Registry data service is unavailable.",
        )),
        (503, "service.unavailable") => Some((
            "Service Unavailable",
            "The Registry mutation service is unavailable.",
        )),
        _ => None,
    }
}

/// One exact source file supplied to the postgres-test-only candidate
/// validator. Paths are not authority: they must exactly match the
/// already-verified package closure.
#[cfg(any(test, feature = "postgres-test"))]
pub struct FixtureSourceFile<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

/// One exact module source in package closure order.
#[cfg(any(test, feature = "postgres-test"))]
pub struct FixtureModuleSource<'a> {
    pub id: &'a str,
    pub path: &'a str,
    pub bytes: &'a [u8],
    pub assets: &'a [FixtureModuleAssetSource<'a>],
}

/// One exact module asset source in deterministic module-relative order.
#[cfg(any(test, feature = "postgres-test"))]
pub struct FixtureModuleAssetSource<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

/// Source-only candidate input. Deployment identity, compiler revision,
/// sequence, prior revision, PostgreSQL version, and schema fingerprint are
/// deliberately absent and cannot be asserted by a tooling caller.
#[cfg(any(test, feature = "postgres-test"))]
pub struct SchemaTestSources<'a> {
    pub project: FixtureSourceFile<'a>,
    pub modules: &'a [FixtureModuleSource<'a>],
    pub migration_plan: FixtureSourceFile<'a>,
}

/// Exact database facts captured by the sealed runner that executed the
/// journeys. There is intentionally no public constructor.
#[derive(Clone, Eq, PartialEq)]
struct SchemaTestExecutionFacts {
    current_database: String,
    package_id: String,
    environment: String,
    instance_id: String,
    package_revision: String,
    database_id: String,
    sequence: u64,
    schema_fingerprint: String,
    postgres_major: u16,
    maintenance_status: String,
}

impl SchemaTestExecutionFacts {
    fn from_database_snapshot(snapshot: DatabaseExecutionSnapshot) -> Self {
        Self {
            current_database: snapshot.current_database,
            package_id: snapshot.package_id,
            environment: snapshot.environment,
            instance_id: snapshot.instance_id,
            package_revision: snapshot.package_revision,
            database_id: snapshot.database_id,
            sequence: snapshot.sequence,
            schema_fingerprint: snapshot.schema_fingerprint,
            postgres_major: snapshot.postgres_major,
            maintenance_status: snapshot.maintenance_status,
        }
    }
}

struct DatabaseExecutionSnapshot {
    current_database: String,
    package_id: String,
    environment: String,
    instance_id: String,
    database_id: String,
    package_revision: String,
    sequence: u64,
    schema_fingerprint: String,
    postgres_major: u16,
    maintenance_status: String,
}

/// A Production-recompiled, VerifiedPackage-bound candidate paired with facts
/// from the same sealed database execution context. Fields and constructors
/// stay private so this type cannot become a self-asserted authority bag.
pub struct ValidatedSchemaTestCandidate {
    registry_revision: String,
    project_source_revision: String,
    compiler_source_revision: String,
    environment: String,
    instance_id: String,
    database_id: String,
    sequence: u64,
    prior_package_revision: Option<String>,
    target_package_revision: String,
    source_closure_sha256: String,
    migration_plan_sha256: String,
    signing_input_sha256: String,
    postgres_major: u16,
    target_managed_schema_fingerprint: String,
}

impl fmt::Debug for ValidatedSchemaTestCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedSchemaTestCandidate")
            .field("sequence", &self.sequence)
            .field("postgres_major", &self.postgres_major)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SchemaTestReceipt {
    api_version: String,
    kind: String,
    registry_revision: String,
    project_source_revision: String,
    compiler_source_revision: String,
    environment: String,
    instance_id: String,
    database_id: String,
    sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    prior_package_revision: Option<String>,
    candidate_package_revision: String,
    source_closure_sha256: String,
    migration_plan_sha256: String,
    signing_input_sha256: String,
    postgres_major: u16,
    target_managed_schema_fingerprint: String,
    successful_journey_ids: Vec<String>,
    journey_file_sha256: String,
}

impl fmt::Debug for SchemaTestReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaTestReceipt")
            .field("sequence", &self.sequence)
            .field("postgres_major", &self.postgres_major)
            .field("journey_count", &self.successful_journey_ids.len())
            .finish_non_exhaustive()
    }
}

impl SchemaTestReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FixtureError> {
        canonicalize_json(
            &serde_json::to_value(self).map_err(|_| FixtureError::ReceiptShapeRefused)?,
        )
        .map_err(|_| FixtureError::ReceiptShapeRefused)
    }

    pub fn successful_journey_ids(&self) -> &[String] {
        &self.successful_journey_ids
    }
}

/// Build a receipt only from the unforgeable all-success token and exact
/// candidate bytes. The receipt intentionally carries no signature, readiness,
/// activation intent, or authorization claim.
fn build_schema_test_receipt(
    candidate: &ValidatedSchemaTestCandidate,
    suite: &ValidatedFixtureJourneys,
    successful: &SuccessfulFixtureJourneys,
) -> Result<SchemaTestReceipt, FixtureError> {
    if successful.registry_revision != suite.registry_revision
        || successful.file_sha256 != suite.file_sha256
        || successful.journey_ids != sorted_journey_ids(suite)
        || successful.candidate_binding_sha256 != candidate_binding_sha256(candidate)
    {
        return Err(FixtureError::ReceiptBindingRefused);
    }
    Ok(receipt_for_candidate(candidate, suite))
}

/// Parse one canonical receipt and rederive every field from exact candidate
/// and journey bytes. This permits later package assembly to require the
/// evidence without treating the receipt as authority.
#[cfg(any(test, feature = "postgres-test"))]
fn revalidate_schema_test_receipt(
    bytes: &[u8],
    candidate: &ValidatedSchemaTestCandidate,
    suite: &ValidatedFixtureJourneys,
) -> Result<SchemaTestReceipt, FixtureError> {
    let receipt = parse_canonical_schema_test_receipt(bytes)?;
    if receipt != receipt_for_candidate(candidate, suite) {
        return Err(FixtureError::ReceiptBindingRefused);
    }
    Ok(receipt)
}

/// Validate a non-authorizing schema-test receipt against the exact unsigned
/// candidate package and reviewed journey suite. Every authoritative field is
/// rederived from package bytes. `postgresMajor` remains execution metadata,
/// but only a supported value can survive the exact receipt comparison.
pub fn validate_schema_test_receipt_for_package(
    bytes: &[u8],
    package: &PreparedPackage,
    suite: &ValidatedFixtureJourneys,
) -> Result<SchemaTestReceipt, FixtureError> {
    let receipt = parse_canonical_schema_test_receipt(bytes)?;
    let (candidate, _) =
        derive_prepared_schema_test_candidate(package, suite, receipt.postgres_major)?;
    if receipt != receipt_for_candidate(&candidate, suite) {
        return Err(FixtureError::ReceiptBindingRefused);
    }
    Ok(receipt)
}

fn parse_canonical_schema_test_receipt(bytes: &[u8]) -> Result<SchemaTestReceipt, FixtureError> {
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err(FixtureError::ReceiptShapeRefused);
    }
    let value = parse_json_strict(bytes).map_err(|_| FixtureError::ReceiptShapeRefused)?;
    let canonical = canonicalize_json(&value).map_err(|_| FixtureError::ReceiptShapeRefused)?;
    if canonical != bytes {
        return Err(FixtureError::ReceiptShapeRefused);
    }
    let receipt: SchemaTestReceipt =
        serde_json::from_value(value).map_err(|_| FixtureError::ReceiptShapeRefused)?;
    if !(MIN_SUPPORTED_POSTGRES_MAJOR..=MAX_SUPPORTED_POSTGRES_MAJOR)
        .contains(&receipt.postgres_major)
    {
        return Err(FixtureError::ReceiptBindingRefused);
    }
    Ok(receipt)
}

fn receipt_for_candidate(
    candidate: &ValidatedSchemaTestCandidate,
    suite: &ValidatedFixtureJourneys,
) -> SchemaTestReceipt {
    SchemaTestReceipt {
        api_version: RECEIPT_API_VERSION.to_owned(),
        kind: RECEIPT_KIND.to_owned(),
        registry_revision: candidate.registry_revision.clone(),
        project_source_revision: candidate.project_source_revision.clone(),
        compiler_source_revision: candidate.compiler_source_revision.to_owned(),
        environment: candidate.environment.to_owned(),
        instance_id: candidate.instance_id.clone(),
        database_id: candidate.database_id.clone(),
        sequence: candidate.sequence,
        prior_package_revision: candidate.prior_package_revision.clone(),
        candidate_package_revision: candidate.target_package_revision.clone(),
        source_closure_sha256: candidate.source_closure_sha256.clone(),
        migration_plan_sha256: candidate.migration_plan_sha256.clone(),
        signing_input_sha256: candidate.signing_input_sha256.clone(),
        postgres_major: candidate.postgres_major,
        target_managed_schema_fingerprint: candidate.target_managed_schema_fingerprint.clone(),
        successful_journey_ids: sorted_journey_ids(suite),
        journey_file_sha256: suite.file_sha256.clone(),
    }
}

#[cfg(any(test, feature = "postgres-test"))]
fn validate_schema_test_candidate(
    package: &VerifiedPackage,
    sources: &SchemaTestSources<'_>,
    execution: &SchemaTestExecutionFacts,
    suite: &ValidatedFixtureJourneys,
) -> Result<ValidatedSchemaTestCandidate, FixtureError> {
    let manifest = package.manifest();
    if package.registry().revision() != suite.registry_revision
        || manifest.compiler.profile != PackageCompileProfile::Production
        || sources.project.path != manifest.sources.project
        || sources.project.bytes.is_empty()
        || sources.project.bytes.len() > MAX_SOURCE_BYTES
        || sources.migration_plan.path != "database/migration-plan.json"
        || sources.migration_plan.bytes.is_empty()
        || sources.migration_plan.bytes.len() > MAX_SOURCE_BYTES
        || execution.package_id != manifest.package_id
        || execution.environment != manifest.environment
        || execution.instance_id != manifest.instance_id
        || execution.package_revision != manifest.package_revision
        || execution.database_id != manifest.database_id
        || execution.sequence != manifest.sequence
        || execution.schema_fingerprint != manifest.schema_fingerprint
        || execution.maintenance_status != "ready"
        || execution.current_database.is_empty()
        || execution.current_database.len() > MAX_BINDING_BYTES
        || !(MIN_SUPPORTED_POSTGRES_MAJOR..=MAX_SUPPORTED_POSTGRES_MAJOR)
            .contains(&execution.postgres_major)
        || !manifest_file_matches(
            manifest,
            PackageFileRole::SourceProject,
            sources.project.path,
            sources.project.bytes,
        )
        || manifest.sources.fixture_journeys != FIXTURE_JOURNEYS_PATH
        || !manifest_file_matches(
            manifest,
            PackageFileRole::FixtureJourneys,
            FIXTURE_JOURNEYS_PATH,
            &suite.file_bytes,
        )
    {
        return Err(FixtureError::CandidateBindingRefused);
    }

    let project = parse_project_yaml(sources.project.bytes)
        .map_err(|_| FixtureError::CandidateBindingRefused)?;
    if sources.modules.len() != manifest.sources.modules.len()
        || project.modules.len() != sources.modules.len()
    {
        return Err(FixtureError::CandidateBindingRefused);
    }
    validate_manifest_source_asset_inventory(manifest)?;
    let mut modules = Vec::with_capacity(sources.modules.len());
    let mut module_assets = Vec::new();
    for ((captured, locked), source) in manifest
        .sources
        .modules
        .iter()
        .zip(&project.modules)
        .zip(sources.modules)
    {
        if source.id != captured.id
            || source.path != captured.path
            || source.id != locked.id
            || source.bytes.is_empty()
            || source.bytes.len() > MAX_SOURCE_BYTES
            || !manifest_file_matches(
                manifest,
                PackageFileRole::SourceModule,
                source.path,
                source.bytes,
            )
        {
            return Err(FixtureError::CandidateBindingRefused);
        }
        let module =
            parse_module_yaml(source.bytes).map_err(|_| FixtureError::CandidateBindingRefused)?;
        let assets = validate_source_module_assets(manifest, captured, source)?;
        let digest = module_digest_with_assets(&module, &assets);
        if module.id != source.id
            || module.version != locked.version
            || locked.digest.as_deref() != Some(digest.as_str())
        {
            return Err(FixtureError::CandidateBindingRefused);
        }
        modules.push(module);
        module_assets.extend(assets);
    }

    let compiled = compile_project_with_assets(
        &project,
        &modules,
        &module_assets,
        CompileProfile::Production,
    )
    .map_err(|_| FixtureError::CandidateBindingRefused)?;
    if compiled != *package.registry() {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let project_identity = compiled
        .package()
        .ok_or(FixtureError::CandidateBindingRefused)?;
    if project_identity.environment != manifest.environment
        || project_identity.instance_id != manifest.instance_id
        || project_identity.sequence != manifest.sequence
        || manifest.migration_plan.from_revision != manifest.prior_revision
        || manifest.migration_plan.reviewed_descriptors.is_empty()
            != package.reviewed_migration_plan().is_none()
    {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let canonical_migration_plan = canonicalize_json(
        &serde_json::to_value(&manifest.migration_plan)
            .map_err(|_| FixtureError::CandidateBindingRefused)?,
    )
    .map_err(|_| FixtureError::CandidateBindingRefused)?;
    if canonical_migration_plan != sources.migration_plan.bytes {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let migration_file = manifest
        .files
        .iter()
        .find(|file| file.role == PackageFileRole::MigrationPlan)
        .ok_or(FixtureError::CandidateBindingRefused)?;
    if migration_file.path != sources.migration_plan.path
        || migration_file.size != sources.migration_plan.bytes.len() as u64
        || migration_file.sha256 != sha256(sources.migration_plan.bytes)
    {
        return Err(FixtureError::CandidateBindingRefused);
    }

    Ok(ValidatedSchemaTestCandidate {
        registry_revision: compiled.revision().to_owned(),
        project_source_revision: project_identity.source_revision.clone(),
        compiler_source_revision: manifest.compiler.source_revision.clone(),
        environment: manifest.environment.clone(),
        instance_id: manifest.instance_id.clone(),
        database_id: manifest.database_id.clone(),
        sequence: manifest.sequence,
        prior_package_revision: manifest.prior_revision.clone(),
        target_package_revision: manifest.package_revision.clone(),
        source_closure_sha256: source_closure_sha256(sources, suite),
        migration_plan_sha256: sha256(sources.migration_plan.bytes),
        signing_input_sha256: sha256(
            &package_canonical_signed_bytes(manifest)
                .map_err(|_| FixtureError::CandidateBindingRefused)?,
        ),
        postgres_major: execution.postgres_major,
        target_managed_schema_fingerprint: execution.schema_fingerprint.clone(),
    })
}

fn validate_prepared_schema_test_candidate(
    package: &PreparedPackage,
    execution: &SchemaTestExecutionFacts,
    suite: &ValidatedFixtureJourneys,
) -> Result<(ValidatedSchemaTestCandidate, CompiledRegistry), FixtureError> {
    let manifest = package.manifest();
    if execution.package_id != manifest.package_id
        || execution.environment != manifest.environment
        || execution.instance_id != manifest.instance_id
        || execution.package_revision != manifest.package_revision
        || execution.database_id != manifest.database_id
        || execution.sequence != manifest.sequence
        || execution.schema_fingerprint != manifest.schema_fingerprint
        || execution.maintenance_status != "ready"
        || execution.current_database.is_empty()
        || execution.current_database.len() > MAX_BINDING_BYTES
    {
        return Err(FixtureError::CandidateBindingRefused);
    }

    derive_prepared_schema_test_candidate(package, suite, execution.postgres_major)
}

fn derive_prepared_schema_test_candidate(
    package: &PreparedPackage,
    suite: &ValidatedFixtureJourneys,
    postgres_major: u16,
) -> Result<(ValidatedSchemaTestCandidate, CompiledRegistry), FixtureError> {
    let manifest = package.manifest();
    if manifest.compiler.profile != PackageCompileProfile::Production
        || !(MIN_SUPPORTED_POSTGRES_MAJOR..=MAX_SUPPORTED_POSTGRES_MAJOR).contains(&postgres_major)
        || manifest.sources.fixture_journeys != FIXTURE_JOURNEYS_PATH
        || !prepared_files_match_manifest(package)
    {
        return Err(FixtureError::CandidateBindingRefused);
    }

    let files = package.file_bytes();
    let project_bytes = files
        .get(&manifest.sources.project)
        .ok_or(FixtureError::CandidateBindingRefused)?;
    if project_bytes.is_empty() || project_bytes.len() > MAX_SOURCE_BYTES {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let project =
        parse_project_yaml(project_bytes).map_err(|_| FixtureError::CandidateBindingRefused)?;
    if project.modules.len() != manifest.sources.modules.len() {
        return Err(FixtureError::CandidateBindingRefused);
    }
    validate_manifest_source_asset_inventory(manifest)?;
    let mut modules = Vec::with_capacity(manifest.sources.modules.len());
    let mut module_assets = Vec::new();
    for (locked, captured) in project.modules.iter().zip(&manifest.sources.modules) {
        if locked.id != captured.id {
            return Err(FixtureError::CandidateBindingRefused);
        }
        let module_bytes = files
            .get(&captured.path)
            .ok_or(FixtureError::CandidateBindingRefused)?;
        if module_bytes.is_empty() || module_bytes.len() > MAX_SOURCE_BYTES {
            return Err(FixtureError::CandidateBindingRefused);
        }
        let assets = prepared_module_assets(captured, files)?;
        let module =
            parse_module_yaml(module_bytes).map_err(|_| FixtureError::CandidateBindingRefused)?;
        if module.id != captured.id
            || module.version != locked.version
            || locked.digest.as_deref()
                != Some(module_digest_with_assets(&module, &assets).as_str())
        {
            return Err(FixtureError::CandidateBindingRefused);
        }
        modules.push(module);
        module_assets.extend(assets);
    }
    let compiled = compile_project_with_assets(
        &project,
        &modules,
        &module_assets,
        CompileProfile::Production,
    )
    .map_err(|_| FixtureError::CandidateBindingRefused)?;
    let project_identity = compiled
        .package()
        .ok_or(FixtureError::CandidateBindingRefused)?;
    if compiled != *package.registry()
        || compiled.revision() != suite.registry_revision
        || compiled.registry_id() != manifest.package_id
        || project_identity.environment != manifest.environment
        || project_identity.instance_id != manifest.instance_id
        || project_identity.sequence != manifest.sequence
        || manifest.migration_plan.from_revision != manifest.prior_revision
    {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let packaged_journeys = files
        .get(FIXTURE_JOURNEYS_PATH)
        .ok_or(FixtureError::CandidateBindingRefused)?;
    if packaged_journeys.as_slice() != suite.file_bytes.as_slice()
        || sha256(packaged_journeys) != suite.file_sha256
        || !manifest_file_matches(
            manifest,
            PackageFileRole::FixtureJourneys,
            FIXTURE_JOURNEYS_PATH,
            packaged_journeys,
        )
    {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let migration_plan_bytes = files
        .get("database/migration-plan.json")
        .ok_or(FixtureError::CandidateBindingRefused)?;
    let canonical_migration_plan = canonicalize_json(
        &serde_json::to_value(&manifest.migration_plan)
            .map_err(|_| FixtureError::CandidateBindingRefused)?,
    )
    .map_err(|_| FixtureError::CandidateBindingRefused)?;
    if migration_plan_bytes.as_slice() != canonical_migration_plan.as_slice() {
        return Err(FixtureError::CandidateBindingRefused);
    }

    Ok((
        ValidatedSchemaTestCandidate {
            registry_revision: compiled.revision().to_owned(),
            project_source_revision: project_identity.source_revision.clone(),
            compiler_source_revision: manifest.compiler.source_revision.clone(),
            environment: manifest.environment.clone(),
            instance_id: manifest.instance_id.clone(),
            database_id: manifest.database_id.clone(),
            sequence: manifest.sequence,
            prior_package_revision: manifest.prior_revision.clone(),
            target_package_revision: manifest.package_revision.clone(),
            source_closure_sha256: source_closure_sha256_from_package(package)?,
            migration_plan_sha256: sha256(migration_plan_bytes),
            signing_input_sha256: sha256(package.canonical_signed_bytes()),
            postgres_major,
            target_managed_schema_fingerprint: manifest.schema_fingerprint.clone(),
        },
        compiled,
    ))
}

fn prepared_files_match_manifest(package: &PreparedPackage) -> bool {
    let files = package.file_bytes();
    if files.len() != package.manifest().files.len() {
        return false;
    }
    package.manifest().files.iter().all(|file| {
        files
            .get(&file.path)
            .is_some_and(|bytes| file.size == bytes.len() as u64 && file.sha256 == sha256(bytes))
    })
}

fn validate_manifest_source_asset_inventory(
    manifest: &crate::package::PackageManifest,
) -> Result<(), FixtureError> {
    let mut declared_paths = BTreeSet::new();
    for module in &manifest.sources.modules {
        let mut prior_asset = None;
        for asset in &module.assets {
            let package_path = source_module_asset_package_path(&module.id, asset)?;
            if prior_asset.is_some_and(|prior: &str| prior >= asset.as_str())
                || !declared_paths.insert(package_path)
            {
                return Err(FixtureError::CandidateBindingRefused);
            }
            prior_asset = Some(asset.as_str());
        }
    }
    let file_paths = manifest
        .files
        .iter()
        .filter(|file| file.role == PackageFileRole::SourceModuleAsset)
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    if declared_paths != file_paths {
        return Err(FixtureError::CandidateBindingRefused);
    }
    Ok(())
}

#[cfg(any(test, feature = "postgres-test"))]
fn validate_source_module_assets(
    manifest: &crate::package::PackageManifest,
    captured: &crate::package::CapturedModule,
    source: &FixtureModuleSource<'_>,
) -> Result<Vec<ModuleAssetSource>, FixtureError> {
    if source.assets.len() != captured.assets.len() {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let mut assets = Vec::with_capacity(source.assets.len());
    let mut seen = BTreeSet::new();
    for (expected, asset) in captured.assets.iter().zip(source.assets) {
        let package_path = source_module_asset_package_path(&captured.id, asset.path)?;
        if asset.path != expected
            || asset.bytes.is_empty()
            || asset.bytes.len() > MAX_DERIVED_SQL_BYTES
            || !seen.insert(asset.path)
            || !manifest_file_matches(
                manifest,
                PackageFileRole::SourceModuleAsset,
                &package_path,
                asset.bytes,
            )
        {
            return Err(FixtureError::CandidateBindingRefused);
        }
        assets.push(ModuleAssetSource {
            module: Some(source.id.to_owned()),
            path: asset.path.to_owned(),
            bytes: asset.bytes.to_vec(),
        });
    }
    Ok(assets)
}

fn prepared_module_assets(
    captured: &crate::package::CapturedModule,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<ModuleAssetSource>, FixtureError> {
    let mut assets = Vec::with_capacity(captured.assets.len());
    for asset in &captured.assets {
        let package_path = source_module_asset_package_path(&captured.id, asset)?;
        let bytes = files
            .get(&package_path)
            .ok_or(FixtureError::CandidateBindingRefused)?;
        if bytes.is_empty() || bytes.len() > MAX_DERIVED_SQL_BYTES {
            return Err(FixtureError::CandidateBindingRefused);
        }
        assets.push(ModuleAssetSource {
            module: Some(captured.id.clone()),
            path: asset.clone(),
            bytes: bytes.clone(),
        });
    }
    Ok(assets)
}

fn source_module_asset_package_path(
    module_id: &str,
    asset_path: &str,
) -> Result<String, FixtureError> {
    if !valid_stable_id(module_id)
        || asset_path.is_empty()
        || asset_path.len() > 256
        || asset_path.contains('\\')
        || asset_path.starts_with('/')
        || asset_path.ends_with('/')
        || !asset_path.ends_with(".sql")
        || asset_path == "module.yaml"
    {
        return Err(FixtureError::CandidateBindingRefused);
    }
    let mut components = 0usize;
    for component in asset_path.split('/') {
        components += 1;
        if component.is_empty() || component == "." || component == ".." {
            return Err(FixtureError::CandidateBindingRefused);
        }
    }
    if components > 12 {
        return Err(FixtureError::CandidateBindingRefused);
    }
    Ok(format!("source/modules/{module_id}/{asset_path}"))
}

fn manifest_file_matches(
    manifest: &crate::package::PackageManifest,
    role: PackageFileRole,
    path: &str,
    bytes: &[u8],
) -> bool {
    manifest.files.iter().any(|file| {
        file.role == role
            && file.path == path
            && file.size == bytes.len() as u64
            && file.sha256 == sha256(bytes)
    })
}

#[cfg(any(test, feature = "postgres-test"))]
fn source_closure_sha256(
    sources: &SchemaTestSources<'_>,
    suite: &ValidatedFixtureJourneys,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"registry-server-schema-test-source-closure-v2\0");
    digest_part(
        &mut digest,
        sources.project.path.as_bytes(),
        sources.project.bytes,
    );
    for source in sources.modules {
        digest_part(&mut digest, source.id.as_bytes(), source.path.as_bytes());
        digest_part(&mut digest, source.path.as_bytes(), source.bytes);
        for asset in source.assets {
            let path = format!("source/modules/{}/{}", source.id, asset.path);
            digest_part(&mut digest, path.as_bytes(), asset.bytes);
        }
    }
    digest_part(
        &mut digest,
        FIXTURE_JOURNEYS_PATH.as_bytes(),
        &suite.file_bytes,
    );
    encoded_sha256(digest.finalize().as_slice())
}

fn source_closure_sha256_from_package(package: &PreparedPackage) -> Result<String, FixtureError> {
    let manifest = package.manifest();
    let files = package.file_bytes();
    let project_bytes = files
        .get(&manifest.sources.project)
        .ok_or(FixtureError::CandidateBindingRefused)?;
    let mut digest = Sha256::new();
    digest.update(b"registry-server-schema-test-source-closure-v2\0");
    digest_part(
        &mut digest,
        manifest.sources.project.as_bytes(),
        project_bytes,
    );
    for module in &manifest.sources.modules {
        let bytes = files
            .get(&module.path)
            .ok_or(FixtureError::CandidateBindingRefused)?;
        digest_part(&mut digest, module.id.as_bytes(), module.path.as_bytes());
        digest_part(&mut digest, module.path.as_bytes(), bytes);
        for asset in &module.assets {
            let path = format!("source/modules/{}/{}", module.id, asset);
            let bytes = files
                .get(&path)
                .ok_or(FixtureError::CandidateBindingRefused)?;
            digest_part(&mut digest, path.as_bytes(), bytes);
        }
    }
    let journeys = files
        .get(FIXTURE_JOURNEYS_PATH)
        .ok_or(FixtureError::CandidateBindingRefused)?;
    digest_part(&mut digest, FIXTURE_JOURNEYS_PATH.as_bytes(), journeys);
    Ok(encoded_sha256(digest.finalize().as_slice()))
}

fn candidate_binding_sha256(candidate: &ValidatedSchemaTestCandidate) -> String {
    let mut digest = Sha256::new();
    digest.update(b"registry-server-schema-test-candidate-binding-v1\0");
    for value in [
        candidate.registry_revision.as_bytes(),
        candidate.target_package_revision.as_bytes(),
        candidate.source_closure_sha256.as_bytes(),
        candidate.migration_plan_sha256.as_bytes(),
        candidate.signing_input_sha256.as_bytes(),
        candidate.target_managed_schema_fingerprint.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(candidate.postgres_major.to_be_bytes());
    encoded_sha256(digest.finalize().as_slice())
}

fn digest_part(digest: &mut Sha256, name: &[u8], bytes: &[u8]) {
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn sorted_journey_ids(suite: &ValidatedFixtureJourneys) -> Vec<String> {
    let mut ids = suite
        .journeys
        .iter()
        .map(|journey| journey.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn valid_stable_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn operation_method(operation: Operation) -> HttpMethod {
    match operation {
        Operation::Create | Operation::Lookup | Operation::Batch | Operation::Invoke => {
            HttpMethod::Post
        }
        Operation::Get | Operation::List | Operation::Revisions | Operation::Snapshot => {
            HttpMethod::Get
        }
        Operation::Patch => HttpMethod::Patch,
        Operation::Tombstone => HttpMethod::Delete,
        Operation::SubmitRequest
        | Operation::ApproveRequest
        | Operation::RejectRequest
        | Operation::RequestRevision
        | Operation::ReviseRequest
        | Operation::CancelRequest
        | Operation::ApplyRequest => HttpMethod::Post,
    }
}

fn is_request_action(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::SubmitRequest
            | Operation::ApproveRequest
            | Operation::RejectRequest
            | Operation::RequestRevision
            | Operation::ReviseRequest
            | Operation::CancelRequest
            | Operation::ApplyRequest
    )
}

fn sha256(bytes: &[u8]) -> String {
    encoded_sha256(Sha256::digest(bytes).as_slice())
}

fn encoded_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(71);
    result.push_str("sha256:");
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::compiler::module_digest;
    use crate::package::{
        load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
        PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, SignaturePolicy,
    };

    const PROJECT_TEMPLATE: &[u8] =
        include_bytes!("../tests/fixtures/fixture-tooling/project.yaml");
    const MODULE_SOURCE: &[u8] = include_bytes!("../tests/fixtures/fixture-tooling/module.yaml");
    const JOURNEY_SOURCE: &[u8] = include_bytes!("../tests/fixtures/fixture-tooling/journeys.yaml");
    const COMPILER_SOURCE_REVISION: &str = "fixture-project-source";
    const DATABASE_ID: &str = "fixture-database";
    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[tokio::test]
    async fn fixture_test_receipt_is_deterministic_and_bound_to_the_exact_candidate() {
        let fixture = package_fixture(DIGEST_A);
        let suite = validate_fixture_journeys(JOURNEY_SOURCE, fixture.package.registry())
            .expect("strict suite validates");
        let execution = execution_facts(&fixture.package, DIGEST_A, 16);
        let candidate = validated_candidate(&fixture, &execution, &suite)
            .expect("verified package and database facts close the candidate");
        let successful = execute_scripted(&suite, &candidate, ScriptMode::Success)
            .await
            .expect("closed responses pass");

        let first = build_schema_test_receipt(&candidate, &suite, &successful)
            .expect("complete run builds receipt");
        let second = build_schema_test_receipt(&candidate, &suite, &successful)
            .expect("identical run facts build again");
        let bytes = first.canonical_bytes().expect("receipt canonicalizes");
        assert_eq!(bytes, second.canonical_bytes().expect("receipt repeats"));
        assert_eq!(first.successful_journey_ids(), ["widget-lifecycle"]);
        assert_eq!(
            revalidate_schema_test_receipt(&bytes, &candidate, &suite)
                .expect("exact receipt revalidates")
                .canonical_bytes()
                .expect("revalidated receipt canonicalizes"),
            bytes
        );
        assert_eq!(
            validate_schema_test_receipt_for_package(&bytes, &fixture.prepared, &suite)
                .expect("ordinary package-bound validator accepts the exact receipt")
                .canonical_bytes()
                .expect("validated receipt canonicalizes"),
            bytes
        );

        assert_candidate_build_substitutions_are_refused(&fixture, &suite, &execution);
        assert_receipt_substitutions_are_refused(&bytes, &candidate, &suite);
        assert_public_receipt_negatives(&bytes, &fixture, &suite);
        assert_closed_response_negatives(&suite, &candidate).await;
    }

    #[test]
    fn schema_test_credentials_require_exact_tuple_and_authorization_mode_preflight() {
        let fixture = package_fixture(DIGEST_A);
        let suite = validate_fixture_journeys(JOURNEY_SOURCE, fixture.package.registry())
            .expect("strict suite validates");
        let exact = || protected_credential_bindings(&suite);
        SchemaTestCredentialBindings::new(&suite, exact())
            .expect("one bearer binding per protected step passes pure preflight");

        let mut missing = exact();
        missing.pop();
        assert_eq!(
            SchemaTestCredentialBindings::new(&suite, missing).unwrap_err(),
            FixtureError::RequestConstructionRefused
        );

        let mut extra = exact();
        extra.push(SchemaTestCredentialBinding::bearer(
            "widget-lifecycle",
            "undeclared-step",
            Zeroizing::new("opaque.extra.token".to_owned()),
        ));
        assert_eq!(
            SchemaTestCredentialBindings::new(&suite, extra).unwrap_err(),
            FixtureError::RequestConstructionRefused
        );

        let mut duplicate = exact();
        duplicate.pop();
        duplicate.push(SchemaTestCredentialBinding::bearer(
            "widget-lifecycle",
            "create-widget",
            Zeroizing::new("opaque.duplicate.token".to_owned()),
        ));
        assert_eq!(
            SchemaTestCredentialBindings::new(&suite, duplicate).unwrap_err(),
            FixtureError::RequestConstructionRefused
        );

        let mut missing_bearer = exact();
        missing_bearer[0] =
            SchemaTestCredentialBinding::anonymous("widget-lifecycle", "create-widget");
        assert_eq!(
            SchemaTestCredentialBindings::new(&suite, missing_bearer).unwrap_err(),
            FixtureError::RequestConstructionRefused
        );

        let mut anonymous_suite = suite.clone();
        anonymous_suite.journeys[0].steps[0].profile.anonymous = true;
        let mut bearer_for_anonymous = exact();
        assert_eq!(
            SchemaTestCredentialBindings::new(&anonymous_suite, bearer_for_anonymous).unwrap_err(),
            FixtureError::RequestConstructionRefused
        );
        bearer_for_anonymous = exact();
        bearer_for_anonymous[0] =
            SchemaTestCredentialBinding::anonymous("widget-lifecycle", "create-widget");
        SchemaTestCredentialBindings::new(&anonymous_suite, bearer_for_anonymous)
            .expect("explicit anonymous mode matches the anonymous step");

        for token in [
            "",
            "contains a space",
            "has/slash",
            "singlecomponent",
            "two.parts",
            "too.many.parts.here",
            ".leading.parts",
            "trailing.parts.",
        ] {
            let mut malformed = exact();
            malformed[0] = SchemaTestCredentialBinding::bearer(
                "widget-lifecycle",
                "create-widget",
                Zeroizing::new(token.to_owned()),
            );
            let error = SchemaTestCredentialBindings::new(&suite, malformed).unwrap_err();
            assert_eq!(error, FixtureError::RequestConstructionRefused);
            if !token.is_empty() {
                assert!(!format!("{error:?}").contains(token));
            }
        }
        let mut oversized = exact();
        oversized[0] = SchemaTestCredentialBinding::bearer(
            "widget-lifecycle",
            "create-widget",
            Zeroizing::new(format!("{}.b.c", "a".repeat(MAX_BEARER_TOKEN_BYTES))),
        );
        assert_eq!(
            SchemaTestCredentialBindings::new(&suite, oversized).unwrap_err(),
            FixtureError::RequestConstructionRefused
        );
        let secret = "secret.canary.token";
        let debug = format!(
            "{:?}",
            SchemaTestCredentialBinding::bearer(
                "widget-lifecycle",
                "create-widget",
                Zeroizing::new(secret.to_owned()),
            )
        );
        assert!(!debug.contains(secret));
    }

    #[test]
    fn schema_test_receipt_binds_the_exact_signing_policy_without_granting_authority() {
        let prepared = production_prepared_package("fixture-signer-one");
        let suite = validate_fixture_journeys(JOURNEY_SOURCE, prepared.registry())
            .expect("Production journey suite validates");
        let (candidate, _) = derive_prepared_schema_test_candidate(&prepared, &suite, 16)
            .expect("unsigned candidate derives without activation authority");
        let bytes = receipt_for_candidate(&candidate, &suite)
            .canonical_bytes()
            .expect("receipt canonicalizes");
        validate_schema_test_receipt_for_package(&bytes, &prepared, &suite)
            .expect("exact unsigned candidate revalidates its receipt");

        let changed_policy = production_prepared_package("fixture-signer-two");
        assert_eq!(
            validate_schema_test_receipt_for_package(&bytes, &changed_policy, &suite),
            Err(FixtureError::ReceiptBindingRefused)
        );
    }

    fn protected_credential_bindings(
        suite: &ValidatedFixtureJourneys,
    ) -> Vec<SchemaTestCredentialBinding> {
        suite
            .journeys
            .iter()
            .flat_map(|journey| {
                journey.steps.iter().map(move |step| {
                    SchemaTestCredentialBinding::bearer(
                        journey.id.clone(),
                        step.id.clone(),
                        Zeroizing::new("opaque.fixture.token".to_owned()),
                    )
                })
            })
            .collect()
    }

    fn assert_public_receipt_negatives(
        bytes: &[u8],
        fixture: &PackageFixture,
        suite: &ValidatedFixtureJourneys,
    ) {
        let noncanonical = [bytes, b"\n"].concat();
        assert_eq!(
            validate_schema_test_receipt_for_package(&noncanonical, &fixture.prepared, suite),
            Err(FixtureError::ReceiptShapeRefused)
        );

        let mut unknown: Value = serde_json::from_slice(bytes).expect("receipt parses");
        unknown["unknownAuthority"] = json!(true);
        let unknown = canonicalize_json(&unknown).expect("unknown receipt canonicalizes");
        assert_eq!(
            validate_schema_test_receipt_for_package(&unknown, &fixture.prepared, suite),
            Err(FixtureError::ReceiptShapeRefused)
        );
        assert_eq!(
            validate_schema_test_receipt_for_package(
                &vec![b'x'; MAX_RECEIPT_BYTES + 1],
                &fixture.prepared,
                suite,
            ),
            Err(FixtureError::ReceiptShapeRefused)
        );

        let changed_journey_bytes = [JOURNEY_SOURCE, b"\n# reviewed change\n"].concat();
        let changed_suite =
            validate_fixture_journeys(&changed_journey_bytes, fixture.package.registry())
                .expect("semantically equivalent changed journey validates");
        assert_eq!(
            validate_schema_test_receipt_for_package(bytes, &fixture.prepared, &changed_suite),
            Err(FixtureError::CandidateBindingRefused)
        );

        let rehashed_substitution = package_fixture_with_journeys(DIGEST_A, &changed_journey_bytes);
        assert_eq!(
            validate_schema_test_receipt_for_package(bytes, &rehashed_substitution.prepared, suite,),
            Err(FixtureError::CandidateBindingRefused)
        );

        let changed_fingerprint = package_fixture(DIGEST_B);
        assert_eq!(
            validate_schema_test_receipt_for_package(bytes, &changed_fingerprint.prepared, suite),
            Err(FixtureError::ReceiptBindingRefused)
        );

        for (field, replacement) in [
            ("apiVersion", json!("registry.invalid/v2")),
            ("kind", json!("ActivationApproval")),
            ("registryRevision", json!(DIGEST_B)),
            ("projectSourceRevision", json!("another-source")),
            ("compilerSourceRevision", json!("another-compiler")),
            ("candidatePackageRevision", json!(DIGEST_B)),
            ("sourceClosureSha256", json!(DIGEST_B)),
            ("migrationPlanSha256", json!(DIGEST_B)),
            ("signingInputSha256", json!(DIGEST_B)),
            ("targetManagedSchemaFingerprint", json!(DIGEST_B)),
            ("environment", json!("staging")),
            ("instanceId", json!("another-instance")),
            ("databaseId", json!("another-database")),
            ("sequence", json!(2)),
            ("priorPackageRevision", json!(DIGEST_B)),
            ("postgresMajor", json!(19)),
            ("successfulJourneyIds", json!(["another-journey"])),
            ("journeyFileSha256", json!(DIGEST_B)),
        ] {
            let mut changed: Value = serde_json::from_slice(bytes).expect("receipt parses");
            changed[field] = replacement;
            let changed = canonicalize_json(&changed).expect("changed receipt canonicalizes");
            assert!(matches!(
                validate_schema_test_receipt_for_package(&changed, &fixture.prepared, suite),
                Err(FixtureError::ReceiptBindingRefused)
            ));
        }
    }

    fn assert_candidate_build_substitutions_are_refused(
        fixture: &PackageFixture,
        suite: &ValidatedFixtureJourneys,
        execution: &SchemaTestExecutionFacts,
    ) {
        let changed_project = [fixture.project.as_slice(), b"\n"].concat();
        let modules = [FixtureModuleSource {
            id: "fixture-core",
            path: "sources/modules/fixture-core.yaml",
            bytes: &fixture.module,
            assets: &[],
        }];
        let changed_project_sources = SchemaTestSources {
            project: FixtureSourceFile {
                path: "sources/project.yaml",
                bytes: &changed_project,
            },
            modules: &modules,
            migration_plan: FixtureSourceFile {
                path: "database/migration-plan.json",
                bytes: &fixture.migration_plan,
            },
        };
        assert!(matches!(
            validate_schema_test_candidate(
                &fixture.package,
                &changed_project_sources,
                execution,
                suite,
            ),
            Err(FixtureError::CandidateBindingRefused)
        ));

        let changed_module = [fixture.module.as_slice(), b"\n"].concat();
        let changed_modules = [FixtureModuleSource {
            id: "fixture-core",
            path: "sources/modules/fixture-core.yaml",
            bytes: &changed_module,
            assets: &[],
        }];
        let changed_module_sources = SchemaTestSources {
            project: FixtureSourceFile {
                path: "sources/project.yaml",
                bytes: &fixture.project,
            },
            modules: &changed_modules,
            migration_plan: FixtureSourceFile {
                path: "database/migration-plan.json",
                bytes: &fixture.migration_plan,
            },
        };
        assert!(matches!(
            validate_schema_test_candidate(
                &fixture.package,
                &changed_module_sources,
                execution,
                suite,
            ),
            Err(FixtureError::CandidateBindingRefused)
        ));

        let changed_digest_project = String::from_utf8(fixture.project.clone())
            .expect("fixture is UTF-8")
            .replacen(
                &module_digest(&parse_module_yaml(&fixture.module).unwrap()),
                DIGEST_B,
                1,
            )
            .into_bytes();
        let changed_digest_sources = SchemaTestSources {
            project: FixtureSourceFile {
                path: "sources/project.yaml",
                bytes: &changed_digest_project,
            },
            modules: &modules,
            migration_plan: FixtureSourceFile {
                path: "database/migration-plan.json",
                bytes: &fixture.migration_plan,
            },
        };
        assert!(matches!(
            validate_schema_test_candidate(
                &fixture.package,
                &changed_digest_sources,
                execution,
                suite,
            ),
            Err(FixtureError::CandidateBindingRefused)
        ));

        let changed_package = package_fixture(DIGEST_B);
        assert!(matches!(
            validated_candidate(&changed_package, execution, suite),
            Err(FixtureError::CandidateBindingRefused)
        ));

        let changed_plan = [fixture.migration_plan.as_slice(), b"\n"].concat();
        let changed_plan_sources = SchemaTestSources {
            project: FixtureSourceFile {
                path: "sources/project.yaml",
                bytes: &fixture.project,
            },
            modules: &modules,
            migration_plan: FixtureSourceFile {
                path: "database/migration-plan.json",
                bytes: &changed_plan,
            },
        };
        assert!(matches!(
            validate_schema_test_candidate(
                &fixture.package,
                &changed_plan_sources,
                execution,
                suite,
            ),
            Err(FixtureError::CandidateBindingRefused)
        ));

        for changed_execution in [
            SchemaTestExecutionFacts {
                schema_fingerprint: DIGEST_B.to_owned(),
                ..execution.clone()
            },
            SchemaTestExecutionFacts {
                package_revision: DIGEST_B.to_owned(),
                ..execution.clone()
            },
            SchemaTestExecutionFacts {
                environment: "staging".to_owned(),
                ..execution.clone()
            },
            SchemaTestExecutionFacts {
                sequence: 2,
                ..execution.clone()
            },
        ] {
            assert!(matches!(
                validated_candidate(fixture, &changed_execution, suite),
                Err(FixtureError::CandidateBindingRefused)
            ));
        }
    }

    fn assert_receipt_substitutions_are_refused(
        bytes: &[u8],
        candidate: &ValidatedSchemaTestCandidate,
        suite: &ValidatedFixtureJourneys,
    ) {
        for (field, replacement) in [
            ("sourceClosureSha256", json!(DIGEST_B)),
            ("journeyFileSha256", json!(DIGEST_B)),
            ("targetManagedSchemaFingerprint", json!(DIGEST_B)),
            ("environment", json!("staging")),
            ("sequence", json!(2)),
            ("priorPackageRevision", json!(DIGEST_B)),
            ("postgresMajor", json!(17)),
            ("projectSourceRevision", json!("substituted")),
            ("compilerSourceRevision", json!("substituted")),
            ("migrationPlanSha256", json!(DIGEST_B)),
        ] {
            let mut value: Value = serde_json::from_slice(bytes).expect("receipt JSON parses");
            value[field] = replacement;
            let changed = canonicalize_json(&value).expect("changed receipt canonicalizes");
            assert_eq!(
                revalidate_schema_test_receipt(&changed, candidate, suite),
                Err(FixtureError::ReceiptBindingRefused)
            );
        }
    }

    async fn assert_closed_response_negatives(
        suite: &ValidatedFixtureJourneys,
        candidate: &ValidatedSchemaTestCandidate,
    ) {
        let create = &suite.journeys[0].steps[0];
        let identifier = "123e4567-e89b-12d3-a456-426614174000";
        let unreadable = json!({
            "data": {
                "recordIdentifier": identifier,
                "revisionIdentifier": "1",
                "snapshot": "rs1_00000000-0000-4000-8000-000000000001",
                "domainData": {
                    "jurisdiction": "zone-a", "label": "first", "note": "initial",
                    "quantity": 1, "record_id": "canary"
                }
            },
            "meta": {
                "registryIdentifier": "fixture-registry",
                "datasetIdentifier": "fixture-registry",
                "entityTypeIdentifier": "widget"
            },
        });
        assert_eq!(
            assert_response(create, StatusCode::CREATED, &unreadable),
            Err(FixtureError::ExpectationMismatch)
        );
        let mut bounded = unreadable.clone();
        bounded["data"]["domainData"]
            .as_object_mut()
            .unwrap()
            .remove("record_id");
        assert_response(create, StatusCode::CREATED, &bounded)
            .expect("current closed mutation envelope is admitted");
        bounded["data"]["snapshot"] = json!("not-a-snapshot-reference");
        assert_eq!(
            assert_response(create, StatusCode::CREATED, &bounded),
            Err(FixtureError::ResponseShapeRefused)
        );
        bounded["data"].as_object_mut().unwrap().remove("snapshot");
        assert_eq!(
            assert_response(create, StatusCode::CREATED, &bounded),
            Err(FixtureError::ResponseShapeRefused)
        );

        let refusal = &suite.journeys[0].steps[5];
        let extra_refusal = json!({
            "type": "urn:registry-server:problem:resource.not_found",
            "title": "Not Found",
            "status": 404,
            "detail": "The requested resource was not found.",
            "code": "resource.not_found",
            "traceId": "11111111111111111111111111111111",
            "canaryDetail": "protected"
        });
        assert_eq!(
            assert_response(refusal, StatusCode::NOT_FOUND, &extra_refusal),
            Err(FixtureError::ResponseShapeRefused)
        );
        let changed_detail = json!({
            "type": "urn:registry-server:problem:resource.not_found",
            "title": "Not Found",
            "status": 404,
            "detail": "protected canary",
            "code": "resource.not_found",
            "traceId": "11111111111111111111111111111111"
        });
        assert_eq!(
            assert_response(refusal, StatusCode::NOT_FOUND, &changed_detail),
            Err(FixtureError::ExpectationMismatch)
        );
        let correlated_refusal = json!({
            "type": "urn:registry-server:problem:resource.not_found",
            "title": "Not Found",
            "status": 404,
            "detail": "The requested resource was not found.",
            "code": "resource.not_found",
            "traceId": "11111111111111111111111111111111"
        });
        let mismatched_trace = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(
                "traceparent",
                "00-22222222222222222222222222222222-3333333333333333-01",
            )
            .body(Body::from(
                serde_json::to_vec(&correlated_refusal).expect("problem response serializes"),
            ))
            .expect("problem response builds");
        let mut observations = BTreeMap::new();
        assert_eq!(
            accept_response(refusal, mismatched_trace, &mut observations).await,
            Err(FixtureError::ResponseShapeRefused),
            "the fixture executor refuses disagreement between body and header trace IDs"
        );

        let malformed_list = json!({
            "items": [{
                "recordIdentifier": identifier,
                "revisionIdentifier": "1",
                "domainData": {"record_id": "canary"}
            }],
            "pageInfo": {"nextCursor": null},
            "meta": {
                "registryIdentifier": "fixture-registry",
                "datasetIdentifier": "fixture-registry",
                "entityTypeIdentifier": "widget"
            }
        });
        assert!(
            assert_response(&suite.journeys[0].steps[2], StatusCode::OK, &malformed_list,).is_err()
        );

        let malformed_batch = json!({
            "results": [{"operation": "create"}, {"operation": "create"}],
            "snapshot": "rs1_00000000-0000-4000-8000-000000000001"
        });
        assert_eq!(
            assert_response(
                &suite.journeys[0].steps[4],
                StatusCode::OK,
                &malformed_batch,
            ),
            Err(FixtureError::ResponseShapeRefused)
        );

        assert_eq!(
            execute_scripted(suite, candidate, ScriptMode::Oversized)
                .await
                .unwrap_err(),
            FixtureError::ResponseTooLarge
        );
        assert_eq!(
            execute_scripted(suite, candidate, ScriptMode::PartialFailure)
                .await
                .unwrap_err(),
            FixtureError::ExpectationMismatch
        );
    }

    struct PackageFixture {
        prepared: PreparedPackage,
        package: VerifiedPackage,
        project: Vec<u8>,
        module: Vec<u8>,
        migration_plan: Vec<u8>,
    }

    fn validated_candidate(
        fixture: &PackageFixture,
        execution: &SchemaTestExecutionFacts,
        suite: &ValidatedFixtureJourneys,
    ) -> Result<ValidatedSchemaTestCandidate, FixtureError> {
        let modules = [FixtureModuleSource {
            id: "fixture-core",
            path: "sources/modules/fixture-core.yaml",
            bytes: &fixture.module,
            assets: &[],
        }];
        validate_schema_test_candidate(
            &fixture.package,
            &SchemaTestSources {
                project: FixtureSourceFile {
                    path: "sources/project.yaml",
                    bytes: &fixture.project,
                },
                modules: &modules,
                migration_plan: FixtureSourceFile {
                    path: "database/migration-plan.json",
                    bytes: &fixture.migration_plan,
                },
            },
            execution,
            suite,
        )
    }

    fn package_fixture(schema_fingerprint: &str) -> PackageFixture {
        package_fixture_with_journeys(schema_fingerprint, JOURNEY_SOURCE)
    }

    fn package_fixture_with_journeys(
        schema_fingerprint: &str,
        journey_source: &[u8],
    ) -> PackageFixture {
        let module = parse_module_yaml(MODULE_SOURCE).expect("module fixture parses");
        let project = String::from_utf8(PROJECT_TEMPLATE.to_vec())
            .expect("project fixture is UTF-8")
            .replace("MODULE_DIGEST", &module_digest(&module))
            .into_bytes();
        let prepared = prepare_package(PackageBuildRequest {
            environment: "local".to_owned(),
            instance_id: "fixture-instance".to_owned(),
            database_id: DATABASE_ID.to_owned(),
            sequence: 1,
            prior_revision: None,
            compiler_source_revision: COMPILER_SOURCE_REVISION.to_owned(),
            schema_fingerprint: schema_fingerprint.to_owned(),
            signature_policy: SignaturePolicy {
                threshold: 0,
                key_ids: Vec::new(),
            },
            project: PackageSourceFile {
                path: "sources/project.yaml".to_owned(),
                bytes: project.clone(),
            },
            modules: vec![PackageModuleSource {
                id: "fixture-core".to_owned(),
                path: "sources/modules/fixture-core.yaml".to_owned(),
                bytes: MODULE_SOURCE.to_vec(),
                assets: Vec::new(),
            }],
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: journey_source.to_vec(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        })
        .expect("fixture package prepares");
        let migration_plan = prepared
            .file_bytes()
            .get("database/migration-plan.json")
            .expect("prepared package contains migration plan")
            .clone();
        let temporary = tempfile::tempdir().expect("temporary root creates");
        let package_root = temporary
            .path()
            .canonicalize()
            .expect("temporary root canonicalizes")
            .join("package");
        prepared
            .publish_to_directory(&package_root, Vec::new())
            .expect("local package publishes");
        let package = load_package(
            &package_root,
            &PackageLoadContext {
                environment: "local",
                instance_id: "fixture-instance",
                database_id: DATABASE_ID,
                database_initialization_environment: "local",
                compiler_source_revision: COMPILER_SOURCE_REVISION,
                trust_anchor: None,
                intent: PackageIntent::InitialActivation,
            },
        )
        .expect("fixture package rederives and verifies");
        PackageFixture {
            prepared,
            package,
            project,
            module: MODULE_SOURCE.to_vec(),
            migration_plan,
        }
    }

    fn production_prepared_package(key_id: &str) -> PreparedPackage {
        let module = parse_module_yaml(MODULE_SOURCE).expect("module fixture parses");
        let project = String::from_utf8(PROJECT_TEMPLATE.to_vec())
            .expect("project fixture is UTF-8")
            .replace("MODULE_DIGEST", &module_digest(&module))
            .replace("environment: local", "environment: production")
            .into_bytes();
        prepare_package(PackageBuildRequest {
            environment: "production".to_owned(),
            instance_id: "fixture-instance".to_owned(),
            database_id: DATABASE_ID.to_owned(),
            sequence: 1,
            prior_revision: None,
            compiler_source_revision: COMPILER_SOURCE_REVISION.to_owned(),
            schema_fingerprint: DIGEST_A.to_owned(),
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.to_owned()],
            },
            project: PackageSourceFile {
                path: "sources/project.yaml".to_owned(),
                bytes: project,
            },
            modules: vec![PackageModuleSource {
                id: "fixture-core".to_owned(),
                path: "sources/modules/fixture-core.yaml".to_owned(),
                bytes: MODULE_SOURCE.to_vec(),
                assets: Vec::new(),
            }],
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: JOURNEY_SOURCE.to_vec(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        })
        .expect("Production candidate package prepares")
    }

    fn execution_facts(
        package: &VerifiedPackage,
        schema_fingerprint: &str,
        postgres_major: u16,
    ) -> SchemaTestExecutionFacts {
        SchemaTestExecutionFacts::from_database_snapshot(DatabaseExecutionSnapshot {
            current_database: "fixture_test_database".to_owned(),
            package_id: package.manifest().package_id.clone(),
            environment: package.manifest().environment.clone(),
            instance_id: package.manifest().instance_id.clone(),
            database_id: package.manifest().database_id.clone(),
            package_revision: package.manifest().package_revision.clone(),
            sequence: package.manifest().sequence,
            schema_fingerprint: schema_fingerprint.to_owned(),
            postgres_major,
            maintenance_status: "ready".to_owned(),
        })
    }

    #[derive(Clone, Copy)]
    enum ScriptMode {
        Success,
        Oversized,
        PartialFailure,
    }

    async fn execute_scripted(
        suite: &ValidatedFixtureJourneys,
        candidate: &ValidatedSchemaTestCandidate,
        mode: ScriptMode,
    ) -> Result<SuccessfulFixtureJourneys, FixtureError> {
        for journey in &suite.journeys {
            let mut observations = BTreeMap::<String, Observation>::new();
            for (index, step) in journey.steps.iter().enumerate() {
                let _request = fixture_request("test-journey", step, &observations, None)?;
                let response = scripted_response(index, mode)?;
                let status = response.status();
                let headers = response.headers().clone();
                let bytes = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
                    .await
                    .map_err(|_| FixtureError::ResponseTooLarge)?;
                let document =
                    parse_json_strict(&bytes).map_err(|_| FixtureError::ResponseShapeRefused)?;
                assert_response(step, status, &document)?;
                if !step.capture_results.is_empty() {
                    capture_immediate_action_results(step, &document, &mut observations)?;
                }
                if let Some(capture) = step.capture.as_ref() {
                    let kind = capture_observation_kind(step, &headers, &document)?;
                    observations.insert(capture.clone(), Observation { kind, document });
                }
            }
        }
        Ok(SuccessfulFixtureJourneys {
            registry_revision: suite.registry_revision.clone(),
            file_sha256: suite.file_sha256.clone(),
            journey_ids: sorted_journey_ids(suite),
            candidate_binding_sha256: candidate_binding_sha256(candidate),
        })
    }

    #[test]
    fn request_action_fixture_uses_discovered_action_if_match() {
        let route = CompiledRoute {
            id: "records.request.request.submit".to_owned(),
            entity_id: "request".to_owned(),
            method: HttpMethod::Post,
            path: "/v1/records/requests/{record_id}/actions/submit".to_owned(),
            operation: Operation::SubmitRequest,
            query_kind: None,
            revision_kind: None,
            request_stage: None,
            maximum_records: Some(1),
            access_profiles: vec!["submitter".to_owned()],
            default_access_profile: "submitter".to_owned(),
        };
        let profile: AccessProfileSource = serde_json::from_value(json!({
            "id": "submitter",
            "principalClaim": "principal",
            "operations": ["submit_request"]
        }))
        .expect("test profile parses");
        let step = ValidatedStep {
            id: "submit-request".to_owned(),
            entity: Some("request".to_owned()),
            action_id: None,
            access_profile: "submitter".to_owned(),
            claims: ClaimsSource::default(),
            route: FixtureRoute::Entity(route),
            profile,
            response_readable_fields: BTreeSet::new(),
            action: ActionSource::SubmitRequest {
                record_ref: "before-submit".to_owned(),
                etag_ref: "before-submit".to_owned(),
            },
            expect: ExpectationSource {
                outcome: ExpectedOutcome::Success,
                status: 200,
                problem_code: None,
                fields: Map::new(),
                count: None,
            },
            capture: None,
            capture_results: BTreeMap::new(),
        };
        let mut observations = BTreeMap::new();
        observations.insert(
            "before-submit".to_owned(),
            Observation {
                kind: ObservationKind::Record {
                    record_id: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
                    etag: "\"rs-ordinary-get-etag\"".to_owned(),
                },
                document: json!({
                    "data": {
                        "recordIdentifier": "123e4567-e89b-12d3-a456-426614174000",
                        "revisionIdentifier": "1",
                        "request": {
                            "serverState": "draft",
                            "proposalVersion": 1,
                            "effectDigest": null,
                            "actions": [{
                                "operation": "submit_request",
                                "stage": null,
                                "href": "/v1/records/requests/123e4567-e89b-12d3-a456-426614174000/actions/submit",
                                "ifMatch": "\"rs-action-submit\""
                            }]
                        },
                        "domainData": {}
                    },
                    "meta": {
                        "registryIdentifier": "fixture-registry",
                        "datasetIdentifier": "fixture-registry",
                        "entityTypeIdentifier": "request"
                    }
                }),
            },
        );

        let request = fixture_request("test-journey", &step, &observations, Some("a.b.c"))
            .expect("request action uses discovered action precondition");
        assert_eq!(
            request
                .headers()
                .get(IF_MATCH)
                .and_then(|value| value.to_str().ok()),
            Some("\"rs-action-submit\"")
        );

        observations
            .get_mut("before-submit")
            .expect("observation exists")
            .document["data"]["request"]
            .as_object_mut()
            .expect("request metadata is object")
            .remove("actions");
        assert_eq!(
            fixture_request("test-journey", &step, &observations, Some("a.b.c")).unwrap_err(),
            FixtureError::RequestConstructionRefused
        );
    }

    fn scripted_response(index: usize, mode: ScriptMode) -> Result<Response<Body>, FixtureError> {
        if matches!(mode, ScriptMode::Oversized) {
            return Response::builder()
                .status(200)
                .body(Body::from(vec![b'x'; MAX_RESPONSE_BYTES + 1]))
                .map_err(|_| FixtureError::ExecutionRefused);
        }
        let id = "123e4567-e89b-12d3-a456-426614174000";
        let second = "123e4567-e89b-12d3-a456-426614174001";
        let third = "123e4567-e89b-12d3-a456-426614174002";
        let meta = json!({
            "registryIdentifier": "fixture-registry",
            "datasetIdentifier": "fixture-registry",
            "entityTypeIdentifier": "widget"
        });
        let (status, document, etag) = match index {
            0 => (
                201,
                json!({
                    "data": {
                        "recordIdentifier": id,
                        "revisionIdentifier": "1",
                        "domainData": {"jurisdiction":"zone-a","label":"first","note":"initial","quantity":1},
                        "snapshot":"rs1_00000000-0000-4000-8000-000000000001"
                    },
                    "meta": meta
                }),
                Some("\"rs-one\""),
            ),
            1 => (
                200,
                json!({
                    "data": {
                        "recordIdentifier": id,
                        "revisionIdentifier": "1",
                        "domainData": {"jurisdiction":"zone-a","label":"first","note":"initial","quantity":1}
                    },
                    "meta": meta
                }),
                Some("\"rs-one\""),
            ),
            2 => (
                200,
                json!({
                    "items":[{
                        "recordIdentifier": id,
                        "revisionIdentifier": "1",
                        "domainData": {"jurisdiction":"zone-a","label":"first","note":"initial","quantity":1}
                    }],
                    "pageInfo":{"nextCursor":null},
                    "meta": meta
                }),
                None,
            ),
            3 => (
                200,
                json!({
                    "data": {
                        "recordIdentifier": id,
                        "revisionIdentifier": "2",
                        "domainData": {"jurisdiction":"zone-a","label":"first","note":"revised","quantity":1},
                        "snapshot":"rs1_00000000-0000-4000-8000-000000000002"
                    },
                    "meta": meta
                }),
                Some("\"rs-two\""),
            ),
            4 => (
                200,
                json!({"results":[
                    {"operation":"create","id":second,"revision":1,"etag":"\"rs-second\"","data":{"jurisdiction":"zone-a","label":"second","quantity":2}},
                    {"operation":"create","id":third,"revision":1,"etag":"\"rs-third\"","data":{"jurisdiction":"zone-a","label":"third","quantity":3}}
                ],"snapshot":"rs1_00000000-0000-4000-8000-000000000003"}),
                None,
            ),
            5 => (
                404,
                json!({
                    "type":"urn:registry-server:problem:resource.not_found",
                    "title":"Not Found",
                    "status":404,
                    "detail":"The requested resource was not found.",
                    "code": if matches!(mode, ScriptMode::PartialFailure) {
                        "query.invalid"
                    } else {
                        "resource.not_found"
                    },
                    "traceId":"11111111111111111111111111111111"
                }),
                None,
            ),
            _ => return Err(FixtureError::ExecutionRefused),
        };
        let mut builder = Response::builder().status(status);
        if let Some(value) = etag {
            builder = builder.header(ETAG, value);
        }
        builder
            .body(Body::from(
                serde_json::to_vec(&document).map_err(|_| FixtureError::ExecutionRefused)?,
            ))
            .map_err(|_| FixtureError::ExecutionRefused)
    }
}
