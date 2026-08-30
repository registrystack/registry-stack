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
use axum::http::{Method, Request, Response, StatusCode};
use axum::Router;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
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
use crate::contract::{parse_module_yaml, parse_project_yaml, ModuleAssetSource};
use crate::contract::{AccessProfileSource, LookupValueOrigin, Operation};
use crate::derived_sql::MAX_DERIVED_SQL_BYTES;
use crate::model::CompiledRoute;
use crate::model::{CompiledRegistry, HttpMethod};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::JourneyTooLarge => "the fixture journey exceeded a fixed bound",
            Self::JourneyShapeRefused => "the fixture journey shape was refused",
            Self::JourneyVersionRefused => "the fixture journey version was refused",
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
    entity: String,
    access_profile: String,
    #[serde(default)]
    claims: ClaimsSource,
    request: ActionSource,
    expect: ExpectationSource,
    #[serde(default)]
    capture: Option<String>,
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
    List,
    Query {
        #[serde(default)]
        select: BTreeSet<String>,
        #[serde(default)]
        top: Option<u16>,
        #[serde(default)]
        count: bool,
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
}

impl ActionSource {
    fn operation(&self) -> Operation {
        match self {
            Self::Create { .. } => Operation::Create,
            Self::Get { .. } => Operation::Get,
            Self::List | Self::Query { .. } | Self::ReadPath { .. } => Operation::List,
            Self::Lookup { .. } => Operation::Lookup,
            Self::Patch { .. } => Operation::Patch,
            Self::Batch { .. } => Operation::Batch,
        }
    }

    fn route_id(&self, entity_id: &str) -> String {
        let suffix = match self {
            Self::Create { .. } => "create".to_owned(),
            Self::Get { .. } => "get".to_owned(),
            Self::List | Self::Query { .. } => "list".to_owned(),
            Self::Lookup { .. } => "lookup".to_owned(),
            Self::ReadPath { path, .. } => format!("path.{path}"),
            Self::Patch { .. } => "patch".to_owned(),
            Self::Batch { .. } => "batch".to_owned(),
        };
        format!("records.{entity_id}.{suffix}")
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FieldChangeSource {
    field: String,
    value: Value,
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
    entity: String,
    access_profile: String,
    claims: ClaimsSource,
    route: CompiledRoute,
    profile: AccessProfileSource,
    response_readable_fields: BTreeSet<String>,
    action: ActionSource,
    expect: ExpectationSource,
    capture: Option<String>,
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
    let document: JourneyDocument = serde_path_to_error::deserialize(deserializer)
        .map_err(|_| FixtureError::JourneyShapeRefused)?;
    if document.api_version != JOURNEY_API_VERSION {
        return Err(FixtureError::JourneyVersionRefused);
    }
    if document.journeys.is_empty() || document.journeys.len() > MAX_JOURNEYS {
        return Err(FixtureError::JourneyBoundsRefused);
    }

    let mut journey_ids = BTreeSet::new();
    let mut step_ids = BTreeSet::new();
    let mut total_steps = 0usize;
    let mut journeys = Vec::with_capacity(document.journeys.len());
    for journey in document.journeys {
        let mut capture_ids = BTreeSet::new();
        if !valid_stable_id(&journey.id) || !journey_ids.insert(journey.id.clone()) {
            return Err(if valid_stable_id(&journey.id) {
                FixtureError::DuplicateIdentifier
            } else {
                FixtureError::LogicalReferenceRefused
            });
        }
        if journey.steps.is_empty() || journey.steps.len() > MAX_STEPS_PER_JOURNEY {
            return Err(FixtureError::JourneyBoundsRefused);
        }
        total_steps = total_steps
            .checked_add(journey.steps.len())
            .ok_or(FixtureError::JourneyBoundsRefused)?;
        if total_steps > MAX_TOTAL_STEPS {
            return Err(FixtureError::JourneyBoundsRefused);
        }
        let mut steps = Vec::with_capacity(journey.steps.len());
        for step in journey.steps {
            if !valid_stable_id(&step.id) || !step_ids.insert(step.id.clone()) {
                return Err(if valid_stable_id(&step.id) {
                    FixtureError::DuplicateIdentifier
                } else {
                    FixtureError::LogicalReferenceRefused
                });
            }
            validate_action_references(&step.request, &capture_ids)?;
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
            let entity = registry
                .entities()
                .get(&step.entity)
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            let profile = entity
                .access_profiles
                .get(&step.access_profile)
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            let operation = step.request.operation();
            if !matches!(step.request, ActionSource::ReadPath { .. })
                && !profile.operations.contains(&operation)
            {
                return Err(FixtureError::LogicalReferenceRefused);
            }
            let expected_route_id = step.request.route_id(&step.entity);
            let route = registry
                .routes()
                .routes
                .iter()
                .find(|route| {
                    route.entity_id == step.entity
                        && route.id == expected_route_id
                        && route.operation == operation
                        && route.method == operation_method(operation)
                        && route.access_profiles.contains(&step.access_profile)
                })
                .cloned()
                .ok_or(FixtureError::LogicalReferenceRefused)?;
            validate_claims(&step.claims, profile, step.expect.outcome)?;
            validate_action_fields(&step.request, registry, entity, profile)?;
            validate_expectation(&step.expect, operation, profile, capture.is_some())?;
            let response_readable_fields = match &step.request {
                ActionSource::ReadPath { path, .. } => profile
                    .read_paths
                    .iter()
                    .find(|grant| grant.path == *path)
                    .map(|grant| grant.readable_fields.clone())
                    .ok_or(FixtureError::LogicalReferenceRefused)?,
                _ => profile.readable_fields.clone(),
            };
            steps.push(ValidatedStep {
                id: step.id,
                entity: step.entity,
                access_profile: step.access_profile,
                claims: step.claims,
                route,
                profile: profile.clone(),
                response_readable_fields,
                action: step.request,
                expect: step.expect,
                capture,
            });
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
    captures: &BTreeSet<String>,
) -> Result<(), FixtureError> {
    let references: &[&str] = match action {
        ActionSource::Get { record_ref } => &[record_ref],
        ActionSource::ReadPath { record_ref, .. } => &[record_ref],
        ActionSource::Patch {
            record_ref,
            etag_ref,
            ..
        } => &[record_ref, etag_ref],
        ActionSource::Create { .. }
        | ActionSource::List
        | ActionSource::Query { .. }
        | ActionSource::Lookup { .. }
        | ActionSource::Batch { .. } => &[],
    };
    if references
        .iter()
        .any(|identifier| !valid_stable_id(identifier) || !captures.contains(*identifier))
    {
        return Err(FixtureError::LogicalReferenceRefused);
    }
    Ok(())
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

fn validate_action_fields(
    action: &ActionSource,
    registry: &CompiledRegistry,
    entity: &crate::model::CompiledEntity,
    profile: &AccessProfileSource,
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
        ActionSource::Get { .. } | ActionSource::List => Ok(()),
        ActionSource::Query { select, top, count } => {
            validate_structured_query(registry, entity, profile, None, select, *top, *count)
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
        ActionSource::ReadPath {
            path,
            select,
            top,
            count,
            ..
        } => validate_structured_query(registry, entity, profile, Some(path), select, *top, *count),
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
    }
}

fn validate_structured_query(
    registry: &CompiledRegistry,
    entity: &crate::model::CompiledEntity,
    profile: &AccessProfileSource,
    read_path: Option<&str>,
    select: &BTreeSet<String>,
    top: Option<u16>,
    count: bool,
) -> Result<(), FixtureError> {
    if top.is_some_and(|top| top == 0 || top > 100) {
        return Err(FixtureError::JourneyBoundsRefused);
    }
    if let Some(path) = read_path {
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
    Ok(())
}

fn compiled_field_exists(entity: &crate::model::CompiledEntity, field: &str) -> bool {
    entity.fields.contains_key(field) || entity.derived_fields.contains_key(field)
}

fn validate_expectation(
    expectation: &ExpectationSource,
    operation: Operation,
    profile: &AccessProfileSource,
    captures: bool,
) -> Result<(), FixtureError> {
    if expectation
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
                | Operation::Batch => 200,
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

struct Observation {
    record_id: String,
    etag: String,
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
        fixture_request(step, &self.observations, Some(bearer)).map(Some)
    }

    /// Execute every validated journey through the captured Registry router.
    /// A failure consumes the runner and therefore cannot be converted into a
    /// completed result or receipt by skipping the remaining steps.
    pub async fn run_all(mut self) -> Result<CompletedPostgresFixtureTest, FixtureError> {
        while let Some(request) = self.next_request()? {
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
        accept_response(&step, response, &mut self.observations).await?;
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
    for journey in &suite.journeys {
        for step in &journey.steps {
            let bearer = credential_map
                .get(&(journey.id.clone(), step.id.clone()))
                .ok_or(FixtureError::RequestConstructionRefused)?;
            match (step.profile.anonymous, bearer.as_ref()) {
                (true, None) => {}
                (true, Some(_)) | (false, None) => {
                    return Err(FixtureError::RequestConstructionRefused);
                }
                (false, Some(token)) => {
                    runtime.authenticate_exact(step, token.as_str()).await?;
                }
            }
            let bearer_token = bearer.as_ref().map(|token| token.as_str());
            let request = fixture_request(step, &observations, bearer_token)?;
            let response = runtime
                .app
                .call(request)
                .await
                .map_err(|error| match error {})?;
            accept_response(step, response, &mut observations).await?;
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
    step: &ValidatedStep,
    observations: &BTreeMap<String, Observation>,
    bearer_token: Option<&str>,
) -> Result<Request<Body>, FixtureError> {
    let mut path = step.route.path.clone();
    let mut method = Method::GET;
    let mut body = Body::empty();
    let mut content_type = None;
    let mut if_match = None;
    let mut extra_query_options = Vec::new();
    match &step.action {
        ActionSource::Create { data } => {
            method = Method::POST;
            body = json_body(&json!({"data": data}))?;
            content_type = Some("application/json");
        }
        ActionSource::Get { record_ref } => {
            let observed = observations
                .get(record_ref)
                .ok_or(FixtureError::RequestConstructionRefused)?;
            path = path.replace("{record_id}", &observed.record_id);
        }
        ActionSource::List => {}
        ActionSource::Query { select, top, count } => {
            extra_query_options = fixture_query_options(step, None, select, *top, *count)?;
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
            let observed = observations
                .get(record_ref)
                .ok_or(FixtureError::RequestConstructionRefused)?;
            path = path.replace("{record_id}", &observed.record_id);
            extra_query_options =
                fixture_query_options(step, Some(read_path), select, *top, *count)?;
        }
        ActionSource::Patch {
            record_ref,
            etag_ref,
            changes,
        } => {
            let record = observations
                .get(record_ref)
                .ok_or(FixtureError::RequestConstructionRefused)?;
            let etag = observations
                .get(etag_ref)
                .ok_or(FixtureError::RequestConstructionRefused)?;
            path = path.replace("{record_id}", &record.record_id);
            method = Method::PATCH;
            body = json_body(&Value::Array(
                changes
                    .iter()
                    .map(|change| {
                        json!({"op":"replace","path":format!("/data/{}", change.field),"value":change.value})
                    })
                    .collect(),
            ))?;
            content_type = Some("application/json-patch+json");
            if_match = Some(etag.etag.as_str());
        }
        ActionSource::Batch { items } => {
            method = Method::POST;
            body = json_body(&batch_body(items))?;
            content_type = Some("application/json");
        }
    }
    if !path.starts_with('/') || path.contains(['?', '#']) || path.contains('{') {
        return Err(FixtureError::RequestConstructionRefused);
    }
    path.push_str("?accessProfile=");
    path.push_str(&step.access_profile);
    for (name, value) in extra_query_options {
        path.push('&');
        path.push_str(name);
        path.push('=');
        path.push_str(&value);
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
        ActionSource::Create { .. } | ActionSource::Patch { .. } | ActionSource::Batch { .. }
    ) {
        let key = format!("fixture-{}-{}", step.entity, step.id);
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
    if step.access_profile.is_empty() {
        return Err(FixtureError::RequestConstructionRefused);
    }
    Ok(parameters)
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
    if let Some(capture) = step.capture.as_ref() {
        let record_id = document
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == *value))
            .ok_or(FixtureError::ResponseShapeRefused)?;
        let etag = headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.len() <= MAX_BINDING_BYTES)
            .ok_or(FixtureError::ResponseShapeRefused)?;
        observations.insert(
            capture.clone(),
            Observation {
                record_id: record_id.to_owned(),
                etag: etag.to_owned(),
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
            let object = exact_object(document, &["type", "title", "status", "detail", "code"])?;
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
            ActionSource::List | ActionSource::Query { .. } | ActionSource::ReadPath { .. } => {
                let include_count = matches!(
                    step.action,
                    ActionSource::Query { count: true, .. }
                        | ActionSource::ReadPath { count: true, .. }
                );
                let expected_keys: &[&str] = if include_count {
                    &["items", "pageInfo", "count"]
                } else {
                    &["items", "pageInfo"]
                };
                let object = exact_object(document, expected_keys)?;
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
                let object = exact_object(document, &["results"])?;
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
                    assert_record_members(object, &step.response_readable_fields, &Map::new())?;
                }
            }
            ActionSource::Create { .. }
            | ActionSource::Get { .. }
            | ActionSource::Lookup { .. }
            | ActionSource::Patch { .. } => {
                assert_record_shape(
                    document,
                    &step.response_readable_fields,
                    &step.expect.fields,
                )?;
            }
        },
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
    let object = exact_object(value, &["id", "revision", "data"])?;
    assert_record_members(object, readable_fields, expected_fields)
}

fn assert_record_members(
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
        Operation::Create | Operation::Lookup | Operation::Batch => HttpMethod::Post,
        Operation::Get | Operation::List | Operation::Revisions => HttpMethod::Get,
        Operation::Patch => HttpMethod::Patch,
        Operation::Tombstone => HttpMethod::Delete,
    }
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
            "id": identifier,
            "revision": 1,
            "data": {
                "jurisdiction": "zone-a", "label": "first", "note": "initial",
                "quantity": 1, "record_id": "canary"
            }
        });
        assert_eq!(
            assert_response(create, StatusCode::CREATED, &unreadable),
            Err(FixtureError::ExpectationMismatch)
        );

        let refusal = &suite.journeys[0].steps[5];
        let extra_refusal = json!({
            "type": "urn:registry-server:problem:resource.not_found",
            "title": "Not Found",
            "status": 404,
            "detail": "The requested resource was not found.",
            "code": "resource.not_found",
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
            "code": "resource.not_found"
        });
        assert_eq!(
            assert_response(refusal, StatusCode::NOT_FOUND, &changed_detail),
            Err(FixtureError::ExpectationMismatch)
        );

        let malformed_list = json!({
            "items": [{"id": identifier, "revision": 1, "data": {"record_id": "canary"}}],
            "nextCursor": null
        });
        assert!(
            assert_response(&suite.journeys[0].steps[2], StatusCode::OK, &malformed_list,).is_err()
        );

        let malformed_batch =
            json!({"results": [{"operation": "create"}, {"operation": "create"}]});
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
                let _request = fixture_request(step, &observations, None)?;
                let response = scripted_response(index, mode)?;
                let status = response.status();
                let headers = response.headers().clone();
                let bytes = to_bytes(response.into_body(), MAX_RESPONSE_BYTES)
                    .await
                    .map_err(|_| FixtureError::ResponseTooLarge)?;
                let document =
                    parse_json_strict(&bytes).map_err(|_| FixtureError::ResponseShapeRefused)?;
                assert_response(step, status, &document)?;
                if let Some(capture) = step.capture.as_ref() {
                    observations.insert(
                        capture.clone(),
                        Observation {
                            record_id: document
                                .get("id")
                                .and_then(Value::as_str)
                                .ok_or(FixtureError::ResponseShapeRefused)?
                                .to_owned(),
                            etag: headers
                                .get(ETAG)
                                .and_then(|value| value.to_str().ok())
                                .ok_or(FixtureError::ResponseShapeRefused)?
                                .to_owned(),
                        },
                    );
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
        let (status, document, etag) = match index {
            0 => (
                201,
                json!({"id":id,"revision":1,"data":{"jurisdiction":"zone-a","label":"first","note":"initial","quantity":1}}),
                Some("\"rs-one\""),
            ),
            1 => (
                200,
                json!({"id":id,"revision":1,"data":{"jurisdiction":"zone-a","label":"first","note":"initial","quantity":1}}),
                Some("\"rs-one\""),
            ),
            2 => (
                200,
                json!({"items":[{"id":id,"revision":1,"data":{"jurisdiction":"zone-a","label":"first","note":"initial","quantity":1}}],"pageInfo":{"nextCursor":null}}),
                None,
            ),
            3 => (
                200,
                json!({"id":id,"revision":2,"data":{"jurisdiction":"zone-a","label":"first","note":"revised","quantity":1}}),
                Some("\"rs-two\""),
            ),
            4 => (
                200,
                json!({"results":[
                    {"operation":"create","id":second,"revision":1,"etag":"\"rs-second\"","data":{"jurisdiction":"zone-a","label":"second","quantity":2}},
                    {"operation":"create","id":third,"revision":1,"etag":"\"rs-third\"","data":{"jurisdiction":"zone-a","label":"third","quantity":3}}
                ]}),
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
                    }
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
