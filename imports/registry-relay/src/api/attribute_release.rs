// SPDX-License-Identifier: Apache-2.0
//! Governed identity attribute-release routes.
//!
//! A release profile is a projection-limited, exactly-one-subject lookup that
//! returns only the attributes approved for a named profile, mapped into
//! OIDC/UserInfo-style claims. A profile is *optionally* purpose-bound: when it
//! declares a `purpose`, the request's `data-purpose` header must equal it
//! before any release; a profile that omits `purpose` carries no such gate. The
//! resolve handler
//! never returns a raw registry row: the response body is built field-by-field
//! from profile metadata and the projected claim set, so no source field absent
//! from the profile, no raw subject value (outside a released claim), and no
//! subject hash can leak.
//!
//! The handler mirrors the SP DCI adapter (`super::spdci`): a `RouteDeps`
//! extractor pulls the runtime snapshot and optional principal, `RouteState`
//! resolves the profile plus its backing entity, and the load-bearing gate
//! order runs each gate to a `Result` before the next so scope/purpose denials
//! land before any source read.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Json, Path};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json as JsonResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use registry_platform_pdp::DecisionAudit as PdpDecisionAudit;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::api::governed::{
    attach_pdp_audit, purpose_header_value, require_governed_read_access, GovernedAccessError,
    GovernedRedactionProjection, GovernedRequestInfo,
};
use crate::attribute_release::AttributeReleaseEvaluator;
use crate::audit::AuditContextExt;
use crate::auth::scopes::require_scope;
use crate::auth::Principal;
use crate::config::{AttributeReleaseProfile, Config, EntityConfig, ReleaseClaimConfig};
use crate::entity::EntityModel;
use crate::error::{AuthError, Error, FilterError, ReleaseError, SchemaError};
use crate::query::{EntityCollectionQuery, EntityFilter, EntityQueryEngine};
use crate::runtime_config::RuntimeSnapshot;

/// Stable PDP route identity recorded in the governed-evidence audit trail.
const ROUTE_IDENTITY: &str = "registry-relay.attribute-release";
/// Disclosure tier passed to the PDP for the requested-disclosure gate.
const REQUESTED_DISCLOSURE: &str = "attribute_release";
/// The only response media type advertised and returned in v1.
const RESPONSE_MEDIA_TYPE: &str = "application/json";

struct RouteDeps {
    runtime: RuntimeSnapshot,
    principal: Option<Extension<Principal>>,
}

impl<S> FromRequestParts<S> for RouteDeps
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            runtime: RuntimeSnapshot::from_request_parts(parts, state).await?,
            principal: Option::<Extension<Principal>>::from_request_parts(parts, state)
                .await
                .unwrap_or(None),
        })
    }
}

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/v1/attribute-releases", get(discovery))
        .route(
            "/v1/attribute-releases/{profile_id}/versions/{version}/resolve",
            post(resolve),
        )
}

/// Inbound resolve request body. JSON only; a wrong/absent `Content-Type`
/// yields 415 and a malformed body 400 through the axum `Json` extractor's
/// default rejection. `claims` absent ⇒ profile default set; an explicit empty
/// list is rejected with 400; any unknown requested claim denies.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    subject: ResolveSubject,
    #[serde(default)]
    claims: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveSubject {
    id_type: String,
    value: Value,
}

async fn resolve(
    Path((profile_id, version)): Path<(String, String)>,
    headers: HeaderMap,
    deps: RouteDeps,
    Json(body): Json<ResolveRequest>,
) -> Response {
    let RouteDeps { runtime, principal } = deps;
    let route = match RouteState::resolve(&runtime, &profile_id, &version) {
        Ok(route) => route,
        // `profile_not_found` renders as a generic 404 that does not confirm
        // enumeration; it carries no audit context because no gate ran. It is
        // still marked non-cacheable so a 404 is never stored.
        Err(error) => return with_release_cache_headers(error.into_response(), None),
    };
    // Only a successful release honours the profile's caching opt-in; every
    // denial is forced to `no-store` below by passing `None`.
    let success_max_age = route.profile.response.max_age_seconds;
    let result = run_resolve(&runtime, &route, &headers, principal, body).await;
    match result {
        Ok(success) => {
            let response = with_audit_context(
                success.response,
                &route,
                ResolveAudit {
                    requested_claims: Some(success.requested_claims),
                    released_claims: Some(success.released_claims),
                    subject_id_raw: success.subject_id_raw,
                    internal_outcome: None,
                    cardinality_outcome: Some("one".to_string()),
                    availability_class: Some("available".to_string()),
                    pdp_audit: success.pdp_audit,
                },
            );
            with_release_cache_headers(response, success_max_age)
        }
        Err(error) => {
            let response = error.error.into_response();
            let response = with_audit_context(response, &route, error.audit);
            with_release_cache_headers(response, None)
        }
    }
}

/// Successful release outcome carried back to the response wrapper so the audit
/// context can record the requested + released claim names without re-deriving
/// them. `subject_id_raw` is the raw subject value; the middleware hashes it
/// (`ar_subject_id_hash`) — it is never serialized to the record or body here.
struct ResolveSuccess {
    response: Response,
    requested_claims: Vec<String>,
    released_claims: Vec<String>,
    subject_id_raw: Option<String>,
    pdp_audit: Option<PdpDecisionAudit>,
}

/// Audit fields attached to every resolve response (success or denial). Denials
/// preserve the distinct internal outcome via `ReleaseError::audit_code()` even
/// though the public body collapses to `release.subject_denied`.
#[derive(Default)]
struct ResolveAudit {
    requested_claims: Option<Vec<String>>,
    released_claims: Option<Vec<String>>,
    subject_id_raw: Option<String>,
    internal_outcome: Option<String>,
    cardinality_outcome: Option<String>,
    availability_class: Option<String>,
    pdp_audit: Option<PdpDecisionAudit>,
}

/// Error carrying the audit context accumulated up to the point of failure, so
/// a collapsed denial still records the internal outcome and any PDP audit.
struct ResolveRunError {
    error: Error,
    audit: ResolveAudit,
}

impl ResolveRunError {
    /// Build a release-error denial. `ar_internal_outcome` carries the distinct
    /// internal label; `ar_released_claims` is the empty list on a denied
    /// outcome so the audit trail records "nothing released".
    fn release(
        error: ReleaseError,
        subject_id_raw: Option<String>,
        requested_claims: Option<Vec<String>>,
        cardinality_outcome: Option<String>,
        availability_class: Option<String>,
        pdp_audit: Option<PdpDecisionAudit>,
    ) -> Self {
        let internal_outcome = error.audit_code().to_string();
        Self {
            error: error.into(),
            audit: ResolveAudit {
                requested_claims,
                released_claims: Some(Vec::new()),
                subject_id_raw,
                internal_outcome: Some(internal_outcome),
                cardinality_outcome,
                availability_class,
                pdp_audit,
            },
        }
    }
}

impl From<Error> for ResolveRunError {
    fn from(error: Error) -> Self {
        Self {
            error,
            audit: ResolveAudit::default(),
        }
    }
}

impl From<GovernedAccessError> for ResolveRunError {
    fn from(error: GovernedAccessError) -> Self {
        Self {
            error: error.error,
            audit: ResolveAudit {
                pdp_audit: error.pdp_audit,
                ..ResolveAudit::default()
            },
        }
    }
}

#[allow(clippy::result_large_err)]
async fn run_resolve(
    runtime: &RuntimeSnapshot,
    route: &RouteState,
    headers: &HeaderMap,
    principal: Option<Extension<Principal>>,
    body: ResolveRequest,
) -> Result<ResolveSuccess, ResolveRunError> {
    let principal_ref = principal.as_ref().map(|Extension(principal)| principal);

    // 1 + 2: authenticate, then require the dataset-bound release scope. The
    // release scope is distinct from the entity read scope, so a caller holding
    // only `:rows` is denied here before any source read.
    require_release_scope(principal_ref, &route.profile.release_scope)?;

    // 3 + 4: purpose + ODRL policy enforced atomically. `DeferredOutput`
    // because redaction applies to the projected claim bundle, not raw entity
    // fields. Denials return before the source read.
    let governed = require_governed_read_access(
        runtime,
        route.dataset_id.as_str(),
        &route.entity,
        headers,
        principal_ref,
        GovernedRequestInfo {
            route_identity: ROUTE_IDENTITY,
            requested_disclosure: REQUESTED_DISCLOSURE,
            checked_scope: &route.profile.release_scope,
            redaction_projection: GovernedRedactionProjection::DeferredOutput,
        },
    )?;
    let pdp_audit = governed.audit.clone();

    // 4b: profile-level purpose binding. When a profile declares a `purpose`, the
    // `data-purpose` header must be present and equal it — enforced here, before
    // the source read, independent of whether the backing entity governs
    // purposes (`require_governed_read_access` only checks purpose when the entity
    // does). When the entity also governs, this is an additional equality
    // constraint on the same header. A profile with no purpose keeps the prior
    // behaviour. Missing header ⇒ 400 auth.purpose_required; mismatch ⇒ 403
    // auth.purpose_denied — surfaced like the entity-governed purpose denials,
    // not collapsed into the subject-denied outcome.
    if let Some(profile_purpose) = route.profile.purpose.as_deref() {
        match purpose_header_value(headers) {
            Some(value) if value == profile_purpose => {}
            Some(_) => {
                return Err(ResolveRunError::from(Error::from(AuthError::PurposeDenied)));
            }
            None => {
                return Err(ResolveRunError::from(Error::from(
                    AuthError::PurposeRequired,
                )));
            }
        }
    }

    // 5: validate the subject id_type/value. A mismatched id_type or a
    // non-scalar/blank value fails closed to release.subject_invalid (400), a
    // request-shape error distinct from the collapsed subject-denied outcome.
    // Both precede the read.
    let subject_value = validate_subject(&route.profile, &body.subject)?;
    let subject_id_raw = subject_audit_raw(&subject_value);

    // Resolve the requested claim set: absent ⇒ profile default; `[]` ⇒ 400;
    // any unknown requested claim ⇒ deny. Done before the read so an unknown
    // claim cannot probe subject existence.
    let requested = resolve_requested_claims(route, &body.claims, &subject_id_raw, &pdp_audit)?;
    let requested_names: Vec<String> = requested.iter().map(|claim| claim.name.clone()).collect();

    // 6: exact lookup projecting only the profile's source fields, with
    // `limit: Some(2)` so a duplicate subject is detectable. The subject match
    // is a gateway-owned trusted filter, not a caller-controlled entity filter.
    let rows = match read_subject_rows(route, subject_value.clone()).await {
        Ok(rows) => rows,
        // A source read failure fails closed to `release.source_unavailable`
        // (503). The underlying error is dropped from the wire so no source
        // internals leak; the audit records the distinct internal outcome.
        Err(_error) => {
            return Err(ResolveRunError::release(
                ReleaseError::SourceUnavailable,
                subject_id_raw,
                Some(requested_names),
                None,
                Some("unavailable".to_string()),
                pdp_audit,
            ));
        }
    };

    // 7: cardinality. 0 ⇒ SubjectNotFound; >1 ⇒ SubjectAmbiguous. Both collapse
    // publicly to `release.subject_denied`; distinct internal outcomes survive.
    let row = match rows.len() {
        1 => rows.into_iter().next().expect("exactly one row"),
        0 => {
            return Err(ResolveRunError::release(
                ReleaseError::SubjectNotFound,
                subject_id_raw,
                Some(requested_names),
                Some("zero".to_string()),
                Some("available".to_string()),
                pdp_audit,
            ));
        }
        _ => {
            return Err(ResolveRunError::release(
                ReleaseError::SubjectAmbiguous,
                subject_id_raw,
                Some(requested_names),
                Some("many".to_string()),
                Some("available".to_string()),
                pdp_audit,
            ));
        }
    };

    // 8: release-condition predicate (CEL). A false predicate, or any evaluation
    // failure, fails closed to SubjectReleaseDenied.
    if let Some(conditions) = route.profile.release_conditions.as_ref() {
        let allowed = route
            .evaluator
            .evaluate_release_predicate(&conditions.expression.cel, &row)
            .unwrap_or(false);
        if !allowed {
            return Err(ResolveRunError::release(
                ReleaseError::SubjectReleaseDenied,
                subject_id_raw,
                Some(requested_names),
                Some("one".to_string()),
                Some("available".to_string()),
                pdp_audit,
            ));
        }
    }

    // 9: project the claim bundle field-by-field. Required claim missing ⇒
    // ClaimUnavailable; optional missing ⇒ omit; a claim whose source field is
    // dropped by governed redaction is treated as unavailable.
    //
    // Governed redaction is field-layer: `claim_is_redacted` gates *direct*
    // claims, but a computed (CEL) claim reads the row directly and would
    // otherwise see a redacted field. Project claims over a row with the
    // redacted fields removed so a CEL reference to one resolves to null/error
    // and the claim fails closed — closing the redaction-bypass path for
    // computed claims. The release predicate above runs over the full row on
    // purpose: it is a disclosure gate whose boolean result reveals no value.
    let projection_row = redact_row(&row, &governed.redaction_fields);
    let mut released = Map::new();
    for claim in &requested {
        if claim_is_redacted(claim, &governed.redaction_fields) {
            if claim.required {
                return Err(ResolveRunError::release(
                    ReleaseError::ClaimUnavailable,
                    subject_id_raw,
                    Some(requested_names),
                    Some("one".to_string()),
                    Some("available".to_string()),
                    pdp_audit,
                ));
            }
            continue;
        }
        match claim_value(&route.evaluator, claim, &projection_row) {
            Some(value) => {
                released.insert(claim.name.clone(), value);
            }
            None if claim.required => {
                return Err(ResolveRunError::release(
                    ReleaseError::ClaimUnavailable,
                    subject_id_raw,
                    Some(requested_names),
                    Some("one".to_string()),
                    Some("available".to_string()),
                    pdp_audit,
                ));
            }
            None => {}
        }
    }
    let released_names: Vec<String> = released.keys().cloned().collect();

    // Build the response body purely from profile metadata + projected claims.
    // The raw entity row is never serialized; the subject value appears only if
    // it was itself projected as a released claim; no subject hash appears. The
    // `source` block is emitted only when the profile opts in via
    // `response.include_source_metadata` (default off), so a minimizing profile
    // never discloses the backing dataset/entity names.
    let mut response_body = Map::new();
    response_body.insert("profile_id".to_string(), json!(route.profile.id));
    response_body.insert("profile_version".to_string(), json!(route.profile.version));
    response_body.insert("claims".to_string(), Value::Object(released));
    if route.profile.response.include_source_metadata {
        response_body.insert(
            "source".to_string(),
            json!({
                "dataset": route.dataset_id,
                "entity": route.entity.name,
                "subject_id_type": body.subject.id_type,
                "cardinality": "one",
                "checked_at": now_rfc3339(),
            }),
        );
    }
    let response = JsonResponse(Value::Object(response_body)).into_response();

    Ok(ResolveSuccess {
        response,
        requested_claims: requested_names,
        released_claims: released_names,
        subject_id_raw,
        pdp_audit,
    })
}

/// Validate the subject id_type and value before any source read. A mismatched
/// id_type, or (for an unpinned profile) a blank id_type, or a non-scalar/blank
/// value fails closed to `release.subject_invalid` (400) — a request-shape error
/// distinct from the collapsed `release.subject_denied`. Unlike subject
/// existence, id_type/value validity reveals nothing about the backing registry,
/// so surfacing it as a distinct, diagnosable code is safe.
fn validate_subject(
    profile: &AttributeReleaseProfile,
    subject: &ResolveSubject,
) -> Result<Value, Error> {
    if let Some(expected) = profile.subject.id_type.as_deref() {
        if subject.id_type != expected {
            return Err(ReleaseError::SubjectInvalid.into());
        }
    } else if subject.id_type.trim().is_empty() {
        return Err(ReleaseError::SubjectInvalid.into());
    }
    match scalar_subject_value(&subject.value) {
        Some(value) => Ok(value),
        None => Err(ReleaseError::SubjectInvalid.into()),
    }
}

/// Accept only non-blank scalar subject values (string/number/bool). Arrays,
/// objects, null, and blank strings are rejected as `filter.invalid_value`.
fn scalar_subject_value(value: &Value) -> Option<Value> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(value.clone()),
        Value::Number(_) | Value::Bool(_) => Some(value.clone()),
        _ => None,
    }
}

/// Canonicalize an accepted scalar subject value into the raw string the audit
/// pipeline keyed-hashes (`ar_subject_id_hash`). Strings use their text; numbers
/// and bools use their canonical JSON scalar form. This closes the gap where a
/// non-string subject was accepted for the lookup but left `subject_id_raw`
/// `None`, so it never appeared (hashed) in the audit trail. The raw value is
/// only ever hashed downstream — it is never logged or serialized in the clear.
fn subject_audit_raw(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Resolve the effective claim set. Absent ⇒ the profile default (all
/// configured claims); explicit `[]` ⇒ 400 invalid value; any name not in the
/// profile ⇒ deny (`release.subject_denied`).
#[allow(clippy::result_large_err)]
fn resolve_requested_claims<'a>(
    route: &'a RouteState,
    requested: &Option<Vec<String>>,
    subject_id_raw: &Option<String>,
    pdp_audit: &Option<PdpDecisionAudit>,
) -> Result<Vec<&'a ReleaseClaimConfig>, ResolveRunError> {
    let Some(names) = requested else {
        return Ok(route.profile.claims.iter().collect());
    };
    if names.is_empty() {
        return Err(ResolveRunError::from(Error::from(
            FilterError::InvalidValue,
        )));
    }
    let mut resolved = Vec::with_capacity(names.len());
    for name in names {
        match route
            .profile
            .claims
            .iter()
            .find(|claim| &claim.name == name)
        {
            Some(claim) => resolved.push(claim),
            // An unknown requested claim is a denial, collapsed publicly so it
            // cannot be used to probe which claims a profile exposes.
            None => {
                return Err(ResolveRunError::release(
                    ReleaseError::SubjectReleaseDenied,
                    subject_id_raw.clone(),
                    None,
                    None,
                    None,
                    pdp_audit.clone(),
                ));
            }
        }
    }
    Ok(resolved)
}

/// Whether a direct-source claim resolves to a field dropped by governed
/// redaction. Computed (CEL) claims carry no `source_field`, so this returns
/// false for them — they are instead redacted at the row layer by
/// [`redact_row`] before evaluation, so a CEL reference to a redacted field
/// fails closed rather than disclosing it.
fn claim_is_redacted(claim: &ReleaseClaimConfig, redaction_fields: &BTreeSet<String>) -> bool {
    claim
        .source_field
        .as_deref()
        .is_some_and(|field| redaction_fields.contains(field))
}

/// Return a copy of the projected subject row with every governed-redacted field
/// removed, so a computed (CEL) claim cannot read a field that field-layer
/// redaction dropped. A removed field makes `source.<field>` resolve to
/// null/error in CEL, so the dependent claim fails closed (required ⇒
/// `ClaimUnavailable`, optional ⇒ omitted) instead of leaking the value. When
/// no fields are redacted this is a cheap clone of the row.
fn redact_row(row: &Value, redaction_fields: &BTreeSet<String>) -> Value {
    match row {
        Value::Object(map) if !redaction_fields.is_empty() => Value::Object(
            map.iter()
                .filter(|(key, _)| !redaction_fields.contains(key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ),
        _ => row.clone(),
    }
}

/// Compute a single claim value from the projected subject row. A direct claim
/// reads its source field (absent ⇒ `None`); a computed claim evaluates its CEL
/// scalar (any failure ⇒ `None`, so a required computed claim fails closed).
fn claim_value(
    evaluator: &AttributeReleaseEvaluator,
    claim: &ReleaseClaimConfig,
    row: &Value,
) -> Option<Value> {
    if let Some(field) = claim.source_field.as_deref() {
        return match row.get(field) {
            Some(Value::Null) | None => None,
            Some(value) => Some(value.clone()),
        };
    }
    if let Some(expression) = claim.expression.as_ref() {
        return evaluator.evaluate_release_scalar(&expression.cel, row).ok();
    }
    None
}

async fn read_subject_rows(route: &RouteState, subject_value: Value) -> Result<Vec<Value>, Error> {
    let result = route
        .query
        .read_collection(
            route.dataset_id.as_str(),
            &route.entity.name,
            EntityCollectionQuery {
                fields: Some(route.source_fields.clone()),
                limit: Some(2),
                trusted_filters: vec![EntityFilter::eq(
                    route.profile.subject.source_field.clone(),
                    subject_value,
                )],
                ..EntityCollectionQuery::default()
            },
        )
        .await?;
    Ok(result.rows)
}

// ----------------------------------------------------------------------------
// Discovery
// ----------------------------------------------------------------------------

async fn discovery(deps: RouteDeps) -> Response {
    let RouteDeps { runtime, principal } = deps;
    let Some(config) = runtime.config() else {
        return Error::from(SchemaError::UnknownResource).into_response();
    };
    let principal = match principal {
        Some(Extension(principal)) => principal,
        // Discovery is authenticated-only; every metadata route requires a
        // principal. No scope string or sensitivity label is ever emitted on an
        // anonymous surface.
        None => return Error::from(AuthError::MissingCredential).into_response(),
    };

    let mut profiles = Vec::new();
    for dataset in &config.datasets {
        for entity in &dataset.entities {
            for profile in &entity.attribute_release_profiles {
                // Per-profile visibility: a caller sees a profile only when it
                // holds that profile's release scope. This mirrors the
                // per-entity metadata-scope gating.
                if !principal.scopes.contains(&profile.release_scope) {
                    continue;
                }
                profiles.push(discovery_profile(profile));
            }
        }
    }

    with_private_metadata_headers(JsonResponse(json!({ "profiles": profiles })).into_response())
}

/// Build the discovery view of one profile. Emits only the visible fields from
/// plan §5.6 — id, version, title, description, purpose, accepted subject id
/// types, claim names, required claims, response media type, and release scope
/// (authenticated-only). Never leaks private source internals (table ids,
/// source field names, paths, secrets, or policy internals).
fn discovery_profile(profile: &AttributeReleaseProfile) -> Value {
    let claim_names: Vec<&str> = profile
        .claims
        .iter()
        .map(|claim| claim.name.as_str())
        .collect();
    let required_claims: Vec<&str> = profile
        .claims
        .iter()
        .filter(|claim| claim.required)
        .map(|claim| claim.name.as_str())
        .collect();
    let accepted_subject_id_types: Vec<&str> =
        profile.subject.id_type.as_deref().into_iter().collect();
    json!({
        "id": profile.id,
        "version": profile.version,
        "title": profile.title,
        "description": profile.description,
        "purpose": profile.purpose,
        "accepted_subject_id_types": accepted_subject_id_types,
        "claim_names": claim_names,
        "required_claims": required_claims,
        "response_media_type": RESPONSE_MEDIA_TYPE,
        "release_scope": profile.release_scope,
    })
}

// ----------------------------------------------------------------------------
// Route state & resolution
// ----------------------------------------------------------------------------

/// Resolved per-request release context: the configured profile, its backing
/// entity model, the owning dataset id, the projected source-field set, and the
/// query engine.
struct RouteState {
    profile: AttributeReleaseProfile,
    entity: EntityModel,
    dataset_id: String,
    source_fields: Vec<String>,
    query: Arc<EntityQueryEngine>,
    evaluator: Arc<AttributeReleaseEvaluator>,
}

impl RouteState {
    /// Resolve a profile by its globally-unique `(profile_id, version)` pair and
    /// bind it to its backing entity. An unknown pair is `ProfileNotFound`
    /// (generic 404). Missing runtime state is a generic unknown-resource error.
    fn resolve(runtime: &RuntimeSnapshot, profile_id: &str, version: &str) -> Result<Self, Error> {
        let config = runtime.config().ok_or(SchemaError::UnknownResource)?;
        let (dataset_id, entity_config, profile) =
            find_profile(&config, profile_id, version).ok_or(ReleaseError::ProfileNotFound)?;
        let registry = runtime
            .entity_registry()
            .ok_or(SchemaError::UnknownResource)?;
        let entity = registry
            .dataset(&dataset_id)
            .and_then(|dataset| dataset.entity(&entity_config.name))
            .cloned()
            .ok_or(SchemaError::UnknownResource)?;
        let query = runtime.query().ok_or(SchemaError::UnknownResource)?;
        let evaluator = runtime
            .attribute_release_evaluator()
            .ok_or(SchemaError::UnknownResource)?;
        let source_fields = profile_source_fields(&profile, &entity);
        Ok(Self {
            profile,
            entity,
            dataset_id,
            source_fields,
            query,
            evaluator,
        })
    }
}

/// Locate the `(dataset_id, entity, profile)` for a `(profile_id, version)`
/// pair. `(id, version)` is globally unique (enforced at config load), so the
/// first match is authoritative.
fn find_profile<'a>(
    config: &'a Config,
    profile_id: &str,
    version: &str,
) -> Option<(String, &'a EntityConfig, AttributeReleaseProfile)> {
    for dataset in &config.datasets {
        for entity in &dataset.entities {
            for profile in &entity.attribute_release_profiles {
                if profile.id == profile_id && profile.version == version {
                    return Some((dataset.id.to_string(), entity, profile.clone()));
                }
            }
        }
    }
    None
}

/// The set of source fields the read projects.
///
/// For a profile with only direct-source claims, this is the subject match
/// field plus each claim's `source_field` — the minimal projection that
/// satisfies "only configured source fields". When the profile carries any CEL
/// expression (a release condition or a computed claim), the expression may
/// reference any exposed source field by free-form text that cannot be parsed
/// here, so the projection widens to the full exposed field set. This only
/// widens what CEL may *read*; the response body is still built field-by-field
/// from the released claim set, so no unconfigured field can ever be emitted.
fn profile_source_fields(profile: &AttributeReleaseProfile, entity: &EntityModel) -> Vec<String> {
    let uses_cel = profile.release_conditions.is_some()
        || profile
            .claims
            .iter()
            .any(|claim| claim.expression.is_some());
    if uses_cel {
        return entity
            .fields
            .iter()
            .map(|field| field.name.clone())
            .collect();
    }
    let mut fields = BTreeSet::new();
    fields.insert(profile.subject.source_field.clone());
    for claim in &profile.claims {
        if let Some(field) = claim.source_field.as_deref() {
            fields.insert(field.to_string());
        }
    }
    fields.into_iter().collect()
}

fn require_release_scope(principal: Option<&Principal>, required: &str) -> Result<(), Error> {
    let Some(principal) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    require_scope(principal, required)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn with_private_metadata_headers(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::VARY,
        axum::http::HeaderValue::from_static("Authorization"),
    );
    response
}

/// Attach caching directives to a resolve response. Released identity attributes
/// are PII, so the default is `private, no-store`: the bundle is never written to
/// a shared or local cache. A profile may opt into bounded *private* caching of a
/// successful release by setting `response.max_age_seconds`, which yields
/// `private, max-age=N` (still never shared-cacheable, still `Vary: Authorization`
/// so a token swap cannot reuse another principal's entry). Denials always pass
/// `max_age = None` so an error is never cached regardless of the profile knob.
fn with_release_cache_headers(mut response: Response, max_age_seconds: Option<u64>) -> Response {
    let directive = match max_age_seconds {
        Some(secs) => format!("private, max-age={secs}"),
        None => "private, no-store".to_string(),
    };
    let value = axum::http::HeaderValue::from_str(&directive)
        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("private, no-store"));
    response
        .headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, value);
    response.headers_mut().insert(
        axum::http::header::VARY,
        axum::http::HeaderValue::from_static("Authorization"),
    );
    response
}

/// Attach the attribute-release audit context to the response. The raw subject
/// value is written to `ar_subject_id_raw` (the middleware keyed-hashes it into
/// `ar_subject_id_hash`); it is never serialized to the record or the body.
fn with_audit_context(mut response: Response, route: &RouteState, audit: ResolveAudit) -> Response {
    let mut context = Some(AuditContextExt {
        dataset_id: Some(route.dataset_id.clone()),
        entity_name: Some(route.entity.name.clone()),
        table_id: Some(route.entity.table_id.clone()),
        ar_profile_id: Some(route.profile.id.clone()),
        ar_profile_version: Some(route.profile.version.clone()),
        ar_subject_id_type: route.profile.subject.id_type.clone(),
        ar_subject_id_raw: audit.subject_id_raw.map(crate::audit::Sensitive::from),
        ar_requested_claims: audit.requested_claims,
        ar_released_claims: audit.released_claims,
        ar_internal_outcome: audit.internal_outcome,
        ar_source_cardinality_outcome: audit.cardinality_outcome,
        ar_source_availability_class: audit.availability_class,
        ..AuditContextExt::default()
    });
    attach_pdp_audit(&mut context, audit.pdp_audit.as_ref());
    if let Some(context) = context {
        response.extensions_mut().insert(context);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_audit_raw_canonicalizes_every_accepted_scalar() {
        assert_eq!(
            subject_audit_raw(&json!("NID-1")),
            Some("NID-1".to_string())
        );
        assert_eq!(subject_audit_raw(&json!(42)), Some("42".to_string()));
        assert_eq!(subject_audit_raw(&json!(true)), Some("true".to_string()));
        // Non-scalars carry no audit raw (and are rejected before any read).
        assert_eq!(subject_audit_raw(&json!(null)), None);
        assert_eq!(subject_audit_raw(&json!({"a": 1})), None);
    }

    #[test]
    fn every_accepted_subject_has_an_audit_raw() {
        // The invariant the audit-canonicalization fix guarantees: any value
        // `scalar_subject_value` accepts yields a hashable `subject_id_raw`, so a
        // non-string subject is never silently dropped from the audit trail.
        for value in [json!("NID-1"), json!(42), json!(true)] {
            let accepted = scalar_subject_value(&value).expect("scalar accepted");
            assert!(
                subject_audit_raw(&accepted).is_some(),
                "accepted subject {value} must have an audit raw"
            );
        }
    }
}
