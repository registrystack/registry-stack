// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use deadpool_postgres::{Client, Transaction};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::contract::{BoundaryOperator, Operation};
use crate::data::{validate_field_value as validate_data_field_value, FieldValue};
use crate::model::{
    CompiledActionEffect, CompiledActionMutation, CompiledActionTargetBinding,
    CompiledActionTargetUseSource, CompiledChangeRequestEffect, CompiledChangeRequestMutation,
    CompiledChangeRequestTargetBinding, CompiledRegistry,
};

use super::{ExpectedRegistryIdentity, PostgresKernelError, RegistryLockKey, Result};

const MAX_CONTEXT_VALUE_BYTES: usize = 512;
const MAX_BOUNDARY_SET_VALUES: usize = 64;
const MAX_BOUNDARY_CONTEXT_BYTES: usize = 64 * 1024;
const MAX_ENTITY_ID_BYTES: usize = 256;
const MAX_TARGET_FIELDS: usize = 128;

/// One finite compiler-validated row boundary installed into PostgreSQL.
#[derive(Clone, Eq, PartialEq)]
pub enum RowBoundaryContext {
    Equals {
        field: String,
        value: String,
    },
    In {
        field: String,
        values: BTreeSet<String>,
    },
}

/// Action-level authority installed for named immediate actions.
///
/// This is deliberately not an entity `ClaimContext`: invoke authority is
/// action-owned, and each target row gets a separate effect context before
/// PostgreSQL row security can admit reads or writes.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ActionClaimContext {
    action_id: String,
    principal: String,
    access_profile: String,
    purpose: Option<String>,
    result_effects: BTreeSet<String>,
}

impl ActionClaimContext {
    pub(crate) fn new(
        action_id: String,
        principal: String,
        access_profile: String,
        purpose: Option<String>,
        result_effects: BTreeSet<String>,
    ) -> Result<Self> {
        let context = Self {
            action_id,
            principal,
            access_profile,
            purpose,
            result_effects,
        };
        context.validate()?;
        Ok(context)
    }

    #[must_use]
    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    #[must_use]
    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }

    #[must_use]
    pub(crate) fn access_profile(&self) -> &str {
        &self.access_profile
    }

    #[must_use]
    pub(crate) fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    #[must_use]
    pub(crate) fn result_effects(&self) -> &BTreeSet<String> {
        &self.result_effects
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.action_id)?;
        validate_required_context_value(&self.principal)?;
        validate_required_context_value(&self.access_profile)?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        if self
            .result_effects
            .iter()
            .any(|effect| validate_required_context_value(effect).is_err())
        {
            return Err(invalid_context());
        }
        Ok(())
    }
}

impl fmt::Debug for ActionClaimContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActionClaimContext")
            .field("action_id", &self.action_id)
            .field("principal", &"<redacted>")
            .field("access_profile", &self.access_profile)
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("result_effects", &self.result_effects)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowBoundaryOperator {
    Equals,
    In,
}

impl RowBoundaryOperator {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "equals",
            Self::In => "in",
        }
    }
}

impl RowBoundaryContext {
    #[must_use]
    pub fn field(&self) -> &str {
        match self {
            Self::Equals { field, .. } | Self::In { field, .. } => field,
        }
    }

    #[must_use]
    pub fn operator(&self) -> RowBoundaryOperator {
        match self {
            Self::Equals { .. } => RowBoundaryOperator::Equals,
            Self::In { .. } => RowBoundaryOperator::In,
        }
    }

    #[must_use]
    pub fn values(&self) -> Vec<&str> {
        match self {
            Self::Equals { value, .. } => vec![value],
            Self::In { values, .. } => values.iter().map(String::as_str).collect(),
        }
    }
}

impl fmt::Debug for RowBoundaryContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowBoundaryContext")
            .field("field", &self.field())
            .field("operator", &self.operator())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// Complete verified authority installed into one PostgreSQL transaction.
///
/// Production construction is possible only against an exact compiled entity
/// and access profile. Raw tokens, headers, query values, and dynamic setting
/// names never enter this type.
#[derive(Clone, Eq, PartialEq)]
pub struct ClaimContext {
    entity_id: String,
    principal: Option<String>,
    access_profile: String,
    purpose: Option<String>,
    row_boundaries: Vec<RowBoundaryContext>,
    canonical_row_boundaries: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpatialBboxContext {
    west: String,
    south: String,
    east: String,
    north: String,
}

impl SpatialBboxContext {
    pub(crate) fn new(west: String, south: String, east: String, north: String) -> Result<Self> {
        for value in [&west, &south, &east, &north] {
            validate_required_context_value(value)?;
        }
        Ok(Self {
            west,
            south,
            east,
            north,
        })
    }
}

impl ClaimContext {
    pub fn for_compiled(
        registry: &CompiledRegistry,
        entity_id: &str,
        principal: Option<String>,
        access_profile: &str,
        purpose: Option<String>,
        row_boundaries: Vec<RowBoundaryContext>,
    ) -> Result<Self> {
        if entity_id.is_empty() || entity_id.len() > MAX_ENTITY_ID_BYTES {
            return Err(invalid_context());
        }
        let entity = registry
            .entities()
            .get(entity_id)
            .ok_or_else(invalid_context)?;
        let profile = entity
            .access_profiles
            .get(access_profile)
            .ok_or_else(invalid_context)?;
        validate_required_context_value(access_profile)?;
        principal
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        if !profile.anonymous && principal.is_none() {
            return Err(invalid_context());
        }
        if !profile.required_purposes.is_empty()
            && !purpose
                .as_ref()
                .is_some_and(|value| profile.required_purposes.contains(value))
        {
            return Err(invalid_context());
        }
        if row_boundaries.len() != profile.row_boundaries.len() {
            return Err(invalid_context());
        }
        for (actual, expected) in row_boundaries.iter().zip(&profile.row_boundaries) {
            let expected_operator = match expected.operator {
                BoundaryOperator::Equals => RowBoundaryOperator::Equals,
                BoundaryOperator::In => RowBoundaryOperator::In,
            };
            if actual.field() != expected.field || actual.operator() != expected_operator {
                return Err(invalid_context());
            }
            validate_boundary(actual)?;
            let field_type = if expected.field == entity.canonical_id.id {
                &entity.canonical_id.field_type
            } else {
                &entity
                    .fields
                    .get(&expected.field)
                    .ok_or_else(invalid_context)?
                    .field_type
            };
            for value in actual.values() {
                validate_field_value(value, field_type)?;
            }
        }
        let canonical_row_boundaries = canonical_boundaries(&row_boundaries)?;
        Ok(Self {
            entity_id: entity_id.to_owned(),
            principal,
            access_profile: access_profile.to_owned(),
            purpose,
            row_boundaries,
            canonical_row_boundaries,
        })
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn kernel_for_test(
        principal: String,
        access_profile: String,
        purpose: Option<String>,
        authority: String,
    ) -> Result<Self> {
        validate_required_context_value(&principal)?;
        validate_required_context_value(&access_profile)?;
        purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        validate_required_context_value(&authority)?;
        let row_boundaries = vec![RowBoundaryContext::Equals {
            field: "authority".to_owned(),
            value: authority,
        }];
        let canonical_row_boundaries = canonical_boundaries(&row_boundaries)?;
        Ok(Self {
            entity_id: "kernel_records".to_owned(),
            principal: Some(principal),
            access_profile,
            purpose,
            row_boundaries,
            canonical_row_boundaries,
        })
    }

    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    #[must_use]
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    #[must_use]
    pub fn access_profile(&self) -> &str {
        &self.access_profile
    }

    #[must_use]
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    #[must_use]
    pub fn row_boundaries(&self) -> &[RowBoundaryContext] {
        &self.row_boundaries
    }

    pub fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.entity_id)?;
        self.principal
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        validate_required_context_value(&self.access_profile)?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        for boundary in &self.row_boundaries {
            validate_boundary(boundary)?;
        }
        if canonical_boundaries(&self.row_boundaries)? != self.canonical_row_boundaries {
            return Err(invalid_context());
        }
        Ok(())
    }
}

impl fmt::Debug for ClaimContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimContext")
            .field("entity_id", &self.entity_id)
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("access_profile", &self.access_profile)
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("row_boundaries", &self.row_boundaries)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ChangeRequestActionContext {
    request_entity_id: String,
    request_id: Uuid,
    proposal_version: i64,
    actor_reference: String,
    contract_fingerprint: String,
    active_package_revision: String,
    selected_profile: String,
    principal: Option<String>,
    purpose: Option<String>,
    operation: Operation,
    stage: Option<String>,
    route_id: String,
    canonical_context: String,
}

impl ChangeRequestActionContext {
    pub(crate) fn for_route(
        registry: &CompiledRegistry,
        request_claims: &ClaimContext,
        route_id: &str,
        request_id: Uuid,
        proposal_version: i64,
        actor_reference: &str,
        active_package_revision: &str,
    ) -> Result<Self> {
        request_claims.validate()?;
        validate_required_context_value(route_id)?;
        validate_required_context_value(actor_reference)?;
        validate_required_context_value(active_package_revision)?;
        if proposal_version <= 0 {
            return Err(invalid_context());
        }
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == route_id)
            .ok_or_else(invalid_context)?;
        if route.entity_id != request_claims.entity_id()
            || !is_change_request_action_operation(route.operation)
            || !route
                .access_profiles
                .iter()
                .any(|profile| profile == request_claims.access_profile())
        {
            return Err(invalid_context());
        }
        let request_entity = registry
            .entities()
            .get(&route.entity_id)
            .ok_or_else(invalid_context)?;
        let request_profile = request_entity
            .access_profiles
            .get(request_claims.access_profile())
            .ok_or_else(invalid_context)?;
        if !request_profile.operations.contains(&route.operation) {
            return Err(invalid_context());
        }
        let plan = request_entity
            .change_request
            .as_ref()
            .ok_or_else(invalid_context)?;
        let expected_route_id = change_request_action_route_id(
            &request_entity.id,
            route.operation,
            route.request_stage.as_deref(),
        );
        if expected_route_id != route.id {
            return Err(invalid_context());
        }
        let action_exists = plan.actions.iter().any(|action| {
            action.operation.access_operation() == route.operation
                && action.review_stage.as_deref() == route.request_stage.as_deref()
        });
        if !action_exists {
            return Err(invalid_context());
        }
        if matches!(
            route.operation,
            Operation::ApproveRequest | Operation::RejectRequest | Operation::RequestRevision
        ) != route.request_stage.is_some()
        {
            return Err(invalid_context());
        }
        let mut context = Self {
            request_entity_id: route.entity_id.clone(),
            request_id,
            proposal_version,
            actor_reference: actor_reference.to_owned(),
            contract_fingerprint: plan.contract_fingerprint.clone(),
            active_package_revision: active_package_revision.to_owned(),
            selected_profile: request_claims.access_profile().to_owned(),
            principal: request_claims.principal().map(str::to_owned),
            purpose: request_claims.purpose().map(str::to_owned),
            operation: route.operation,
            stage: route.request_stage.clone(),
            route_id: route.id.clone(),
            canonical_context: String::new(),
        };
        context.canonical_context = Self::canonicalize(&context)?;
        context.validate()?;
        Ok(context)
    }

    #[must_use]
    pub(crate) fn canonical_context(&self) -> &str {
        &self.canonical_context
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.request_entity_id)?;
        validate_required_context_value(&self.actor_reference)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_required_context_value(&self.active_package_revision)?;
        validate_required_context_value(&self.selected_profile)?;
        self.principal
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        self.stage
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        validate_required_context_value(&self.route_id)?;
        if self.proposal_version <= 0 || !is_change_request_action_operation(self.operation) {
            return Err(invalid_context());
        }
        if matches!(
            self.operation,
            Operation::ApproveRequest | Operation::RejectRequest | Operation::RequestRevision
        ) != self.stage.is_some()
        {
            return Err(invalid_context());
        }
        if Self::canonicalize(self)? != self.canonical_context {
            return Err(invalid_context());
        }
        Ok(())
    }

    fn canonicalize(context: &Self) -> Result<String> {
        let payload = json!({
            "version": 1,
            "requestEntityId": context.request_entity_id,
            "requestId": context.request_id.to_string(),
            "proposalVersion": context.proposal_version,
            "actorReference": context.actor_reference,
            "contractFingerprint": context.contract_fingerprint,
            "activePackageRevision": context.active_package_revision,
            "selectedAccessProfile": context.selected_profile,
            "principal": context.principal,
            "purpose": context.purpose,
            "operation": change_request_action_operation_name(context.operation),
            "stage": context.stage,
            "routeId": context.route_id,
        });
        let bytes = canonicalize_json(&payload).map_err(|_| invalid_context())?;
        if bytes.len() > MAX_BOUNDARY_CONTEXT_BYTES {
            return Err(invalid_context());
        }
        String::from_utf8(bytes).map_err(|_| invalid_context())
    }
}

impl fmt::Debug for ChangeRequestActionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeRequestActionContext")
            .field("request_entity_id", &self.request_entity_id)
            .field("request_id", &self.request_id)
            .field("proposal_version", &self.proposal_version)
            .field("actor_reference", &"<redacted>")
            .field("contract_fingerprint", &self.contract_fingerprint)
            .field("active_package_revision", &self.active_package_revision)
            .field("selected_profile", &self.selected_profile)
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("operation", &self.operation)
            .field("stage", &self.stage)
            .field("route_id", &self.route_id)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ChangeRequestPresenceContext {
    request_entity_id: String,
    target_entity_id: String,
    target_record_id: Uuid,
    contract_fingerprint: String,
    active_package_revision: String,
    selected_profile: String,
    principal: Option<String>,
    purpose: Option<String>,
    request_row_boundaries: Vec<RowBoundaryContext>,
    canonical_context: String,
}

impl ChangeRequestPresenceContext {
    pub(crate) fn for_presence(
        registry: &CompiledRegistry,
        target_claims: &ClaimContext,
        request_entity_id: &str,
        target_entity_id: &str,
        target_record_id: Uuid,
        request_row_boundaries: Vec<RowBoundaryContext>,
        active_package_revision: &str,
    ) -> Result<Self> {
        target_claims.validate()?;
        validate_required_context_value(request_entity_id)?;
        validate_required_context_value(target_entity_id)?;
        validate_required_context_value(active_package_revision)?;
        if target_claims.entity_id() != target_entity_id {
            return Err(invalid_context());
        }
        let request_entity = registry
            .entities()
            .get(request_entity_id)
            .ok_or_else(invalid_context)?;
        let target_entity = registry
            .entities()
            .get(target_entity_id)
            .ok_or_else(invalid_context)?;
        let target_profile = target_entity
            .access_profiles
            .get(target_claims.access_profile())
            .ok_or_else(invalid_context)?;
        if !target_profile.request_presence.iter().any(|grant| {
            grant.request_type == request_entity_id
                && grant.row_boundaries.len() == request_row_boundaries.len()
                && grant
                    .row_boundaries
                    .iter()
                    .zip(&request_row_boundaries)
                    .all(|(expected, actual)| presence_boundary_matches_source(actual, expected))
        }) {
            return Err(invalid_context());
        }
        let plan = request_entity
            .change_request
            .as_ref()
            .ok_or_else(invalid_context)?;
        let compiled_grant = plan
            .presence_grants
            .iter()
            .find(|grant| {
                grant.profile_id == target_claims.access_profile()
                    && grant.target_entity_id == target_entity_id
                    && grant.request_row_boundaries.len() == request_row_boundaries.len()
                    && grant
                        .request_row_boundaries
                        .iter()
                        .zip(&request_row_boundaries)
                        .all(|(expected, actual)| {
                            presence_boundary_matches_source(actual, expected)
                        })
            })
            .ok_or_else(invalid_context)?;
        validate_target_boundaries(
            registry,
            request_entity_id,
            &request_row_boundaries,
            &compiled_grant.request_row_boundaries,
        )?;
        let mut context = Self {
            request_entity_id: request_entity.id.clone(),
            target_entity_id: target_entity.id.clone(),
            target_record_id,
            contract_fingerprint: plan.contract_fingerprint.clone(),
            active_package_revision: active_package_revision.to_owned(),
            selected_profile: target_claims.access_profile().to_owned(),
            principal: target_claims.principal().map(str::to_owned),
            purpose: target_claims.purpose().map(str::to_owned),
            request_row_boundaries,
            canonical_context: String::new(),
        };
        context.canonical_context = Self::canonicalize(&context)?;
        context.validate()?;
        Ok(context)
    }

    #[must_use]
    pub(crate) fn canonical_context(&self) -> &str {
        &self.canonical_context
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.request_entity_id)?;
        validate_required_context_value(&self.target_entity_id)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_required_context_value(&self.active_package_revision)?;
        validate_required_context_value(&self.selected_profile)?;
        self.principal
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        for boundary in &self.request_row_boundaries {
            validate_boundary(boundary)?;
        }
        if Self::canonicalize(self)? != self.canonical_context {
            return Err(invalid_context());
        }
        Ok(())
    }

    fn canonicalize(context: &Self) -> Result<String> {
        let request_boundaries = Value::Array(
            context
                .request_row_boundaries
                .iter()
                .map(|boundary| {
                    json!({
                        "field": boundary.field(),
                        "operator": boundary.operator().as_str(),
                        "values": boundary.values(),
                    })
                })
                .collect(),
        );
        let payload = json!({
            "version": 1,
            "requestEntityId": context.request_entity_id,
            "targetEntityId": context.target_entity_id,
            "targetRecordId": context.target_record_id.to_string(),
            "contractFingerprint": context.contract_fingerprint,
            "activePackageRevision": context.active_package_revision,
            "selectedAccessProfile": context.selected_profile,
            "principal": context.principal,
            "purpose": context.purpose,
            "requestRowBoundaries": request_boundaries,
        });
        let bytes = canonicalize_json(&payload).map_err(|_| invalid_context())?;
        if bytes.len() > MAX_BOUNDARY_CONTEXT_BYTES {
            return Err(invalid_context());
        }
        String::from_utf8(bytes).map_err(|_| invalid_context())
    }
}

impl fmt::Debug for ChangeRequestPresenceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeRequestPresenceContext")
            .field("request_entity_id", &self.request_entity_id)
            .field("target_entity_id", &self.target_entity_id)
            .field("target_record_id", &self.target_record_id)
            .field("contract_fingerprint", &self.contract_fingerprint)
            .field("active_package_revision", &self.active_package_revision)
            .field("selected_profile", &self.selected_profile)
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field(
                "request_row_boundary_count",
                &self.request_row_boundaries.len(),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ChangeRequestTargetPhase {
    Preparation,
    Review { stage: String },
    Application,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChangeRequestTargetBinding {
    pub request_entity_id: String,
    pub request_id: Uuid,
    pub proposal_version: i64,
    pub actor_reference: String,
    pub contract_fingerprint: String,
    pub effect_digest: String,
    pub active_package_revision: String,
    pub effect_id: String,
    pub target_entity_id: String,
    pub target_record_id: Uuid,
    pub operation: Operation,
    pub fields: BTreeSet<String>,
    pub expected_revision: Option<i64>,
}

impl ChangeRequestTargetBinding {
    fn validate_basic(&self) -> Result<()> {
        validate_required_context_value(&self.request_entity_id)?;
        validate_required_context_value(&self.actor_reference)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_sha256_fingerprint(&self.effect_digest)?;
        validate_required_context_value(&self.active_package_revision)?;
        validate_required_context_value(&self.effect_id)?;
        validate_required_context_value(&self.target_entity_id)?;
        if self.proposal_version <= 0
            || self.expected_revision.is_some_and(|revision| revision <= 0)
        {
            return Err(invalid_context());
        }
        if self.fields.is_empty()
            || self.fields.len() > MAX_TARGET_FIELDS
            || self
                .fields
                .iter()
                .any(|field| validate_required_context_value(field).is_err())
        {
            return Err(invalid_context());
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ChangeRequestTargetContext {
    phase: ChangeRequestTargetPhase,
    request_entity_id: String,
    request_id: Uuid,
    proposal_version: i64,
    actor_reference: String,
    contract_fingerprint: String,
    effect_digest: String,
    active_package_revision: String,
    selected_profile: String,
    principal: Option<String>,
    purpose: Option<String>,
    effect_id: String,
    target_entity_id: String,
    target_record_id: Uuid,
    operation: Operation,
    fields: BTreeSet<String>,
    expected_revision: Option<i64>,
    target_row_boundaries: Vec<RowBoundaryContext>,
    canonical_context: String,
}

impl ChangeRequestTargetContext {
    pub(crate) fn for_preparation(
        registry: &CompiledRegistry,
        request_claims: &ClaimContext,
        binding: ChangeRequestTargetBinding,
    ) -> Result<Self> {
        Self::for_compiled(
            registry,
            request_claims,
            ChangeRequestTargetPhase::Preparation,
            Vec::new(),
            binding,
        )
    }

    pub(crate) fn for_review(
        registry: &CompiledRegistry,
        request_claims: &ClaimContext,
        stage: &str,
        target_boundaries: Vec<RowBoundaryContext>,
        binding: ChangeRequestTargetBinding,
    ) -> Result<Self> {
        validate_required_context_value(stage)?;
        Self::for_compiled(
            registry,
            request_claims,
            ChangeRequestTargetPhase::Review {
                stage: stage.to_owned(),
            },
            target_boundaries,
            binding,
        )
    }

    pub(crate) fn for_application(
        registry: &CompiledRegistry,
        request_claims: &ClaimContext,
        target_boundaries: Vec<RowBoundaryContext>,
        binding: ChangeRequestTargetBinding,
    ) -> Result<Self> {
        Self::for_compiled(
            registry,
            request_claims,
            ChangeRequestTargetPhase::Application,
            target_boundaries,
            binding,
        )
    }

    #[must_use]
    pub(crate) fn canonical_context(&self) -> &str {
        &self.canonical_context
    }

    pub(crate) fn authorize_rows(
        &self,
        target_entity: &crate::model::CompiledEntity,
        before: Option<&serde_json::Map<String, Value>>,
        after: &serde_json::Map<String, Value>,
        record_id: Uuid,
    ) -> Result<()> {
        self.validate()?;
        if target_entity.id != self.target_entity_id || record_id != self.target_record_id {
            return Err(invalid_context());
        }
        match self.operation {
            Operation::Create if before.is_some() => return Err(invalid_context()),
            Operation::Patch if before.is_none() => return Err(invalid_context()),
            Operation::Create | Operation::Patch => {}
            _ => return Err(invalid_context()),
        }
        if let Some(before) = before {
            validate_snapshot_boundaries(
                target_entity,
                before,
                record_id,
                &self.target_row_boundaries,
            )?;
        }
        validate_snapshot_boundaries(target_entity, after, record_id, &self.target_row_boundaries)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.request_entity_id)?;
        validate_required_context_value(&self.actor_reference)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_sha256_fingerprint(&self.effect_digest)?;
        validate_required_context_value(&self.active_package_revision)?;
        validate_required_context_value(&self.selected_profile)?;
        self.principal
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        validate_required_context_value(&self.effect_id)?;
        validate_required_context_value(&self.target_entity_id)?;
        if self.proposal_version <= 0
            || self.expected_revision.is_some_and(|revision| revision <= 0)
        {
            return Err(invalid_context());
        }
        if self.fields.is_empty()
            || self.fields.len() > MAX_TARGET_FIELDS
            || self
                .fields
                .iter()
                .any(|field| validate_required_context_value(field).is_err())
        {
            return Err(invalid_context());
        }
        for boundary in &self.target_row_boundaries {
            validate_boundary(boundary)?;
        }
        if Self::canonicalize(self)? != self.canonical_context {
            return Err(invalid_context());
        }
        Ok(())
    }

    fn for_compiled(
        registry: &CompiledRegistry,
        request_claims: &ClaimContext,
        phase: ChangeRequestTargetPhase,
        target_boundaries: Vec<RowBoundaryContext>,
        binding: ChangeRequestTargetBinding,
    ) -> Result<Self> {
        request_claims.validate()?;
        binding.validate_basic()?;
        if request_claims.entity_id() != binding.request_entity_id {
            return Err(invalid_context());
        }
        let request_entity = registry
            .entities()
            .get(&binding.request_entity_id)
            .ok_or_else(invalid_context)?;
        let request_profile = request_entity
            .access_profiles
            .get(request_claims.access_profile())
            .ok_or_else(invalid_context)?;
        let plan = request_entity
            .change_request
            .as_ref()
            .ok_or_else(invalid_context)?;
        if plan.contract_fingerprint != binding.contract_fingerprint {
            return Err(invalid_context());
        }
        let effect = plan
            .effects
            .iter()
            .find(|effect| effect.id == binding.effect_id)
            .ok_or_else(invalid_context)?;
        validate_effect_binding(effect, &binding, &phase)?;

        match &phase {
            ChangeRequestTargetPhase::Preparation => {
                if !request_profile.operations.iter().any(|operation| {
                    matches!(
                        operation,
                        Operation::SubmitRequest | Operation::ReviseRequest
                    )
                }) {
                    return Err(invalid_context());
                }
                if !target_boundaries.is_empty() {
                    return Err(invalid_context());
                }
            }
            ChangeRequestTargetPhase::Review { stage } => {
                if !request_profile.operations.iter().any(|operation| {
                    matches!(
                        operation,
                        Operation::ApproveRequest
                            | Operation::RejectRequest
                            | Operation::RequestRevision
                    )
                }) {
                    return Err(invalid_context());
                }
                let grant = plan
                    .review_grants
                    .iter()
                    .find(|grant| {
                        grant.profile_id == request_claims.access_profile()
                            && grant.stage == *stage
                            && grant.target_entity_id == binding.target_entity_id
                    })
                    .ok_or_else(invalid_context)?;
                validate_target_boundaries(
                    registry,
                    &binding.target_entity_id,
                    &target_boundaries,
                    &grant.row_boundaries,
                )?;
                if !binding.fields.is_subset(&grant.readable_fields) {
                    return Err(invalid_context());
                }
            }
            ChangeRequestTargetPhase::Application => {
                if !request_profile
                    .operations
                    .contains(&Operation::ApplyRequest)
                {
                    return Err(invalid_context());
                }
                let grant = plan
                    .apply_grants
                    .iter()
                    .find(|grant| {
                        grant.profile_id == request_claims.access_profile()
                            && grant.target_entity_id == binding.target_entity_id
                    })
                    .ok_or_else(invalid_context)?;
                validate_target_boundaries(
                    registry,
                    &binding.target_entity_id,
                    &target_boundaries,
                    &grant.row_boundaries,
                )?;
            }
        }

        let mut context = Self {
            phase,
            request_entity_id: binding.request_entity_id,
            request_id: binding.request_id,
            proposal_version: binding.proposal_version,
            actor_reference: binding.actor_reference,
            contract_fingerprint: binding.contract_fingerprint,
            effect_digest: binding.effect_digest,
            active_package_revision: binding.active_package_revision,
            selected_profile: request_claims.access_profile().to_owned(),
            principal: request_claims.principal().map(str::to_owned),
            purpose: request_claims.purpose().map(str::to_owned),
            effect_id: binding.effect_id,
            target_entity_id: binding.target_entity_id,
            target_record_id: binding.target_record_id,
            operation: binding.operation,
            fields: binding.fields,
            expected_revision: binding.expected_revision,
            target_row_boundaries: target_boundaries,
            canonical_context: String::new(),
        };
        context.canonical_context = Self::canonicalize(&context)?;
        context.validate()?;
        Ok(context)
    }

    fn canonicalize(context: &Self) -> Result<String> {
        let phase = match &context.phase {
            ChangeRequestTargetPhase::Preparation => json!({"kind": "preparation"}),
            ChangeRequestTargetPhase::Review { stage } => {
                json!({"kind": "review", "stage": stage})
            }
            ChangeRequestTargetPhase::Application => json!({"kind": "application"}),
        };
        let target_boundaries = Value::Array(
            context
                .target_row_boundaries
                .iter()
                .map(|boundary| {
                    json!({
                        "field": boundary.field(),
                        "operator": boundary.operator().as_str(),
                        "values": boundary.values(),
                    })
                })
                .collect(),
        );
        let payload = json!({
            "version": 1,
            "phase": phase,
            "requestEntityId": context.request_entity_id,
            "requestId": context.request_id.to_string(),
            "proposalVersion": context.proposal_version,
            "actorReference": context.actor_reference,
            "contractFingerprint": context.contract_fingerprint,
            "effectDigest": context.effect_digest,
            "activePackageRevision": context.active_package_revision,
            "selectedAccessProfile": context.selected_profile,
            "principal": context.principal,
            "purpose": context.purpose,
            "effectId": context.effect_id,
            "targetEntityId": context.target_entity_id,
            "targetRecordId": context.target_record_id.to_string(),
            "operation": operation_context_name(context.operation),
            "fields": context.fields,
            "expectedRevision": context.expected_revision,
            "targetRowBoundaries": target_boundaries,
        });
        let bytes = canonicalize_json(&payload).map_err(|_| invalid_context())?;
        if bytes.len() > MAX_BOUNDARY_CONTEXT_BYTES {
            return Err(invalid_context());
        }
        String::from_utf8(bytes).map_err(|_| invalid_context())
    }
}

impl fmt::Debug for ChangeRequestTargetContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChangeRequestTargetContext")
            .field("phase", &self.phase)
            .field("request_entity_id", &self.request_entity_id)
            .field("request_id", &self.request_id)
            .field("proposal_version", &self.proposal_version)
            .field("actor_reference", &"<redacted>")
            .field("contract_fingerprint", &self.contract_fingerprint)
            .field("effect_digest", &self.effect_digest)
            .field("active_package_revision", &self.active_package_revision)
            .field("selected_profile", &self.selected_profile)
            .field("principal", &self.principal.as_ref().map(|_| "<redacted>"))
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("effect_id", &self.effect_id)
            .field("target_entity_id", &self.target_entity_id)
            .field("target_record_id", &self.target_record_id)
            .field("operation", &self.operation)
            .field("fields", &self.fields)
            .field("expected_revision", &self.expected_revision)
            .field("target_row_boundaries", &self.target_row_boundaries)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ImmediateActionTargetBinding {
    pub action_id: String,
    pub contract_fingerprint: String,
    pub active_package_revision: String,
    pub effect_ids: BTreeSet<String>,
    pub target_entity_id: String,
    pub target_record_id: Uuid,
    pub operation: Operation,
    pub fields: BTreeSet<String>,
    pub expected_revision: Option<i64>,
    pub lock_only: bool,
    pub application_id: Option<Uuid>,
}

impl ImmediateActionTargetBinding {
    fn validate_basic(&self) -> Result<()> {
        validate_required_context_value(&self.action_id)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_required_context_value(&self.active_package_revision)?;
        if self.effect_ids.is_empty()
            || self.effect_ids.len() > MAX_TARGET_FIELDS
            || self
                .effect_ids
                .iter()
                .any(|effect_id| validate_required_context_value(effect_id).is_err())
        {
            return Err(invalid_context());
        }
        validate_required_context_value(&self.target_entity_id)?;
        if self.lock_only && self.expected_revision.is_some() {
            return Err(invalid_context());
        }
        if self.expected_revision.is_some_and(|revision| revision <= 0)
            || self.fields.is_empty()
            || self.fields.len() > MAX_TARGET_FIELDS
            || self
                .fields
                .iter()
                .any(|field| validate_required_context_value(field).is_err())
        {
            return Err(invalid_context());
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ImmediateActionTargetContext {
    action_id: String,
    contract_fingerprint: String,
    active_package_revision: String,
    selected_profile: String,
    principal: String,
    purpose: Option<String>,
    effect_ids: BTreeSet<String>,
    target_entity_id: String,
    target_record_id: Uuid,
    operation: Operation,
    fields: BTreeSet<String>,
    expected_revision: Option<i64>,
    lock_only: bool,
    application_id: Option<Uuid>,
    target_row_boundaries: Vec<RowBoundaryContext>,
    canonical_context: String,
}

impl ImmediateActionTargetContext {
    pub(crate) fn for_effect(
        registry: &CompiledRegistry,
        action_claims: &ActionClaimContext,
        target_boundaries: Vec<RowBoundaryContext>,
        binding: ImmediateActionTargetBinding,
    ) -> Result<Self> {
        action_claims.validate()?;
        binding.validate_basic()?;
        if action_claims.action_id() != binding.action_id {
            return Err(invalid_context());
        }
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == binding.action_id)
            .ok_or_else(invalid_context)?;
        if action.contract_fingerprint != binding.contract_fingerprint {
            return Err(invalid_context());
        }
        let mut effects = Vec::with_capacity(binding.effect_ids.len());
        for effect_id in &binding.effect_ids {
            effects.push(
                action
                    .effects
                    .iter()
                    .find(|effect| effect.id == *effect_id)
                    .ok_or_else(invalid_context)?,
            );
        }
        validate_action_effect_binding(&effects, &binding)?;
        let grant = action
            .grants
            .iter()
            .find(|grant| {
                grant.profile_id == action_claims.access_profile()
                    && grant.operations.contains(&Operation::Invoke)
                    && grant
                        .targets
                        .iter()
                        .any(|target| target.entity_id == binding.target_entity_id)
            })
            .ok_or_else(invalid_context)?;
        let target_grant = grant
            .targets
            .iter()
            .find(|target| target.entity_id == binding.target_entity_id)
            .ok_or_else(invalid_context)?;
        validate_target_boundaries(
            registry,
            &binding.target_entity_id,
            &target_boundaries,
            &target_grant.row_boundaries,
        )?;
        let mut context = Self {
            action_id: binding.action_id,
            contract_fingerprint: binding.contract_fingerprint,
            active_package_revision: binding.active_package_revision,
            selected_profile: action_claims.access_profile().to_owned(),
            principal: action_claims.principal().to_owned(),
            purpose: action_claims.purpose().map(str::to_owned),
            effect_ids: binding.effect_ids,
            target_entity_id: binding.target_entity_id,
            target_record_id: binding.target_record_id,
            operation: binding.operation,
            fields: binding.fields,
            expected_revision: binding.expected_revision,
            lock_only: binding.lock_only,
            application_id: binding.application_id,
            target_row_boundaries: target_boundaries,
            canonical_context: String::new(),
        };
        context.canonical_context = Self::canonicalize(&context)?;
        context.validate()?;
        Ok(context)
    }

    #[must_use]
    pub(crate) fn canonical_context(&self) -> &str {
        &self.canonical_context
    }

    pub(crate) fn authorize_rows(
        &self,
        target_entity: &crate::model::CompiledEntity,
        before: Option<&serde_json::Map<String, Value>>,
        after: &serde_json::Map<String, Value>,
        record_id: Uuid,
    ) -> Result<()> {
        self.validate()?;
        if target_entity.id != self.target_entity_id || record_id != self.target_record_id {
            return Err(invalid_context());
        }
        match self.operation {
            Operation::Create if before.is_some() => return Err(invalid_context()),
            Operation::Patch if before.is_none() => return Err(invalid_context()),
            Operation::Create | Operation::Patch => {}
            _ => return Err(invalid_context()),
        }
        if let Some(before) = before {
            validate_action_field_delta(target_entity, before, after, &self.fields)?;
            validate_snapshot_boundaries(
                target_entity,
                before,
                record_id,
                &self.target_row_boundaries,
            )?;
        }
        validate_snapshot_boundaries(target_entity, after, record_id, &self.target_row_boundaries)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.action_id)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_required_context_value(&self.active_package_revision)?;
        validate_required_context_value(&self.selected_profile)?;
        validate_required_context_value(&self.principal)?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        if self.effect_ids.is_empty()
            || self.effect_ids.len() > MAX_TARGET_FIELDS
            || self
                .effect_ids
                .iter()
                .any(|effect_id| validate_required_context_value(effect_id).is_err())
        {
            return Err(invalid_context());
        }
        validate_required_context_value(&self.target_entity_id)?;
        if self.lock_only && self.expected_revision.is_some() {
            return Err(invalid_context());
        }
        if self.expected_revision.is_some_and(|revision| revision <= 0)
            || self.fields.is_empty()
            || self.fields.len() > MAX_TARGET_FIELDS
            || self
                .fields
                .iter()
                .any(|field| validate_required_context_value(field).is_err())
        {
            return Err(invalid_context());
        }
        for boundary in &self.target_row_boundaries {
            validate_boundary(boundary)?;
        }
        if Self::canonicalize(self)? != self.canonical_context {
            return Err(invalid_context());
        }
        Ok(())
    }

    fn canonicalize(context: &Self) -> Result<String> {
        let target_boundaries = Value::Array(
            context
                .target_row_boundaries
                .iter()
                .map(|boundary| {
                    json!({
                        "field": boundary.field(),
                        "operator": boundary.operator().as_str(),
                        "values": boundary.values(),
                    })
                })
                .collect(),
        );
        let application_id = context.application_id.map(|id| id.to_string());
        let payload = json!({
            "version": 1,
            "actionId": context.action_id,
            "contractFingerprint": context.contract_fingerprint,
            "activePackageRevision": context.active_package_revision,
            "selectedAccessProfile": context.selected_profile,
            "principal": context.principal,
            "purpose": context.purpose,
            "effectIds": context.effect_ids,
            "applicationId": application_id,
            "targetEntityId": context.target_entity_id,
            "targetRecordId": context.target_record_id.to_string(),
            "operation": operation_context_name(context.operation),
            "fields": context.fields,
            "expectedRevision": context.expected_revision,
            "lockOnly": context.lock_only,
            "targetRowBoundaries": target_boundaries,
        });
        let bytes = canonicalize_json(&payload).map_err(|_| invalid_context())?;
        if bytes.len() > MAX_BOUNDARY_CONTEXT_BYTES {
            return Err(invalid_context());
        }
        String::from_utf8(bytes).map_err(|_| invalid_context())
    }
}

impl fmt::Debug for ImmediateActionTargetContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmediateActionTargetContext")
            .field("action_id", &self.action_id)
            .field("contract_fingerprint", &self.contract_fingerprint)
            .field("active_package_revision", &self.active_package_revision)
            .field("selected_profile", &self.selected_profile)
            .field("principal", &"<redacted>")
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("effect_ids", &self.effect_ids)
            .field("application_id", &self.application_id)
            .field("target_entity_id", &self.target_entity_id)
            .field("target_record_id", &self.target_record_id)
            .field("operation", &self.operation)
            .field("fields", &self.fields)
            .field("expected_revision", &self.expected_revision)
            .field("lock_only", &self.lock_only)
            .field("target_row_boundaries", &self.target_row_boundaries)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ImmediateActionLinkBinding {
    pub action_id: String,
    pub contract_fingerprint: String,
    pub active_package_revision: String,
    pub input_id: String,
    pub target_entity_id: String,
    pub target_record_id: Uuid,
}

impl ImmediateActionLinkBinding {
    fn validate_basic(&self) -> Result<()> {
        validate_required_context_value(&self.action_id)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_required_context_value(&self.active_package_revision)?;
        validate_required_context_value(&self.input_id)?;
        validate_required_context_value(&self.target_entity_id)?;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ImmediateActionLinkContext {
    action_id: String,
    contract_fingerprint: String,
    active_package_revision: String,
    selected_profile: String,
    principal: String,
    purpose: Option<String>,
    input_id: String,
    target_entity_id: String,
    target_record_id: Uuid,
    target_row_boundaries: Vec<RowBoundaryContext>,
    canonical_context: String,
}

impl ImmediateActionLinkContext {
    pub(crate) fn for_input(
        registry: &CompiledRegistry,
        action_claims: &ActionClaimContext,
        target_boundaries: Vec<RowBoundaryContext>,
        binding: ImmediateActionLinkBinding,
    ) -> Result<Self> {
        action_claims.validate()?;
        binding.validate_basic()?;
        if action_claims.action_id() != binding.action_id {
            return Err(invalid_context());
        }
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == binding.action_id)
            .ok_or_else(invalid_context)?;
        if action.contract_fingerprint != binding.contract_fingerprint {
            return Err(invalid_context());
        }
        let input = action
            .inputs
            .iter()
            .find(|input| input.id == binding.input_id)
            .ok_or_else(invalid_context)?;
        let crate::contract::FieldTypeSource::Reference { target, .. } = &input.field_type else {
            return Err(invalid_context());
        };
        if target != &binding.target_entity_id {
            return Err(invalid_context());
        }
        if !action.target_uses.iter().any(|target_use| {
            target_use.entity_id == binding.target_entity_id
                && target_use.operation == Operation::Invoke
                && target_use.fields.is_empty()
                && !target_use.condition_required
                && matches!(
                    &target_use.source,
                    CompiledActionTargetUseSource::Input { input } if input == &binding.input_id
                )
        }) {
            return Err(invalid_context());
        }
        let grant = action
            .grants
            .iter()
            .find(|grant| {
                grant.profile_id == action_claims.access_profile()
                    && grant.operations.contains(&Operation::Invoke)
                    && grant
                        .targets
                        .iter()
                        .any(|target| target.entity_id == binding.target_entity_id)
            })
            .ok_or_else(invalid_context)?;
        let target_grant = grant
            .targets
            .iter()
            .find(|target| target.entity_id == binding.target_entity_id)
            .ok_or_else(invalid_context)?;
        validate_target_boundaries(
            registry,
            &binding.target_entity_id,
            &target_boundaries,
            &target_grant.row_boundaries,
        )?;
        let mut context = Self {
            action_id: binding.action_id,
            contract_fingerprint: binding.contract_fingerprint,
            active_package_revision: binding.active_package_revision,
            selected_profile: action_claims.access_profile().to_owned(),
            principal: action_claims.principal().to_owned(),
            purpose: action_claims.purpose().map(str::to_owned),
            input_id: binding.input_id,
            target_entity_id: binding.target_entity_id,
            target_record_id: binding.target_record_id,
            target_row_boundaries: target_boundaries,
            canonical_context: String::new(),
        };
        context.canonical_context = Self::canonicalize(&context)?;
        context.validate()?;
        Ok(context)
    }

    #[must_use]
    pub(crate) fn canonical_context(&self) -> &str {
        &self.canonical_context
    }

    pub(crate) fn authorize_row(
        &self,
        target_entity: &crate::model::CompiledEntity,
        row: &serde_json::Map<String, Value>,
        record_id: Uuid,
    ) -> Result<()> {
        self.validate()?;
        if target_entity.id != self.target_entity_id || record_id != self.target_record_id {
            return Err(invalid_context());
        }
        validate_snapshot_boundaries(target_entity, row, record_id, &self.target_row_boundaries)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_required_context_value(&self.action_id)?;
        validate_sha256_fingerprint(&self.contract_fingerprint)?;
        validate_required_context_value(&self.active_package_revision)?;
        validate_required_context_value(&self.selected_profile)?;
        validate_required_context_value(&self.principal)?;
        self.purpose
            .as_deref()
            .map(validate_required_context_value)
            .transpose()?;
        validate_required_context_value(&self.input_id)?;
        validate_required_context_value(&self.target_entity_id)?;
        for boundary in &self.target_row_boundaries {
            validate_boundary(boundary)?;
        }
        if Self::canonicalize(self)? != self.canonical_context {
            return Err(invalid_context());
        }
        Ok(())
    }

    fn canonicalize(context: &Self) -> Result<String> {
        let target_boundaries = Value::Array(
            context
                .target_row_boundaries
                .iter()
                .map(|boundary| {
                    json!({
                        "field": boundary.field(),
                        "operator": boundary.operator().as_str(),
                        "values": boundary.values(),
                    })
                })
                .collect(),
        );
        let payload = json!({
            "version": 1,
            "actionId": context.action_id,
            "contractFingerprint": context.contract_fingerprint,
            "activePackageRevision": context.active_package_revision,
            "selectedAccessProfile": context.selected_profile,
            "principal": context.principal,
            "purpose": context.purpose,
            "inputId": context.input_id,
            "targetEntityId": context.target_entity_id,
            "targetRecordId": context.target_record_id.to_string(),
            "operation": "invoke",
            "targetRowBoundaries": target_boundaries,
        });
        let bytes = canonicalize_json(&payload).map_err(|_| invalid_context())?;
        if bytes.len() > MAX_BOUNDARY_CONTEXT_BYTES {
            return Err(invalid_context());
        }
        String::from_utf8(bytes).map_err(|_| invalid_context())
    }
}

impl fmt::Debug for ImmediateActionLinkContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmediateActionLinkContext")
            .field("action_id", &self.action_id)
            .field("contract_fingerprint", &self.contract_fingerprint)
            .field("active_package_revision", &self.active_package_revision)
            .field("selected_profile", &self.selected_profile)
            .field("principal", &"<redacted>")
            .field("purpose", &self.purpose.as_ref().map(|_| "<redacted>"))
            .field("input_id", &self.input_id)
            .field("target_entity_id", &self.target_entity_id)
            .field("target_record_id", &self.target_record_id)
            .field("target_row_boundaries", &self.target_row_boundaries)
            .finish()
    }
}

fn validate_action_effect_binding(
    effects: &[&CompiledActionEffect],
    binding: &ImmediateActionTargetBinding,
) -> Result<()> {
    if effects.is_empty() {
        return Err(invalid_context());
    }
    let expected_fields = action_effect_fields(effects);
    if expected_fields != binding.fields {
        return Err(invalid_context());
    }
    for effect in effects {
        if effect.target.entity_id != binding.target_entity_id
            || effect.operation != binding.operation
        {
            return Err(invalid_context());
        }
    }
    match (
        binding.operation,
        binding.expected_revision,
        binding.lock_only,
    ) {
        (Operation::Create, None, false) => {
            if effects.len() != 1
                || !matches!(
                    effects[0].target.binding,
                    CompiledActionTargetBinding::Create
                )
            {
                return Err(invalid_context());
            }
        }
        (Operation::Patch, None, true) => {
            if effects.iter().any(|effect| {
                !matches!(
                    effect.target.binding,
                    CompiledActionTargetBinding::Existing { .. }
                )
            }) {
                return Err(invalid_context());
            }
        }
        (Operation::Patch, _, false) => {
            if effects.iter().any(|effect| {
                !matches!(
                    effect.target.binding,
                    CompiledActionTargetBinding::Existing { .. }
                )
            }) {
                return Err(invalid_context());
            }
        }
        _ => return Err(invalid_context()),
    }
    Ok(())
}

fn action_effect_fields(effects: &[&CompiledActionEffect]) -> BTreeSet<String> {
    effects
        .iter()
        .flat_map(|effect| &effect.mutations)
        .map(|mutation| match mutation {
            CompiledActionMutation::Set { field, .. } | CompiledActionMutation::Clear { field } => {
                field.clone()
            }
        })
        .collect()
}

fn validate_action_field_delta(
    target_entity: &crate::model::CompiledEntity,
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
    allowed_fields: &BTreeSet<String>,
) -> Result<()> {
    for field_id in target_entity.fields.keys() {
        if before.get(field_id) != after.get(field_id) && !allowed_fields.contains(field_id) {
            return Err(invalid_context());
        }
    }
    Ok(())
}

fn validate_effect_binding(
    effect: &CompiledChangeRequestEffect,
    binding: &ChangeRequestTargetBinding,
    phase: &ChangeRequestTargetPhase,
) -> Result<()> {
    if effect.target.entity_id != binding.target_entity_id || effect.operation != binding.operation
    {
        return Err(invalid_context());
    }
    let expected_fields = effect
        .mutations
        .iter()
        .map(|mutation| match mutation {
            CompiledChangeRequestMutation::Set { field, .. }
            | CompiledChangeRequestMutation::Clear { field } => field.clone(),
        })
        .collect::<BTreeSet<_>>();
    if expected_fields != binding.fields {
        return Err(invalid_context());
    }
    match (
        &effect.target.binding,
        binding.operation,
        binding.expected_revision,
    ) {
        (
            CompiledChangeRequestTargetBinding::ReservedCreate { effect },
            Operation::Create,
            None,
        ) if effect == &binding.effect_id => {}
        (CompiledChangeRequestTargetBinding::Existing { .. }, Operation::Patch, None)
            if matches!(phase, ChangeRequestTargetPhase::Preparation) => {}
        (CompiledChangeRequestTargetBinding::Existing { .. }, Operation::Patch, Some(_))
            if !matches!(phase, ChangeRequestTargetPhase::Preparation) => {}
        _ => return Err(invalid_context()),
    }
    Ok(())
}

fn validate_target_boundaries(
    registry: &CompiledRegistry,
    target_entity_id: &str,
    actual: &[RowBoundaryContext],
    expected: &[crate::contract::RowBoundarySource],
) -> Result<()> {
    let entity = registry
        .entities()
        .get(target_entity_id)
        .ok_or_else(invalid_context)?;
    if actual.len() != expected.len() {
        return Err(invalid_context());
    }
    for (actual, expected) in actual.iter().zip(expected) {
        let expected_operator = match expected.operator {
            BoundaryOperator::Equals => RowBoundaryOperator::Equals,
            BoundaryOperator::In => RowBoundaryOperator::In,
        };
        if actual.field() != expected.field || actual.operator() != expected_operator {
            return Err(invalid_context());
        }
        validate_boundary(actual)?;
        let field_type = if expected.field == entity.canonical_id.id {
            &entity.canonical_id.field_type
        } else {
            &entity
                .fields
                .get(&expected.field)
                .ok_or_else(invalid_context)?
                .field_type
        };
        for value in actual.values() {
            validate_field_value(value, field_type)?;
        }
    }
    Ok(())
}

fn presence_boundary_matches_source(
    actual: &RowBoundaryContext,
    expected: &crate::contract::RowBoundarySource,
) -> bool {
    let expected_operator = match expected.operator {
        BoundaryOperator::Equals => RowBoundaryOperator::Equals,
        BoundaryOperator::In => RowBoundaryOperator::In,
    };
    actual.field() == expected.field && actual.operator() == expected_operator
}

fn is_change_request_action_operation(operation: Operation) -> bool {
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

fn change_request_action_operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::SubmitRequest => "submit_request",
        Operation::ApproveRequest => "approve_request",
        Operation::RejectRequest => "reject_request",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise_request",
        Operation::CancelRequest => "cancel_request",
        Operation::ApplyRequest => "apply_request",
        _ => "unsupported",
    }
}

fn change_request_action_route_id(
    entity_id: &str,
    operation: Operation,
    stage: Option<&str>,
) -> String {
    let action_id = match operation {
        Operation::SubmitRequest => "submit",
        Operation::ApproveRequest => "approve",
        Operation::RejectRequest => "reject",
        Operation::RequestRevision => "request_revision",
        Operation::ReviseRequest => "revise",
        Operation::CancelRequest => "cancel",
        Operation::ApplyRequest => "apply",
        _ => "unsupported",
    };
    match stage {
        Some(stage) => format!("records.{entity_id}.request.stages.{stage}.{action_id}"),
        None => format!("records.{entity_id}.request.{action_id}"),
    }
}

fn operation_context_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Patch => "patch",
        Operation::Invoke => "invoke",
        _ => "unsupported",
    }
}

fn validate_snapshot_boundaries(
    entity: &crate::model::CompiledEntity,
    row: &serde_json::Map<String, Value>,
    record_id: Uuid,
    boundaries: &[RowBoundaryContext],
) -> Result<()> {
    for boundary in boundaries {
        let actual = if boundary.field() == entity.canonical_id.id {
            record_id.to_string()
        } else {
            let field = entity
                .fields
                .get(boundary.field())
                .ok_or_else(invalid_context)?;
            let value = row.get(boundary.field()).ok_or_else(invalid_context)?;
            canonical_snapshot_field_value(value, &field.field_type)?
        };
        match boundary {
            RowBoundaryContext::Equals { value, .. } if &actual == value => {}
            RowBoundaryContext::In { values, .. } if values.contains(&actual) => {}
            RowBoundaryContext::Equals { .. } | RowBoundaryContext::In { .. } => {
                return Err(invalid_context());
            }
        }
    }
    Ok(())
}

fn canonical_snapshot_field_value(
    value: &Value,
    field_type: &crate::contract::FieldTypeSource,
) -> Result<String> {
    if !validate_data_field_value(FieldValue::Json(value), field_type) {
        return Err(invalid_context());
    }
    match field_type {
        crate::contract::FieldTypeSource::Boolean => value
            .as_bool()
            .map(|value| value.to_string())
            .ok_or_else(invalid_context),
        crate::contract::FieldTypeSource::Int64 => value
            .as_i64()
            .map(|value| value.to_string())
            .ok_or_else(invalid_context),
        crate::contract::FieldTypeSource::Crs84Point { .. }
        | crate::contract::FieldTypeSource::Structured { .. } => {
            let bytes = canonicalize_json(value).map_err(|_| invalid_context())?;
            String::from_utf8(bytes).map_err(|_| invalid_context())
        }
        _ => value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_context),
    }
}

fn validate_boundary(boundary: &RowBoundaryContext) -> Result<()> {
    validate_required_context_value(boundary.field())?;
    let values = boundary.values();
    if values.is_empty()
        || values.len() > MAX_BOUNDARY_SET_VALUES
        || values
            .iter()
            .any(|value| validate_required_context_value(value).is_err())
    {
        return Err(invalid_context());
    }
    Ok(())
}

fn validate_required_context_value(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CONTEXT_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(invalid_context());
    }
    Ok(())
}

fn validate_sha256_fingerprint(value: &str) -> Result<()> {
    validate_required_context_value(value)?;
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid_context());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_context());
    }
    Ok(())
}

pub(crate) fn validate_field_value(
    value: &str,
    field_type: &crate::contract::FieldTypeSource,
) -> Result<()> {
    if !validate_data_field_value(FieldValue::Text(value), field_type) {
        return Err(invalid_context());
    }
    Ok(())
}

fn canonical_boundaries(boundaries: &[RowBoundaryContext]) -> Result<String> {
    let value = Value::Array(
        boundaries
            .iter()
            .map(|boundary| {
                json!({
                    "field": boundary.field(),
                    "operator": boundary.operator().as_str(),
                    "values": boundary.values(),
                })
            })
            .collect(),
    );
    let bytes = canonicalize_json(&value).map_err(|_| invalid_context())?;
    if bytes.len() > MAX_BOUNDARY_CONTEXT_BYTES {
        return Err(invalid_context());
    }
    String::from_utf8(bytes).map_err(|_| invalid_context())
}

fn invalid_context() -> PostgresKernelError {
    PostgresKernelError::Configuration("verified database context is incomplete or invalid")
}

/// A record transaction that has passed maintenance, package, and claim gates.
pub struct GuardedTransaction<'a> {
    transaction: Transaction<'a>,
}

impl GuardedTransaction<'_> {
    #[allow(
        dead_code,
        reason = "trusted transaction modules consume this crate-private handle"
    )]
    pub(crate) fn transaction(&self) -> &tokio_postgres::Transaction<'_> {
        &self.transaction
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn transaction_for_test(&self) -> &tokio_postgres::Transaction<'_> {
        self.transaction()
    }

    pub async fn commit(self) -> Result<()> {
        self.transaction.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> Result<()> {
        self.transaction.rollback().await?;
        Ok(())
    }

    pub(crate) async fn install_change_request_action_context(
        &self,
        context: &ChangeRequestActionContext,
    ) -> Result<()> {
        context.validate()?;
        self.transaction
            .execute(
                "SELECT set_config('registry.change_request_action_context', $1, true)",
                &[&context.canonical_context()],
            )
            .await?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "read-side request presence integration installs this crate-private context after export"
    )]
    pub(crate) async fn install_change_request_presence_context(
        &self,
        context: &ChangeRequestPresenceContext,
    ) -> Result<()> {
        context.validate()?;
        self.transaction
            .execute(
                "SELECT set_config('registry.change_request_presence_context', $1, true)",
                &[&context.canonical_context()],
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn install_change_request_target_context(
        &self,
        context: &ChangeRequestTargetContext,
    ) -> Result<()> {
        context.validate()?;
        self.transaction
            .execute(
                "SELECT set_config('registry.change_request_target_context', $1, true)",
                &[&context.canonical_context()],
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn install_immediate_action_target_context(
        &self,
        context: &ImmediateActionTargetContext,
    ) -> Result<()> {
        context.validate()?;
        self.transaction
            .execute(
                "SELECT set_config('registry.immediate_action_target_context', $1, true)",
                &[&context.canonical_context()],
            )
            .await?;
        Ok(())
    }

    #[allow(
        dead_code,
        reason = "action runtime currently installs this link-only context from a raw transaction"
    )]
    pub(crate) async fn install_immediate_action_link_context(
        &self,
        context: &ImmediateActionLinkContext,
    ) -> Result<()> {
        context.validate()?;
        self.transaction
            .execute(
                "SELECT set_config('registry.immediate_action_link_context', $1, true)",
                &[&context.canonical_context()],
            )
            .await?;
        Ok(())
    }
}

/// Starts a record transaction and installs authority only after the shared
/// Registry lock and exact active-package checks succeed.
pub async fn begin_record_transaction<'a>(
    client: &'a mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    claims: &ClaimContext,
) -> Result<GuardedTransaction<'a>> {
    expected.validate()?;
    claims.validate()?;
    if lock_timeout.is_zero() || lock_timeout > Duration::from_secs(30) {
        return Err(PostgresKernelError::Configuration(
            "record lock timeout must be between 1 millisecond and 30 seconds",
        ));
    }
    let transaction = client.transaction().await?;
    let timeout_millis = i32::try_from(lock_timeout.as_millis()).map_err(|_| {
        PostgresKernelError::Configuration("record lock timeout is outside PostgreSQL bounds")
    })?;
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1::text, true)",
            &[&format!("{timeout_millis}ms")],
        )
        .await?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let state = transaction
        .query_opt(
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await?
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let ready = state.get::<_, String>(7) == "ready"
        && state.get::<_, String>(0) == expected.package_id
        && state.get::<_, String>(1) == expected.environment
        && state.get::<_, String>(2) == expected.instance_id
        && state.get::<_, String>(3) == expected.database_id
        && state.get::<_, String>(4) == expected.package_revision
        && state.get::<_, String>(5) == expected.schema_fingerprint
        && state.get::<_, i64>(6) == expected.package_sequence;
    if !ready {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    transaction
        .execute(
            "SELECT set_config('registry.principal', $1, true),
                    set_config('registry.access_profile', $2, true),
                    set_config('registry.purpose', $3, true),
                    set_config('registry.row_boundaries', $4, true),
                    set_config('registry.active_package_revision', $5, true)",
            &[
                &claims.principal.as_deref().unwrap_or(""),
                &claims.access_profile,
                &claims.purpose.as_deref().unwrap_or(""),
                &claims.canonical_row_boundaries,
                &expected.package_revision,
            ],
        )
        .await?;
    Ok(GuardedTransaction { transaction })
}

/// Starts an action transaction after the shared Registry lock and active
/// package checks. It installs action authority without claiming entity CRUD
/// rights; target RLS is supplied later through `ImmediateActionTargetContext`.
pub async fn begin_action_transaction<'a>(
    client: &'a mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
    claims: &ActionClaimContext,
) -> Result<GuardedTransaction<'a>> {
    expected.validate()?;
    claims.validate()?;
    if lock_timeout.is_zero() || lock_timeout > Duration::from_secs(30) {
        return Err(PostgresKernelError::Configuration(
            "record lock timeout must be between 1 millisecond and 30 seconds",
        ));
    }
    let transaction = client.transaction().await?;
    let timeout_millis = i32::try_from(lock_timeout.as_millis()).map_err(|_| {
        PostgresKernelError::Configuration("record lock timeout is outside PostgreSQL bounds")
    })?;
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1::text, true)",
            &[&format!("{timeout_millis}ms")],
        )
        .await?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let state = transaction
        .query_opt(
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await?
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let ready = state.get::<_, String>(7) == "ready"
        && state.get::<_, String>(0) == expected.package_id
        && state.get::<_, String>(1) == expected.environment
        && state.get::<_, String>(2) == expected.instance_id
        && state.get::<_, String>(3) == expected.database_id
        && state.get::<_, String>(4) == expected.package_revision
        && state.get::<_, String>(5) == expected.schema_fingerprint
        && state.get::<_, i64>(6) == expected.package_sequence;
    if !ready {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    transaction
        .execute(
            "SELECT set_config('registry.principal', $1, true),
                    set_config('registry.access_profile', $2, true),
                    set_config('registry.purpose', $3, true),
                    set_config('registry.row_boundaries', $4, true),
                    set_config('registry.active_package_revision', $5, true)",
            &[
                &claims.principal(),
                &claims.access_profile(),
                &claims.purpose().unwrap_or(""),
                &"[]",
                &expected.package_revision,
            ],
        )
        .await?;
    Ok(GuardedTransaction { transaction })
}

pub(crate) async fn install_spatial_bbox_context(
    transaction: &tokio_postgres::Transaction<'_>,
    context: &SpatialBboxContext,
) -> Result<()> {
    transaction
        .execute(
            "SELECT set_config('registry.bbox_west', $1, true),
                    set_config('registry.bbox_south', $2, true),
                    set_config('registry.bbox_east', $3, true),
                    set_config('registry.bbox_north', $4, true)",
            &[&context.west, &context.south, &context.east, &context.north],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use uuid::Uuid;

    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::{
        parse_project_json, AccessGrantSource, Classification, EntitySource, FieldSource,
        FieldTypeSource, MutationMode, Operation, ProjectAccessProfileSource, RegistryProject,
        RowBoundarySource,
    };

    use super::*;

    #[test]
    fn compiled_context_is_exact_bounded_and_value_redacted() {
        let registry = compiled_registry();
        let boundaries = vec![
            RowBoundaryContext::Equals {
                field: "tenant".to_owned(),
                value: "tenant-a".to_owned(),
            },
            RowBoundaryContext::In {
                field: "region".to_owned(),
                values: BTreeSet::from(["north".to_owned(), "south".to_owned()]),
            },
        ];
        let context = ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal-canary".to_owned()),
            "operator",
            Some("operations".to_owned()),
            boundaries.clone(),
        )
        .expect("exact compiled context is accepted");
        assert_eq!(context.entity_id(), "entry");
        assert_eq!(context.access_profile(), "operator");
        assert_eq!(context.row_boundaries(), boundaries);
        assert_eq!(
            context.canonical_row_boundaries,
            r#"[{"field":"tenant","operator":"equals","values":["tenant-a"]},{"field":"region","operator":"in","values":["north","south"]}]"#
        );
        let debug = format!("{context:?}");
        assert!(!debug.contains("principal-canary"));
        assert!(!debug.contains("tenant-a"));

        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            None,
            "operator",
            Some("operations".to_owned()),
            boundaries.clone(),
        )
        .is_err());
        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "operator",
            Some("wrong".to_owned()),
            boundaries.clone(),
        )
        .is_err());
        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "operator",
            Some("operations".to_owned()),
            boundaries.into_iter().rev().collect(),
        )
        .is_err());
    }

    #[test]
    fn compiled_context_rejects_every_noncanonical_field_value_before_postgres() {
        let registry = compiled_typed_registry();
        let valid = typed_boundaries();
        ClaimContext::for_compiled(
            &registry,
            "typed-entry",
            Some("principal".to_owned()),
            "typed",
            None,
            valid.clone(),
        )
        .expect("canonical values for every compiled field type are accepted");

        let invalid = [
            (0, equals("enabled", "TRUE")),
            (1, in_values("count", &["01"])),
            (1, in_values("count", &["9223372036854775808"])),
            (2, equals("amount", "01.20")),
            (2, equals("amount", "10.00")),
            (3, equals("effective-on", "2023-02-29")),
            (4, in_values("observed-at", &["2024-01-02 03:04:05+00"])),
            (5, equals("identifier", "123e4567e89b12d3a456426614174000")),
            (
                5,
                equals("identifier", "123E4567-E89B-12D3-A456-426614174000"),
            ),
            (
                6,
                in_values("parent", &["urn:uuid:123e4567-e89b-12d3-a456-426614174000"]),
            ),
            (
                6,
                in_values("parent", &["123E4567-E89B-12D3-A456-426614174000"]),
            ),
            (7, equals("short-name", "abcde")),
            (8, in_values("notes", &["1234567"])),
            (9, equals("color", "green")),
        ];
        for (index, replacement) in invalid {
            let mut boundaries = valid.clone();
            boundaries[index] = replacement;
            let error = ClaimContext::for_compiled(
                &registry,
                "typed-entry",
                Some("principal".to_owned()),
                "typed",
                None,
                boundaries,
            )
            .expect_err("noncanonical typed value must be refused before a transaction");
            assert_eq!(
                error.to_string(),
                "invalid PostgreSQL configuration: verified database context is incomplete or invalid"
            );
            assert!(!error.to_string().contains("green"));
        }
    }

    #[test]
    fn compiled_context_accepts_a_canonical_id_row_boundary() {
        let registry = compiled_registry();
        ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "viewer",
            None,
            vec![equals("id", "123e4567-e89b-12d3-a456-426614174000")],
        )
        .expect("the compiled canonical UUID boundary is accepted");
        assert!(ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "viewer",
            None,
            vec![equals("id", "not-a-uuid")],
        )
        .is_err());
    }

    #[test]
    fn immediate_action_target_context_binds_grouped_effects_fields_and_application() {
        let registry = compiled_action_context_registry();
        let action = registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == "rename-household-local")
            .expect("action compiles");
        let claims = ActionClaimContext::new(
            action.id.clone(),
            "principal-canary".to_owned(),
            "contact-registrar".to_owned(),
            Some("contact-registration".to_owned()),
            BTreeSet::from([
                "household-code-update".to_owned(),
                "household-note-update".to_owned(),
            ]),
        )
        .expect("action claims compile");
        let target_id =
            Uuid::parse_str("00000000-0000-4000-8000-000000000101").expect("target UUID parses");
        let application_id = Uuid::parse_str("00000000-0000-4000-8000-000000000a11")
            .expect("application UUID parses");
        let binding = ImmediateActionTargetBinding {
            action_id: action.id.clone(),
            contract_fingerprint: action.contract_fingerprint.clone(),
            active_package_revision: "package-1".to_owned(),
            effect_ids: BTreeSet::from([
                "household-code-update".to_owned(),
                "household-note-update".to_owned(),
            ]),
            target_entity_id: "household".to_owned(),
            target_record_id: target_id,
            operation: Operation::Patch,
            fields: BTreeSet::from(["household-code".to_owned(), "status-note".to_owned()]),
            expected_revision: Some(7),
            lock_only: false,
            application_id: Some(application_id),
        };
        let context = ImmediateActionTargetContext::for_effect(
            &registry,
            &claims,
            vec![equals("jurisdiction", "zone-a")],
            binding.clone(),
        )
        .expect("grouped action target context derives from compiled action grant");
        assert!(context
            .canonical_context()
            .contains("\"effectIds\":[\"household-code-update\",\"household-note-update\"]"));
        assert!(context
            .canonical_context()
            .contains("\"fields\":[\"household-code\",\"status-note\"]"));
        assert!(context
            .canonical_context()
            .contains("\"applicationId\":\"00000000-0000-4000-8000-000000000a11\""));
        let before = serde_json::Map::from_iter([
            ("household-code".to_owned(), json!("H-001")),
            ("jurisdiction".to_owned(), json!("zone-a")),
            ("status-note".to_owned(), json!("old note")),
        ]);
        let after = serde_json::Map::from_iter([
            ("household-code".to_owned(), json!("H-RENAMED")),
            ("jurisdiction".to_owned(), json!("zone-a")),
            ("status-note".to_owned(), json!("new note")),
        ]);
        context
            .authorize_rows(
                &registry.entities()["household"],
                Some(&before),
                &after,
                target_id,
            )
            .expect("the grouped field plan admits only its declared field changes");
        let mut escaped_after = after.clone();
        escaped_after.insert("jurisdiction".to_owned(), json!("zone-b"));
        assert!(context
            .authorize_rows(
                &registry.entities()["household"],
                Some(&before),
                &escaped_after,
                target_id,
            )
            .is_err());

        let mut subset_effects = binding.clone();
        subset_effects.effect_ids.remove("household-note-update");
        assert!(ImmediateActionTargetContext::for_effect(
            &registry,
            &claims,
            vec![equals("jurisdiction", "zone-a")],
            subset_effects,
        )
        .is_err());

        let mut superset_effects = binding.clone();
        superset_effects
            .effect_ids
            .insert("unknown-effect".to_owned());
        assert!(ImmediateActionTargetContext::for_effect(
            &registry,
            &claims,
            vec![equals("jurisdiction", "zone-a")],
            superset_effects,
        )
        .is_err());

        let mut mismatched_fields = binding;
        mismatched_fields.fields.insert("jurisdiction".to_owned());
        assert!(ImmediateActionTargetContext::for_effect(
            &registry,
            &claims,
            vec![equals("jurisdiction", "zone-a")],
            mismatched_fields,
        )
        .is_err());
    }

    #[test]
    fn change_request_presence_context_binds_target_reader_to_request_type_and_boundaries() {
        let registry = compiled_change_request_registry();
        let target_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000902").expect("target UUID parses");
        let plan = registry.entities()["placement-correction-request"]
            .change_request
            .as_ref()
            .expect("request plan compiles");
        let steward = ClaimContext::for_compiled(
            &registry,
            "asset-placement",
            Some("steward-canary".to_owned()),
            "steward",
            None,
            Vec::new(),
        )
        .expect("target reader context compiles");
        let context = ChangeRequestPresenceContext::for_presence(
            &registry,
            &steward,
            "placement-correction-request",
            "asset-placement",
            target_id,
            vec![equals("tenant", "tenant-a")],
            "package-1",
        )
        .expect("presence context derives from compiled requestPresence grant");
        assert!(context.canonical_context().contains(&format!(
            "\"contractFingerprint\":\"{}\"",
            plan.contract_fingerprint
        )));
        assert!(context
            .canonical_context()
            .contains("\"requestRowBoundaries\":[{\"field\":\"tenant\""));
        let debug = format!("{context:?}");
        assert!(!debug.contains("steward-canary"));
        assert!(!debug.contains("tenant-a"));

        assert!(ChangeRequestPresenceContext::for_presence(
            &registry,
            &steward,
            "placement-correction-request",
            "asset-site",
            target_id,
            vec![equals("tenant", "tenant-a")],
            "package-1",
        )
        .is_err());

        assert!(ChangeRequestPresenceContext::for_presence(
            &registry,
            &steward,
            "placement-correction-request",
            "asset-placement",
            target_id,
            vec![equals("reason", "tenant-a")],
            "package-1",
        )
        .is_err());
    }

    #[test]
    fn change_request_action_context_binds_compiled_route_and_request_authority() {
        let registry = compiled_change_request_registry();
        let request_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000901").expect("request UUID parses");
        let plan = registry.entities()["placement-correction-request"]
            .change_request
            .as_ref()
            .expect("request plan compiles");
        let reviewer = ClaimContext::for_compiled(
            &registry,
            "placement-correction-request",
            Some("reviewer-canary".to_owned()),
            "reviewer",
            Some("review".to_owned()),
            Vec::new(),
        )
        .expect("reviewer request context compiles");
        let context = ChangeRequestActionContext::for_route(
            &registry,
            &reviewer,
            "records.placement-correction-request.request.stages.review.approve",
            request_id,
            1,
            "actor-reference-canary",
            "package-1",
        )
        .expect("action context derives from the compiled route");
        assert!(context.canonical_context().contains(&format!(
            "\"contractFingerprint\":\"{}\"",
            plan.contract_fingerprint
        )));
        assert!(context.canonical_context().contains(
            "\"routeId\":\"records.placement-correction-request.request.stages.review.approve\""
        ));
        let debug = format!("{context:?}");
        assert!(!debug.contains("reviewer-canary"));
        assert!(!debug.contains("actor-reference-canary"));

        assert!(ChangeRequestActionContext::for_route(
            &registry,
            &reviewer,
            "records.placement-correction-request.request.stages.other.approve",
            request_id,
            1,
            "actor-reference-canary",
            "package-1",
        )
        .is_err());

        let submitter = ClaimContext::for_compiled(
            &registry,
            "placement-correction-request",
            Some("submitter-canary".to_owned()),
            "submitter",
            None,
            Vec::new(),
        )
        .expect("submitter request context compiles");
        assert!(ChangeRequestActionContext::for_route(
            &registry,
            &submitter,
            "records.placement-correction-request.request.stages.review.approve",
            request_id,
            1,
            "actor-reference-canary",
            "package-1",
        )
        .is_err());
    }

    #[test]
    fn change_request_target_context_binds_compiled_effect_and_review_authority() {
        let registry = compiled_change_request_registry();
        let request_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000901").expect("request UUID parses");
        let target_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000902").expect("target UUID parses");
        let plan = registry.entities()["placement-correction-request"]
            .change_request
            .as_ref()
            .expect("request plan compiles");
        let binding = ChangeRequestTargetBinding {
            request_entity_id: "placement-correction-request".to_owned(),
            request_id,
            proposal_version: 1,
            actor_reference: "actor-reference-canary".to_owned(),
            contract_fingerprint: plan.contract_fingerprint.clone(),
            effect_digest:
                "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
            active_package_revision: "package-1".to_owned(),
            effect_id: plan.effects[0].id.clone(),
            target_entity_id: "asset-placement".to_owned(),
            target_record_id: target_id,
            operation: Operation::Patch,
            fields: BTreeSet::from(["site".to_owned()]),
            expected_revision: Some(7),
        };
        let submitter = ClaimContext::for_compiled(
            &registry,
            "placement-correction-request",
            Some("principal-canary".to_owned()),
            "submitter",
            None,
            Vec::new(),
        )
        .expect("submitter request context compiles");
        let mut preparation_binding = binding.clone();
        preparation_binding.expected_revision = None;
        let preparation =
            ChangeRequestTargetContext::for_preparation(&registry, &submitter, preparation_binding)
                .expect("preparation context derives from fixed effect");
        assert!(preparation
            .canonical_context()
            .contains("\"effectDigest\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\""));
        let debug = format!("{preparation:?}");
        assert!(!debug.contains("principal-canary"));

        let reviewer = ClaimContext::for_compiled(
            &registry,
            "placement-correction-request",
            Some("reviewer-canary".to_owned()),
            "reviewer",
            Some("review".to_owned()),
            Vec::new(),
        )
        .expect("reviewer request context compiles");
        let review = ChangeRequestTargetContext::for_review(
            &registry,
            &reviewer,
            "review",
            vec![equals("tenant", "tenant-a")],
            binding.clone(),
        )
        .expect("review context derives from review grant and target boundary");
        assert!(review
            .canonical_context()
            .contains("\"phase\":{\"kind\":\"review\",\"stage\":\"review\"}"));
        let before = serde_json::Map::from_iter([
            ("tenant".to_owned(), json!("tenant-a")),
            (
                "site".to_owned(),
                json!("00000000-0000-0000-0000-000000000111"),
            ),
        ]);
        let after = serde_json::Map::from_iter([
            ("tenant".to_owned(), json!("tenant-a")),
            (
                "site".to_owned(),
                json!("00000000-0000-0000-0000-000000000112"),
            ),
        ]);
        review
            .authorize_rows(
                &registry.entities()["asset-placement"],
                Some(&before),
                &after,
                target_id,
            )
            .expect("review snapshots satisfy the target boundary exactly");
        let wrong_after = serde_json::Map::from_iter([
            ("tenant".to_owned(), json!("tenant-b")),
            (
                "site".to_owned(),
                json!("00000000-0000-0000-0000-000000000112"),
            ),
        ]);
        assert!(review
            .authorize_rows(
                &registry.entities()["asset-placement"],
                Some(&before),
                &wrong_after,
                target_id,
            )
            .is_err());

        let mut wrong_fields = binding.clone();
        wrong_fields.fields.insert("tenant".to_owned());
        assert!(ChangeRequestTargetContext::for_review(
            &registry,
            &reviewer,
            "review",
            vec![equals("tenant", "tenant-a")],
            wrong_fields,
        )
        .is_err());

        let mut missing_revision = binding.clone();
        missing_revision.expected_revision = None;
        assert!(ChangeRequestTargetContext::for_application(
            &registry,
            &reviewer,
            vec![equals("tenant", "tenant-a")],
            missing_revision,
        )
        .is_err());

        let applier = ClaimContext::for_compiled(
            &registry,
            "placement-correction-request",
            Some("applier-canary".to_owned()),
            "applier",
            Some("apply".to_owned()),
            Vec::new(),
        )
        .expect("applier request context compiles");
        ChangeRequestTargetContext::for_application(
            &registry,
            &applier,
            vec![equals("tenant", "tenant-a")],
            binding,
        )
        .expect("application context derives from apply grant and target boundary");
    }

    fn equals(field: &str, value: &str) -> RowBoundaryContext {
        RowBoundaryContext::Equals {
            field: field.to_owned(),
            value: value.to_owned(),
        }
    }

    fn in_values(field: &str, values: &[&str]) -> RowBoundaryContext {
        RowBoundaryContext::In {
            field: field.to_owned(),
            values: values.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn typed_boundaries() -> Vec<RowBoundaryContext> {
        vec![
            equals("enabled", "true"),
            in_values("count", &["-1", "2"]),
            equals("amount", "1.20"),
            equals("effective-on", "2024-02-29"),
            in_values("observed-at", &["2024-01-02T03:04:05Z"]),
            equals("identifier", "123e4567-e89b-12d3-a456-426614174000"),
            in_values("parent", &["123e4567-e89b-12d3-a456-426614174001"]),
            equals("short-name", "abcd"),
            in_values("notes", &["abcdef"]),
            equals("color", "red"),
        ]
    }

    fn compiled_typed_registry() -> CompiledRegistry {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"typed-context","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "entities":[
                {
                  "id":"parent-entry","primaryDataset":"test-dataset","route":"parents","mutationMode":"mutable",
                  "fields":[{"id":"name","type":"string","minLength":1,"maxLength":8,"required":true,"classification":"internal"}]
                },
                {
                  "id":"typed-entry","primaryDataset":"test-dataset","route":"typed","mutationMode":"mutable",
                  "fields":[
                    {"id":"enabled","type":"boolean","required":true,"classification":"internal"},
                    {"id":"count","type":"int64","required":true,"classification":"internal"},
                    {"id":"amount","type":"decimal","precision":4,"scale":2,"minimum":"0.00","maximum":"9.99","required":true,"classification":"internal"},
                    {"id":"effective-on","type":"date","required":true,"classification":"internal"},
                    {"id":"observed-at","type":"timestamp","required":true,"classification":"internal"},
                    {"id":"identifier","type":"uuid","required":true,"classification":"internal"},
                    {"id":"parent","type":"reference","target":"parent-entry","required":true,"classification":"internal"},
                    {"id":"short-name","type":"string","minLength":1,"maxLength":4,"required":true,"classification":"internal"},
                    {"id":"notes","type":"text","maxLength":6,"required":true,"classification":"internal"},
                    {"id":"color","type":"vocabulary-code","vocabulary":"colors","required":true,"classification":"internal"}
                  ]
                }
              ],
              "accessProfiles":[{
                "id":"typed","default":true,"principalClaim":"registry_principal",
                "grants":[
                  {
                    "entity":"parent-entry","operations":["get"],"readableFields":["name"]
                  },
                  {
                    "entity":"typed-entry","operations":["get"],
                    "readableFields":["enabled","count","amount","effective-on","observed-at","identifier","parent","short-name","notes","color"],
                    "rowBoundaries":[
                      {"field":"enabled","claim":"enabled_claim","operator":"equals"},
                      {"field":"count","claim":"count_claim","operator":"in"},
                      {"field":"amount","claim":"amount_claim","operator":"equals"},
                      {"field":"effective-on","claim":"date_claim","operator":"equals"},
                      {"field":"observed-at","claim":"timestamp_claim","operator":"in"},
                      {"field":"identifier","claim":"uuid_claim","operator":"equals"},
                      {"field":"parent","claim":"reference_claim","operator":"in"},
                      {"field":"short-name","claim":"string_claim","operator":"equals"},
                      {"field":"notes","claim":"text_claim","operator":"in"},
                      {"field":"color","claim":"vocabulary_claim","operator":"equals"}
                    ]
                  }
                ]
              }],
              "vocabularies":[{"id":"colors","values":["red","blue"]}]
            }"#,
        )
        .expect("typed context project parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("typed context project compiles")
    }

    fn compiled_registry() -> CompiledRegistry {
        let mut operations = BTreeSet::new();
        operations.insert(Operation::Get);
        let project = RegistryProject {
            api_version: crate::compiler::AUTHORING_API_VERSION.to_owned(),
            kind: "RegistryProject".to_owned(),
            registry: crate::contract::RegistryIdentitySource {
                id: "context-test".to_owned(),
                version: "0.1.0".to_owned(),
                default_language: "en".to_owned(),
                canonical_base_iri: "https://context.example.test".to_owned(),
            },
            package: None,
            manifest_projection: None,
            modules: Vec::new(),
            entities: vec![EntitySource {
                id: "entry".to_owned(),
                primary_dataset: "context-test".to_owned(),
                route: "entries".to_owned(),
                mutation_mode: MutationMode::Mutable,
                tombstone: false,
                batch: None,
                classification: Classification::Internal,
                access_requirements: None,
                geojson: None,
                derived: Vec::new(),
                selector_profiles: Vec::new(),
                read_paths: Vec::new(),
                change_control: None,
                change_request: None,
                fields: vec![
                    FieldSource {
                        id: "tenant".to_owned(),
                        api_name: None,
                        field_type: FieldTypeSource::String {
                            min_length: 1,
                            max_length: 64,
                        },
                        required: true,
                        classification: Classification::Internal,
                        valid_time_role: None,
                    },
                    FieldSource {
                        id: "region".to_owned(),
                        api_name: None,
                        field_type: FieldTypeSource::String {
                            min_length: 1,
                            max_length: 64,
                        },
                        required: true,
                        classification: Classification::Internal,
                        valid_time_role: None,
                    },
                ],
                constraints: Vec::new(),
                temporal: None,
                indexes: Vec::new(),
                access_profiles: Vec::new(),
                events: Vec::new(),
            }],
            actions: Vec::new(),
            access_profiles: vec![
                ProjectAccessProfileSource {
                    id: "operator".to_owned(),
                    default: true,
                    anonymous: false,
                    principal_claim: Some("registry_principal".to_owned()),
                    required_scopes: BTreeSet::new(),
                    required_purposes: BTreeSet::from(["operations".to_owned()]),
                    grants: vec![AccessGrantSource {
                        entity: "entry".to_owned(),
                        action: None,
                        operations: operations.clone(),
                        readable_fields: BTreeSet::from(["tenant".to_owned(), "region".to_owned()]),
                        writable_fields: BTreeSet::new(),
                        filterable_fields: BTreeSet::new(),
                        sortable_fields: BTreeSet::new(),
                        spatial_queries: None,
                        row_boundaries: vec![
                            RowBoundarySource {
                                field: "tenant".to_owned(),
                                claim: "tenant_claim".to_owned(),
                                operator: BoundaryOperator::Equals,
                            },
                            RowBoundarySource {
                                field: "region".to_owned(),
                                claim: "region_claim".to_owned(),
                                operator: BoundaryOperator::In,
                            },
                        ],
                        revision_access: false,
                        provenance_fields: Vec::new(),
                        allow_data_export: false,
                        lookups: Vec::new(),
                        read_paths: Vec::new(),
                        review_stages: Vec::new(),
                        apply_targets: Vec::new(),
                        request_presence: Vec::new(),
                        targets: Vec::new(),
                        results: BTreeSet::new(),
                        allow_count: false,
                    }],
                },
                ProjectAccessProfileSource {
                    id: "viewer".to_owned(),
                    default: false,
                    anonymous: false,
                    principal_claim: Some("registry_principal".to_owned()),
                    required_scopes: BTreeSet::new(),
                    required_purposes: BTreeSet::new(),
                    grants: vec![AccessGrantSource {
                        entity: "entry".to_owned(),
                        action: None,
                        operations,
                        readable_fields: BTreeSet::from(["tenant".to_owned()]),
                        writable_fields: BTreeSet::new(),
                        filterable_fields: BTreeSet::new(),
                        sortable_fields: BTreeSet::new(),
                        spatial_queries: None,
                        row_boundaries: vec![RowBoundarySource {
                            field: "id".to_owned(),
                            claim: "record_id_claim".to_owned(),
                            operator: BoundaryOperator::Equals,
                        }],
                        revision_access: false,
                        provenance_fields: Vec::new(),
                        allow_data_export: false,
                        lookups: Vec::new(),
                        read_paths: Vec::new(),
                        review_stages: Vec::new(),
                        apply_targets: Vec::new(),
                        request_presence: Vec::new(),
                        targets: Vec::new(),
                        results: BTreeSet::new(),
                        allow_count: false,
                    }],
                },
            ],
            vocabularies: Vec::new(),
        };
        compile_project(&project, &[], CompileProfile::Authoring).expect("test project compiles")
    }

    fn compiled_action_context_registry() -> CompiledRegistry {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"action-context","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "entities":[{
                "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
                "fields":[
                  {"id":"household-code","apiName":"householdCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
                  {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"},
                  {"id":"status-note","apiName":"statusNote","type":"string","maxLength":160,"classification":"restricted"}
                ]
              }],
              "actions":[{
                "id":"rename-household-local",
                "inputs":[
                  {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
                  {"id":"household-code","apiName":"householdCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
                  {"id":"status-note","apiName":"statusNote","type":"string","maxLength":160,"required":true,"classification":"restricted"}
                ],
                "effects":[
                  {"id":"household-code-update","target":{"fromField":"household"},"operation":"patch",
                    "set":{"household-code":{"fromField":"household-code"}}},
                  {"id":"household-note-update","target":{"fromField":"household"},"operation":"patch",
                    "set":{"status-note":{"fromField":"status-note"}}}
                ]
              }],
              "accessProfiles":[{
                "id":"contact-registrar",
                "default":true,
                "principalClaim":"registry_principal",
                "requiredPurposes":["contact-registration"],
                "grants":[{
                  "action":"rename-household-local",
                  "operations":["invoke"],
                  "targets":[{"entity":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
                  "results":["household-code-update","household-note-update"]
                }]
              }]
            }"#,
        )
        .expect("action context project parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("action context project compiles")
    }

    fn compiled_change_request_registry() -> CompiledRegistry {
        let project = parse_project_json(
            br#"{
              "apiVersion":"registry.registrystack.org/v1alpha1",
              "kind":"RegistryProject",
              "registry":{"id":"change-request-context","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "entities":[
                {
                  "id":"asset-site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable",
                  "fields":[
                    {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                    {"id":"name","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
                  ]
                },
                {
                  "id":"asset-placement","primaryDataset":"test-dataset","route":"placements","mutationMode":"mutable",
                  "changeControl":{"requiredFor":["patch"]},
                  "fields":[
                    {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                    {"id":"site","type":"reference","target":"asset-site","required":true,"classification":"internal"}
                  ]
                },
                {
                  "id":"placement-correction-request","primaryDataset":"test-dataset","route":"placement-correction-requests","mutationMode":"mutable",
                  "fields":[
                    {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                    {"id":"placement","type":"reference","target":"asset-placement","required":true,"classification":"internal"},
                    {"id":"proposed-site","type":"reference","target":"asset-site","required":true,"classification":"internal"},
                    {"id":"reason","type":"text","maxLength":1000,"required":true,"classification":"internal"}
                  ],
                  "changeRequest":{
                    "effects":[{
                      "target":{"fromField":"placement"},
                      "operation":"patch",
                      "set":{"site":{"fromField":"proposed-site"}}
                    }],
                    "review":{"stages":[{"id":"review","approvals":1,"excludeSubmitter":true}]}
                  }
                }
              ],
              "accessProfiles":[
                {
                  "id":"steward","default":true,"principalClaim":"registry_principal",
                  "grants":[{
                    "entity":"asset-placement",
                    "operations":["get","list"],
                    "readableFields":["tenant","site"],
                    "requestPresence":[{"requestType":"placement-correction-request","rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]}]
                  }]
                },
                {
                  "id":"submitter","default":true,"principalClaim":"registry_principal",
                  "grants":[{
                    "entity":"placement-correction-request",
                    "operations":["create","get","list","patch","submit_request","revise_request"],
                    "readableFields":["placement","proposed-site","reason"],
                    "writableFields":["placement","proposed-site","reason"]
                  }]
                },
                {
                  "id":"reviewer","principalClaim":"registry_principal","requiredPurposes":["review"],
                  "grants":[{
                    "entity":"placement-correction-request",
                    "operations":["get","list","approve_request","reject_request","request_revision"],
                    "readableFields":["placement","proposed-site","reason"],
                    "reviewStages":[{
                      "stage":"review",
                      "targets":[{
                        "entity":"asset-placement",
                        "readableFields":["site"],
                        "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                      }]
                    }]
                  }]
                },
                {
                  "id":"applier","principalClaim":"registry_principal","requiredPurposes":["apply"],
                  "grants":[{
                    "entity":"placement-correction-request",
                    "operations":["get","apply_request"],
                    "readableFields":["placement","proposed-site","reason"],
                    "applyTargets":[{
                      "entity":"asset-placement",
                      "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
                    }]
                  }]
                }
              ]
            }"#,
        )
        .expect("change-request context project parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("change-request context project compiles")
    }
}
