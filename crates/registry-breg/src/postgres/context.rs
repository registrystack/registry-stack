// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use deadpool_postgres::{Client, Transaction};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio_postgres::types::Type;
use uuid::Uuid;

use crate::contract::{BoundaryOperator, Operation};
use crate::data::{validate_field_value as validate_data_field_value, FieldValue};
use crate::model::{
    CompiledActionTargetUseSource, CompiledPlanEffect, CompiledPlanMutation,
    CompiledPlanTargetBinding, CompiledRegistry,
};

use super::{ExpectedRegistryIdentity, PostgresKernelError, RegistryLockKey, Result};

#[path = "proposal_context.rs"]
mod proposal;
pub(crate) use proposal::{
    begin_proposal_transaction, ProposalAuthority, ProposalAuthorityOperation, ProposalTargetPhase,
};

const MAX_CONTEXT_VALUE_BYTES: usize = 512;
const MAX_BOUNDARY_SET_VALUES: usize = 64;
const MAX_BOUNDARY_CONTEXT_BYTES: usize = 64 * 1024;
const MAX_ENTITY_ID_BYTES: usize = 256;
const MAX_TARGET_FIELDS: usize = crate::model::MAX_TARGET_CONTEXT_FIELDS;

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
    grant_audit: Option<crate::audit::GrantAuditContext>,
    task_grant: Option<crate::task_grant::TaskGrantBinding>,
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
            grant_audit: None,
            task_grant: None,
        };
        context.validate()?;
        Ok(context)
    }

    pub(crate) fn with_grant_audit(
        mut self,
        grant: Option<crate::audit::GrantAuditContext>,
    ) -> Self {
        self.grant_audit = grant;
        self
    }
    pub(crate) fn grant_audit(&self) -> Option<&crate::audit::GrantAuditContext> {
        self.grant_audit.as_ref()
    }

    pub(crate) fn with_task_grant(
        mut self,
        grant: crate::task_grant::TaskGrantBinding,
    ) -> Result<Self> {
        grant.validate().map_err(|_| invalid_context())?;
        if self.principal != grant.principal()
            || self.purpose.as_deref() != Some(grant.purpose())
            || !grant
                .bounds()
                .breg_permissions()
                .is_some_and(|permissions| {
                    permissions.iter().any(|permission| {
                        permission.collection() == format!("action:{}", self.action_id)
                            && permission
                                .operations()
                                .iter()
                                .any(|operation| operation == "invoke")
                    })
                })
        {
            return Err(invalid_context());
        }
        self.task_grant = Some(grant);
        Ok(self)
    }

    pub(crate) fn with_proposal_task_grant(
        mut self,
        grant: crate::task_grant::TaskGrantBinding,
        operation: ProposalAuthorityOperation,
    ) -> Result<Self> {
        grant.validate().map_err(|_| invalid_context())?;
        let operation_name = crate::mutation::proposal_operation_name(operation);
        let permits_operation = grant
            .bounds()
            .breg_permissions()
            .is_some_and(|permissions| {
                permissions.iter().any(|permission| {
                    let collection_matches = match operation {
                        ProposalAuthorityOperation::Start => {
                            permission.collection() == format!("action:{}", self.action_id)
                        }
                        ProposalAuthorityOperation::Lifecycle(_) => permission
                            .collection()
                            .strip_prefix("proposal:")
                            .and_then(|id| {
                                Uuid::parse_str(id)
                                    .ok()
                                    .filter(|parsed| parsed.to_string() == id)
                            })
                            .is_some(),
                    };
                    collection_matches
                        && permission
                            .operations()
                            .iter()
                            .any(|name| name == operation_name)
                })
            });
        if self.principal != grant.principal()
            || self.purpose.as_deref() != Some(grant.purpose())
            || !permits_operation
        {
            return Err(invalid_context());
        }
        self.task_grant = Some(grant);
        Ok(self)
    }

    pub(crate) fn task_grant(&self) -> Option<&crate::task_grant::TaskGrantBinding> {
        self.task_grant.as_ref()
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
    task_grant: Option<crate::task_grant::TaskGrantBinding>,
    grant_audit: Option<crate::audit::GrantAuditContext>,
    human_identity: Option<registry_review_client::HumanIdentity>,
    recipients: BTreeSet<String>,
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
    pub(crate) fn with_grant_audit(
        mut self,
        grant: Option<crate::audit::GrantAuditContext>,
    ) -> Self {
        self.grant_audit = grant;
        self
    }
    pub(crate) fn grant_audit(&self) -> Option<&crate::audit::GrantAuditContext> {
        self.grant_audit.as_ref()
    }

    pub(crate) fn with_human_identity(
        mut self,
        identity: Option<registry_review_client::HumanIdentity>,
    ) -> Result<Self> {
        self.human_identity = identity;
        Ok(self)
    }

    /// Install the verified client's consent recipient set, written to
    /// `registry.recipients` for every consent probe of this transaction.
    pub fn with_recipients(mut self, recipients: BTreeSet<String>) -> Result<Self> {
        validate_recipients(&recipients)?;
        self.recipients = recipients;
        Ok(self)
    }

    #[must_use]
    pub fn recipients(&self) -> &BTreeSet<String> {
        &self.recipients
    }

    pub(crate) fn with_task_grant(
        mut self,
        grant: crate::task_grant::TaskGrantBinding,
    ) -> Result<Self> {
        if self.principal.as_deref() != Some(grant.principal())
            || self.purpose.as_deref() != Some(grant.purpose())
        {
            return Err(invalid_context());
        }
        self.task_grant = Some(grant);
        Ok(self)
    }

    pub fn task_grant(&self) -> Option<&crate::task_grant::TaskGrantBinding> {
        self.task_grant.as_ref()
    }

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
        if principal.is_none() {
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
            task_grant: None,
            grant_audit: None,
            human_identity: None,
            recipients: BTreeSet::new(),
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
            task_grant: None,
            grant_audit: None,
            human_identity: None,
            recipients: BTreeSet::new(),
        })
    }

    /// Switch only the verified row predicates within the existing selected-profile transaction.
    pub(crate) async fn install_row_boundaries(
        &self,
        transaction: &tokio_postgres::Transaction<'_>,
    ) -> Result<()> {
        self.validate()?;
        transaction
            .execute(
                "SELECT set_config('registry.row_boundaries', $1, true)",
                &[&self.canonical_row_boundaries],
            )
            .await?;
        Ok(())
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
        validate_recipients(&self.recipients)?;
        Ok(())
    }

    /// Check one prospective record with the same typed canonical values that
    /// the generated PostgreSQL row policies compare. A false result is an
    /// ordinary authorization refusal; malformed compiled context remains an
    /// internal error.
    pub(crate) fn authorizes_record_snapshot(
        &self,
        entity: &crate::model::CompiledEntity,
        row: &serde_json::Map<String, Value>,
        record_id: Uuid,
    ) -> Result<bool> {
        self.validate()?;
        if entity.id != self.entity_id {
            return Err(invalid_context());
        }
        snapshot_matches_boundaries(entity, row, record_id, &self.row_boundaries)
    }
}

/// One organization plus at most 63 groups, each a bounded context value.
const MAX_RECIPIENTS: usize = 64;

fn validate_recipients(recipients: &BTreeSet<String>) -> Result<()> {
    if recipients.len() > MAX_RECIPIENTS {
        return Err(invalid_context());
    }
    for recipient in recipients {
        validate_required_context_value(recipient)?;
    }
    Ok(())
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
            .field("recipient_count", &self.recipients.len())
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
        if action.definition_revision != binding.contract_fingerprint {
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
            .permissions
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
    operation: Operation,
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
        if action.definition_revision != binding.contract_fingerprint {
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
        let target_use = action
            .target_uses
            .iter()
            .find(|target_use| {
                target_use.entity_id == binding.target_entity_id
                    && (target_use.operation == Operation::Get
                        || (target_use.operation == Operation::Invoke
                            && target_use.fields.is_empty()))
                    && matches!(
                        &target_use.source,
                        CompiledActionTargetUseSource::Input { input } if input == &binding.input_id
                    )
            })
            .ok_or_else(invalid_context)?;
        let grant = action
            .permissions
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
            operation: target_use.operation,
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
        if !matches!(self.operation, Operation::Get | Operation::Invoke) {
            return Err(invalid_context());
        }
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
            "operation": operation_context_name(context.operation),
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
    effects: &[&CompiledPlanEffect],
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
                || !matches!(effects[0].target.binding, CompiledPlanTargetBinding::Create)
            {
                return Err(invalid_context());
            }
        }
        (Operation::Patch, None, true) => {
            if effects.iter().any(|effect| {
                !matches!(
                    effect.target.binding,
                    CompiledPlanTargetBinding::Existing { .. }
                )
            }) {
                return Err(invalid_context());
            }
        }
        (Operation::Patch, _, false) => {
            if effects.iter().any(|effect| {
                !matches!(
                    effect.target.binding,
                    CompiledPlanTargetBinding::Existing { .. }
                )
            }) {
                return Err(invalid_context());
            }
        }
        _ => return Err(invalid_context()),
    }
    Ok(())
}

fn action_effect_fields(effects: &[&CompiledPlanEffect]) -> BTreeSet<String> {
    effects
        .iter()
        .flat_map(|effect| &effect.mutations)
        .map(|mutation| match mutation {
            CompiledPlanMutation::Set { field, .. } | CompiledPlanMutation::Clear { field } => {
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

fn operation_context_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Get => "get",
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
    if snapshot_matches_boundaries(entity, row, record_id, boundaries)? {
        Ok(())
    } else {
        Err(invalid_context())
    }
}

pub(crate) fn snapshot_matches_boundaries(
    entity: &crate::model::CompiledEntity,
    row: &serde_json::Map<String, Value>,
    record_id: Uuid,
    boundaries: &[RowBoundaryContext],
) -> Result<bool> {
    for boundary in boundaries {
        let (actual, field_type) = if boundary.field() == entity.canonical_id.id {
            (record_id.to_string(), &entity.canonical_id.field_type)
        } else {
            let field = entity
                .fields
                .get(boundary.field())
                .ok_or_else(invalid_context)?;
            let Some(value) = row.get(boundary.field()) else {
                if field.required {
                    return Err(invalid_context());
                }
                return Ok(false);
            };
            if value.is_null() && !field.required {
                return Ok(false);
            }
            (
                canonical_snapshot_field_value(value, &field.field_type)?,
                &field.field_type,
            )
        };
        let matches = |expected: &str| boundary_value_matches(&actual, expected, field_type);
        match boundary {
            RowBoundaryContext::Equals { value, .. } if matches(value) => {}
            RowBoundaryContext::In { values, .. } if values.iter().any(|value| matches(value)) => {}
            RowBoundaryContext::Equals { .. } | RowBoundaryContext::In { .. } => {
                return Ok(false);
            }
        }
    }
    Ok(true)
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

/// Compare one snapshot value with one row-boundary value as the generated
/// RLS policy does, which casts both sides to the field's SQL type.
///
/// Claim values and snapshot values are both validated against the boundary
/// field's own type before they reach this comparison. That admits exactly
/// one spelling per boolean, int64, decimal (the field's exact scale, no
/// leading zero, no negative zero), date, and lowercase UUID value, so an
/// exact comparison is the typed one for those types, and text types compare
/// exactly under PostgreSQL too. RFC 3339 admits many spellings of one
/// timestamp, so timestamps compare by instant.
fn boundary_value_matches(
    actual: &str,
    expected: &str,
    field_type: &crate::contract::FieldTypeSource,
) -> bool {
    match field_type {
        crate::contract::FieldTypeSource::Timestamp => {
            match (
                postgres_timestamp_micros(actual),
                postgres_timestamp_micros(expected),
            ) {
                (Some(actual), Some(expected)) => actual == expected,
                _ => false,
            }
        }
        _ => actual == expected,
    }
}

/// The instant PostgreSQL's `timestamptz` input assigns to an RFC 3339 value,
/// in microseconds since the Unix epoch. PostgreSQL keeps microseconds and
/// rounds a longer fraction as `rint(strtod(fraction) * 1e6)`, which is
/// mirrored here. It reads second 60 as the start of the next minute, where
/// `time` reads it as the last nanosecond of second 59.
fn postgres_timestamp_micros(value: &str) -> Option<i128> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    // RFC 3339 fixes the date and time digits, so the seconds are bytes 17
    // and 18 and any fraction starts at byte 19.
    let leap_second = value.get(17..19) == Some("60");
    let micros = match value.get(19..)?.strip_prefix('.') {
        Some(rest) => {
            let digits = rest
                .find(|character: char| !character.is_ascii_digit())
                .map_or(rest, |end| &rest[..end]);
            let fraction = format!("0.{digits}").parse::<f64>().ok()?;
            (fraction * 1_000_000.0).round_ties_even() as i128
        }
        None => 0,
    };
    Some((i128::from(parsed.unix_timestamp()) + i128::from(leap_second)) * 1_000_000 + micros)
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

    /// Bounds every later statement in this transaction. A statement that
    /// outruns the budget fails its read instead of holding the shared
    /// Registry lock and a pooled connection for an unbounded time.
    pub(crate) async fn set_statement_budget(&self, budget: Duration) -> Result<()> {
        if budget.is_zero() || budget > Duration::from_secs(30) {
            return Err(PostgresKernelError::Configuration(
                "statement budget must be between 1 millisecond and 30 seconds",
            ));
        }
        let budget_millis = i32::try_from(budget.as_millis()).map_err(|_| {
            PostgresKernelError::Configuration("statement budget is outside PostgreSQL bounds")
        })?;
        self.transaction
            .execute(
                "SELECT set_config('statement_timeout', $1::text, true)",
                &[&format!("{budget_millis}ms")],
            )
            .await?;
        Ok(())
    }

    pub async fn commit(self) -> Result<()> {
        self.transaction.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> Result<()> {
        self.transaction.rollback().await?;
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

/// Holds the shared package lock and admits the exact active registry identity.
/// It installs no caller or target authority, so workers can fence durable claims
/// without inheriting Record or Action permissions.
pub(crate) async fn begin_registry_transaction<'a>(
    client: &'a mut Client,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: &ExpectedRegistryIdentity,
) -> Result<GuardedTransaction<'a>> {
    expected.validate()?;
    if lock_timeout.is_zero() || lock_timeout > Duration::from_secs(30) {
        return Err(PostgresKernelError::Configuration(
            "record lock timeout must be between 1 millisecond and 30 seconds",
        ));
    }
    let transaction = client.transaction().await?;
    let timeout_millis = i32::try_from(lock_timeout.as_millis()).map_err(|_| {
        PostgresKernelError::Configuration("record lock timeout is outside PostgreSQL bounds")
    })?;
    // These fixed statements have known parameter types. Sending their parse,
    // bind and execution together avoids a separate prepare round trip while
    // every gate still executes in order with fresh transaction-local values.
    transaction
        .execute_typed(
            "SELECT set_config('lock_timeout', $1::text, true)",
            &[(&format!("{timeout_millis}ms"), Type::TEXT)],
        )
        .await?;
    // Date and timestamp casts, ordering and rendering all read the session
    // time zone. Pin it so a record or history answer never depends on the
    // deployment's database default.
    transaction
        .execute_typed("SELECT set_config('TimeZone', 'UTC', true)", &[])
        .await?;
    transaction
        .execute_typed(
            "SELECT pg_advisory_xact_lock_shared($1)",
            &[(&lock_key.get(), Type::INT8)],
        )
        .await
        .map_err(|_| PostgresKernelError::RegistryUnavailable)?;
    let state = transaction
        .query_typed_opt(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint, maintenance_status
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await?
        .ok_or(PostgresKernelError::RegistryUnavailable)?;
    let ready = state.get::<_, String>(5) == "ready"
        && state.get::<_, String>(0) == expected.package_id
        && state.get::<_, String>(1) == expected.database_id
        && state.get::<_, String>(2) == expected.package_digest
        && state.get::<_, String>(3) == expected.activation_id
        && state.get::<_, String>(4) == expected.schema_fingerprint;
    if !ready {
        return Err(PostgresKernelError::RegistryUnavailable);
    }
    Ok(GuardedTransaction { transaction })
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
    claims.validate()?;
    let guarded = begin_registry_transaction(client, lock_key, lock_timeout, expected).await?;
    let transaction = guarded.transaction();
    // A JSON array of strings; `[]` for a client no organization lists.
    let recipients = serde_json::to_string(&claims.recipients).map_err(|_| invalid_context())?;
    transaction
        .execute_typed(
            "SELECT set_config('registry.principal', $1, true),
                    set_config('registry.access_profile', $2, true),
                    set_config('registry.purpose', $3, true),
                    set_config('registry.row_boundaries', $4, true),
                    set_config('registry.active_package_revision', $5, true),
                    set_config('registry.recipients', $6, true)",
            &[
                (&claims.principal.as_deref().unwrap_or(""), Type::TEXT),
                (&claims.access_profile, Type::TEXT),
                (&claims.purpose.as_deref().unwrap_or(""), Type::TEXT),
                (&claims.canonical_row_boundaries, Type::TEXT),
                (&expected.activation_id, Type::TEXT),
                (&recipients, Type::TEXT),
            ],
        )
        .await?;
    Ok(guarded)
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
    claims.validate()?;
    let guarded = begin_registry_transaction(client, lock_key, lock_timeout, expected).await?;
    let transaction = guarded.transaction();
    transaction
        .execute(
            "SELECT set_config('registry.principal', $1, true),
                    set_config('registry.access_profile', $2, true),
                    set_config('registry.purpose', $3, true),
                    set_config('registry.row_boundaries', $4, true),
                    set_config('registry.active_package_revision', $5, true),
                    set_config('registry.recipients', $6, true)",
            &[
                &claims.principal(),
                &claims.access_profile(),
                &claims.purpose().unwrap_or(""),
                &"[]",
                &expected.activation_id,
                // Gated profiles cannot invoke actions, so no action path
                // evaluates a consent probe.
                &"[]",
            ],
        )
        .await?;
    Ok(guarded)
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
    use crate::contract::{parse_project_json, Operation};

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
    fn optional_boundary_absence_is_a_refusal_while_malformed_snapshots_are_invalid() {
        let registry = compiled_registry();
        let entity = &registry.entities()["entry"];
        let context = ClaimContext::for_compiled(
            &registry,
            "entry",
            Some("principal".to_owned()),
            "operator",
            Some("operations".to_owned()),
            vec![
                equals("tenant", "tenant-a"),
                in_values("region", &["north"]),
            ],
        )
        .expect("compiled boundary context is valid");
        let record_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000123").expect("record UUID parses");

        let omitted = serde_json::Map::from_iter([("tenant".to_owned(), json!("tenant-a"))]);
        assert!(!context
            .authorizes_record_snapshot(entity, &omitted, record_id)
            .expect("an omitted optional boundary is an ordinary mismatch"));

        let nullable = serde_json::Map::from_iter([
            ("tenant".to_owned(), json!("tenant-a")),
            ("region".to_owned(), Value::Null),
        ]);
        assert!(!context
            .authorizes_record_snapshot(entity, &nullable, record_id)
            .expect("a null optional boundary is an ordinary mismatch"));

        let malformed_optional = serde_json::Map::from_iter([
            ("tenant".to_owned(), json!("tenant-a")),
            ("region".to_owned(), json!(7)),
        ]);
        assert!(context
            .authorizes_record_snapshot(entity, &malformed_optional, record_id)
            .is_err());

        let malformed_required = serde_json::Map::from_iter([
            ("tenant".to_owned(), Value::Null),
            ("region".to_owned(), json!("north")),
        ]);
        assert!(context
            .authorizes_record_snapshot(entity, &malformed_required, record_id)
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

    fn observed_at_matches(boundary: RowBoundaryContext, observed_at: &str) -> bool {
        let registry = compiled_typed_registry();
        let entity = &registry.entities()["typed-entry"];
        let row = serde_json::Map::from_iter([("observed-at".to_owned(), json!(observed_at))]);
        snapshot_matches_boundaries(entity, &row, Uuid::nil(), &[boundary])
            .expect("a valid timestamp snapshot is compared, not refused")
    }

    #[test]
    fn timestamp_boundaries_compare_the_instant_postgres_casts_both_sides_to() {
        let same_instant = [
            ("2026-01-01T00:00:00Z", "2025-12-31T19:00:00-05:00"),
            ("2026-01-01T05:30:00+05:30", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00"),
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00-00:00"),
            ("2026-01-01T00:00:00z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000000Z"),
            (
                "2026-01-01T00:00:00.5Z",
                "2026-01-01T00:00:00.500000000+00:00",
            ),
            // PostgreSQL keeps microseconds, rounding a longer fraction as
            // `rint(fraction * 1e6)`; each pair below was read back from
            // PostgreSQL 17.
            ("2026-01-01T00:00:00.0000004Z", "2026-01-01T00:00:00Z"),
            ("2026-01-01T00:00:00.0000005Z", "2026-01-01T00:00:00Z"),
            (
                "2026-01-01T00:00:00.0000006Z",
                "2026-01-01T00:00:00.000001Z",
            ),
            (
                "2026-01-01T00:00:00.0000015Z",
                "2026-01-01T00:00:00.000002Z",
            ),
            (
                "2026-01-01T00:00:00.0000025Z",
                "2026-01-01T00:00:00.000002Z",
            ),
            (
                "2026-01-01T00:00:00.1234565Z",
                "2026-01-01T00:00:00.123456Z",
            ),
            (
                "2026-01-01T00:00:00.1234575Z",
                "2026-01-01T00:00:00.123458Z",
            ),
            ("2026-01-01T00:00:00.9999995Z", "2026-01-01T00:00:01Z"),
            (
                "2026-01-01T00:00:00.00000050000001Z",
                "2026-01-01T00:00:00.000001Z",
            ),
            // PostgreSQL reads second 60 as the start of the next minute.
            ("2016-12-31T23:59:60Z", "2017-01-01T00:00:00Z"),
        ];
        for (claim, row) in same_instant {
            assert!(
                observed_at_matches(equals("observed-at", claim), row),
                "{claim} equals {row}"
            );
            assert!(
                observed_at_matches(equals("observed-at", row), claim),
                "{row} equals {claim}"
            );
            assert!(
                observed_at_matches(
                    in_values("observed-at", &["2020-01-01T00:00:00Z", claim]),
                    row
                ),
                "{row} is in a set holding {claim}"
            );
        }

        let different_instants = [
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00-05:00"),
            ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000001Z"),
            (
                "2026-01-01T00:00:00.0000015Z",
                "2026-01-01T00:00:00.000001Z",
            ),
            ("2016-12-31T23:59:60Z", "2016-12-31T23:59:59.999999Z"),
        ];
        for (claim, row) in different_instants {
            assert!(
                !observed_at_matches(equals("observed-at", claim), row),
                "{claim} differs from {row}"
            );
            assert!(
                !observed_at_matches(in_values("observed-at", &[claim]), row),
                "{row} is not in a set holding only {claim}"
            );
        }
    }

    #[test]
    fn a_boundary_value_that_is_not_the_field_type_never_matches() {
        let registry = compiled_typed_registry();
        let entity = &registry.entities()["typed-entry"];
        let row = serde_json::Map::from_iter([
            ("observed-at".to_owned(), json!("2026-01-01T00:00:00Z")),
            ("amount".to_owned(), json!("1.20")),
            (
                "identifier".to_owned(),
                json!("123e4567-e89b-12d3-a456-426614174000"),
            ),
        ]);
        for boundary in [
            equals("observed-at", "not-a-timestamp"),
            in_values("observed-at", &["2026-01-01", "2026-01-01 00:00:00"]),
            equals("amount", "one"),
            in_values("identifier", &["not-a-uuid"]),
        ] {
            assert!(
                !snapshot_matches_boundaries(entity, &row, Uuid::nil(), &[boundary])
                    .expect("an unparseable boundary value is an ordinary mismatch")
            );
        }
    }

    #[test]
    fn decimal_and_uuid_boundaries_compare_their_one_canonical_spelling() {
        // Claim values and row values are both validated against the
        // boundary field's own type, which admits exactly one spelling per
        // decimal and UUID value, so an exact comparison is the typed one.
        let registry = compiled_typed_registry();
        let entity = &registry.entities()["typed-entry"];
        let row = serde_json::Map::from_iter([
            ("amount".to_owned(), json!("1.20")),
            (
                "identifier".to_owned(),
                json!("123e4567-e89b-12d3-a456-426614174000"),
            ),
        ]);
        assert!(snapshot_matches_boundaries(
            entity,
            &row,
            Uuid::nil(),
            &[
                equals("amount", "1.20"),
                equals("identifier", "123e4567-e89b-12d3-a456-426614174000"),
            ],
        )
        .expect("canonical values compare"));
        assert!(!snapshot_matches_boundaries(
            entity,
            &row,
            Uuid::nil(),
            &[in_values("amount", &["1.21", "0.20"])],
        )
        .expect("a different decimal is an ordinary mismatch"));

        for (field, spelling) in [
            ("amount", "1.2"),
            ("amount", "01.20"),
            ("identifier", "123E4567-E89B-12D3-A456-426614174000"),
        ] {
            let other = serde_json::Map::from_iter([(field.to_owned(), json!(spelling))]);
            assert!(
                snapshot_matches_boundaries(
                    entity,
                    &other,
                    Uuid::nil(),
                    &[equals(field, spelling)],
                )
                .is_err(),
                "a row spelling {spelling} is refused before any comparison"
            );
        }
    }

    #[test]
    fn a_prospective_row_in_another_offset_is_authorized() {
        let registry = compiled_typed_registry();
        let entity = &registry.entities()["typed-entry"];
        let context = ClaimContext::for_compiled(
            &registry,
            "typed-entry",
            Some("principal".to_owned()),
            "typed",
            None,
            typed_boundaries(),
        )
        .expect("canonical typed boundaries are accepted");
        let row = serde_json::Map::from_iter([
            ("enabled".to_owned(), json!(true)),
            ("count".to_owned(), json!(2)),
            ("amount".to_owned(), json!("1.20")),
            ("effective-on".to_owned(), json!("2024-02-29")),
            (
                "observed-at".to_owned(),
                json!("2024-01-01T22:04:05.000-05:00"),
            ),
            (
                "identifier".to_owned(),
                json!("123e4567-e89b-12d3-a456-426614174000"),
            ),
            (
                "parent".to_owned(),
                json!("123e4567-e89b-12d3-a456-426614174001"),
            ),
            ("short-name".to_owned(), json!("abcd")),
            ("notes".to_owned(), json!("abcdef")),
            ("color".to_owned(), json!("red")),
        ]);
        assert!(context
            .authorizes_record_snapshot(entity, &row, Uuid::nil())
            .expect("the typed snapshot is compared"));
        assert!(
            validate_snapshot_boundaries(entity, &row, Uuid::nil(), context.row_boundaries())
                .is_ok()
        );
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
            contract_fingerprint: action.definition_revision.clone(),
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
        .expect("grouped action target context derives from compiled action permission");
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
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{"id":"typed-context","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "datasets":[{"id":"test-dataset"}],
              "recordTypes":[
                {
                  "id":"parent-entry","primaryDataset":"test-dataset","route":"parents","mutationMode":"mutable",
                  "fields":[{"id":"name","type":"string","minimumLength":1,"maximumLength":8,"required":true,"classification":"internal"}]
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
                    {"id":"short-name","type":"string","minimumLength":1,"maximumLength":4,"required":true,"classification":"internal"},
                    {"id":"notes","type":"text","maximumLength":6,"required":true,"classification":"internal"},
                    {"id":"color","type":"vocabulary-code","vocabulary":"colors","required":true,"classification":"internal"}
                  ]
                }
              ],
              "accessProfiles":[{
                "id":"typed","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
                "permissions":{"records":[
                    {
                      "recordType":"parent-entry","operations":["get"],"readableFields":["name"],
                      "rowBoundaries": "unrestricted"
                    },
                    {
                      "recordType":"typed-entry","operations":["get"],
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
                }
              }],
              "vocabularies":[{"id":"colors","values":["red","blue"]}]
            }"#,
        )
        .expect("typed context project parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("typed context project compiles")
    }

    fn compiled_registry() -> CompiledRegistry {
        let source = json!({
            "apiVersion": crate::compiler::AUTHORING_API_VERSION, "kind":"BRegProject",
            "project":{"id":"context-test","version":"0.1.0","defaultLanguage":"en",
                "canonicalBaseIri":"https://context.example.test"},
            "datasets":[{"id":"context-test"}],
            "recordTypes":[{"id":"entry","primaryDataset":"context-test","route":"entries","mutationMode":"mutable",
                "fields":[
                    {"id":"tenant","type":"string","minimumLength":1,"maximumLength":64,"required":true,"classification":"internal"},
                    {"id":"region","type":"string","minimumLength":1,"maximumLength":64,"required":false,"classification":"internal"}]}],
            "accessProfiles":[
                {"id":"operator","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
                    "requiredPurposes":["operations"],"permissions":{"records":[{"recordType":"entry","operations":["get"],
                    "readableFields":["tenant","region"],"rowBoundaries":[
                        {"field":"tenant","claim":"tenant_claim","operator":"equals"},
                        {"field":"region","claim":"region_claim","operator":"in"}]}]}},
                {"id":"viewer","principalClaim":"registry_principal","requiredScopes":"unrestricted",
                    "permissions":{"records":[{"recordType":"entry","operations":["get"],"readableFields":["tenant"],
                    "rowBoundaries":[{"field":"id","claim":"record_id_claim","operator":"equals"}]}]}}
            ]
        });
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        compile_project(&project, &[], CompileProfile::Authoring).expect("test project compiles")
    }

    fn compiled_action_context_registry() -> CompiledRegistry {
        let project = parse_project_json(
            br#"{
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{"id":"action-context","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "datasets":[{"id":"test-dataset"}],
              "recordTypes":[{
                "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
                "fields":[
                  {"id":"household-code","apiName":"householdCode","type":"string","maximumLength":64,"required":true,"classification":"restricted"},
                  {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maximumLength":64,"required":true,"classification":"restricted"},
                  {"id":"status-note","apiName":"statusNote","type":"string","maximumLength":160,"classification":"restricted"}
                ]
              }],
              "actions":[{
                "id":"rename-household-local",
                "execution":{"mode":"immediate"},
                "inputs":[
                  {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
                  {"id":"household-code","apiName":"householdCode","type":"string","maximumLength":64,"required":true,"classification":"restricted"},
                  {"id":"status-note","apiName":"statusNote","type":"string","maximumLength":160,"required":true,"classification":"restricted"}
                ],
                "plan":{"type":"fixed","effects":[
                  {"id":"household-code-update","target":{"fromInput":"household"},"operation":"patch",
                    "set":{"household-code":{"fromInput":"household-code"}}},
                  {"id":"household-note-update","target":{"fromInput":"household"},"operation":"patch",
                    "set":{"status-note":{"fromInput":"status-note"}}}
                ]}
              }],
              "accessProfiles":[{
                "id":"contact-registrar",
                "default":true,
                "principalClaim":"registry_principal",
                "requiredScopes":"unrestricted",
                "requiredPurposes":["contact-registration"],
                "permissions":{"actions":[{
                  "action":"rename-household-local",
                  "operations":["invoke"],
                  "targets":[{"recordType":"household","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}],
                  "results":["household-code-update","household-note-update"]
                }]}
              }]
            }"#,
        )
        .expect("action context project parses");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("action context project compiles")
    }
}
