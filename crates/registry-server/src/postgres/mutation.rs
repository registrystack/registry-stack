// SPDX-License-Identifier: Apache-2.0

//! Concrete PostgreSQL mutation runtime for the compiled HTTP surface.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use registry_platform_audit::AuditProfile;
use serde_json::Map;

use crate::api::{
    AuthorizedRequestContext, BatchMutationInput, ConditionalMutationInput,
    RowBoundaryOperator as ApiRowBoundaryOperator, VerifiedRowBoundary,
};
use crate::audit::{record_http_refusal_audit, HttpRefusalAudit};
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::model::{CompiledRegistry, HttpMethod};
#[cfg(feature = "postgres-test")]
use crate::mutation::MutationFaultPoint;
use crate::mutation::{
    BatchMutationRequest, MutationBody, MutationCoordinator, MutationError, MutationOutcome,
    MutationPlan, MutationRequest, PatchOperation,
};

use super::{
    ClaimContext, ExpectedRegistryIdentity, RegistryLockKey, RowBoundaryContext, RuntimePool,
};

#[derive(Clone)]
pub struct PostgresRecordMutationService {
    pool: RuntimePool,
    registry: Arc<CompiledRegistry>,
    coordinator: MutationCoordinator,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit_profile: AuditProfile,
    fault: MutationFaultControl,
}

impl PostgresRecordMutationService {
    #[must_use]
    pub fn new(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit_profile: AuditProfile,
    ) -> Self {
        Self::new_with_event_destinations(
            pool,
            registry,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
            None,
        )
    }

    #[must_use]
    pub fn new_with_event_destinations(
        pool: RuntimePool,
        registry: Arc<CompiledRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit_profile: AuditProfile,
        event_destinations: Option<Arc<ActivatedEventDestinationRegistry>>,
    ) -> Self {
        let coordinator = MutationCoordinator::new_with_event_destinations(
            lock_key,
            lock_timeout,
            expected.clone(),
            audit_profile.clone(),
            event_destinations,
        );
        Self {
            pool,
            registry,
            coordinator,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
            fault: MutationFaultControl::Disabled,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_fault_for_test(mut self, fault: MutationFaultPoint) -> Self {
        self.fault = MutationFaultControl::At(fault);
        self
    }

    #[cfg(feature = "postgres-test")]
    #[must_use]
    #[doc(hidden)]
    pub fn with_refusal_audit_fault_for_test(mut self) -> Self {
        self.fault = MutationFaultControl::RefusalAudit;
        self
    }

    pub async fn record_refusal(
        &self,
        method: HttpMethod,
        operation_id: &str,
        target_record: Option<&str>,
        principal: Option<&str>,
        selected_access_profile: Option<&str>,
        purpose_present: bool,
    ) -> Result<(), MutationError> {
        #[cfg(feature = "postgres-test")]
        if matches!(self.fault, MutationFaultControl::RefusalAudit) {
            return Err(MutationError::Unavailable);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        record_http_refusal_audit(
            &mut client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            &self.audit_profile,
            HttpRefusalAudit {
                method,
                operation_id,
                target_record,
                principal,
                selected_access_profile,
                purpose_present,
            },
        )
        .await
        .map_err(MutationError::from)
    }

    pub async fn create(
        &self,
        route_id: &str,
        idempotency_key: &str,
        context: &AuthorizedRequestContext,
        entity_id: &str,
        data: Map<String, serde_json::Value>,
        response_fields: BTreeSet<String>,
    ) -> Result<MutationOutcome, MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, context, entity_id)?;
        let plan = MutationPlan::from_compiled(&self.registry, route_id)?;
        self.execute_request(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key,
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(data),
                response_fields,
            },
        )
        .await
    }

    pub async fn patch(
        &self,
        input: ConditionalMutationInput<'_>,
        patch: Vec<PatchOperation>,
    ) -> Result<MutationOutcome, MutationError> {
        self.conditional_mutation(input, MutationBody::Patch(patch))
            .await
    }

    pub async fn batch(
        &self,
        input: BatchMutationInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, input.context, input.entity_id)?;
        let plan = MutationPlan::from_compiled(&self.registry, input.route_id)?;
        let request = BatchMutationRequest {
            plan: &plan,
            idempotency_key: input.idempotency_key,
            claims: &claims,
            items: input.items,
            response_fields: input.response_fields,
            body_bytes: input.body_bytes,
        };
        #[cfg(feature = "postgres-test")]
        if let MutationFaultControl::At(fault) = self.fault {
            return self
                .coordinator
                .execute_batch_with_fault(&mut client, request, fault)
                .await;
        }
        self.coordinator.execute_batch(&mut client, request).await
    }

    pub async fn tombstone(
        &self,
        input: ConditionalMutationInput<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        self.conditional_mutation(input, MutationBody::Tombstone)
            .await
    }

    async fn conditional_mutation(
        &self,
        input: ConditionalMutationInput<'_>,
        body: MutationBody,
    ) -> Result<MutationOutcome, MutationError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let claims = strict_claim_context(&self.registry, input.context, input.entity_id)?;
        let plan = MutationPlan::from_compiled(&self.registry, input.route_id)?;
        self.execute_request(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key: input.idempotency_key,
                claims: &claims,
                record_id: Some(input.record_id),
                expected_etag: Some(input.if_match),
                body,
                response_fields: input.response_fields,
            },
        )
        .await
    }

    async fn execute_request(
        &self,
        client: &mut deadpool_postgres::Client,
        request: MutationRequest<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        #[cfg(feature = "postgres-test")]
        if let MutationFaultControl::At(fault) = self.fault {
            return self
                .coordinator
                .execute_with_fault(client, request, fault)
                .await;
        }
        let _ = self.fault;
        self.coordinator.execute(client, request).await
    }
}

#[derive(Clone, Copy)]
enum MutationFaultControl {
    Disabled,
    #[cfg(feature = "postgres-test")]
    At(MutationFaultPoint),
    #[cfg(feature = "postgres-test")]
    RefusalAudit,
}

fn strict_claim_context(
    registry: &CompiledRegistry,
    context: &AuthorizedRequestContext,
    entity_id: &str,
) -> Result<ClaimContext, MutationError> {
    let row_boundaries = context
        .row_boundaries()
        .iter()
        .map(api_boundary)
        .collect::<Result<Vec<_>, _>>()?;
    ClaimContext::for_compiled(
        registry,
        entity_id,
        context.principal().map(str::to_owned),
        context.selected_profile(),
        context.purpose().map(str::to_owned),
        row_boundaries,
    )
    .map_err(|_| MutationError::InvalidRequest)
}

fn api_boundary(boundary: &VerifiedRowBoundary) -> Result<RowBoundaryContext, MutationError> {
    match boundary.operator() {
        ApiRowBoundaryOperator::Equals => {
            let value = boundary
                .values()
                .iter()
                .next()
                .ok_or(MutationError::InvalidRequest)?;
            if boundary.values().len() != 1 {
                return Err(MutationError::InvalidRequest);
            }
            Ok(RowBoundaryContext::Equals {
                field: boundary.field().to_owned(),
                value: value.clone(),
            })
        }
        ApiRowBoundaryOperator::In => Ok(RowBoundaryContext::In {
            field: boundary.field().to_owned(),
            values: boundary.values().clone(),
        }),
    }
}
