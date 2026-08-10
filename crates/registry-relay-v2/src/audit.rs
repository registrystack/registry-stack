// SPDX-License-Identifier: Apache-2.0
//! Relay V2's closed, value-free audit event vocabulary and release gate.

use std::sync::Arc;
use std::{future::Future, pin::Pin};

use registry_platform_audit::{AuditError, AuditSink, ChainState};
use serde::Serialize;
use serde_json::Value;
use ulid::Ulid;

use crate::problem::TraceId;
use crate::sqlite_runtime::SourceRevision;

pub const AUDIT_SCHEMA: &str = "registry.relay.consultation-audit/v2alpha1";

#[derive(Clone)]
pub struct RelayAudit {
    chain: Arc<ChainState>,
    sink: Arc<dyn AuditSink>,
    readiness: AuditReadiness,
}

type AuditReadiness = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

impl RelayAudit {
    #[must_use]
    pub fn new(chain: Arc<ChainState>, sink: Arc<dyn AuditSink>) -> Self {
        let observed_chain = Arc::clone(&chain);
        Self {
            chain,
            sink,
            readiness: Arc::new(move || {
                let ready = observed_chain.try_last_hash().is_some();
                Box::pin(async move { ready })
            }),
        }
    }

    /// Install an async, value-free concrete sink probe. Production startup
    /// uses this with the keyed sink verifier it already owns, allowing
    /// readiness to detect an unavailable or replaced audit destination.
    #[must_use]
    pub fn with_readiness_check<F, Fut>(mut self, check: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        self.readiness = Arc::new(move || Box::pin(check()));
        self
    }

    #[must_use]
    pub fn operation_id() -> String {
        Ulid::new().to_string()
    }

    pub async fn attempt(&self, context: &AuditContext) -> Result<(), AuditError> {
        self.append(AuditEvent::from_context(context, AuditPhase::Attempt, None))
            .await
    }

    pub async fn refusal(
        &self,
        context: &AuditContext,
        outcome: AuditOutcome,
    ) -> Result<(), AuditError> {
        self.append(AuditEvent::from_context(
            context,
            AuditPhase::Refusal,
            Some(outcome),
        ))
        .await
    }

    pub async fn terminal(
        &self,
        context: &AuditContext,
        outcome: AuditOutcome,
        _exact_response_bytes: Option<&[u8]>,
    ) -> Result<(), AuditError> {
        self.append(AuditEvent::from_context(
            context,
            AuditPhase::Terminal,
            Some(outcome),
        ))
        .await
    }

    async fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.chain.append(self.sink.as_ref(), event).await?;
        Ok(())
    }

    #[must_use]
    pub async fn ready(&self) -> bool {
        self.chain.try_last_hash().is_some() && (self.readiness)().await
    }
}

#[derive(Clone, Debug)]
pub struct AuditContext {
    pub operation_id: String,
    pub trace_id: TraceId,
    pub registry_identifier: String,
    pub resource_identifier: Option<String>,
    pub operation_identifier: Option<String>,
    pub access_rule_revision: Option<String>,
    pub purpose: Option<String>,
    pub row_boundary_kind: RowBoundaryKind,
    pub representation: Option<String>,
    pub disclosure_profile: Option<String>,
    pub processing_description_identifiers: Vec<String>,
    pub selected_properties: Vec<String>,
    pub processing_handling: Option<String>,
    pub disclosure_handling: Option<String>,
    pub transform_identifiers: Vec<String>,
    pub contract_revision: String,
    pub source_revision: Option<SourceRevision>,
    pub principal_kind: PrincipalKind,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    Anonymous,
    Authenticated,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RowBoundaryKind {
    None,
    Principal,
    VerifiedClaim,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditOutcome {
    Released,
    NotModified,
    Unresolved,
    InvalidRequest,
    MissingCredential,
    InvalidCredential,
    Denied,
    RateLimited,
    TimedOut,
    SourceFailed,
    InternalFailed,
    NotFound,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum AuditPhase {
    Attempt,
    Refusal,
    Terminal,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEvent {
    schema: &'static str,
    phase: AuditPhase,
    operation_id: String,
    trace_id: String,
    registry_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_rule_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    row_boundary_kind: RowBoundaryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    representation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_profile: Option<String>,
    processing_description_identifiers: Vec<String>,
    selected_properties: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    processing_handling: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_handling: Option<String>,
    transform_identifiers: Vec<String>,
    contract_revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_revision: Option<Value>,
    principal_kind: PrincipalKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<AuditOutcome>,
}

impl AuditEvent {
    fn from_context(
        context: &AuditContext,
        phase: AuditPhase,
        outcome: Option<AuditOutcome>,
    ) -> Self {
        Self {
            schema: AUDIT_SCHEMA,
            phase,
            operation_id: context.operation_id.clone(),
            trace_id: context.trace_id.as_str().to_owned(),
            registry_identifier: context.registry_identifier.clone(),
            resource_identifier: context.resource_identifier.clone(),
            operation_identifier: context.operation_identifier.clone(),
            access_rule_revision: context.access_rule_revision.clone(),
            purpose: context.purpose.clone(),
            row_boundary_kind: context.row_boundary_kind,
            representation: context.representation.clone(),
            disclosure_profile: context.disclosure_profile.clone(),
            processing_description_identifiers: context.processing_description_identifiers.clone(),
            selected_properties: context.selected_properties.clone(),
            processing_handling: context.processing_handling.clone(),
            disclosure_handling: context.disclosure_handling.clone(),
            transform_identifiers: context.transform_identifiers.clone(),
            contract_revision: context.contract_revision.clone(),
            source_revision: context.source_revision.as_ref().map(source_revision),
            principal_kind: context.principal_kind,
            outcome,
        }
    }
}

fn source_revision(revision: &SourceRevision) -> Value {
    match revision {
        SourceRevision::Snapshot(value) => serde_json::json!({
            "profile": "snapshot",
            "status": "versioned",
            "value": value,
        }),
        SourceRevision::LiveUnversioned => serde_json::json!({
            "profile": "live",
            "status": "unversioned",
            "value": null,
        }),
    }
}
