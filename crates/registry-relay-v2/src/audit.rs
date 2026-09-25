// SPDX-License-Identifier: Apache-2.0
//! Relay V2's closed, value-free audit event vocabulary and release gate.

use registry_platform_audit::{AuditEntry, AuditUnavailable, AuditWriter};
use serde::Serialize;
use serde_json::Value;
use ulid::Ulid;

use crate::problem::TraceId;
use crate::sqlite_runtime::SourceRevision;

/// Schema identifier carried in the envelope of every Relay audit line.
pub const AUDIT_SCHEMA: &str = "registry.relay.audit/v2alpha2";

/// Relay's audit release gate over the platform audit writer.
///
/// An `attempt` is a `request` entry written before source access; a
/// `refusal` or `terminal` is a `response` entry written before any response
/// byte leaves the process. Both halves of one request share its operation
/// identifier as the envelope `correlation`. An append that is not accepted
/// returns `AuditUnavailable`, and callers refuse with `audit.unavailable`.
#[derive(Clone)]
pub struct RelayAudit {
    writer: AuditWriter,
}

impl RelayAudit {
    #[must_use]
    pub fn new(writer: AuditWriter) -> Self {
        Self { writer }
    }

    #[must_use]
    pub fn operation_id() -> String {
        Ulid::new().to_string()
    }

    pub async fn attempt(&self, context: &AuditContext) -> Result<(), AuditUnavailable> {
        self.append(AuditEvent::from_context(context, AuditPhase::Attempt, None))
            .await
    }

    pub async fn refusal(
        &self,
        context: &AuditContext,
        outcome: AuditOutcome,
    ) -> Result<(), AuditUnavailable> {
        self.append(AuditEvent::from_context(
            context,
            AuditPhase::Refusal,
            Some(outcome),
        ))
        .await
    }

    /// Record the outcome of an operation that reached its source. Callers
    /// hold the exact serialized response bytes until this returns `Ok`, so
    /// the entry gates their release; it does not describe or bind them.
    pub async fn terminal(
        &self,
        context: &AuditContext,
        outcome: AuditOutcome,
    ) -> Result<(), AuditUnavailable> {
        self.append(AuditEvent::from_context(
            context,
            AuditPhase::Terminal,
            Some(outcome),
        ))
        .await
    }

    async fn append(&self, event: AuditEvent) -> Result<(), AuditUnavailable> {
        let correlation = event.operation_id.clone();
        // The record is a closed struct of strings, enums, and lists, so it
        // always serializes to an object. Should that ever fail, the writer
        // refuses the null record as an invalid entry and the caller refuses
        // the request rather than proceeding unaudited.
        let record = serde_json::to_value(&event).unwrap_or(Value::Null);
        let entry = match event.phase {
            AuditPhase::Attempt => AuditEntry::request(AUDIT_SCHEMA, correlation, record),
            AuditPhase::Refusal | AuditPhase::Terminal => {
                AuditEntry::response(AUDIT_SCHEMA, correlation, record)
            }
        };
        self.writer.append(entry).await
    }

    #[must_use]
    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }
}

#[derive(Clone, Debug)]
pub struct AuditContext {
    pub operation_id: String,
    pub trace_id: TraceId,
    pub registry_identifier: String,
    pub resource_identifier: Option<String>,
    pub operation_identifier: Option<String>,
    pub operation_surface: OperationSurface,
    pub query_shape: Option<QueryShape>,
    pub access_rule_revision: Option<String>,
    pub purpose: Option<String>,
    pub row_boundary_kind: RowBoundaryKind,
    pub access_profile: Option<String>,
    pub disclosure_profile: Option<String>,
    pub wire_format: Option<String>,
    pub format_profile: Option<String>,
    pub processing_description_identifiers: Vec<String>,
    pub selected_properties: Vec<String>,
    pub processing_handling: Option<String>,
    pub disclosure_handling: Option<String>,
    pub transform_identifiers: Vec<String>,
    pub contract_revision: String,
    pub source_revision: Option<SourceRevision>,
    pub principal_kind: PrincipalKind,
}

/// Value-free request category. The stable capability identity remains in
/// `operation_identifier`; this field distinguishes the HTTP action and wire
/// surface sharing that capability without inventing a second entitlement.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationSurface {
    RecordList,
    RecordRead,
    RecordLookup,
    RecordSearch,
    SdmxData,
    SdmxDataflowStructure,
    SdmxDatastructureStructure,
    Unknown,
}

/// The only SDMX request-shape distinctions retained by audit. Component
/// names, keys, constraints, offsets, limits, and source values remain absent.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QueryShape {
    SdmxKeyedTimePeriod,
    SdmxKeyedAllDimensions,
    SdmxOmittedKeyTimePeriod,
    SdmxOmittedKeyAllDimensions,
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
    phase: AuditPhase,
    operation_id: String,
    trace_id: String,
    registry_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_identifier: Option<String>,
    operation_surface: OperationSurface,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_shape: Option<QueryShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_rule_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    row_boundary_kind: RowBoundaryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wire_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format_profile: Option<String>,
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
            phase,
            operation_id: context.operation_id.clone(),
            trace_id: context.trace_id.as_str().to_owned(),
            registry_identifier: context.registry_identifier.clone(),
            resource_identifier: context.resource_identifier.clone(),
            operation_identifier: context.operation_identifier.clone(),
            operation_surface: context.operation_surface,
            query_shape: context.query_shape,
            access_rule_revision: context.access_rule_revision.clone(),
            purpose: context.purpose.clone(),
            row_boundary_kind: context.row_boundary_kind,
            access_profile: context.access_profile.clone(),
            disclosure_profile: context.disclosure_profile.clone(),
            wire_format: context.wire_format.clone(),
            format_profile: context.format_profile.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_serializes_only_the_access_profile_field() {
        let context = AuditContext {
            operation_id: "operation-1".into(),
            trace_id: TraceId::parse("00112233445566778899aabbccddeeff").expect("trace identifier"),
            registry_identifier: "registry-1".into(),
            resource_identifier: Some("record".into()),
            operation_identifier: Some("record.read".into()),
            operation_surface: OperationSurface::RecordRead,
            query_shape: None,
            access_rule_revision: Some("sha256:access".into()),
            purpose: None,
            row_boundary_kind: RowBoundaryKind::None,
            access_profile: Some("public".into()),
            disclosure_profile: Some("public".into()),
            wire_format: None,
            format_profile: None,
            processing_description_identifiers: Vec::new(),
            selected_properties: vec!["name".into()],
            processing_handling: Some("public".into()),
            disclosure_handling: Some("public".into()),
            transform_identifiers: Vec::new(),
            contract_revision: "sha256:contract".into(),
            source_revision: Some(SourceRevision::LiveUnversioned),
            principal_kind: PrincipalKind::Anonymous,
        };
        let value = serde_json::to_value(AuditEvent::from_context(
            &context,
            AuditPhase::Attempt,
            None,
        ))
        .expect("audit serializes");

        assert_eq!(value["accessProfile"], "public");
        assert_eq!(value["operationSurface"], "record-read");
        assert!(value.get("representation").is_none());
        assert!(
            value.get("schema").is_none(),
            "the schema identifier lives in the envelope"
        );
    }
}
