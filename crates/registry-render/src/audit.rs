//! The render audit: value-free lines written through the shared platform
//! audit writer. A render writes a `request` entry before the worker starts
//! and a `response` entry carrying the outcome before the document leaves;
//! both fail closed. A refusal decided before any render (validation, 401,
//! 413) is one `response` entry, so the log distinguishes "no attempt" from
//! a refused one. A render whose call ends before its outcome is written, a
//! caller that disconnects included, writes an `unfinished` response, so no
//! request entry stays unpaired. The pairing correlation is drawn by the
//! server for every call; the caller's `Idempotency-Key` is only echoed in
//! the record as `correlationId`. The log carries no hash chain or signature.
//!
//! Events carry no data values and no asset bytes: identifiers, versions,
//! hashes, outcomes, caller, trace and correlation ids only.

use serde::Serialize;

use registry_platform_audit::{AuditDestination, AuditEntry, AuditRequest, AuditWriter};

use crate::problem::{ProblemKind, RenderProblem};

/// The schema id every Render audit line carries in its envelope.
pub const AUDIT_SCHEMA: &str = "render.registrystack.org/audit/v1";

#[derive(Clone, Debug)]
pub struct RenderAudit {
    writer: AuditWriter,
}

/// One value-free audit event. Field set is closed; adding a field is a
/// reviewed change.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderAuditEvent {
    pub document_id: String,
    pub document_version: u32,
    pub bundle_version: u32,
    pub bundle_hash: String,
    /// "rendered", "refused", or "unfinished" for a call that ended before
    /// its outcome; absent on the request entry written before the render
    /// starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    /// Problem slug for refusals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_sha256: Option<String>,
    /// API-key fingerprint (never the key).
    pub caller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub renderer_version: String,
    pub typst_pin: String,
}

impl RenderAuditEvent {
    /// The request entry for a render about to start: its identity, with
    /// no outcome yet.
    pub fn started(
        document_id: &str,
        document_version: u32,
        bundle_version: u32,
        bundle_hash: &str,
        caller: &str,
        correlation_id: Option<&str>,
        trace_id: Option<&str>,
    ) -> Self {
        Self {
            document_id: document_id.to_owned(),
            document_version,
            bundle_version,
            bundle_hash: bundle_hash.to_owned(),
            outcome: None,
            problem: None,
            pdf_sha256: None,
            data_sha256: None,
            caller: caller.to_owned(),
            correlation_id: correlation_id.map(str::to_owned),
            trace_id: trace_id.map(str::to_owned),
            renderer_version: crate::display_version(),
            typst_pin: crate::TYPST_PIN.to_owned(),
        }
    }

    /// The response entry for a render that failed after it started: the
    /// request entry's identity, refused with `problem`.
    pub fn refused_after_start(self, problem: &RenderProblem) -> Self {
        Self {
            outcome: Some("refused"),
            problem: Some(problem.kind.slug().to_owned()),
            ..self
        }
    }

    pub fn refused(
        document_id: &str,
        problem: &RenderProblem,
        caller: &str,
        correlation_id: Option<&str>,
        trace_id: Option<&str>,
    ) -> Self {
        Self {
            document_id: document_id.to_owned(),
            document_version: 0,
            bundle_version: 0,
            bundle_hash: String::new(),
            outcome: Some("refused"),
            problem: Some(problem.kind.slug().to_owned()),
            pdf_sha256: None,
            data_sha256: None,
            caller: caller.to_owned(),
            correlation_id: correlation_id.map(str::to_owned),
            trace_id: trace_id.map(str::to_owned),
            renderer_version: crate::display_version(),
            typst_pin: crate::TYPST_PIN.to_owned(),
        }
    }
}

/// The envelope correlation for one call: a fresh random id the server
/// draws. The caller's `Idempotency-Key` is not unique to one call, so it is
/// never the value that pairs a call's entries.
pub fn correlation() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl RenderAudit {
    /// Open the configured destination. A file destination takes the
    /// single-writer lock and creates an owner-only parent directory.
    pub async fn open(destination: AuditDestination) -> Result<Self, RenderProblem> {
        let writer = AuditWriter::open(destination).await.map_err(|err| {
            RenderProblem::new(
                ProblemKind::AuditFailed,
                format!("cannot open audit destination: {err}"),
            )
        })?;
        Ok(Self::new(writer))
    }

    pub fn new(writer: AuditWriter) -> Self {
        Self { writer }
    }

    /// Append the request entry and return the handle that owes its
    /// response. It must be accepted before the render starts. A call that
    /// ends before it responds writes `unfinished` as the response.
    pub async fn request(
        &self,
        correlation: &str,
        event: RenderAuditEvent,
    ) -> Result<AuditRequest, RenderProblem> {
        let mut unfinished = record(RenderAuditEvent {
            outcome: Some("unfinished"),
            ..event.clone()
        })?;
        if let Some(fields) = unfinished.as_object_mut() {
            fields.remove("pdfSha256");
            fields.remove("dataSha256");
        }
        let record = record(event)?;
        self.writer
            .begin(AUDIT_SCHEMA, correlation, record, unfinished)
            .await
            .map_err(|err| {
                RenderProblem::new(ProblemKind::AuditFailed, format!("audit append: {err}"))
            })
    }

    /// Append the response entry. It must be accepted before the caller
    /// receives anything but an audit failure.
    pub async fn response(
        &self,
        correlation: &str,
        event: RenderAuditEvent,
    ) -> Result<(), RenderProblem> {
        let record = record(event)?;
        self.append(AuditEntry::response(AUDIT_SCHEMA, correlation, record))
            .await
    }

    async fn append(&self, entry: AuditEntry) -> Result<(), RenderProblem> {
        self.writer.append(entry).await.map_err(|err| {
            RenderProblem::new(ProblemKind::AuditFailed, format!("audit append: {err}"))
        })
    }

    /// Wait for the unfinished response entries dropped calls handed to a
    /// stream destination.
    #[cfg(test)]
    pub(crate) fn wait_for_detached_entries(&self) {
        self.writer.wait_for_detached_entries();
    }

    /// Readiness: the destination still accepts entries.
    pub async fn ready(&self) -> bool {
        self.writer.ready().await
    }
}

fn record(event: RenderAuditEvent) -> Result<serde_json::Value, RenderProblem> {
    serde_json::to_value(event)
        .map_err(|err| RenderProblem::new(ProblemKind::Internal, format!("audit event: {err}")))
}
