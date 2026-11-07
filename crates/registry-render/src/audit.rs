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
//! hashes, outcomes, caller, trace and correlation ids only. A sealed
//! document's entries add the seal id and, on the response, the hashes of
//! what was sealed, the certificate and the timestamp token; never a
//! certificate subject, a signer name or a token.

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
    /// "rendered", "sealed", "refused", or "unfinished" for a call that
    /// ended before its outcome; absent on the request entry written before
    /// the render starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    /// Problem slug for refusals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// The value-free reason a refusal names, when its problem has one: the
    /// failing check of a timestamp exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_sha256: Option<String>,
    /// The runtime seal id, on every entry of a call to the seal route that
    /// named a sealable document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_id: Option<String>,
    /// Whether the runtime declares `assuranceProfile: local`: present, `true`, on
    /// every entry naming a test-only seal, and absent otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub test_only: bool,
    /// `sha256:<hex>` over the first revision, the rendered document a seal
    /// covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_digest: Option<String>,
    /// `sha256:<hex>` over the whole signed file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_file_digest: Option<String>,
    /// `sha256:<hex>` over the seal certificate's DER: its fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_digest: Option<String>,
    /// `sha256:<hex>` over the embedded timestamp token's DER, on a B-T seal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_token_digest: Option<String>,
    /// Verified credential fingerprint (never the token or principal claims).
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
            reason: None,
            pdf_sha256: None,
            data_sha256: None,
            seal_id: None,
            test_only: false,
            document_digest: None,
            signed_file_digest: None,
            certificate_digest: None,
            timestamp_token_digest: None,
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
            reason: problem.reason(),
            ..self
        }
    }

    /// The same event for a call to the seal route naming `seal_id`, a
    /// test-only seal when `test_only`.
    pub fn for_seal(self, seal_id: &str, test_only: bool) -> Self {
        Self {
            seal_id: Some(seal_id.to_owned()),
            test_only,
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
            reason: problem.reason(),
            pdf_sha256: None,
            data_sha256: None,
            seal_id: None,
            test_only: false,
            document_digest: None,
            signed_file_digest: None,
            certificate_digest: None,
            timestamp_token_digest: None,
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
        let unfinished = unfinished(event.clone())?;
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

/// The response a call that ends before its outcome writes: the request
/// entry's identity, with no value only an outcome produces.
fn unfinished(event: RenderAuditEvent) -> Result<serde_json::Value, RenderProblem> {
    let mut unfinished = record(RenderAuditEvent {
        outcome: Some("unfinished"),
        ..event
    })?;
    if let Some(fields) = unfinished.as_object_mut() {
        for field in [
            "pdfSha256",
            "dataSha256",
            "documentDigest",
            "signedFileDigest",
            "certificateDigest",
            "timestampTokenDigest",
        ] {
            fields.remove(field);
        }
    }
    Ok(unfinished)
}

fn record(event: RenderAuditEvent) -> Result<serde_json::Value, RenderProblem> {
    serde_json::to_value(event)
        .map_err(|err| RenderProblem::new(ProblemKind::Internal, format!("audit event: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started() -> RenderAuditEvent {
        RenderAuditEvent::started("notice", 2, 1, "bundle-hash", "caller", None, None)
    }

    #[test]
    fn a_seal_request_entry_names_its_seal_and_no_response_value() {
        let request = record(started().for_seal("ministry", false)).unwrap();
        assert_eq!(request["sealId"], "ministry");
        for field in [
            "outcome",
            "documentDigest",
            "signedFileDigest",
            "certificateDigest",
            "timestampTokenDigest",
        ] {
            assert!(request.get(field).is_none(), "{field}: {request}");
        }
        assert!(request.get("testOnly").is_none(), "{request}");
        let test_only = record(started().for_seal("ministry", true)).unwrap();
        assert_eq!(test_only["testOnly"], true);
        let plain = record(started()).unwrap();
        assert!(plain.get("sealId").is_none(), "{plain}");
    }

    #[test]
    fn an_unfinished_seal_keeps_its_seal_and_drops_every_response_value() {
        let sealed = RenderAuditEvent {
            outcome: Some("sealed"),
            data_sha256: Some("d".repeat(64)),
            document_digest: Some(format!("sha256:{}", "a".repeat(64))),
            signed_file_digest: Some(format!("sha256:{}", "b".repeat(64))),
            certificate_digest: Some(format!("sha256:{}", "c".repeat(64))),
            timestamp_token_digest: Some(format!("sha256:{}", "e".repeat(64))),
            ..started().for_seal("ministry", false)
        };
        let entry = unfinished(sealed).unwrap();
        assert_eq!(entry["outcome"], "unfinished");
        assert_eq!(entry["sealId"], "ministry");
        for field in [
            "pdfSha256",
            "dataSha256",
            "documentDigest",
            "signedFileDigest",
            "certificateDigest",
            "timestampTokenDigest",
        ] {
            assert!(entry.get(field).is_none(), "{field}: {entry}");
        }
    }

    #[test]
    fn a_seal_refusal_names_its_seal() {
        let problem = RenderProblem::new(ProblemKind::SealClientNotAllowed, "refused");
        let entry = record(
            RenderAuditEvent::refused("notice", &problem, "caller", None, None)
                .for_seal("ministry", false),
        )
        .unwrap();
        assert_eq!(entry["sealId"], "ministry");
        assert_eq!(entry["problem"], "seal-client-not-allowed");
    }
}
