//! The render audit ledger: one keyed, hash-chained, sealed-segment JSONL
//! event per service render — appended before the response is sent, failing
//! closed. Failed attempts (validation, timeout, panic, 401) are audited
//! too, so the ledger can distinguish "no attempt" from "erased".
//!
//! Events carry no data values and no asset bytes: identifiers, versions,
//! hashes, outcomes, caller, trace and correlation ids only.

use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use zeroize::Zeroizing;

use registry_platform_audit::{
    require_audit_under, verify_segmented_audit_chain, AuditChainProfile, AuditSink, ChainState,
    DurableSegmentedJsonlSink,
};

use crate::problem::{ProblemKind, RenderProblem};

pub struct RenderAudit {
    chain: Arc<ChainState>,
    sink: Arc<DurableSegmentedJsonlSink>,
    #[allow(dead_code)]
    hasher: registry_platform_audit::AuditChainHasher,
}

/// One value-free audit event. Field set is closed; adding a field is a
/// reviewed change.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderAuditEvent {
    pub document_id: String,
    pub document_version: u32,
    pub bundle_version: u32,
    pub bundle_hash: String,
    /// "rendered" or "refused".
    pub outcome: &'static str,
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
            outcome: "refused",
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

impl RenderAudit {
    /// Open (or bootstrap) the ledger with the production keyed profile.
    pub async fn open(
        directory: &Path,
        integrity_key: Vec<u8>,
        max_segment_bytes: u64,
    ) -> Result<Self, RenderProblem> {
        let problem = |detail: String| RenderProblem::new(ProblemKind::AuditFailed, detail);
        if !directory.exists() {
            std::fs::create_dir(directory)
                .map_err(|err| problem(format!("cannot create audit directory: {err}")))?;
        }
        // The sink policy requires an owner-only ledger directory; when we
        // create it ourselves we create it compliant.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(directory)
                .map(|m| m.permissions().mode())
                .unwrap_or(0o755);
            if mode & 0o077 != 0 {
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode & 0o700))
                    .map_err(|err| problem(format!("cannot tighten audit directory: {err}")))?;
            }
        }
        require_audit_under(directory, directory)
            .map_err(|err| problem(format!("audit directory not owner-controlled: {err}")))?;
        let hasher = AuditChainProfile::production_from_secret_bytes(Zeroizing::new(integrity_key))
            .map_err(|err| problem(format!("audit integrity key rejected: {err}")))?
            .hasher();
        let ledger = directory.join("ledger.jsonl");
        let sink = Arc::new(
            DurableSegmentedJsonlSink::open(&ledger, max_segment_bytes)
                .map_err(|err| problem(format!("cannot open audit ledger: {err}")))?,
        );
        let chain = ChainState::bootstrap_or_start_empty(sink.as_ref(), hasher.clone())
            .await
            .map_err(|err| problem(format!("audit chain bootstrap: {err}")))?;
        let chain = Arc::new(chain);
        Ok(Self {
            chain,
            sink,
            hasher,
        })
    }

    /// Append one event. The write must succeed before the caller responds.
    pub async fn append(&self, event: RenderAuditEvent) -> Result<(), RenderProblem> {
        let record = serde_json::to_value(event).map_err(|err| {
            RenderProblem::new(ProblemKind::Internal, format!("audit event: {err}"))
        })?;
        self.chain
            .append(self.sink.as_ref() as &dyn AuditSink, record)
            .await
            .map(|_| ())
            .map_err(|err| {
                RenderProblem::new(ProblemKind::AuditFailed, format!("audit append: {err}"))
            })
    }

    /// Readiness: the sink must answer a keyed tail read.
    pub async fn ready(&self) -> bool {
        self.sink.ready().await
    }
}

/// `render audit-verify`: prove a retained ledger end to end.
pub fn verify_chain(
    runtime_path: &Path,
    directory: &Path,
    key_ref: &str,
) -> Result<i32, RenderProblem> {
    let key = crate::runtime::resolve_secret(runtime_path, key_ref)?;
    let hasher = AuditChainProfile::production_from_secret_bytes(Zeroizing::new(key))
        .map_err(|err| {
            RenderProblem::new(ProblemKind::AuditFailed, format!("integrity key: {err}"))
        })?
        .hasher();
    let ledger = directory.join("ledger.jsonl");
    let summary = verify_segmented_audit_chain(&ledger, &hasher).map_err(|err| {
        RenderProblem::new(
            ProblemKind::AuditFailed,
            format!("chain verification: {err}"),
        )
    })?;
    println!(
        "audit chain verified: {} record(s) across {} segment(s)",
        summary.records, summary.segments
    );
    if summary.records == 0 {
        let non_empty = std::fs::metadata(&ledger).is_ok_and(|m| m.len() > 0);
        if non_empty {
            println!(
                "note: no records verified although {} is non-empty; a running serve holds                  the active segment and verification skips it — verify again after shutdown",
                ledger.display()
            );
        }
    }
    Ok(0)
}
