// SPDX-License-Identifier: Apache-2.0

//! Listener-free acquisition for externally governed record projections.
//! The caller authorizes purpose, selectors and fields before entering this
//! seam and rechecks its grant before publishing. This module cannot store
//! records and never creates acquisition authority from a source response.

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

use registry_adapter_core::{
    projection_token_valid, AdapterPack, ComponentKind, EvidenceAuthenticationPolicy,
    EvidenceClientIdentityPolicy, EvidenceConnectionPolicy, ProjectionAbsence, ProjectionMode,
    ProjectionRecord, ProjectionRequest, ProjectionResult, ProjectionRetention,
    ProjectionRouteContract, ProjectionRow,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    artifacts::PackArtifactBytes,
    evidence::{
        check_schema, compile_read_pack_with_schemas, load_schema, reachable_endpoint_ids,
        CheckedEvidenceSchema, EvidenceAcquisition, EvidenceCompileError, EvidenceHostHooks,
        EvidenceLimits, EvidencePackProgram, EvidenceProgram, EvidenceRuntimeBindings,
        EvidenceSchemaKind,
    },
    host_protocol::HostProtocolRegistry,
    replay::ReplayTranscript,
};

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("the reviewed projection operation is missing or incompatible")]
    Contract,
    #[error("the projection route or its operator connection did not compile")]
    Compile(#[from] EvidenceCompileError),
    #[error("the indexed operation lacks explicit retention permission")]
    RetentionRefused,
    #[error("the source response does not permit retention")]
    NoStore,
    #[error("the request is outside the projection operation contract")]
    InvalidRequest,
    #[error("the source result does not satisfy the projection contract")]
    InvalidResult,
    #[error("the source could not supply a verified complete result")]
    Unavailable,
}

/// Trusted transport metadata; scripts never see or modify these flags.
#[derive(Default)]
pub(crate) struct ProjectionHttpState {
    retention_restricted: AtomicBool,
    failed: AtomicBool,
    successful: AtomicU64,
}

impl ProjectionHttpState {
    pub(crate) fn restrict_retention(&self) {
        self.retention_restricted.store(true, Ordering::Relaxed);
    }

    pub(crate) fn observe_cache_control<'a>(&self, fields: impl Iterator<Item = &'a str>) {
        // Treat no-store with a nonstandard argument as restrictive too.
        // Splitting quoted extension values conservatively can only withhold
        // retention. A malformed/non-UTF-8 transport field also fails closed.
        if fields.flat_map(|field| field.split(',')).any(|directive| {
            directive
                .split('=')
                .next()
                .is_some_and(|name| name.trim().eq_ignore_ascii_case("no-store"))
        }) {
            self.restrict_retention();
        }
    }

    /// The status test shared by success counting and no-store handling: a
    /// 2xx that is not a 202 acceptance carries data.
    pub(crate) fn status_successful(status: u16) -> bool {
        (200..300).contains(&status) && status != 202
    }

    pub(crate) fn observe_response(&self, successful: bool) {
        if successful {
            self.successful.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed.store(true, Ordering::Relaxed);
        }
    }
}

pub struct ProjectionPackProgram {
    contract: ProjectionRouteContract,
    program: EvidencePackProgram,
}

/// Compile a route in the same closed read engine used by other embedding
/// hosts. The caller supplies the AdapterPack from the pinned pack document;
/// this compiler verifies the exact bytes of every consumed pack artifact.
pub fn compile_projection_pack(
    pack: &AdapterPack,
    route: &str,
    artifacts: &PackArtifactBytes,
    limits: EvidenceLimits,
) -> Result<ProjectionPackProgram, ProjectionError> {
    let source = pack
        .source_routes
        .get(route)
        .ok_or(ProjectionError::Contract)?;
    let contract = source
        .projection
        .as_ref()
        .ok_or(ProjectionError::Contract)?;
    if !contract.identifiers_valid()
        || source.evidence.is_some()
        || source.read_support.is_some()
        || source.scan.is_some()
        || source.next_recovery.is_some()
        || source.edits.is_some()
        || source.rescan_delay_seconds.is_some()
    {
        return Err(ProjectionError::Contract);
    }
    // This initial seam observes every raw data response. Permit only the
    // ordinary HTTP path, so a different component or host protocol cannot
    // evade that observer.
    let endpoints = reachable_endpoint_ids(pack, source)?;
    if endpoints.is_empty()
        || endpoints.iter().any(|id| {
            !pack.endpoints.get(id).is_some_and(|endpoint| {
                endpoint.component == ComponentKind::Http && endpoint.host_protocol.is_none()
            })
        })
    {
        return Err(ProjectionError::Contract);
    }

    let input_schema = check_schema(
        EvidenceSchemaKind::Inputs,
        json!({
            "type":"object",
            "additionalProperties":false,
            "required":["type","fields"],
            "properties":{
                "type":{"enum":["exact","batch","by-parent"]},
                "fields":{"type":"array","items":{"type":"string"}},
                "key":{"type":"string"},
                "keys":{"type":"array","items":{"type":"string"}},
                "parentKey":{"type":"string"},
                "cursor":{"type":"string"}
            }
        }),
    )
    .map_err(EvidenceCompileError::from)?;
    let fields_schema = load_schema(
        artifacts,
        &contract.fields_schema,
        EvidenceSchemaKind::Facts,
    )?;
    if !fields_schema
        .as_value()
        .get("properties")
        .is_some_and(Value::is_object)
    {
        return Err(ProjectionError::Contract);
    }
    let program = compile_read_pack_with_schemas(
        pack,
        source,
        artifacts,
        limits,
        &HostProtocolRegistry::default(),
        input_schema,
        fields_schema,
    )?;
    Ok(ProjectionPackProgram {
        contract: contract.clone(),
        program,
    })
}

impl ProjectionPackProgram {
    #[must_use]
    pub fn contract(&self) -> &ProjectionRouteContract {
        &self.contract
    }

    #[must_use]
    pub fn fields_schema(&self) -> &CheckedEvidenceSchema {
        self.program.facts_schema()
    }

    pub fn bind_live(
        self,
        runtime: &EvidenceRuntimeBindings,
        connection_id: &str,
        connection: &[EvidenceConnectionPolicy],
    ) -> Result<ProjectionProgram, ProjectionError> {
        if connection.is_empty()
            || connection.iter().any(|policy| {
                matches!(policy.authentication, EvidenceAuthenticationPolicy::None {})
                    && policy.client_identity != EvidenceClientIdentityPolicy::Required
            })
        {
            return Err(ProjectionError::Contract);
        }
        Ok(ProjectionProgram {
            contract: self.contract,
            program: self
                .program
                .bind_live(runtime, Some(connection_id), connection)?,
        })
    }

    /// Execute the same reviewed route against a sealed synthetic transcript.
    /// This path has no live connection, identity, or credentials.
    pub fn bind_replay(
        self,
        transcript: Arc<ReplayTranscript>,
    ) -> Result<ProjectionProgram, ProjectionError> {
        Ok(ProjectionProgram {
            contract: self.contract,
            program: self.program.bind_replay(transcript)?,
        })
    }
}

pub struct ProjectionProgram {
    contract: ProjectionRouteContract,
    program: EvidenceProgram,
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum SourceResult {
    Exact {
        record: ProjectionRecord,
    },
    Batch {
        records: Vec<ProjectionRecord>,
    },
    ByParent {
        parent_key: String,
        snapshot: String,
        rows: Vec<ProjectionRow>,
        complete: bool,
        next_cursor: Option<String>,
    },
    Unavailable {},
}

impl ProjectionProgram {
    #[must_use]
    pub fn contract(&self) -> &ProjectionRouteContract {
        &self.contract
    }

    #[must_use]
    pub fn fields_schema(&self) -> &CheckedEvidenceSchema {
        self.program.facts_schema()
    }

    /// Run one bounded acquisition under the caller's current grant. All
    /// pages share the same audited acquisition and operation/byte budgets.
    pub async fn acquire(
        &self,
        hooks: Arc<dyn EvidenceHostHooks>,
        mode: ProjectionMode,
        request: ProjectionRequest,
        fields: &BTreeSet<String>,
    ) -> Result<ProjectionResult, ProjectionError> {
        self.acquire_until(hooks, mode, request, fields, None).await
    }

    /// Apply a stricter host grant deadline without resetting the operation
    /// budget or cancelling a durable audit append in progress.
    pub async fn acquire_until(
        &self,
        hooks: Arc<dyn EvidenceHostHooks>,
        mode: ProjectionMode,
        request: ProjectionRequest,
        fields: &BTreeSet<String>,
        maximum_deadline: Option<tokio::time::Instant>,
    ) -> Result<ProjectionResult, ProjectionError> {
        if mode == ProjectionMode::Indexed && self.contract.retention != ProjectionRetention::Retain
        {
            return Err(ProjectionError::RetentionRefused);
        }
        self.check_request(mode, &request, fields)?;
        let mut acquisition = self
            .program
            .begin_acquisition_inner(hooks, None, chrono::Utc::now(), maximum_deadline)
            .await
            .map_err(|_| ProjectionError::Unavailable)?;
        acquisition.projection_http = Some(ProjectionHttpState::default());

        match request {
            ProjectionRequest::Exact { key } => {
                match self
                    .execute(
                        &acquisition,
                        mode,
                        json!({"type":"exact","key":key,"fields":fields}),
                    )
                    .await?
                {
                    SourceResult::Exact { record } if record.key() == key => {
                        self.check_record(&record, fields)?;
                        Ok(ProjectionResult::Exact { record })
                    }
                    _ => Err(ProjectionError::InvalidResult),
                }
            }
            ProjectionRequest::Batch { keys } => {
                match self
                    .execute(
                        &acquisition,
                        mode,
                        json!({"type":"batch","keys":keys,"fields":fields}),
                    )
                    .await?
                {
                    SourceResult::Batch { records } => {
                        let mut remaining: BTreeSet<&str> =
                            keys.iter().map(String::as_str).collect();
                        for record in &records {
                            if !remaining.remove(record.key()) {
                                return Err(ProjectionError::InvalidResult);
                            }
                            self.check_record(record, fields)?;
                        }
                        if !remaining.is_empty() {
                            return Err(ProjectionError::InvalidResult);
                        }
                        Ok(ProjectionResult::Batch { records })
                    }
                    _ => Err(ProjectionError::InvalidResult),
                }
            }
            ProjectionRequest::ByParent { parent_key } => {
                self.collect(&acquisition, mode, parent_key, fields).await
            }
        }
    }

    fn check_request(
        &self,
        mode: ProjectionMode,
        request: &ProjectionRequest,
        fields: &BTreeSet<String>,
    ) -> Result<(), ProjectionError> {
        let known_fields = self.fields_schema().as_value()["properties"]
            .as_object()
            .ok_or(ProjectionError::Contract)?;
        if request.kind() != self.contract.operation
            || fields.len() > 256
            || fields.iter().any(|field| !known_fields.contains_key(field))
        {
            return Err(ProjectionError::InvalidRequest);
        }
        let valid = match request {
            ProjectionRequest::Exact { key } => projection_token_valid(key),
            ProjectionRequest::Batch { keys } => {
                mode == ProjectionMode::Indexed
                    && !keys.is_empty()
                    && keys.len() as u64 <= self.contract.maximum_batch_keys.get()
                    && keys.iter().all(|key| projection_token_valid(key))
                    && keys.iter().collect::<BTreeSet<_>>().len() == keys.len()
            }
            ProjectionRequest::ByParent { parent_key } => projection_token_valid(parent_key),
        };
        if !valid {
            return Err(ProjectionError::InvalidRequest);
        }
        Ok(())
    }

    async fn execute(
        &self,
        acquisition: &EvidenceAcquisition,
        mode: ProjectionMode,
        input: Value,
    ) -> Result<SourceResult, ProjectionError> {
        let http = acquisition
            .projection_http
            .as_ref()
            .ok_or(ProjectionError::Contract)?;
        let previous_successes = http.successful.load(Ordering::Relaxed);
        let result = self.program.execute_raw(acquisition, input).await;
        // A response that forbids retention outranks every failure: BReg
        // drops the cached snapshot for `NoStore` but keeps it for
        // `Unavailable`.
        if mode == ProjectionMode::Indexed && http.retention_restricted.load(Ordering::Relaxed) {
            return Err(ProjectionError::NoStore);
        }
        if http.failed.load(Ordering::Relaxed)
            || http.successful.load(Ordering::Relaxed) == previous_successes
        {
            return Err(ProjectionError::Unavailable);
        }
        let value = result.map_err(|_| ProjectionError::Unavailable)?;
        match serde_json::from_value(value) {
            Ok(SourceResult::Unavailable {}) => Err(ProjectionError::Unavailable),
            Ok(result) => Ok(result),
            Err(_) => Err(ProjectionError::InvalidResult),
        }
    }

    fn check_record(
        &self,
        record: &ProjectionRecord,
        fields: &BTreeSet<String>,
    ) -> Result<(), ProjectionError> {
        match record {
            ProjectionRecord::Present {
                fields: returned,
                source_revision,
                ..
            } => self.check_fields(returned, source_revision.as_deref(), fields),
            ProjectionRecord::AuthoritativeAbsent {
                source_revision, ..
            } => {
                if self.contract.absence != ProjectionAbsence::Authoritative {
                    return Err(ProjectionError::Unavailable);
                }
                check_revision(source_revision.as_deref())
            }
            ProjectionRecord::Unavailable { .. } => Ok(()),
        }
    }

    fn check_fields(
        &self,
        returned: &Map<String, Value>,
        revision: Option<&str>,
        fields: &BTreeSet<String>,
    ) -> Result<(), ProjectionError> {
        // A missing requested field is not an authoritative absence. A
        // nullable field can be explicitly null under the reviewed schema.
        if returned.len() != fields.len()
            || returned.keys().any(|field| !fields.contains(field))
            || !self
                .fields_schema()
                .validate(&Value::Object(returned.clone()))
        {
            return Err(ProjectionError::InvalidResult);
        }
        check_revision(revision)
    }

    async fn collect(
        &self,
        acquisition: &EvidenceAcquisition,
        mode: ProjectionMode,
        parent_key: String,
        fields: &BTreeSet<String>,
    ) -> Result<ProjectionResult, ProjectionError> {
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_rows = BTreeSet::new();
        let mut snapshot = None;
        let mut rows = Vec::new();
        for _ in 0..self.contract.maximum_pages.get() {
            let mut input = json!({"type":"by-parent","parentKey":parent_key,"fields":fields});
            if let Some(cursor) = cursor.take() {
                input["cursor"] = Value::String(cursor);
            }
            let SourceResult::ByParent {
                parent_key: returned_parent,
                snapshot: current_snapshot,
                rows: page,
                complete,
                next_cursor,
            } = self.execute(acquisition, mode, input).await?
            else {
                return Err(ProjectionError::InvalidResult);
            };
            if returned_parent != parent_key
                || !projection_token_valid(&current_snapshot)
                || snapshot
                    .as_ref()
                    .is_some_and(|prior| prior != &current_snapshot)
                || rows.len().saturating_add(page.len()) as u64 > self.contract.maximum_rows.get()
            {
                return Err(ProjectionError::InvalidResult);
            }
            for row in &page {
                if row.parent_key != parent_key
                    || !projection_token_valid(&row.key)
                    || !seen_rows.insert(row.key.clone())
                {
                    return Err(ProjectionError::InvalidResult);
                }
                self.check_fields(&row.fields, row.source_revision.as_deref(), fields)?;
            }
            rows.extend(page);
            if complete && next_cursor.is_none() {
                return Ok(ProjectionResult::ByParent {
                    parent_key,
                    snapshot: current_snapshot,
                    rows,
                });
            }
            if complete {
                return Err(ProjectionError::InvalidResult);
            }
            let next = next_cursor.ok_or(ProjectionError::Unavailable)?;
            if !projection_token_valid(&next) || !seen_cursors.insert(next.clone()) {
                return Err(ProjectionError::InvalidResult);
            }
            cursor = Some(next);
            snapshot = Some(current_snapshot);
        }
        Err(ProjectionError::Unavailable)
    }
}

fn check_revision(revision: Option<&str>) -> Result<(), ProjectionError> {
    if revision.is_some_and(|value| !projection_token_valid(value)) {
        return Err(ProjectionError::InvalidResult);
    }
    Ok(())
}
