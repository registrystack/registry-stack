// SPDX-License-Identifier: Apache-2.0
//! Authenticated HTTP data workflows for Base Registry Engine.
//!
//! This module owns only ctl-side package inspection, file checkpoints, and
//! HTTP dispatch. Data shape, chunking, idempotency, and response validation
//! remain in `registry_breg::data`.

use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use registry_breg::data::{
    execute_export_page, execute_import_chunk, DataError, DataExportCheckpoint,
    DataExportOutputState, DataExportPlan, DataExportResumeState, DataHttpMethod, DataHttpRequest,
    DataHttpResponse, DataImportCheckpoint, DataImportOperation, DataImportPlan,
    MAX_DATA_HTTP_RESPONSE_BYTES, MAX_DATA_IMPORT_INPUT_BYTES,
};
use registry_breg::package::{inspect_package_integrity, PackageEnvelope, PackageError};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_httputil::client::{
    build_client, OutboundOptions, ServiceBaseUrl, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
};
use registry_platform_httputil::{read_bounded, validate_response_headers};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, Method, Url};
use serde::{Deserialize, Serialize};

use crate::safe_path::{SafeDir, SafeEntry, SafePathError};

const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 1024 * 1024;
const DATA_HTTP_USER_AGENT: &str = "bregctl-data";
const DATA_STATE_API_VERSION: &str = "registry.registrystack.org/bregctl-data/v1";
const IMPORT_STATE_KIND: &str = "BRegctlDataImportState";
const MAX_ATOMIC_WRITE_TEMP_ATTEMPTS: usize = 16;
/// The longest output tail a resuming export discards. The export appends one
/// bounded page and then publishes the checkpoint that records it, so a run
/// stopped between the two leaves at most one page the checkpoint never
/// recorded, and a page never exceeds the bounded HTTP response it is built
/// from. Anything longer did not come from that window.
const MAX_UNCOMMITTED_EXPORT_TAIL_BYTES: u64 = MAX_DATA_HTTP_RESPONSE_BYTES as u64;

static DATA_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) enum DataLifecycleError {
    PackagePath,
    Package(PackageError),
    PackageManifest,
    Input,
    Output,
    Checkpoint,
    BRegUrl,
    Token,
    Runtime,
    Transport,
    Data(DataError),
    /// The export output file and its checkpoint file were not both present.
    ExportPair(ExportPairState),
}

/// Which half of an export's output and checkpoint pair is missing.
///
/// An export reserves the empty output first and publishes its first
/// checkpoint second, so a run stopped between the two leaves a zero-byte
/// output with no checkpoint. Neither half carries the other's state, so the
/// rerun refuses and names the file the operator has to deal with.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExportPairState {
    /// The output exists and its checkpoint does not.
    CheckpointMissing,
    /// The checkpoint exists and its output does not.
    OutputMissing,
}

pub(crate) struct DataValidateRequest<'a> {
    pub package: &'a Path,
    pub entity: &'a str,
    pub operation: DataImportOperation,
    pub profile: &'a str,
    pub input: &'a Path,
}

pub(crate) struct DataImportRequest<'a> {
    pub package: &'a Path,
    pub breg_url: &'a str,
    pub access_token_file: &'a Path,
    pub entity: &'a str,
    pub operation: DataImportOperation,
    pub profile: &'a str,
    pub input: &'a Path,
    pub checkpoint: &'a Path,
    pub max_chunks: Option<u64>,
}

pub(crate) struct DataExportRequest<'a> {
    pub package: &'a Path,
    pub breg_url: &'a str,
    pub access_token_file: &'a Path,
    pub entity: &'a str,
    pub profile: &'a str,
    pub fields: &'a [String],
    pub output: &'a Path,
    pub checkpoint: &'a Path,
    pub max_pages: Option<u64>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DataValidateOutcome {
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub entity_id: String,
    pub profile_id: String,
    pub operation: DataImportOperation,
    pub input_length: u64,
    pub item_count: u64,
    pub chunk_count: usize,
    pub maximum_items: u16,
    pub maximum_bytes: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DataImportOutcome {
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub entity_id: String,
    pub profile_id: String,
    pub operation: DataImportOperation,
    pub input_length: u64,
    pub item_count: u64,
    pub completed_chunk_count: u64,
    pub committed_items: u64,
    pub complete: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DataExportOutcome {
    pub package_revision: String,
    pub schema_fingerprint: String,
    pub entity_id: String,
    pub profile_id: String,
    pub requested_fields: Vec<String>,
    pub completed_page_count: u64,
    pub record_count: u64,
    pub output_length: u64,
    pub complete: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ImportState {
    api_version: String,
    kind: String,
    package_revision: String,
    schema_fingerprint: String,
    entity_id: String,
    operation: DataImportOperation,
    profile_id: String,
    input_digest: String,
    import_id: String,
}

pub(crate) fn validate_import(
    request: DataValidateRequest<'_>,
) -> Result<DataValidateOutcome, DataLifecycleError> {
    let inspected = inspect_data_package(request.package)?;
    let input = read_bounded_regular(request.input, MAX_DATA_IMPORT_INPUT_BYTES as u64)
        .map_err(|_| DataLifecycleError::Input)?;
    let plan = DataImportPlan::from_jsonl(
        inspected.registry(),
        request.entity,
        request.operation,
        request.profile,
        &input,
    )
    .map_err(DataLifecycleError::Data)?;
    Ok(DataValidateOutcome {
        package_revision: inspected.package_revision,
        schema_fingerprint: inspected.schema_fingerprint,
        entity_id: plan.entity_id().to_owned(),
        profile_id: plan.profile_id().to_owned(),
        operation: plan.operation(),
        input_length: plan.input_length(),
        item_count: plan.item_count(),
        chunk_count: plan.chunks().len(),
        maximum_items: plan.maximum_items(),
        maximum_bytes: plan.maximum_bytes(),
    })
}

pub(crate) fn run_import(
    request: DataImportRequest<'_>,
) -> Result<DataImportOutcome, DataLifecycleError> {
    let inspected = inspect_data_package(request.package)?;
    let input = read_bounded_regular(request.input, MAX_DATA_IMPORT_INPUT_BYTES as u64)
        .map_err(|_| DataLifecycleError::Input)?;
    let plan = DataImportPlan::from_jsonl(
        inspected.registry(),
        request.entity,
        request.operation,
        request.profile,
        &input,
    )
    .map_err(DataLifecycleError::Data)?;
    if request.max_chunks == Some(0) {
        return Err(DataLifecycleError::Data(DataError::InvalidBinding));
    }
    let breg_url = parse_breg_url(request.breg_url)?;
    let token = read_access_token(request.access_token_file)?;
    let destinations = ImportDestinations::resolve(request.checkpoint)?;
    let (mut checkpoint, import_id) = load_or_start_import(&plan, &inspected, &destinations)?;
    let client = build_data_http_client()?;
    let (_committed_chunks, _committed_items) = run_import_chunks(
        &plan,
        &mut checkpoint,
        ImportExecutionBinding {
            package_revision: &inspected.package_revision,
            schema_fingerprint: &inspected.schema_fingerprint,
            import_id: &import_id,
        },
        request.max_chunks,
        |checkpoint| publish_import_checkpoint(&destinations.checkpoint, checkpoint),
        |data_request| dispatch_http(&client, &breg_url, &token, data_request),
    )?;
    Ok(DataImportOutcome {
        package_revision: inspected.package_revision,
        schema_fingerprint: inspected.schema_fingerprint,
        entity_id: plan.entity_id().to_owned(),
        profile_id: plan.profile_id().to_owned(),
        operation: plan.operation(),
        input_length: plan.input_length(),
        item_count: plan.item_count(),
        completed_chunk_count: checkpoint.completed_chunk_count(),
        committed_items: checkpoint.next_item_index(),
        complete: checkpoint.is_complete(),
    })
}

struct ImportExecutionBinding<'a> {
    package_revision: &'a str,
    schema_fingerprint: &'a str,
    import_id: &'a str,
}

fn run_import_chunks<Dispatch, DispatchFuture, DispatchError, AfterChunk>(
    plan: &DataImportPlan,
    checkpoint: &mut DataImportCheckpoint,
    binding: ImportExecutionBinding<'_>,
    max_chunks: Option<u64>,
    mut after_chunk: AfterChunk,
    mut dispatch: Dispatch,
) -> Result<(u64, u64), DataLifecycleError>
where
    Dispatch: FnMut(DataHttpRequest) -> DispatchFuture,
    DispatchFuture: Future<Output = Result<DataHttpResponse, DispatchError>>,
    AfterChunk: FnMut(&DataImportCheckpoint) -> Result<(), DataLifecycleError>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| DataLifecycleError::Runtime)?;
    let mut committed_items = 0u64;
    let mut committed_chunks = 0u64;
    let max_chunks = max_chunks.unwrap_or(u64::MAX);
    while !checkpoint.is_complete() && committed_chunks < max_chunks {
        let progress = runtime
            .block_on(execute_import_chunk(
                plan,
                checkpoint,
                binding.package_revision,
                binding.schema_fingerprint,
                binding.import_id,
                &mut dispatch,
            ))
            .map_err(map_data_or_transport)?;
        let Some(progress) = progress else {
            break;
        };
        committed_items = committed_items
            .checked_add(progress.committed_items())
            .ok_or(DataLifecycleError::Checkpoint)?;
        committed_chunks = committed_chunks
            .checked_add(1)
            .ok_or(DataLifecycleError::Checkpoint)?;
        after_chunk(checkpoint)?;
    }
    Ok((committed_chunks, committed_items))
}

pub(crate) fn run_export(
    request: DataExportRequest<'_>,
) -> Result<DataExportOutcome, DataLifecycleError> {
    let inspected = inspect_data_package(request.package)?;
    if request.max_pages == Some(0) {
        return Err(DataLifecycleError::Data(DataError::InvalidBinding));
    }
    let plan = DataExportPlan::from_compiled(
        inspected.registry(),
        request.entity,
        request.profile,
        request.fields.iter().cloned(),
    )
    .map_err(DataLifecycleError::Data)?;
    let breg_url = parse_breg_url(request.breg_url)?;
    let token = read_access_token(request.access_token_file)?;
    let mut started = load_or_start_export(&plan, &inspected, request.output, request.checkpoint)?;
    let client = build_data_http_client()?;
    run_export_pages(
        &plan,
        &inspected,
        &mut started,
        request.max_pages,
        |data_request| dispatch_http(&client, &breg_url, &token, data_request),
    )?;
    Ok(DataExportOutcome {
        package_revision: inspected.package_revision,
        schema_fingerprint: inspected.schema_fingerprint,
        entity_id: plan.entity_id().to_owned(),
        profile_id: plan.profile_id().to_owned(),
        requested_fields: plan.requested_fields().to_vec(),
        completed_page_count: started.checkpoint.completed_page_count(),
        record_count: started.checkpoint.record_count(),
        output_length: started.checkpoint.output_length(),
        complete: started.checkpoint.is_complete(),
    })
}

/// Advance an export until it completes, exhausts its page budget, or the
/// server reports nothing further.
///
/// Every page append and every checkpoint publication acts through the
/// destinations the run resolved, so an ancestor replaced while the run is in
/// flight cannot redirect either write or land the two in different trees.
fn run_export_pages<Dispatch, DispatchFuture, DispatchError>(
    plan: &DataExportPlan,
    inspected: &InspectedDataPackage,
    started: &mut StartedExport,
    max_pages: Option<u64>,
    mut dispatch: Dispatch,
) -> Result<(), DataLifecycleError>
where
    Dispatch: FnMut(DataHttpRequest) -> DispatchFuture,
    DispatchFuture: Future<Output = Result<DataHttpResponse, DispatchError>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| DataLifecycleError::Runtime)?;
    let mut pages = 0u64;
    let max_pages = max_pages.unwrap_or(u64::MAX);
    while !started.checkpoint.is_complete() && pages < max_pages {
        let progress = runtime
            .block_on(execute_export_page(
                plan,
                &mut started.checkpoint,
                &inspected.package_revision,
                &inspected.schema_fingerprint,
                &started.output_state,
                &started.resume_state,
                &mut dispatch,
            ))
            .map_err(map_data_or_transport)?;
        let Some(progress) = progress else {
            break;
        };
        let (page_bytes, next_output_state, next_resume_state) = progress.into_parts();
        pages = pages.checked_add(1).ok_or(DataLifecycleError::Checkpoint)?;
        append_export_page(&started.destinations.output, &page_bytes)?;
        write_atomic_entry(
            &started.destinations.checkpoint,
            &started
                .checkpoint
                .canonical_json()
                .map_err(DataLifecycleError::Data)?,
        )?;
        started.output_state = next_output_state;
        started.resume_state = next_resume_state;
    }
    Ok(())
}

async fn dispatch_http(
    client: &Client,
    base: &ServiceBaseUrl,
    token: &str,
    request: DataHttpRequest,
) -> Result<DataHttpResponse, ()> {
    let url = data_endpoint(base, request.path_and_query())?;
    let method = match request.method() {
        DataHttpMethod::Get => Method::GET,
        DataHttpMethod::Post => Method::POST,
    };
    let mut builder = client
        .request(method, url)
        .header(AUTHORIZATION, format!("Bearer {token}"));
    if let Some(content_type) = request.content_type() {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    if let Some(idempotency_key) = request.idempotency_key() {
        builder = builder.header("idempotency-key", idempotency_key);
    }
    let response = builder
        .body(request.body().to_vec())
        .send()
        .await
        .map_err(|_| ())?;
    let status = response.status().as_u16();
    validate_response_headers(response.headers()).map_err(|_| ())?;
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = read_data_http_body(response).await.map_err(|_| ())?;
    DataHttpResponse::new(status, content_type, body).map_err(|_| ())
}

fn build_data_http_client() -> Result<Client, DataLifecycleError> {
    build_data_http_client_with_timeouts(DEFAULT_REQUEST_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)
}

fn build_data_http_client_with_timeouts(
    request_timeout: Duration,
    connect_timeout: Duration,
) -> Result<Client, DataLifecycleError> {
    build_client(OutboundOptions {
        request_timeout,
        connect_timeout,
        user_agent: Some(DATA_HTTP_USER_AGENT),
        trusted_root_certificates: None,
    })
    .map_err(|_| DataLifecycleError::Transport)
}

async fn read_data_http_body(
    response: reqwest::Response,
) -> Result<Vec<u8>, registry_platform_httputil::BoundedReadError> {
    read_bounded(response, MAX_DATA_HTTP_RESPONSE_BYTES as u64).await
}

fn map_data_or_transport(error: DataError) -> DataLifecycleError {
    match error {
        DataError::TransportUnavailable => DataLifecycleError::Transport,
        other => DataLifecycleError::Data(other),
    }
}

struct InspectedDataPackage {
    package_revision: String,
    schema_fingerprint: String,
    registry: registry_breg::CompiledRegistry,
}

impl InspectedDataPackage {
    fn registry(&self) -> &registry_breg::CompiledRegistry {
        &self.registry
    }
}

fn inspect_data_package(package: &Path) -> Result<InspectedDataPackage, DataLifecycleError> {
    if !package.is_absolute() {
        return Err(DataLifecycleError::PackagePath);
    }
    let inspected = inspect_package_integrity(package).map_err(DataLifecycleError::Package)?;
    let manifest_bytes = read_bounded_regular(&package.join("package.json"), MAX_CHECKPOINT_BYTES)
        .map_err(|_| DataLifecycleError::PackageManifest)?;
    let envelope: PackageEnvelope = serde_json::from_value(
        parse_json_strict(&manifest_bytes).map_err(|_| DataLifecycleError::PackageManifest)?,
    )
    .map_err(|_| DataLifecycleError::PackageManifest)?;
    if envelope.signed.package_revision != inspected.package_revision() {
        return Err(DataLifecycleError::PackageManifest);
    }
    Ok(InspectedDataPackage {
        package_revision: envelope.signed.package_revision,
        schema_fingerprint: envelope.signed.schema_fingerprint,
        registry: inspected.registry().clone(),
    })
}

/// The two files one import run reads and writes, each resolved to a held
/// parent directory descriptor when the run validates them.
///
/// Every existence check, every read, and every checkpoint publication of the
/// run acts through these, so an ancestor replaced while the run is in flight
/// can neither redirect a write nor leave the checkpoint and the state file
/// that binds it in different trees.
struct ImportDestinations {
    checkpoint: SafeEntry,
    state: SafeEntry,
}

impl ImportDestinations {
    fn resolve(checkpoint: &Path) -> Result<Self, DataLifecycleError> {
        let state = import_state_path(checkpoint);
        Ok(ImportDestinations {
            checkpoint: resolve_write_destination(checkpoint)
                .map_err(|_| DataLifecycleError::Checkpoint)?,
            state: resolve_write_destination(&state).map_err(|_| DataLifecycleError::Checkpoint)?,
        })
    }
}

/// Replace the checkpoint an import run advances, through the destination the
/// run resolved at its start.
fn publish_import_checkpoint(
    destination: &SafeEntry,
    checkpoint: &DataImportCheckpoint,
) -> Result<(), DataLifecycleError> {
    write_atomic_entry(
        destination,
        &checkpoint
            .canonical_json()
            .map_err(DataLifecycleError::Data)?,
    )
}

fn load_or_start_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    destinations: &ImportDestinations,
) -> Result<(DataImportCheckpoint, String), DataLifecycleError> {
    let checkpoint_exists = destinations
        .checkpoint
        .exists()
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    let state_exists = destinations
        .state
        .exists()
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    match (checkpoint_exists, state_exists) {
        (false, false) => start_new_import(plan, inspected, destinations),
        (false, true) => recover_state_only_import(plan, inspected, destinations),
        (true, true) => load_existing_import(plan, inspected, destinations),
        (true, false) => Err(DataLifecycleError::Checkpoint),
    }
}

/// The two files one export run writes, each resolved to a held parent
/// directory descriptor when the run validates them.
///
/// Every page append and every checkpoint publication of the run acts through
/// these, so an ancestor replaced while the run is in flight can neither
/// redirect a write nor leave the output and the checkpoint in different trees.
struct ExportDestinations {
    output: SafeEntry,
    checkpoint: SafeEntry,
}

impl ExportDestinations {
    fn resolve(output: &Path, checkpoint: &Path) -> Result<Self, DataLifecycleError> {
        Ok(ExportDestinations {
            output: resolve_write_destination(output)?,
            checkpoint: resolve_write_destination(checkpoint)?,
        })
    }
}

/// One export run once its files are validated: the destinations every write of
/// the run acts through, the checkpoint it advances, and the position the next
/// page continues from.
struct StartedExport {
    destinations: ExportDestinations,
    checkpoint: DataExportCheckpoint,
    output_state: DataExportOutputState,
    resume_state: DataExportResumeState,
}

fn load_or_start_export(
    plan: &DataExportPlan,
    inspected: &InspectedDataPackage,
    output_path: &Path,
    checkpoint_path: &Path,
) -> Result<StartedExport, DataLifecycleError> {
    let destinations = ExportDestinations::resolve(output_path, checkpoint_path)?;
    let output_exists = destinations
        .output
        .exists()
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    let checkpoint_exists = destinations
        .checkpoint
        .exists()
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    match (output_exists, checkpoint_exists) {
        (false, false) => {
            let (checkpoint, resume_state) = DataExportCheckpoint::start(
                plan,
                &inspected.package_revision,
                &inspected.schema_fingerprint,
            )
            .map_err(DataLifecycleError::Data)?;
            let checkpoint_bytes = checkpoint
                .canonical_json()
                .map_err(DataLifecycleError::Data)?;
            reserve_export_paths(&destinations, &checkpoint_bytes)?;
            Ok(StartedExport {
                destinations,
                checkpoint,
                output_state: DataExportOutputState::empty(),
                resume_state,
            })
        }
        (true, true) => resume_existing_export(plan, inspected, destinations),
        (true, false) => Err(DataLifecycleError::ExportPair(
            ExportPairState::CheckpointMissing,
        )),
        (false, true) => Err(DataLifecycleError::ExportPair(
            ExportPairState::OutputMissing,
        )),
    }
}

fn start_new_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    destinations: &ImportDestinations,
) -> Result<(DataImportCheckpoint, String), DataLifecycleError> {
    let checkpoint = DataImportCheckpoint::start(
        plan,
        &inspected.package_revision,
        &inspected.schema_fingerprint,
    )
    .map_err(DataLifecycleError::Data)?;
    let state = import_state_for_checkpoint(plan, inspected, &checkpoint);
    let state_bytes = canonical_import_state(&state)?;
    let checkpoint_bytes = checkpoint
        .canonical_json()
        .map_err(DataLifecycleError::Data)?;
    write_atomic_create_new_entry(&destinations.state, &state_bytes)
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    if write_atomic_create_new_entry(&destinations.checkpoint, &checkpoint_bytes).is_err() {
        return load_existing_import(plan, inspected, destinations)
            .map_err(|_| DataLifecycleError::Checkpoint);
    }
    Ok((checkpoint, state.import_id))
}

fn recover_state_only_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    destinations: &ImportDestinations,
) -> Result<(DataImportCheckpoint, String), DataLifecycleError> {
    let state = read_import_state(&destinations.state, plan, inspected)?;
    let checkpoint = start_checkpoint_from_state(plan, inspected, &state)?;
    let checkpoint_bytes = checkpoint
        .canonical_json()
        .map_err(DataLifecycleError::Data)?;
    match write_atomic_create_new_entry(&destinations.checkpoint, &checkpoint_bytes) {
        Ok(_) => Ok((checkpoint, state.import_id)),
        Err(_) => load_existing_import(plan, inspected, destinations)
            .map_err(|_| DataLifecycleError::Checkpoint),
    }
}

fn load_existing_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    destinations: &ImportDestinations,
) -> Result<(DataImportCheckpoint, String), DataLifecycleError> {
    let state = read_import_state(&destinations.state, plan, inspected)?;
    let checkpoint_bytes = read_bounded_entry(&destinations.checkpoint, MAX_CHECKPOINT_BYTES)
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    let checkpoint = DataImportCheckpoint::from_json(
        &checkpoint_bytes,
        plan,
        &inspected.package_revision,
        &inspected.schema_fingerprint,
        &state.import_id,
    )
    .map_err(DataLifecycleError::Data)?;
    Ok((checkpoint, state.import_id))
}

fn import_state_for_checkpoint(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    checkpoint: &DataImportCheckpoint,
) -> ImportState {
    ImportState {
        api_version: DATA_STATE_API_VERSION.to_owned(),
        kind: IMPORT_STATE_KIND.to_owned(),
        package_revision: inspected.package_revision.clone(),
        schema_fingerprint: inspected.schema_fingerprint.clone(),
        entity_id: plan.entity_id().to_owned(),
        operation: plan.operation(),
        profile_id: plan.profile_id().to_owned(),
        input_digest: plan.input_digest().to_owned(),
        import_id: checkpoint.import_id().to_owned(),
    }
}

fn canonical_import_state(state: &ImportState) -> Result<Vec<u8>, DataLifecycleError> {
    canonicalize_json(&serde_json::to_value(state).map_err(|_| DataLifecycleError::Checkpoint)?)
        .map_err(|_| DataLifecycleError::Checkpoint)
}

fn start_checkpoint_from_state(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    state: &ImportState,
) -> Result<DataImportCheckpoint, DataLifecycleError> {
    let checkpoint = DataImportCheckpoint::start(
        plan,
        &inspected.package_revision,
        &inspected.schema_fingerprint,
    )
    .map_err(DataLifecycleError::Data)?;
    let mut value =
        serde_json::to_value(&checkpoint).map_err(|_| DataLifecycleError::Checkpoint)?;
    value["importId"] = serde_json::Value::String(state.import_id.clone());
    let bytes = canonicalize_json(&value).map_err(|_| DataLifecycleError::Checkpoint)?;
    DataImportCheckpoint::from_json(
        &bytes,
        plan,
        &inspected.package_revision,
        &inspected.schema_fingerprint,
        &state.import_id,
    )
    .map_err(DataLifecycleError::Data)
}

fn read_import_state(
    entry: &SafeEntry,
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
) -> Result<ImportState, DataLifecycleError> {
    let bytes = read_bounded_entry(entry, MAX_CHECKPOINT_BYTES)
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    let state: ImportState = serde_json::from_value(
        parse_json_strict(&bytes).map_err(|_| DataLifecycleError::Checkpoint)?,
    )
    .map_err(|_| DataLifecycleError::Checkpoint)?;
    if state.api_version != DATA_STATE_API_VERSION
        || state.kind != IMPORT_STATE_KIND
        || state.package_revision != inspected.package_revision
        || state.schema_fingerprint != inspected.schema_fingerprint
        || state.entity_id != plan.entity_id()
        || state.operation != plan.operation()
        || state.profile_id != plan.profile_id()
        || state.input_digest != plan.input_digest()
    {
        return Err(DataLifecycleError::Checkpoint);
    }
    Ok(state)
}

fn import_state_path(checkpoint_path: &Path) -> PathBuf {
    let mut state = checkpoint_path.as_os_str().to_owned();
    state.push(".state");
    PathBuf::from(state)
}

fn read_access_token(path: &Path) -> Result<String, DataLifecycleError> {
    if !path.is_absolute() {
        return Err(DataLifecycleError::Token);
    }
    let bytes =
        read_bounded_regular(path, MAX_TOKEN_BYTES).map_err(|_| DataLifecycleError::Token)?;
    let token = std::str::from_utf8(&bytes).map_err(|_| DataLifecycleError::Token)?;
    let token = token.trim_end_matches(['\r', '\n']);
    if token.is_empty()
        || token.len() > MAX_TOKEN_BYTES as usize
        || token.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
    {
        return Err(DataLifecycleError::Token);
    }
    Ok(token.to_owned())
}

fn parse_breg_url(value: &str) -> Result<ServiceBaseUrl, DataLifecycleError> {
    let url = Url::parse(value).map_err(|_| DataLifecycleError::BRegUrl)?;
    ServiceBaseUrl::new(url).map_err(|_| DataLifecycleError::BRegUrl)
}

fn data_endpoint(base: &ServiceBaseUrl, path_and_query: &str) -> Result<Url, ()> {
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
    let path = path.strip_prefix('/').ok_or(())?;
    let mut url = base.join(path).map_err(|_| ())?;
    url.set_query(query);
    Ok(url)
}

fn read_bounded_regular(path: &Path, max_bytes: u64) -> Result<Vec<u8>, io::Error> {
    read_bounded_entry(
        &SafeEntry::resolve(path).map_err(SafePathError::into_io)?,
        max_bytes,
    )
}

/// Read a bounded regular file through a held entry, so the bytes come from the
/// file that entry resolved.
fn read_bounded_entry(entry: &SafeEntry, max_bytes: u64) -> Result<Vec<u8>, io::Error> {
    let file = entry.open_read()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(io::Error::other("invalid file"));
    }
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| io::Error::other("invalid file limit"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| io::Error::other("invalid file"))?,
    );
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(io::Error::other("invalid file"));
    }
    Ok(bytes)
}

fn reserve_export_paths(
    destinations: &ExportDestinations,
    checkpoint_bytes: &[u8],
) -> Result<(), DataLifecycleError> {
    write_atomic_create_new_entry(&destinations.output, &[])?;
    write_atomic_create_new_entry(&destinations.checkpoint, checkpoint_bytes)
}

/// Restore an export from its output file and the checkpoint that records the
/// committed prefix of that file.
///
/// The export appends one page and then publishes the checkpoint recording it,
/// so a killed process or a refused checkpoint publication leaves an output
/// file one page longer than the checkpoint accounts for. Recovery streams
/// exactly the checkpointed prefix, requires the checkpoint to describe those
/// bytes, and only then discards the tail past them through the descriptor the
/// prefix was read from. An output shorter than the checkpoint, a prefix the
/// checkpoint does not describe, a checkpoint bound to another export, a tail
/// longer than one page, and any tail following a checkpoint that already
/// reports the export complete are refused, and refusal leaves both files as
/// they are.
fn resume_existing_export(
    plan: &DataExportPlan,
    inspected: &InspectedDataPackage,
    destinations: ExportDestinations,
) -> Result<StartedExport, DataLifecycleError> {
    let checkpoint_bytes = read_bounded_entry(&destinations.checkpoint, MAX_CHECKPOINT_BYTES)
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    let committed_length = checkpointed_output_length(&checkpoint_bytes)?;
    // One descriptor serves the prefix read and the tail discard, so the file
    // whose prefix matched the checkpoint is the file that gets shortened.
    let file = destinations
        .output
        .open_read_write()
        .map_err(|_| DataLifecycleError::Output)?;
    let metadata = file.metadata().map_err(|_| DataLifecycleError::Output)?;
    if !metadata.is_file() {
        return Err(DataLifecycleError::Output);
    }
    let tail_length = metadata
        .len()
        .checked_sub(committed_length)
        .ok_or(DataLifecycleError::Data(DataError::CheckpointMismatch))?;
    if tail_length > MAX_UNCOMMITTED_EXPORT_TAIL_BYTES {
        return Err(DataLifecycleError::Data(DataError::CheckpointMismatch));
    }
    let output_state = read_export_output_prefix(&file, committed_length)?;
    let (checkpoint, resume_state) = DataExportCheckpoint::resume_from_json(
        &checkpoint_bytes,
        plan,
        &inspected.package_revision,
        &inspected.schema_fingerprint,
        &output_state,
    )
    .map_err(DataLifecycleError::Data)?;
    if tail_length > 0 {
        // A checkpoint reporting the export complete is published after the
        // last page, so no interrupted append can follow it.
        if checkpoint.is_complete() {
            return Err(DataLifecycleError::Data(DataError::CheckpointMismatch));
        }
        file.set_len(committed_length)
            .and_then(|()| file.sync_all())
            .map_err(|_| DataLifecycleError::Output)?;
    }
    Ok(StartedExport {
        destinations,
        checkpoint,
        output_state,
        resume_state,
    })
}

/// The output length the checkpoint records, read before the checkpoint is
/// validated so recovery knows how much of the output file it covers. The value
/// only bounds the prefix that is streamed; the checkpoint is still matched
/// against the bytes that prefix hashes to.
fn checkpointed_output_length(checkpoint_bytes: &[u8]) -> Result<u64, DataLifecycleError> {
    parse_json_strict(checkpoint_bytes)
        .map_err(|_| DataLifecycleError::Checkpoint)?
        .get("outputLength")
        .and_then(serde_json::Value::as_u64)
        .ok_or(DataLifecycleError::Checkpoint)
}

/// Stream exactly the checkpointed prefix of an open output file into the
/// incremental state the checkpoint is matched against. A prefix that ends
/// inside a record is refused, since it is not canonical JSON Lines.
fn read_export_output_prefix(
    file: &File,
    length: u64,
) -> Result<DataExportOutputState, DataLifecycleError> {
    DataExportOutputState::from_reader(file.take(length)).map_err(DataLifecycleError::Data)
}

fn append_export_page(destination: &SafeEntry, page: &[u8]) -> Result<(), DataLifecycleError> {
    check_write_destination(destination, true)?;
    let mut file = destination
        .open_append()
        .map_err(|_| DataLifecycleError::Output)?;
    if !file
        .metadata()
        .map_err(|_| DataLifecycleError::Output)?
        .is_file()
    {
        return Err(DataLifecycleError::Output);
    }
    file.write_all(page)
        .and_then(|()| file.sync_all())
        .map_err(|_| DataLifecycleError::Output)
}

/// Replace a destination's bytes through its held parent descriptor: stage a
/// sibling temporary, then rename it over the destination.
fn write_atomic_entry(destination: &SafeEntry, bytes: &[u8]) -> Result<(), DataLifecycleError> {
    check_write_destination(destination, true)?;
    let temporary = write_atomic_temporary(destination.parent(), bytes)?;
    destination.replace_from(&temporary).map_err(|_| {
        let _ = destination.parent().remove_file(&temporary);
        DataLifecycleError::Output
    })
}

/// Create a destination through its held parent descriptor, refusing to replace
/// an entry that already exists.
fn write_atomic_create_new_entry(
    destination: &SafeEntry,
    bytes: &[u8],
) -> Result<(), DataLifecycleError> {
    check_write_destination(destination, false)?;
    let temporary = write_atomic_temporary(destination.parent(), bytes)?;
    // A hard link never replaces an existing destination, so a losing writer
    // keeps the winner's bytes.
    destination
        .publish_new_from(&temporary)
        .map_err(|_| DataLifecycleError::Output)
}

/// Resolve an output path to its held parent directory descriptor. Every later
/// staging, append, link, rename, and cleanup runs through the returned
/// descriptor, so replacing an ancestor afterwards cannot redirect the write.
fn resolve_write_destination(path: &Path) -> Result<SafeEntry, DataLifecycleError> {
    if path.as_os_str().is_empty() || super::has_parent_component(path) {
        return Err(DataLifecycleError::Output);
    }
    SafeEntry::resolve(path).map_err(|_| DataLifecycleError::Output)
}

/// Refuse a destination that is neither absent nor an existing regular file.
/// The entry is read through the held parent descriptor, so the check covers
/// the entry the write acts on rather than whatever the pathname reaches.
fn check_write_destination(
    destination: &SafeEntry,
    allow_existing_regular_file: bool,
) -> Result<(), DataLifecycleError> {
    match destination.stat() {
        Ok(stat) if stat.is_symlink() || !stat.is_file() => Err(DataLifecycleError::Output),
        Ok(_) if !allow_existing_regular_file => Err(DataLifecycleError::Output),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(DataLifecycleError::Output),
    }
}

fn write_atomic_temporary(parent: &SafeDir, bytes: &[u8]) -> Result<OsString, DataLifecycleError> {
    for _ in 0..MAX_ATOMIC_WRITE_TEMP_ATTEMPTS {
        let temporary =
            atomic_write_temporary_name(DATA_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed));
        let mut file = match parent.create_new(&temporary, 0o600) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(DataLifecycleError::Output),
        };
        if file
            .write_all(bytes)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = parent.remove_file(&temporary);
            return Err(DataLifecycleError::Output);
        }
        drop(file);
        return Ok(temporary);
    }
    Err(DataLifecycleError::Output)
}

fn atomic_write_temporary_name(sequence: u64) -> OsString {
    OsString::from(format!(
        ".bregctl-data-{}-{sequence}.tmp",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        Arc, Mutex,
    };
    use std::thread;
    use std::time::{Duration as StdDuration, Instant};

    use registry_breg::compiler::{compile_project, CompileProfile};
    use registry_breg::contract::parse_project_json;
    use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
    use serde_json::{json, Value};

    use super::*;

    const ENTITY: &str = "record";
    const PROFILE: &str = "operator";
    const PACKAGE: &str = "package-revision";
    const SCHEMA: &str = "schema-fingerprint";

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(StdDuration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut header_end = None;
        let mut buffer = [0_u8; 1024];
        while header_end.is_none() {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                return request;
            }
            request.extend_from_slice(&buffer[..read]);
            header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4);
        }
        let header_end = header_end.unwrap();
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while request.len() < header_end.saturating_add(content_length) {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        request
    }

    fn spawn_one_response_server(response: Vec<u8>) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
            request
        });
        (address, handle)
    }

    fn test_directory(label: &str) -> PathBuf {
        let directory = std::env::current_dir().unwrap().join(format!(
            ".bregctl-data-test-{}-{}-{}",
            std::process::id(),
            label,
            DATA_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        directory
    }

    fn compiled() -> registry_breg::CompiledRegistry {
        let source = json!({
            "apiVersion": "registry.registrystack.org/v1alpha1",
            "kind": "RegistryProject",
            "registry": {"id": "ctl-data", "version": "1", "defaultLanguage": "en",
                         "canonicalBaseIri": "https://ctl-data.example.test"},
            "entities": [{
                "id": ENTITY,
                "primaryDataset": "test-dataset",
                "route": "records",
                "mutationMode": "create_only",
                "batch": {"maximumItems": 2, "maximumBytes": 400},
                "fields": [
                    {"id": "code", "type": "string", "minLength": 2, "maxLength": 16,
                     "required": true, "classification": "internal"}
                ]
            }],
            "accessProfiles": [{
                "id": PROFILE,
                "principalClaim": "principal",
                "grants": [{
                    "entity": ENTITY,
                    "operations": ["create", "batch", "list"],
                    "readableFields": ["code"],
                    "writableFields": ["code"],
                    "allowDataExport": true,
                  "rowBoundaries": []
                }]
            }]
        });
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        compile_project(&project, &[], CompileProfile::Authoring).unwrap()
    }

    fn import_plan_and_inspected() -> (DataImportPlan, InspectedDataPackage) {
        let registry = compiled();
        let input = br#"{"operation":"create","data":{"code":"AA"}}
"#;
        let plan = DataImportPlan::from_jsonl(
            &registry,
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            input,
        )
        .unwrap();
        let inspected = InspectedDataPackage {
            package_revision: PACKAGE.to_owned(),
            schema_fingerprint: SCHEMA.to_owned(),
            registry,
        };
        (plan, inspected)
    }

    fn export_plan_and_inspected() -> (DataExportPlan, InspectedDataPackage) {
        let registry = compiled();
        let plan = DataExportPlan::from_compiled(&registry, ENTITY, PROFILE, ["code"]).unwrap();
        let inspected = InspectedDataPackage {
            package_revision: PACKAGE.to_owned(),
            schema_fingerprint: SCHEMA.to_owned(),
            registry,
        };
        (plan, inspected)
    }

    fn export_response(code: &str, next_cursor: Option<&str>) -> DataHttpResponse {
        let body = canonicalize_json(&json!({
            "items": [{
                "recordIdentifier": "00000000-0000-4000-8000-000000000001",
                "revisionIdentifier": "1",
                "domainData": {"code": code}
            }],
            "pageInfo": {"nextCursor": next_cursor},
            "meta": {
                "registryIdentifier": "ctl-data",
                "datasetIdentifier": "test-dataset",
                "entityTypeIdentifier": ENTITY
            }
        }))
        .unwrap();
        DataHttpResponse::new(200, Some("application/json".to_owned()), body).unwrap()
    }

    #[test]
    fn authenticated_import_transport_uses_the_compiled_batch_request_shape() {
        let input = br#"{"operation":"create","data":{"code":"AA"}}
"#;
        let plan = DataImportPlan::from_jsonl(
            &compiled(),
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            input,
        )
        .unwrap();
        let mut checkpoint = DataImportCheckpoint::start(&plan, PACKAGE, SCHEMA).unwrap();
        let import_id = checkpoint.import_id().to_owned();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_request = Arc::clone(&captured);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let progress = runtime
            .block_on(execute_import_chunk(
                &plan,
                &mut checkpoint,
                PACKAGE,
                SCHEMA,
                &import_id,
                move |request| {
                    let captured_request = Arc::clone(&captured_request);
                    async move {
                        captured_request.lock().unwrap().push((
                            request.method(),
                            request.path_and_query().to_owned(),
                            request.content_type(),
                            request.idempotency_key().map(str::to_owned),
                            request.body().to_vec(),
                        ));
                        let body = canonicalize_json(&json!({
                            "snapshot": "breg1_00000000-0000-4000-8000-000000000001",
                            "results": [{
                                "operation": "create",
                                "id": "018f06d6-0248-4c7f-8a7e-df9dfbd83d2c",
                                "revision": 1,
                                "etag": "\"breg-revision\"",
                                "data": {"code": "AA"}
                            }]
                        }))
                        .unwrap();
                        DataHttpResponse::new(200, Some("application/json".to_owned()), body)
                    }
                },
            ))
            .unwrap()
            .expect("one chunk commits");

        assert!(progress.is_complete());
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (method, path, content_type, idempotency_key, body) = &captured[0];
        assert_eq!(*method, DataHttpMethod::Post);
        assert_eq!(path, "/v1/records/records:batch?accessProfile=operator");
        assert_eq!(*content_type, Some("application/json"));
        assert!(idempotency_key
            .as_deref()
            .is_some_and(|key| key.starts_with("breg-data-v1-")));
        let body = parse_json_strict(body).unwrap();
        assert_eq!(body["items"].as_array().unwrap().len(), 1);
        assert_eq!(body["items"][0]["data"]["code"], "AA");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_skips_temp_symlink_collision_and_refuses_final_symlink() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = test_directory("atomic-symlink");
        let canary = directory.join("canary.txt");
        let destination = directory.join("checkpoint.json");
        let final_symlink = directory.join("final-symlink.json");
        fs::write(&canary, b"unchanged").unwrap();

        let collided_sequence = DATA_WRITE_COUNTER.load(Ordering::Relaxed);
        let collided_temporary = directory.join(atomic_write_temporary_name(collided_sequence));
        std::os::unix::fs::symlink(&canary, &collided_temporary).unwrap();

        write_atomic_entry(
            &resolve_write_destination(&destination).unwrap(),
            b"checkpoint",
        )
        .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"checkpoint");
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&canary).unwrap(), b"unchanged");
        assert!(fs::symlink_metadata(&collided_temporary)
            .unwrap()
            .file_type()
            .is_symlink());

        std::os::unix::fs::symlink(&canary, &final_symlink).unwrap();
        assert!(matches!(
            write_atomic_entry(
                &resolve_write_destination(&final_symlink).unwrap(),
                b"must-not-follow"
            ),
            Err(DataLifecycleError::Output)
        ));
        assert_eq!(fs::read(&canary).unwrap(), b"unchanged");

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_regular_read_refuses_symlinks_and_growth_past_the_limit() {
        let directory = test_directory("bounded-read");
        let target = directory.join("token.txt");
        let symlink = directory.join("token-link.txt");
        fs::write(&target, b"token").unwrap();
        std::os::unix::fs::symlink(&target, &symlink).unwrap();

        assert!(read_bounded_regular(&symlink, MAX_TOKEN_BYTES).is_err());
        assert!(read_bounded_regular(&target, 4).is_err());
        assert_eq!(read_bounded_regular(&target, 5).unwrap(), b"token");

        fs::remove_dir_all(directory).unwrap();
    }

    /// Deterministic ancestor-swap regressions for the surfaces this module
    /// owns. They run wherever the descriptor-relative primitive exists.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod ancestor_swap {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        #[test]
        fn bounded_reads_after_an_ancestor_swap_read_only_the_named_file() {
            let tree = race_tree();
            let named = tree.named("input.ndjson");
            fs::write(&named, b"genuine").unwrap();
            fs::write(tree.outside("input.ndjson"), b"attacker").unwrap();

            let guard = tree.arm();
            let bytes = read_bounded_regular(&named, MAX_TOKEN_BYTES).unwrap();
            drop(guard);

            assert_eq!(bytes, b"genuine");
            // The window is real: the same pathname now reaches the attacker
            // tree.
            assert_eq!(fs::read(&named).unwrap(), b"attacker");
        }

        #[test]
        fn a_checkpoint_write_after_an_ancestor_swap_publishes_only_in_the_named_tree() {
            let tree = race_tree();

            let guard = tree.arm();
            write_atomic_entry(
                &resolve_write_destination(&tree.named("export.checkpoint.json")).unwrap(),
                b"checkpoint",
            )
            .unwrap();
            drop(guard);

            assert_eq!(
                fs::read(tree.moved("export.checkpoint.json")).unwrap(),
                b"checkpoint"
            );
            assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
        }

        #[test]
        fn an_export_reservation_after_an_ancestor_swap_creates_nothing_outside_the_named_tree() {
            let tree = race_tree();

            let guard = tree.arm();
            write_atomic_create_new_entry(
                &resolve_write_destination(&tree.named("records.jsonl")).unwrap(),
                b"reserved",
            )
            .unwrap();
            drop(guard);

            assert_eq!(fs::read(tree.moved("records.jsonl")).unwrap(), b"reserved");
            assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
        }

        #[test]
        fn an_export_page_append_after_an_ancestor_swap_appends_only_to_the_named_file() {
            let tree = race_tree();
            let named = tree.named("records.jsonl");
            fs::write(&named, b"first\n").unwrap();
            fs::write(tree.outside("records.jsonl"), b"decoy\n").unwrap();

            let guard = tree.arm();
            let destination = resolve_write_destination(&named).unwrap();
            append_export_page(&destination, b"second\n").unwrap();
            drop(guard);

            assert_eq!(
                fs::read(tree.moved("records.jsonl")).unwrap(),
                b"first\nsecond\n"
            );
            assert_eq!(fs::read(tree.outside("records.jsonl")).unwrap(), b"decoy\n");
        }

        #[test]
        fn an_export_run_writes_every_page_and_checkpoint_in_the_tree_it_resolved() {
            let (plan, inspected) = export_plan_and_inspected();
            let tree = race_tree();
            let output_path = tree.named("records.jsonl");
            let checkpoint_path = tree.named("export.checkpoint.json");
            // The substitute tree carries an output file of its own, so a run
            // that resolved its paths again would append there rather than
            // refuse a missing file.
            fs::write(tree.outside("records.jsonl"), b"decoy\n").unwrap();

            let mut started =
                load_or_start_export(&plan, &inspected, &output_path, &checkpoint_path).unwrap();

            // The ancestor the run resolved is renamed away and a different
            // directory takes its place, so both operator pathnames reach the
            // substitute tree without meeting a symbolic link.
            fs::rename(
                tree.root().join("genuine"),
                tree.root().join("genuine-moved"),
            )
            .unwrap();
            fs::rename(tree.root().join("attacker"), tree.root().join("genuine")).unwrap();
            let substitute = tree.root().join("genuine/inner");

            let mut served = 0u32;
            run_export_pages(&plan, &inspected, &mut started, None, |_| {
                served += 1;
                let response = if served == 1 {
                    export_response("AA", Some("SERVER-CURSOR"))
                } else {
                    export_response("BB", None)
                };
                async move { Ok::<_, ()>(response) }
            })
            .unwrap();

            // Both writes stay in the tree the run resolved, and the published
            // pair belongs together: the checkpoint accounts for exactly the
            // bytes the output holds.
            let output = fs::read(tree.moved("records.jsonl")).unwrap();
            assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 2);
            assert_eq!(
                fs::read(tree.moved("export.checkpoint.json")).unwrap(),
                started.checkpoint.canonical_json().unwrap()
            );
            assert_eq!(started.checkpoint.output_length(), output.len() as u64);
            assert!(started.checkpoint.is_complete());

            // Nothing lands in the substitute tree.
            assert_eq!(
                fs::read(substitute.join("records.jsonl")).unwrap(),
                b"decoy\n"
            );
            let mut substituted: Vec<_> = fs::read_dir(&substitute)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            substituted.sort();
            assert_eq!(substituted, vec!["records.jsonl", "target"]);
        }

        #[test]
        fn an_import_run_writes_every_checkpoint_in_the_tree_it_resolved() {
            let (plan, inspected) = import_plan_and_inspected();
            let tree = race_tree();
            let checkpoint_path = tree.named("import.checkpoint.json");

            let destinations = ImportDestinations::resolve(&checkpoint_path).unwrap();
            let (mut checkpoint, import_id) =
                load_or_start_import(&plan, &inspected, &destinations).unwrap();

            // The ancestor the run resolved is renamed away and a different
            // directory takes its place, so the operator pathname reaches the
            // substitute tree without meeting a symbolic link.
            fs::rename(
                tree.root().join("genuine"),
                tree.root().join("genuine-moved"),
            )
            .unwrap();
            fs::rename(tree.root().join("attacker"), tree.root().join("genuine")).unwrap();
            let substitute = tree.root().join("genuine/inner");

            run_import_chunks(
                &plan,
                &mut checkpoint,
                ImportExecutionBinding {
                    package_revision: &inspected.package_revision,
                    schema_fingerprint: &inspected.schema_fingerprint,
                    import_id: &import_id,
                },
                None,
                |checkpoint| publish_import_checkpoint(&destinations.checkpoint, checkpoint),
                |request| async move {
                    let body = parse_json_strict(request.body()).unwrap();
                    let results = body["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            json!({
                                "operation": item["operation"],
                                "id": "018f06d6-0248-4c7f-8a7e-df9dfbd83d2c",
                                "revision": 1,
                                "etag": "\"breg-revision\"",
                                "data": item["data"]
                            })
                        })
                        .collect::<Vec<_>>();
                    let body = canonicalize_json(&json!({
                        "results": results,
                        "snapshot": "breg1_00000000-0000-4000-8000-000000000001"
                    }))
                    .unwrap();
                    Ok::<_, ()>(
                        DataHttpResponse::new(200, Some("application/json".to_owned()), body)
                            .unwrap(),
                    )
                },
            )
            .unwrap();

            // The advanced checkpoint stays beside the state file that binds
            // it, in the tree the run resolved.
            assert!(checkpoint.is_complete());
            assert_eq!(
                fs::read(tree.moved("import.checkpoint.json")).unwrap(),
                checkpoint.canonical_json().unwrap()
            );
            assert!(tree.moved("import.checkpoint.json.state").exists());

            // Nothing lands in the substitute tree.
            let mut substituted: Vec<_> = fs::read_dir(&substitute)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            substituted.sort();
            assert_eq!(substituted, vec!["target"]);
        }

        #[test]
        fn an_export_state_read_after_an_ancestor_swap_reads_only_the_named_file() {
            let tree = race_tree();
            let named = tree.named("records.jsonl");
            let record = b"{\"id\":\"one\"}\n";
            fs::write(&named, record).unwrap();
            // Bytes no export state can be built from, so reading the tree the
            // operator never named would fail rather than pass quietly.
            fs::write(tree.outside("records.jsonl"), b"not a record\n").unwrap();

            let guard = tree.arm();
            let file = SafeEntry::resolve(&named)
                .unwrap()
                .open_read_write()
                .unwrap();
            drop(guard);
            let state = read_export_output_prefix(&file, record.len() as u64).unwrap();

            assert!(format!("{state:?}").contains("record_count: 1"));
        }

        #[test]
        fn an_export_tail_discard_after_an_ancestor_swap_shortens_only_the_named_file() {
            let tree = race_tree();
            let named = tree.named("records.jsonl");
            let record = b"{\"id\":\"one\"}\n";
            let mut appended = record.to_vec();
            appended.extend_from_slice(b"{\"id\":\"two\"}\n");
            fs::write(&named, &appended).unwrap();
            fs::write(tree.outside("records.jsonl"), &appended).unwrap();

            let guard = tree.arm();
            let file = SafeEntry::resolve(&named)
                .unwrap()
                .open_read_write()
                .unwrap();
            drop(guard);
            file.set_len(record.len() as u64).unwrap();
            file.sync_all().unwrap();

            assert_eq!(fs::read(tree.moved("records.jsonl")).unwrap(), record);
            assert_eq!(fs::read(tree.outside("records.jsonl")).unwrap(), appended);
        }
    }

    #[test]
    fn export_paths_are_reserved_without_clobbering_a_concurrent_file() {
        let directory = test_directory("export-reservation");
        let output = directory.join("records.jsonl");
        let checkpoint = directory.join("export.checkpoint.json");
        let destinations = ExportDestinations::resolve(&output, &checkpoint).unwrap();

        fs::write(&checkpoint, b"concurrent-checkpoint").unwrap();
        assert!(matches!(
            reserve_export_paths(&destinations, b"initial-checkpoint"),
            Err(DataLifecycleError::Output)
        ));
        assert_eq!(fs::read(&output).unwrap(), b"");
        assert_eq!(fs::read(&checkpoint).unwrap(), b"concurrent-checkpoint");

        fs::remove_file(&output).unwrap();
        fs::remove_file(&checkpoint).unwrap();
        reserve_export_paths(&destinations, b"initial-checkpoint").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"");
        assert_eq!(fs::read(&checkpoint).unwrap(), b"initial-checkpoint");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn export_reloads_the_checkpoint_and_appends_only_the_next_page() {
        let (plan, inspected) = export_plan_and_inspected();
        let directory = test_directory("export-resume");
        let output_path = directory.join("records.jsonl");
        let checkpoint_path = directory.join("export.checkpoint.json");
        let mut started =
            load_or_start_export(&plan, &inspected, &output_path, &checkpoint_path).unwrap();

        let first = test_runtime()
            .block_on(execute_export_page(
                &plan,
                &mut started.checkpoint,
                PACKAGE,
                SCHEMA,
                &started.output_state,
                &started.resume_state,
                |_| async { Ok::<_, ()>(export_response("AA", Some("SERVER-CURSOR"))) },
            ))
            .unwrap()
            .unwrap();
        let (first_page, _, _) = first.into_parts();
        append_export_page(&started.destinations.output, &first_page).unwrap();
        publish_checkpoint(&started);

        let mut resumed =
            load_or_start_export(&plan, &inspected, &output_path, &checkpoint_path).unwrap();
        let second = test_runtime()
            .block_on(execute_export_page(
                &plan,
                &mut resumed.checkpoint,
                PACKAGE,
                SCHEMA,
                &resumed.output_state,
                &resumed.resume_state,
                |request| async move {
                    assert!(request
                        .path_and_query()
                        .contains("$skiptoken=SERVER-CURSOR"));
                    Ok::<_, ()>(export_response("BB", None))
                },
            ))
            .unwrap()
            .unwrap();
        let (second_page, _, _) = second.into_parts();
        append_export_page(&resumed.destinations.output, &second_page).unwrap();

        let output = fs::read(&output_path).unwrap();
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 2);
        DataExportOutputState::from_bytes(&output)
            .expect("appended output remains canonical JSONL");
        assert_eq!(resumed.checkpoint.completed_page_count(), 2);
        assert_eq!(resumed.checkpoint.record_count(), 2);
        assert!(resumed.checkpoint.is_complete());

        publish_checkpoint(&resumed);
        append_export_page(&resumed.destinations.output, b"{\"code\":\"TAMPERED\"}\n").unwrap();
        assert!(matches!(
            load_or_start_export(&plan, &inspected, &output_path, &checkpoint_path),
            Err(DataLifecycleError::Data(DataError::CheckpointMismatch))
        ));

        fs::remove_dir_all(directory).unwrap();
    }

    /// Drive one export page through the executor and append it to the output
    /// file, leaving the matching checkpoint publication to the caller. That
    /// gap is the interruption window these regressions exercise.
    fn append_one_export_page(
        plan: &DataExportPlan,
        started: &mut StartedExport,
        code: &str,
        next_cursor: Option<&str>,
    ) {
        let progress = test_runtime()
            .block_on(execute_export_page(
                plan,
                &mut started.checkpoint,
                PACKAGE,
                SCHEMA,
                &started.output_state,
                &started.resume_state,
                |_| {
                    let response = export_response(code, next_cursor);
                    async move { Ok::<_, ()>(response) }
                },
            ))
            .unwrap()
            .unwrap();
        let (page, next_output, next_resume) = progress.into_parts();
        append_export_page(&started.destinations.output, &page).unwrap();
        started.output_state = next_output;
        started.resume_state = next_resume;
    }

    /// Publish the checkpoint an export run has advanced to, through the
    /// destination that run resolved.
    fn publish_checkpoint(started: &StartedExport) {
        write_atomic_entry(
            &started.destinations.checkpoint,
            &started.checkpoint.canonical_json().unwrap(),
        )
        .unwrap();
    }

    /// One export with a single committed page: the output holds that page, the
    /// checkpoint records it, and the in-memory run is positioned to request
    /// the next one.
    struct CommittedExport {
        directory: PathBuf,
        output_path: PathBuf,
        checkpoint_path: PathBuf,
        started: StartedExport,
        committed_output: Vec<u8>,
        committed_checkpoint: Vec<u8>,
    }

    fn committed_export(
        plan: &DataExportPlan,
        inspected: &InspectedDataPackage,
        label: &str,
    ) -> CommittedExport {
        let directory = test_directory(label);
        let output_path = directory.join("records.jsonl");
        let checkpoint_path = directory.join("export.checkpoint.json");
        let mut started =
            load_or_start_export(plan, inspected, &output_path, &checkpoint_path).unwrap();
        append_one_export_page(plan, &mut started, "AA", Some("SERVER-CURSOR"));
        publish_checkpoint(&started);
        CommittedExport {
            committed_output: fs::read(&output_path).unwrap(),
            committed_checkpoint: fs::read(&checkpoint_path).unwrap(),
            directory,
            output_path,
            checkpoint_path,
            started,
        }
    }

    #[test]
    fn export_resumes_after_a_page_append_without_its_checkpoint() {
        let (plan, inspected) = export_plan_and_inspected();
        let mut committed = committed_export(&plan, &inspected, "export-interrupted-append");

        // The process stops after the second page is appended and before the
        // checkpoint that records it is published.
        append_one_export_page(&plan, &mut committed.started, "BB", Some("SECOND-CURSOR"));
        assert!(fs::read(&committed.output_path).unwrap().len() > committed.committed_output.len());

        let mut recovered = load_or_start_export(
            &plan,
            &inspected,
            &committed.output_path,
            &committed.checkpoint_path,
        )
        .unwrap();

        assert_eq!(
            fs::read(&committed.output_path).unwrap(),
            committed.committed_output
        );
        assert_eq!(
            fs::read(&committed.checkpoint_path).unwrap(),
            committed.committed_checkpoint
        );
        assert_eq!(recovered.checkpoint.completed_page_count(), 1);
        assert_eq!(recovered.checkpoint.record_count(), 1);

        // The resumed run continues from the committed cursor rather than
        // starting the export again.
        let progress = test_runtime()
            .block_on(execute_export_page(
                &plan,
                &mut recovered.checkpoint,
                PACKAGE,
                SCHEMA,
                &recovered.output_state,
                &recovered.resume_state,
                |request| async move {
                    assert!(request
                        .path_and_query()
                        .contains("$skiptoken=SERVER-CURSOR"));
                    Ok::<_, ()>(export_response("BB", None))
                },
            ))
            .unwrap()
            .unwrap();
        let (page, _, _) = progress.into_parts();
        append_export_page(&recovered.destinations.output, &page).unwrap();
        publish_checkpoint(&recovered);

        let output = fs::read(&committed.output_path).unwrap();
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 2);
        DataExportOutputState::from_bytes(&output).expect("the resumed output remains canonical");
        assert_eq!(recovered.checkpoint.record_count(), 2);
        assert!(recovered.checkpoint.is_complete());

        fs::remove_dir_all(committed.directory).unwrap();
    }

    #[test]
    fn export_resumes_after_a_refused_checkpoint_publication() {
        let (plan, inspected) = export_plan_and_inspected();
        let mut committed = committed_export(&plan, &inspected, "export-refused-checkpoint");

        append_one_export_page(&plan, &mut committed.started, "BB", Some("SECOND-CURSOR"));

        // Stand in for any checkpoint publication failure: the destination is
        // no longer a regular file, so the staged bytes are never renamed over
        // it and the committed checkpoint survives untouched.
        let held = committed.directory.join("export.checkpoint.json.held");
        fs::rename(&committed.checkpoint_path, &held).unwrap();
        fs::create_dir(&committed.checkpoint_path).unwrap();
        assert!(matches!(
            write_atomic_entry(
                &committed.started.destinations.checkpoint,
                &committed.started.checkpoint.canonical_json().unwrap()
            ),
            Err(DataLifecycleError::Output)
        ));
        fs::remove_dir(&committed.checkpoint_path).unwrap();
        fs::rename(&held, &committed.checkpoint_path).unwrap();
        assert_eq!(
            fs::read(&committed.checkpoint_path).unwrap(),
            committed.committed_checkpoint
        );

        let recovered = load_or_start_export(
            &plan,
            &inspected,
            &committed.output_path,
            &committed.checkpoint_path,
        )
        .unwrap();

        assert_eq!(
            fs::read(&committed.output_path).unwrap(),
            committed.committed_output
        );
        assert_eq!(recovered.checkpoint.completed_page_count(), 1);
        assert_eq!(recovered.checkpoint.record_count(), 1);
        assert!(!recovered.checkpoint.is_complete());

        fs::remove_dir_all(committed.directory).unwrap();
    }

    #[test]
    fn export_refuses_an_output_shorter_than_its_checkpoint() {
        let (plan, inspected) = export_plan_and_inspected();
        let committed = committed_export(&plan, &inspected, "export-short-output");

        let shortened = committed.committed_output[..committed.committed_output.len() - 1].to_vec();
        fs::write(&committed.output_path, &shortened).unwrap();

        assert!(matches!(
            load_or_start_export(
                &plan,
                &inspected,
                &committed.output_path,
                &committed.checkpoint_path
            ),
            Err(DataLifecycleError::Data(DataError::CheckpointMismatch))
        ));
        assert_eq!(fs::read(&committed.output_path).unwrap(), shortened);
        assert_eq!(
            fs::read(&committed.checkpoint_path).unwrap(),
            committed.committed_checkpoint
        );

        fs::remove_dir_all(committed.directory).unwrap();
    }

    #[test]
    fn export_refuses_an_altered_committed_prefix() {
        let (plan, inspected) = export_plan_and_inspected();
        let committed = committed_export(&plan, &inspected, "export-altered-prefix");

        // Same length, same canonical shape, different committed bytes.
        let altered = String::from_utf8(committed.committed_output.clone())
            .unwrap()
            .replace("\"AA\"", "\"AB\"");
        assert_ne!(altered.as_bytes(), committed.committed_output.as_slice());
        assert_eq!(altered.len(), committed.committed_output.len());
        fs::write(&committed.output_path, altered.as_bytes()).unwrap();

        assert!(matches!(
            load_or_start_export(
                &plan,
                &inspected,
                &committed.output_path,
                &committed.checkpoint_path
            ),
            Err(DataLifecycleError::Data(DataError::CheckpointMismatch))
        ));
        assert_eq!(
            fs::read(&committed.output_path).unwrap(),
            altered.as_bytes()
        );

        fs::remove_dir_all(committed.directory).unwrap();
    }

    #[test]
    fn export_refuses_a_substituted_checkpoint() {
        let (plan, inspected) = export_plan_and_inspected();
        let committed = committed_export(&plan, &inspected, "export-substituted-checkpoint");

        for (field, replacement) in [
            ("packageRevision", json!("other-package-revision")),
            (
                "outputPrefixDigest",
                json!("0000000000000000000000000000000000000000000000000000000000000000"),
            ),
            ("outputLength", json!(1)),
        ] {
            let mut substituted = parse_json_strict(&committed.committed_checkpoint).unwrap();
            substituted[field] = replacement;
            fs::write(
                &committed.checkpoint_path,
                canonicalize_json(&substituted).unwrap(),
            )
            .unwrap();

            assert!(matches!(
                load_or_start_export(
                    &plan,
                    &inspected,
                    &committed.output_path,
                    &committed.checkpoint_path
                ),
                Err(DataLifecycleError::Data(DataError::CheckpointMismatch))
            ));
            assert_eq!(
                fs::read(&committed.output_path).unwrap(),
                committed.committed_output
            );
        }

        fs::remove_dir_all(committed.directory).unwrap();
    }

    #[test]
    fn export_refuses_more_than_one_unrecorded_page() {
        let (plan, inspected) = export_plan_and_inspected();
        let committed = committed_export(&plan, &inspected, "export-oversized-tail");

        let mut oversized = committed.committed_output.clone();
        oversized.resize(
            committed.committed_output.len() + MAX_DATA_HTTP_RESPONSE_BYTES + 1,
            b'x',
        );
        fs::write(&committed.output_path, &oversized).unwrap();

        assert!(matches!(
            load_or_start_export(
                &plan,
                &inspected,
                &committed.output_path,
                &committed.checkpoint_path
            ),
            Err(DataLifecycleError::Data(DataError::CheckpointMismatch))
        ));
        assert_eq!(fs::read(&committed.output_path).unwrap(), oversized);

        fs::remove_dir_all(committed.directory).unwrap();
    }

    #[test]
    fn export_refuses_anything_appended_after_a_complete_checkpoint() {
        let (plan, inspected) = export_plan_and_inspected();
        let mut committed = committed_export(&plan, &inspected, "export-complete-tail");

        append_one_export_page(&plan, &mut committed.started, "BB", None);
        publish_checkpoint(&committed.started);
        assert!(committed.started.checkpoint.is_complete());
        let complete_output = fs::read(&committed.output_path).unwrap();

        // The checkpoint that reports the export complete is published after
        // the last page, so no interrupted append can follow it.
        append_export_page(
            &committed.started.destinations.output,
            b"{\"code\":\"CC\"}\n",
        )
        .unwrap();
        assert!(matches!(
            load_or_start_export(
                &plan,
                &inspected,
                &committed.output_path,
                &committed.checkpoint_path
            ),
            Err(DataLifecycleError::Data(DataError::CheckpointMismatch))
        ));
        assert_eq!(
            fs::read(&committed.output_path).unwrap().len(),
            complete_output.len() + 14
        );

        fs::remove_dir_all(committed.directory).unwrap();
    }

    #[test]
    fn export_refuses_a_half_reserved_pair_by_naming_the_missing_file() {
        let (plan, inspected) = export_plan_and_inspected();
        let directory = test_directory("export-half-reserved");
        let output_path = directory.join("records.jsonl");
        let checkpoint_path = directory.join("export.checkpoint.json");

        // The reservation creates the empty output and then publishes the
        // first checkpoint, so a crash between the two leaves a zero-byte
        // output with no checkpoint.
        fs::write(&output_path, b"").unwrap();
        assert!(matches!(
            load_or_start_export(&plan, &inspected, &output_path, &checkpoint_path),
            Err(DataLifecycleError::ExportPair(
                ExportPairState::CheckpointMissing
            ))
        ));
        assert_eq!(fs::read(&output_path).unwrap(), b"");

        // The mirror image, an output removed while its checkpoint stayed, is
        // refused by the file it names instead.
        fs::remove_file(&output_path).unwrap();
        fs::write(&checkpoint_path, b"{}").unwrap();
        assert!(matches!(
            load_or_start_export(&plan, &inspected, &output_path, &checkpoint_path),
            Err(DataLifecycleError::ExportPair(
                ExportPairState::OutputMissing
            ))
        ));
        assert_eq!(fs::read(&checkpoint_path).unwrap(), b"{}");

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn first_import_creation_does_not_clobber_staged_state_or_checkpoint_collisions() {
        let (plan, inspected) = import_plan_and_inspected();
        let directory = test_directory("initial-collisions");
        let checkpoint_path = directory.join("import.checkpoint.json");
        let state_path = import_state_path(&checkpoint_path);
        let destinations = ImportDestinations::resolve(&checkpoint_path).unwrap();

        fs::write(&state_path, b"existing-state").unwrap();
        assert!(matches!(
            start_new_import(&plan, &inspected, &destinations),
            Err(DataLifecycleError::Checkpoint)
        ));
        assert_eq!(fs::read(&state_path).unwrap(), b"existing-state");
        assert!(!checkpoint_path.try_exists().unwrap());
        fs::remove_file(&state_path).unwrap();

        fs::write(&checkpoint_path, b"existing-checkpoint").unwrap();
        assert!(matches!(
            start_new_import(&plan, &inspected, &destinations),
            Err(DataLifecycleError::Checkpoint)
        ));
        assert_eq!(fs::read(&checkpoint_path).unwrap(), b"existing-checkpoint");
        read_import_state(&destinations.state, &plan, &inspected).unwrap();

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn first_import_loser_keeps_state_after_concurrent_state_only_repair() {
        let (plan, inspected) = import_plan_and_inspected();
        let directory = test_directory("state-repair-race");
        let checkpoint_path = directory.join("import.checkpoint.json");
        let state_path = import_state_path(&checkpoint_path);
        let destinations = ImportDestinations::resolve(&checkpoint_path).unwrap();
        let checkpoint = DataImportCheckpoint::start(
            &plan,
            &inspected.package_revision,
            &inspected.schema_fingerprint,
        )
        .unwrap();
        let state = import_state_for_checkpoint(&plan, &inspected, &checkpoint);
        let state_bytes = canonical_import_state(&state).unwrap();
        let checkpoint_bytes = checkpoint.canonical_json().unwrap();

        write_atomic_create_new_entry(&destinations.state, &state_bytes).unwrap();

        let (repaired, repaired_import_id) =
            recover_state_only_import(&plan, &inspected, &destinations).unwrap();

        assert_eq!(repaired_import_id, checkpoint.import_id());
        assert_eq!(repaired.import_id(), checkpoint.import_id());

        assert!(matches!(
            write_atomic_create_new_entry(&destinations.checkpoint, &checkpoint_bytes),
            Err(DataLifecycleError::Output)
        ));
        assert_eq!(fs::read(&state_path).unwrap(), state_bytes);

        let (loaded, loaded_import_id) =
            load_existing_import(&plan, &inspected, &destinations).unwrap();
        assert_eq!(loaded_import_id, checkpoint.import_id());
        assert_eq!(loaded.import_id(), checkpoint.import_id());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn state_only_half_start_is_repaired_but_checkpoint_only_is_not_authority() {
        let (plan, inspected) = import_plan_and_inspected();
        let directory = test_directory("partial-start");
        let checkpoint_path = directory.join("import.checkpoint.json");
        let state_path = import_state_path(&checkpoint_path);
        let checkpoint = DataImportCheckpoint::start(
            &plan,
            &inspected.package_revision,
            &inspected.schema_fingerprint,
        )
        .unwrap();
        let state = import_state_for_checkpoint(&plan, &inspected, &checkpoint);
        let state_bytes = canonical_import_state(&state).unwrap();
        fs::write(&state_path, &state_bytes).unwrap();

        let (repaired, import_id) = load_or_start_import(
            &plan,
            &inspected,
            &ImportDestinations::resolve(&checkpoint_path).unwrap(),
        )
        .unwrap();

        assert_eq!(import_id, checkpoint.import_id());
        assert_eq!(repaired.import_id(), checkpoint.import_id());
        assert_eq!(fs::read(&state_path).unwrap(), state_bytes);
        let repaired_bytes = fs::read(&checkpoint_path).unwrap();
        let reloaded = DataImportCheckpoint::from_json(
            &repaired_bytes,
            &plan,
            &inspected.package_revision,
            &inspected.schema_fingerprint,
            checkpoint.import_id(),
        )
        .unwrap();
        assert_eq!(reloaded.import_id(), checkpoint.import_id());
        fs::remove_dir_all(&directory).unwrap();

        let directory = test_directory("checkpoint-only");
        let checkpoint_path = directory.join("import.checkpoint.json");
        let state_path = import_state_path(&checkpoint_path);
        let checkpoint = DataImportCheckpoint::start(
            &plan,
            &inspected.package_revision,
            &inspected.schema_fingerprint,
        )
        .unwrap();
        fs::write(&checkpoint_path, checkpoint.canonical_json().unwrap()).unwrap();
        assert!(matches!(
            load_or_start_import(
                &plan,
                &inspected,
                &ImportDestinations::resolve(&checkpoint_path).unwrap()
            ),
            Err(DataLifecycleError::Checkpoint)
        ));
        assert!(!state_path.try_exists().unwrap());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn data_http_client_does_not_follow_redirects() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let attempts_for_server = Arc::clone(&attempts);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            attempts_for_server.fetch_add(1, AtomicOrdering::SeqCst);
            let request = read_http_request(&mut stream);
            assert!(String::from_utf8_lossy(&request)
                .starts_with("POST /v1/records/records:batch?accessProfile=operator "));
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /redirect-target\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();

            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + StdDuration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut redirected, _)) => {
                        attempts_for_server.fetch_add(1, AtomicOrdering::SeqCst);
                        let _ = read_http_request(&mut redirected);
                        let _ = redirected
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfollowed");
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(10));
                    }
                    Err(error) => panic!("redirect listener failed: {error}"),
                }
            }
        });

        let input = br#"{"operation":"create","data":{"code":"AA"}}
"#;
        let plan = DataImportPlan::from_jsonl(
            &compiled(),
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            input,
        )
        .unwrap();
        let mut checkpoint = DataImportCheckpoint::start(&plan, PACKAGE, SCHEMA).unwrap();
        let import_id = checkpoint.import_id().to_owned();
        let runtime = test_runtime();
        let client = build_data_http_client_with_timeouts(
            StdDuration::from_secs(2),
            StdDuration::from_secs(1),
        )
        .unwrap();
        let base = parse_breg_url(&format!("http://{address}")).unwrap();

        let error = runtime
            .block_on(execute_import_chunk(
                &plan,
                &mut checkpoint,
                PACKAGE,
                SCHEMA,
                &import_id,
                |request| dispatch_http(&client, &base, "TEST-TOKEN", request),
            ))
            .unwrap_err();

        assert_eq!(error, DataError::OperationRefused);
        handle.join().unwrap();
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn data_http_client_ignores_ambient_proxy_variables_in_an_isolated_process() {
        if std::env::var_os("BREGCTL_DATA_PROXY_CHILD").is_some() {
            return;
        }
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("data_lifecycle::tests::data_http_client_ignores_ambient_proxy_variables_child")
            .arg("--nocapture")
            .env("BREGCTL_DATA_PROXY_CHILD", "1")
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("https_proxy", "http://127.0.0.1:1")
            .env("all_proxy", "http://127.0.0.1:1")
            .env("no_proxy", "")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn data_http_client_ignores_ambient_proxy_variables_child() {
        if std::env::var_os("BREGCTL_DATA_PROXY_CHILD").is_none() {
            return;
        }
        let (address, handle) = spawn_one_response_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect".to_vec(),
        );
        let client = build_data_http_client_with_timeouts(
            StdDuration::from_secs(2),
            StdDuration::from_secs(1),
        )
        .unwrap();
        let runtime = test_runtime();
        let response = runtime
            .block_on(async { client.get(format!("http://{address}/direct")).send().await })
            .expect("the hardened data client connects directly");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            runtime.block_on(read_data_http_body(response)).unwrap(),
            b"direct"
        );
        let request = handle.join().unwrap();
        assert!(String::from_utf8_lossy(&request).starts_with("GET /direct "));
    }

    #[test]
    fn data_http_client_applies_the_request_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_http_request(&mut stream);
            thread::sleep(StdDuration::from_millis(300));
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        });
        let client = build_data_http_client_with_timeouts(
            StdDuration::from_millis(50),
            StdDuration::from_millis(50),
        )
        .unwrap();
        let runtime = test_runtime();
        let started = Instant::now();
        let error = runtime
            .block_on(async { client.get(format!("http://{address}/slow")).send().await })
            .expect_err("the configured request timeout elapses");
        assert!(error.is_timeout());
        assert!(started.elapsed() < StdDuration::from_secs(1));
        handle.join().unwrap();
    }

    #[test]
    fn data_http_client_does_not_retry_failed_exchanges() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let attempts_for_server = Arc::clone(&attempts);
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            attempts_for_server.fetch_add(1, AtomicOrdering::SeqCst);
            let _ = read_http_request(&mut stream);
            drop(stream);

            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + StdDuration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry, _)) => {
                        attempts_for_server.fetch_add(1, AtomicOrdering::SeqCst);
                        let _ = read_http_request(&mut retry);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(10));
                    }
                    Err(error) => panic!("retry listener failed: {error}"),
                }
            }
        });
        let client = build_data_http_client_with_timeouts(
            StdDuration::from_secs(2),
            StdDuration::from_secs(1),
        )
        .unwrap();
        let runtime = test_runtime();
        let error = runtime
            .block_on(async { client.get(format!("http://{address}/drop")).send().await })
            .expect_err("the failed exchange is not retried");
        assert!(!error.is_timeout());
        handle.join().unwrap();
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn data_http_body_reader_rejects_oversized_content_length_before_body_read() {
        let response_bound = MAX_DATA_HTTP_RESPONSE_BYTES as u64;
        let advertised = response_bound + 1;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {advertised}\r\n\r\n"
        );
        let (address, handle) = spawn_one_response_server(response.into_bytes());
        let client = build_data_http_client_with_timeouts(
            StdDuration::from_secs(2),
            StdDuration::from_secs(1),
        )
        .unwrap();
        let runtime = test_runtime();
        let response = runtime
            .block_on(async {
                client
                    .get(format!("http://{address}/oversized"))
                    .send()
                    .await
            })
            .unwrap();
        let error = runtime
            .block_on(read_data_http_body(response))
            .expect_err("oversized content-length is rejected");

        assert!(matches!(
            error,
            registry_platform_httputil::BoundedReadError::ContentLengthExceeded {
                content_length,
                max_bytes
            } if content_length == advertised && max_bytes == response_bound
        ));
        let request = handle.join().unwrap();
        assert!(String::from_utf8_lossy(&request).starts_with("GET /oversized "));
    }

    #[test]
    fn max_chunks_counts_committed_chunks_not_committed_items() {
        let input = br#"{"operation":"create","data":{"code":"AA"}}
{"operation":"create","data":{"code":"BB"}}
{"operation":"create","data":{"code":"CC"}}
"#;
        let plan = DataImportPlan::from_jsonl(
            &compiled(),
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            input,
        )
        .unwrap();
        assert_eq!(plan.chunks().len(), 2);
        let mut checkpoint = DataImportCheckpoint::start(&plan, PACKAGE, SCHEMA).unwrap();
        let import_id = checkpoint.import_id().to_owned();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_request = Arc::clone(&captured);

        let (committed_chunks, committed_items) = run_import_chunks(
            &plan,
            &mut checkpoint,
            ImportExecutionBinding {
                package_revision: PACKAGE,
                schema_fingerprint: SCHEMA,
                import_id: &import_id,
            },
            Some(2),
            |_| Ok(()),
            move |request| {
                let captured_request = Arc::clone(&captured_request);
                async move {
                    let body = parse_json_strict(request.body()).unwrap();
                    let submitted = body["items"].as_array().unwrap();
                    captured_request.lock().unwrap().push((
                        request.path_and_query().to_owned(),
                        request.idempotency_key().map(str::to_owned),
                        submitted.len(),
                    ));
                    let results = submitted
                        .iter()
                        .map(|item| {
                            json!({
                                "operation": item["operation"],
                                "id": "018f06d6-0248-4c7f-8a7e-df9dfbd83d2c",
                                "revision": 1,
                                "etag": "\"breg-revision\"",
                                "data": item["data"]
                            })
                        })
                        .collect::<Vec<_>>();
                    let body = canonicalize_json(&json!({
                        "results": results,
                        "snapshot": "breg1_00000000-0000-4000-8000-000000000001"
                    }))
                    .unwrap();
                    DataHttpResponse::new(200, Some("application/json".to_owned()), body)
                }
            },
        )
        .unwrap();

        assert_eq!(committed_chunks, 2);
        assert_eq!(committed_items, 3);
        assert!(checkpoint.is_complete());
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].2, 2);
        assert_eq!(captured[1].2, 1);
        assert_ne!(captured[0].1, captured[1].1);
        assert!(captured
            .iter()
            .all(|(path, _, _)| path == "/v1/records/records:batch?accessProfile=operator"));
    }

    #[test]
    fn breg_urls_are_closed_and_remote_http_is_refused() {
        assert!(parse_breg_url("https://registry.example.test").is_ok());
        assert!(parse_breg_url("http://127.0.0.1:8080").is_ok());
        assert!(parse_breg_url("http://localhost:8080").is_ok());
        let prefixed = parse_breg_url("https://registry.example.test/deployment").unwrap();
        assert_eq!(
            data_endpoint(&prefixed, "/v1/records/people?accessProfile=operator")
                .unwrap()
                .as_str(),
            "https://registry.example.test/deployment/v1/records/people?accessProfile=operator"
        );

        for refused in [
            "http://registry.example.test",
            "https://user:pass@registry.example.test",
            "https://registry.example.test?x=1",
            "https://registry.example.test/#fragment",
            "https://registry.example.test/a//b",
            "file:///tmp/registry",
        ] {
            assert!(parse_breg_url(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn import_state_rejects_unknown_or_changed_binding_without_rendering_values() {
        let input = br#"{"operation":"create","data":{"code":"AA"}}
"#;
        let plan = DataImportPlan::from_jsonl(
            &compiled(),
            ENTITY,
            DataImportOperation::Create,
            PROFILE,
            input,
        )
        .unwrap();
        let inspected = InspectedDataPackage {
            package_revision: PACKAGE.to_owned(),
            schema_fingerprint: SCHEMA.to_owned(),
            registry: compiled(),
        };
        let directory = std::env::current_dir()
            .unwrap()
            .join(format!(".bregctl-data-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let state_path = directory.join("import.state");
        let state = ImportState {
            api_version: DATA_STATE_API_VERSION.to_owned(),
            kind: IMPORT_STATE_KIND.to_owned(),
            package_revision: PACKAGE.to_owned(),
            schema_fingerprint: SCHEMA.to_owned(),
            entity_id: ENTITY.to_owned(),
            operation: DataImportOperation::Create,
            profile_id: PROFILE.to_owned(),
            input_digest: plan.input_digest().to_owned(),
            import_id: "018f06d6-0248-4c7f-8a7e-df9dfbd83d2c".to_owned(),
        };
        let mut value = serde_json::to_value(&state).unwrap();
        value["unknownCredential"] = json!("SECRET-CANARY");
        fs::write(&state_path, canonicalize_json(&value).unwrap()).unwrap();

        let state_entry = resolve_write_destination(&state_path).unwrap();
        let error = read_import_state(&state_entry, &plan, &inspected).unwrap_err();
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("SECRET-CANARY"));
        assert!(!rendered.contains(PACKAGE));
        assert!(!rendered.contains(PROFILE));

        let mut changed: Value = serde_json::to_value(&state).unwrap();
        changed["profileId"] = json!("other-profile-canary");
        fs::write(&state_path, canonicalize_json(&changed).unwrap()).unwrap();
        assert!(read_import_state(&state_entry, &plan, &inspected).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
