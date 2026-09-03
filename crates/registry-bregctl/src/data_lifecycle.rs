// SPDX-License-Identifier: Apache-2.0
//! Authenticated HTTP data workflows for Base Registry Engine.
//!
//! This module owns only ctl-side package inspection, file checkpoints, and
//! HTTP dispatch. Data shape, chunking, idempotency, and response validation
//! remain in `registry_breg::data`.

use std::fs;
use std::future::Future;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use registry_breg::data::{
    execute_export_page, execute_import_chunk, DataError, DataExportCheckpoint, DataExportPlan,
    DataHttpMethod, DataHttpRequest, DataHttpResponse, DataImportCheckpoint, DataImportOperation,
    DataImportPlan, MAX_DATA_HTTP_RESPONSE_BYTES, MAX_DATA_IMPORT_INPUT_BYTES,
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

const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_CHECKPOINT_BYTES: u64 = 1024 * 1024;
const DATA_HTTP_USER_AGENT: &str = "bregctl-data";
const DATA_STATE_API_VERSION: &str = "registry.registrystack.org/bregctl-data/v1";
const IMPORT_STATE_KIND: &str = "BRegctlDataImportState";
const MAX_ATOMIC_WRITE_TEMP_ATTEMPTS: usize = 16;

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
    let state_path = import_state_path(request.checkpoint);
    let (mut checkpoint, import_id) =
        load_or_start_import(&plan, &inspected, request.checkpoint, &state_path)?;
    let client = build_data_http_client()?;
    let (_committed_chunks, committed_items) = run_import_chunks(
        &plan,
        &mut checkpoint,
        ImportExecutionBinding {
            package_revision: &inspected.package_revision,
            schema_fingerprint: &inspected.schema_fingerprint,
            import_id: &import_id,
        },
        request.max_chunks,
        |checkpoint| {
            write_atomic(
                request.checkpoint,
                &checkpoint
                    .canonical_json()
                    .map_err(DataLifecycleError::Data)?,
            )
        },
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
        committed_items,
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
    let (mut checkpoint, mut resume_state) = DataExportCheckpoint::start(
        &plan,
        &inspected.package_revision,
        &inspected.schema_fingerprint,
    )
    .map_err(DataLifecycleError::Data)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| DataLifecycleError::Runtime)?;
    let client = build_data_http_client()?;
    reserve_export_paths(request.output, request.checkpoint)?;
    let mut output_prefix = Vec::new();
    let mut pages = 0u64;
    let max_pages = request.max_pages.unwrap_or(u64::MAX);
    while !checkpoint.is_complete() && pages < max_pages {
        let progress = runtime
            .block_on(execute_export_page(
                &plan,
                &mut checkpoint,
                &inspected.package_revision,
                &inspected.schema_fingerprint,
                &output_prefix,
                &resume_state,
                |data_request| dispatch_http(&client, &breg_url, &token, data_request),
            ))
            .map_err(map_data_or_transport)?;
        let Some(progress) = progress else {
            break;
        };
        let parts = progress.into_parts();
        output_prefix = parts.0;
        resume_state = parts.1;
        pages = pages.checked_add(1).ok_or(DataLifecycleError::Checkpoint)?;
        write_atomic(request.output, &output_prefix)?;
        write_atomic(
            request.checkpoint,
            &checkpoint
                .canonical_json()
                .map_err(DataLifecycleError::Data)?,
        )?;
    }
    Ok(DataExportOutcome {
        package_revision: inspected.package_revision,
        schema_fingerprint: inspected.schema_fingerprint,
        entity_id: plan.entity_id().to_owned(),
        profile_id: plan.profile_id().to_owned(),
        requested_fields: plan.requested_fields().to_vec(),
        completed_page_count: pages,
        record_count: checkpoint.record_count(),
        output_length: checkpoint.output_length(),
        complete: checkpoint.is_complete(),
    })
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

fn load_or_start_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    checkpoint_path: &Path,
    state_path: &Path,
) -> Result<(DataImportCheckpoint, String), DataLifecycleError> {
    let checkpoint_exists = checkpoint_path
        .try_exists()
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    let state_exists = state_path
        .try_exists()
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    match (checkpoint_exists, state_exists) {
        (false, false) => start_new_import(plan, inspected, checkpoint_path, state_path),
        (false, true) => recover_state_only_import(plan, inspected, checkpoint_path, state_path),
        (true, true) => load_existing_import(plan, inspected, checkpoint_path, state_path),
        (true, false) => Err(DataLifecycleError::Checkpoint),
    }
}

fn start_new_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    checkpoint_path: &Path,
    state_path: &Path,
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
    write_atomic_create_new(state_path, &state_bytes)
        .map_err(|_| DataLifecycleError::Checkpoint)?;
    if write_atomic_create_new(checkpoint_path, &checkpoint_bytes).is_err() {
        return load_existing_import(plan, inspected, checkpoint_path, state_path)
            .map_err(|_| DataLifecycleError::Checkpoint);
    }
    Ok((checkpoint, state.import_id))
}

fn recover_state_only_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    checkpoint_path: &Path,
    state_path: &Path,
) -> Result<(DataImportCheckpoint, String), DataLifecycleError> {
    let state = read_import_state(state_path, plan, inspected)?;
    let checkpoint = start_checkpoint_from_state(plan, inspected, &state)?;
    let checkpoint_bytes = checkpoint
        .canonical_json()
        .map_err(DataLifecycleError::Data)?;
    match write_atomic_create_new(checkpoint_path, &checkpoint_bytes) {
        Ok(_) => Ok((checkpoint, state.import_id)),
        Err(_) => load_existing_import(plan, inspected, checkpoint_path, state_path)
            .map_err(|_| DataLifecycleError::Checkpoint),
    }
}

fn load_existing_import(
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
    checkpoint_path: &Path,
    state_path: &Path,
) -> Result<(DataImportCheckpoint, String), DataLifecycleError> {
    let state = read_import_state(state_path, plan, inspected)?;
    let checkpoint_bytes = read_bounded_regular(checkpoint_path, MAX_CHECKPOINT_BYTES)
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
    path: &Path,
    plan: &DataImportPlan,
    inspected: &InspectedDataPackage,
) -> Result<ImportState, DataLifecycleError> {
    let bytes = read_bounded_regular(path, MAX_CHECKPOINT_BYTES)
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
    super::ensure_no_symlink_components(path, "data.input.invalid", "data")
        .map_err(|_| io::Error::other("unsafe path"))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(io::Error::other("invalid file"));
    }
    fs::read(path)
}

fn reserve_export_paths(output: &Path, checkpoint: &Path) -> Result<(), DataLifecycleError> {
    write_atomic_create_new(output, &[])?;
    write_atomic_create_new(checkpoint, &[])
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), DataLifecycleError> {
    let parent = prepare_atomic_write_path(path, true)?;
    let temporary = write_atomic_temporary(parent, bytes)?;
    fs::rename(&temporary, path).map_err(|_| {
        let _ = fs::remove_file(&temporary);
        DataLifecycleError::Output
    })
}

fn write_atomic_create_new(path: &Path, bytes: &[u8]) -> Result<(), DataLifecycleError> {
    let parent = prepare_atomic_write_path(path, false)?;
    let temporary = write_atomic_temporary(parent, bytes)?;
    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            let _ = fs::remove_file(&temporary);
            Ok(())
        }
        Err(_) => {
            let _ = fs::remove_file(&temporary);
            Err(DataLifecycleError::Output)
        }
    }
}

fn prepare_atomic_write_path(
    path: &Path,
    allow_existing_regular_file: bool,
) -> Result<&Path, DataLifecycleError> {
    if path.as_os_str().is_empty() || super::has_parent_component(path) {
        return Err(DataLifecycleError::Output);
    }
    let parent = path.parent().ok_or(DataLifecycleError::Output)?;
    super::ensure_no_symlink_components(parent, "data.output.invalid", "output")
        .map_err(|_| DataLifecycleError::Output)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(DataLifecycleError::Output);
        }
        Ok(_) if !allow_existing_regular_file => return Err(DataLifecycleError::Output),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(DataLifecycleError::Output),
    }
    Ok(parent)
}

fn write_atomic_temporary(parent: &Path, bytes: &[u8]) -> Result<PathBuf, DataLifecycleError> {
    for _ in 0..MAX_ATOMIC_WRITE_TEMP_ATTEMPTS {
        let temporary =
            atomic_write_temporary_path(parent, DATA_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = match options.open(&temporary) {
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
            let _ = fs::remove_file(&temporary);
            return Err(DataLifecycleError::Output);
        }
        drop(file);
        return Ok(temporary);
    }
    Err(DataLifecycleError::Output)
}

fn atomic_write_temporary_path(parent: &Path, sequence: u64) -> PathBuf {
    parent.join(format!(
        ".bregctl-data-{}-{sequence}.tmp",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
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
                    "allowDataExport": true
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
        let collided_temporary = atomic_write_temporary_path(&directory, collided_sequence);
        std::os::unix::fs::symlink(&canary, &collided_temporary).unwrap();

        write_atomic(&destination, b"checkpoint").unwrap();

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
            write_atomic(&final_symlink, b"must-not-follow"),
            Err(DataLifecycleError::Output)
        ));
        assert_eq!(fs::read(&canary).unwrap(), b"unchanged");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn export_paths_are_reserved_without_clobbering_a_concurrent_file() {
        let directory = test_directory("export-reservation");
        let output = directory.join("records.jsonl");
        let checkpoint = directory.join("export.checkpoint.json");

        fs::write(&checkpoint, b"concurrent-checkpoint").unwrap();
        assert!(matches!(
            reserve_export_paths(&output, &checkpoint),
            Err(DataLifecycleError::Output)
        ));
        assert_eq!(fs::read(&output).unwrap(), b"");
        assert_eq!(fs::read(&checkpoint).unwrap(), b"concurrent-checkpoint");

        fs::remove_file(&output).unwrap();
        fs::remove_file(&checkpoint).unwrap();
        reserve_export_paths(&output, &checkpoint).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"");
        assert_eq!(fs::read(&checkpoint).unwrap(), b"");

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn first_import_creation_does_not_clobber_staged_state_or_checkpoint_collisions() {
        let (plan, inspected) = import_plan_and_inspected();
        let directory = test_directory("initial-collisions");
        let checkpoint_path = directory.join("import.checkpoint.json");
        let state_path = import_state_path(&checkpoint_path);

        fs::write(&state_path, b"existing-state").unwrap();
        assert!(matches!(
            start_new_import(&plan, &inspected, &checkpoint_path, &state_path),
            Err(DataLifecycleError::Checkpoint)
        ));
        assert_eq!(fs::read(&state_path).unwrap(), b"existing-state");
        assert!(!checkpoint_path.try_exists().unwrap());
        fs::remove_file(&state_path).unwrap();

        fs::write(&checkpoint_path, b"existing-checkpoint").unwrap();
        assert!(matches!(
            start_new_import(&plan, &inspected, &checkpoint_path, &state_path),
            Err(DataLifecycleError::Checkpoint)
        ));
        assert_eq!(fs::read(&checkpoint_path).unwrap(), b"existing-checkpoint");
        read_import_state(&state_path, &plan, &inspected).unwrap();

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn first_import_loser_keeps_state_after_concurrent_state_only_repair() {
        let (plan, inspected) = import_plan_and_inspected();
        let directory = test_directory("state-repair-race");
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
        let checkpoint_bytes = checkpoint.canonical_json().unwrap();

        write_atomic_create_new(&state_path, &state_bytes).unwrap();

        let (repaired, repaired_import_id) =
            recover_state_only_import(&plan, &inspected, &checkpoint_path, &state_path).unwrap();

        assert_eq!(repaired_import_id, checkpoint.import_id());
        assert_eq!(repaired.import_id(), checkpoint.import_id());

        assert!(matches!(
            write_atomic_create_new(&checkpoint_path, &checkpoint_bytes),
            Err(DataLifecycleError::Output)
        ));
        assert_eq!(fs::read(&state_path).unwrap(), state_bytes);

        let (loaded, loaded_import_id) =
            load_existing_import(&plan, &inspected, &checkpoint_path, &state_path).unwrap();
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

        let (repaired, import_id) =
            load_or_start_import(&plan, &inspected, &checkpoint_path, &state_path).unwrap();

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
            load_or_start_import(&plan, &inspected, &checkpoint_path, &state_path),
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

        let error = read_import_state(&state_path, &plan, &inspected).unwrap_err();
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("SECRET-CANARY"));
        assert!(!rendered.contains(PACKAGE));
        assert!(!rendered.contains(PROFILE));

        let mut changed: Value = serde_json::to_value(&state).unwrap();
        changed["profileId"] = json!("other-profile-canary");
        fs::write(&state_path, canonicalize_json(&changed).unwrap()).unwrap();
        assert!(read_import_state(&state_path, &plan, &inspected).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
