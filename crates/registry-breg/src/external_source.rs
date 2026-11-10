// SPDX-License-Identifier: Apache-2.0

//! Bind reviewed Adapter acquisitions to the active BReg projection contract.
//! The HTTP host proves each local selector and field grant before invoking
//! the service. This layer establishes the independent acquisition grant.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Component, Path},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use registry_adapter_core::{
    AdapterEndpointBindings, AdapterPack, EvidenceConnectionPolicy, ProjectionLocalDisclosure,
    ProjectionMode, ProjectionOperationKind, ProjectionRecord, ProjectionRequest, ProjectionResult,
    ProjectionRetention, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
};
use registry_adapter_engine::{
    artifacts::PackArtifactBytes,
    evidence::{EvidenceHostHooks, EvidenceLimits, EvidenceRuntimeBindings},
    projection::{
        compile_projection_pack, ProjectionError, ProjectionPackProgram, ProjectionProgram,
    },
};
use registry_platform_config::{sha256_uri, SecretResolver};
use registry_platform_yaml::{
    lookalike_local_id_pairs, ApiVersion, BoundedU64, Digest, EnvelopeRule, Expect, FormatSpec,
    Identified, LocalId, Reader, UniqueIdList, UniqueList,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    external_views::{
        ExternalCardinality, ExternalFieldType, ExternalProjectionMode, ExternalProjectionSource,
        ExternalRecordTypeSource,
    },
    model::CompiledRegistry,
};

const MAXIMUM_BINDINGS: usize = 128;
const MAXIMUM_PACK_BYTES: usize = 1_048_576;
const MAXIMUM_CLOSURE_FILES: usize = 512;
const MAXIMUM_CLOSURE_FILE_BYTES: usize = 2 * 1_048_576;
const MAXIMUM_CLOSURE_BYTES: usize = 16 * 1_048_576;
const MAXIMUM_RESPONSE_BYTES: u64 = 16 * 1_048_576;
const MAXIMUM_CA_BYTES: usize =
    registry_platform_httputil::destination::MAX_DESTINATION_CA_BUNDLE_BYTES;
const MAXIMUM_CACHE_TTL_SECONDS: u64 = crate::external_views::MAXIMUM_CACHE_TTL_SECONDS as u64;

/// Operator binding for one already declared projection. The reviewed pack
/// provides the acquisition ceiling; runtime configuration can narrow it.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalSourceBinding {
    pub id: LocalId,
    pub pack_file: String,
    pub pack_digest: Digest,
    pub connection: AdapterEndpointBindings,
    pub endpoint_policies: UniqueIdList<EvidenceConnectionPolicy>,
    pub allowed_fields: UniqueList<LocalId>,
    /// The reviewed source grant cutoff, as an RFC 3339 timestamp.
    pub grant_valid_until: String,
    /// An optional shorter cache lifetime for an indexed projection. The
    /// cache keeps a value for the shorter of this and the authored
    /// cacheTtlSeconds, then purges it. A live projection refuses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_seconds: Option<BoundedU64<1, MAXIMUM_CACHE_TTL_SECONDS>>,
    pub acquisition: ExternalSourceAcquisition,
}

impl Identified for ExternalSourceBinding {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalSourceAcquisition {
    pub maximum_data_operations: BoundedU64<1, 1000>,
    pub attempt_timeout_milliseconds: BoundedU64<1, 60000>,
    pub maximum_response_bytes: BoundedU64<1, MAXIMUM_RESPONSE_BYTES>,
}

#[derive(Debug, Error)]
pub enum ExternalSourceError {
    #[error("the external source binding is invalid")]
    Configuration,
    #[error("the external source pack or its pinned artifact could not be verified")]
    Artifact,
    #[error("the external source operation does not match the compiled projection")]
    Contract,
    #[error("no external source is bound to this projection")]
    Unbound,
    #[error("the active package declares no projection with this ID")]
    UnknownProjection,
    #[error("another binding describes the same connection differently")]
    ConnectionConflict,
    #[error("the external source grant does not permit this acquisition")]
    Grant,
    #[error("the source result is incompatible with the approved BReg field types")]
    Result,
    #[error("the external source acquisition was refused: {0}")]
    Acquisition(#[from] ProjectionError),
}

#[derive(Default)]
pub struct ExternalSourceService {
    bindings: BTreeMap<String, BoundExternalSource>,
    unavailable: BTreeMap<String, String>,
}

pub struct BoundExternalSource {
    program: ProjectionProgram,
    fields: BTreeSet<String>,
    mode: ExternalProjectionMode,
    grant_valid_until: DateTime<Utc>,
    binding_fingerprint: String,
    grant_fingerprint: String,
    cache_ttl_seconds: Option<u32>,
    field_types: BTreeMap<String, (ExternalFieldType, bool)>,
}

impl BoundExternalSource {
    pub fn binding_fingerprint(&self) -> &str {
        &self.binding_fingerprint
    }

    pub fn grant_fingerprint(&self) -> &str {
        &self.grant_fingerprint
    }

    pub fn grant_valid_until(&self) -> DateTime<Utc> {
        self.grant_valid_until
    }

    pub fn mode(&self) -> ExternalProjectionMode {
        self.mode
    }

    pub fn effective_cache_ttl_seconds(&self) -> Option<u32> {
        self.cache_ttl_seconds
    }

    pub fn maximum_batch_keys(&self) -> usize {
        self.program.contract().maximum_batch_keys.get() as usize
    }

    pub fn allowed_fields(&self) -> &BTreeSet<String> {
        &self.fields
    }
}

impl ExternalSourceService {
    /// Capture the pack and public TLS material without source calls or
    /// resolving service credentials. Missing bindings never get a fallback.
    /// Only a malformed binding list refuses the whole load. A binding that
    /// fails its own checks leaves that projection unavailable, with the
    /// reason, while every other projection keeps its binding.
    pub fn load(
        compiled: &CompiledRegistry,
        bindings: &[ExternalSourceBinding],
        resolver: Arc<SecretResolver>,
    ) -> Result<Self, ExternalSourceError> {
        validate_bindings(bindings)?;
        let mut result = Self::default();
        let mut connections = BTreeMap::new();
        for binding in bindings {
            let id = binding.id.as_str();
            match bind_one(compiled, binding, &mut connections, &resolver) {
                Ok(bound) => {
                    result.bindings.insert(id.to_owned(), bound);
                }
                Err(error) => {
                    result.unavailable.insert(id.to_owned(), error.to_string());
                }
            }
        }
        for id in compiled.external_views().projections.keys() {
            if !result.bindings.contains_key(id) && !result.unavailable.contains_key(id) {
                result
                    .unavailable
                    .insert(id.clone(), ExternalSourceError::Unbound.to_string());
            }
        }
        Ok(result)
    }

    /// Every declared or configured projection without a usable binding,
    /// with the reason. Views over these projections answer unavailable.
    pub fn unavailable_projections(&self) -> &BTreeMap<String, String> {
        &self.unavailable
    }

    /// Withdraw one projection's binding for this process, recording why.
    pub(crate) fn refuse(&mut self, projection: &str, reason: String) {
        self.bindings.remove(projection);
        self.unavailable.insert(projection.to_owned(), reason);
    }

    pub fn binding(&self, projection: &str) -> Option<&BoundExternalSource> {
        self.bindings.get(projection)
    }

    /// Acquire only the preauthorized local keys and fields. A grant that
    /// expires during I/O never produces an accepted result.
    pub async fn acquire(
        &self,
        projection: &str,
        hooks: Arc<dyn EvidenceHostHooks>,
        request: ProjectionRequest,
        fields: &BTreeSet<String>,
        clock: impl Fn() -> DateTime<Utc> + Send + Sync,
    ) -> Result<ProjectionResult, ExternalSourceError> {
        let bound = self
            .binding(projection)
            .ok_or(ExternalSourceError::Unbound)?;
        let now = clock();
        if now >= bound.grant_valid_until || fields.is_empty() || !fields.is_subset(&bound.fields) {
            return Err(ExternalSourceError::Grant);
        }
        let mode = match bound.mode {
            ExternalProjectionMode::Live => ProjectionMode::Live,
            ExternalProjectionMode::Indexed => ProjectionMode::Indexed,
        };
        let remaining = bound
            .grant_valid_until
            .signed_duration_since(now)
            .to_std()
            .map_err(|_| ExternalSourceError::Grant)?;
        let grant_deadline = tokio::time::Instant::now()
            .checked_add(remaining)
            .ok_or(ExternalSourceError::Grant)?;
        let mut result = bound
            .program
            .acquire_until(hooks, mode, request, fields, Some(grant_deadline))
            .await?;
        check_result(&result, &bound.field_types)?;
        decimals_to_wire(&mut result, &bound.field_types)?;
        if clock() >= bound.grant_valid_until {
            return Err(ExternalSourceError::Grant);
        }
        Ok(result)
    }
}

type SharedConnections<'a> = BTreeMap<&'a str, (String, EvidenceRuntimeBindings)>;

fn bind_one<'a>(
    compiled: &CompiledRegistry,
    binding: &'a ExternalSourceBinding,
    connections: &mut SharedConnections<'a>,
    resolver: &Arc<SecretResolver>,
) -> Result<BoundExternalSource, ExternalSourceError> {
    let catalog = compiled.external_views();
    let projection = catalog
        .projections
        .get(binding.id.as_str())
        .ok_or(ExternalSourceError::UnknownProjection)?;
    let record = catalog
        .record_types
        .get(projection.record_type.as_str())
        .ok_or(ExternalSourceError::Contract)?;
    let (pack, artifacts) = load_pack(Path::new(&binding.pack_file), &binding.pack_digest)?;
    let limits = EvidenceLimits::try_new(
        binding.acquisition.maximum_data_operations.get(),
        binding.acquisition.attempt_timeout_milliseconds.get(),
        binding.acquisition.maximum_response_bytes.get() as usize,
    )
    .map_err(|_| ExternalSourceError::Configuration)?;
    let program = compile_projection_pack(&pack, projection.operation.as_str(), &artifacts, limits)
        .map_err(|_| ExternalSourceError::Contract)?;
    check_pack_contract(projection, record, &program)?;
    let (fields, field_types) = project_fields(projection, record, binding)?;
    let cache_ttl_seconds =
        effective_ttl(projection, binding.cache_ttl_seconds.map(|ttl| ttl.get()))?;
    let grant_valid_until = parse_grant_cutoff(&binding.grant_valid_until)?;

    let ca_bundles = capture_ca_bundles(&binding.connection)?;
    let ca_digests: BTreeMap<_, _> = ca_bundles
        .iter()
        .map(|(name, bytes)| (name, sha256_uri(bytes)))
        .collect();
    // Bindings that share a connection must describe it identically. This
    // fingerprint only enforces that; it grants no authority.
    let connection_fingerprint = fingerprint(&json!({
        "connection":binding.connection,
        "endpointPolicies":binding.endpoint_policies,
        "caDigests":ca_digests
    }))?;
    let connection_id = binding.connection.id.as_str();
    let connection = match connections.entry(connection_id) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            &entry
                .insert((
                    connection_fingerprint,
                    EvidenceRuntimeBindings::from_shared_http(
                        binding.connection.clone(),
                        Arc::clone(resolver),
                        ca_bundles,
                    ),
                ))
                .1
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            let (previous, runtime) = entry.into_mut();
            if previous.as_str() != connection_fingerprint.as_str() {
                return Err(ExternalSourceError::ConnectionConflict);
            }
            runtime
        }
    };
    let program = program
        .bind_live(connection, connection_id, &binding.endpoint_policies)
        .map_err(|_| ExternalSourceError::Contract)?;
    // The scope fingerprints cover only what grants authority over cached
    // rows: the reviewed source contract, its operation and the allowed
    // fields. Connection details, CA bundles, acquisition limits, the grant
    // cutoff and the cache lifetime can change without discarding the cache.
    let source_contract = program.contract();
    let binding_fingerprint = fingerprint(&json!({
        "operation":projection.operation,
        "sourceContract":source_contract
    }))?;
    let grant_fingerprint = fingerprint(&json!({
        "operation":projection.operation,
        "sourceContract":source_contract,
        "allowedFields":fields
    }))?;
    Ok(BoundExternalSource {
        program,
        fields,
        mode: projection.mode,
        grant_valid_until,
        binding_fingerprint,
        grant_fingerprint,
        cache_ttl_seconds,
        field_types,
    })
}

pub(crate) fn validate_bindings(
    bindings: &[ExternalSourceBinding],
) -> Result<(), ExternalSourceError> {
    let mut ids = BTreeSet::new();
    if bindings.len() > MAXIMUM_BINDINGS
        || !bindings
            .iter()
            .all(|binding| ids.insert(binding.id.as_str()))
        || !lookalike_local_id_pairs(bindings.iter().map(Identified::id)).is_empty()
    {
        return Err(ExternalSourceError::Configuration);
    }
    for binding in bindings {
        parse_grant_cutoff(&binding.grant_valid_until)?;
        if !valid_absolute_file(&binding.pack_file)
            || binding.allowed_fields.is_empty()
            || binding.allowed_fields.len() > 256
            || binding.endpoint_policies.is_empty()
        {
            return Err(ExternalSourceError::Configuration);
        }
    }
    Ok(())
}

fn parse_grant_cutoff(value: &str) -> Result<DateTime<Utc>, ExternalSourceError> {
    if value.len() > 64 {
        return Err(ExternalSourceError::Configuration);
    }
    DateTime::parse_from_rfc3339(value)
        .map(|cutoff| cutoff.to_utc())
        .map_err(|_| ExternalSourceError::Configuration)
}

fn check_pack_contract(
    projection: &ExternalProjectionSource,
    record: &ExternalRecordTypeSource,
    program: &ProjectionPackProgram,
) -> Result<(), ExternalSourceError> {
    let contract = program.contract();
    let expected_operation = match (projection.mode, projection.cardinality) {
        (_, ExternalCardinality::Many) => ProjectionOperationKind::ByParent,
        (ExternalProjectionMode::Live, ExternalCardinality::One) => ProjectionOperationKind::Exact,
        (ExternalProjectionMode::Indexed, ExternalCardinality::One) => {
            ProjectionOperationKind::Batch
        }
    };
    if contract.local_disclosure != ProjectionLocalDisclosure::HostProfiles
        || contract.operation != expected_operation
        || contract.operation_version != projection.operation_version.as_str()
        || contract.authority != record.authority.as_str()
        || contract.purpose != projection.purpose.as_str()
        || contract.scope != projection.scope.as_str()
        || contract.selector_scheme != projection.selector_scheme.as_str()
        || contract.record_key_scheme != record.identifier_scheme.as_str()
        || (projection.mode == ExternalProjectionMode::Indexed
            && contract.retention != ProjectionRetention::Retain)
    {
        return Err(ExternalSourceError::Contract);
    }
    for id in projection.fields.iter() {
        let field = record
            .fields
            .iter()
            .find(|field| field.id == *id)
            .ok_or(ExternalSourceError::Contract)?;
        let schema = program.fields_schema().as_value()["properties"]
            .get(id.as_str())
            .ok_or(ExternalSourceError::Contract)?;
        if !compatible_field(field.value_type, field.nullable, schema) {
            return Err(ExternalSourceError::Contract);
        }
    }
    Ok(())
}

fn compatible_field(value_type: ExternalFieldType, nullable: bool, schema: &Value) -> bool {
    let (expected, format) = match value_type {
        ExternalFieldType::String => ("string", None),
        ExternalFieldType::Integer => ("integer", None),
        ExternalFieldType::Boolean => ("boolean", None),
        ExternalFieldType::Decimal => ("number", None),
        ExternalFieldType::Date => ("string", Some("date")),
        ExternalFieldType::Uuid => ("string", Some("uuid")),
    };
    if format.is_some_and(|format| schema["format"].as_str() != Some(format)) {
        return false;
    }
    if let Some(declared) = schema["type"].as_str() {
        return declared == expected;
    }
    if let Some(variants) = schema["type"].as_array() {
        return variants
            .iter()
            .any(|variant| variant.as_str() == Some(expected))
            && variants.iter().all(|variant| {
                variant.as_str() == Some(expected) || nullable && variant.as_str() == Some("null")
            });
    }
    schema["enum"].as_array().is_some_and(|values| {
        !values.is_empty()
            && values
                .iter()
                .all(|value| typed_value(value_type, nullable, value))
    })
}

type FieldTypes = BTreeMap<String, (ExternalFieldType, bool)>;

fn project_fields(
    projection: &ExternalProjectionSource,
    record: &ExternalRecordTypeSource,
    binding: &ExternalSourceBinding,
) -> Result<(BTreeSet<String>, FieldTypes), ExternalSourceError> {
    let approved: BTreeSet<_> = binding.allowed_fields.iter().map(LocalId::as_str).collect();
    let mut fields = BTreeSet::new();
    let mut types = BTreeMap::new();
    for id in projection.fields.iter() {
        if !approved.contains(id.as_str()) {
            return Err(ExternalSourceError::Grant);
        }
        let field = record
            .fields
            .iter()
            .find(|field| field.id == *id)
            .ok_or(ExternalSourceError::Contract)?;
        fields.insert(id.as_str().to_owned());
        types.insert(id.as_str().to_owned(), (field.value_type, field.nullable));
    }
    Ok((fields, types))
}

/// One cache lifetime: the authored cacheTtlSeconds, which a deployment may
/// only shorten. A cached value is purged when it expires.
fn effective_ttl(
    projection: &ExternalProjectionSource,
    deployment: Option<u64>,
) -> Result<Option<u32>, ExternalSourceError> {
    match (projection.mode, projection.cache_ttl_seconds, deployment) {
        (ExternalProjectionMode::Live, None, None) => Ok(None),
        (ExternalProjectionMode::Indexed, Some(authored), deployment) => {
            let authored = authored.get();
            let shortened = deployment.map_or(authored, |ttl| {
                u32::try_from(ttl).map_or(authored, |ttl| authored.min(ttl))
            });
            Ok(Some(shortened))
        }
        _ => Err(ExternalSourceError::Configuration),
    }
}

fn check_result(result: &ProjectionResult, types: &FieldTypes) -> Result<(), ExternalSourceError> {
    let check = |fields: &Map<String, Value>| {
        fields.iter().all(|(name, value)| {
            types
                .get(name)
                .is_some_and(|&(value_type, nullable)| typed_value(value_type, nullable, value))
        })
    };
    let record_valid = |record: &ProjectionRecord| match record {
        ProjectionRecord::Present { fields, .. } => check(fields),
        _ => true,
    };
    let valid = match result {
        ProjectionResult::Exact { record } => record_valid(record),
        ProjectionResult::Batch { records } => records.iter().all(record_valid),
        ProjectionResult::ByParent { rows, .. } => rows.iter().all(|row| check(&row.fields)),
    };
    if valid {
        Ok(())
    } else {
        Err(ExternalSourceError::Result)
    }
}

/// The source contract states a decimal as a JSON number; BReg serves and
/// stores it as the JSON string its own decimal fields use on the wire. An
/// integer keeps its exact digits; any other number is read as a double and
/// spelled without an exponent.
fn decimals_to_wire(
    result: &mut ProjectionResult,
    types: &FieldTypes,
) -> Result<(), ExternalSourceError> {
    let convert = |fields: &mut Map<String, Value>| {
        for (name, value) in fields.iter_mut() {
            let is_decimal = types
                .get(name)
                .is_some_and(|&(value_type, _)| value_type == ExternalFieldType::Decimal);
            let Value::Number(number) = value else {
                continue;
            };
            if !is_decimal {
                continue;
            }
            let text = if number.is_f64() {
                // `f64` Display never uses an exponent form.
                number.as_f64().map_or_else(String::new, |f| f.to_string())
            } else {
                number.to_string()
            };
            if !plain_decimal(&text) {
                return Err(ExternalSourceError::Result);
            }
            *value = Value::String(text);
        }
        Ok(())
    };
    match result {
        ProjectionResult::Exact { record } => match record {
            ProjectionRecord::Present { fields, .. } => convert(fields),
            _ => Ok(()),
        },
        ProjectionResult::Batch { records } => {
            records.iter_mut().try_for_each(|record| match record {
                ProjectionRecord::Present { fields, .. } => convert(fields),
                _ => Ok(()),
            })
        }
        ProjectionResult::ByParent { rows, .. } => {
            rows.iter_mut().try_for_each(|row| convert(&mut row.fields))
        }
    }
}

/// Whether `text` is an optional minus sign, digits, and an optional fraction
/// of digits: the pattern the served decimal schema states.
fn plain_decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let mut parts = digits.split('.');
    let digits_only =
        |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    parts.next().is_some_and(digits_only)
        && parts.next().is_none_or(digits_only)
        && parts.next().is_none()
}

fn typed_value(value_type: ExternalFieldType, nullable: bool, value: &Value) -> bool {
    if value.is_null() {
        return nullable;
    }
    match value_type {
        ExternalFieldType::String => value.is_string(),
        ExternalFieldType::Integer => value.as_i64().is_some(),
        ExternalFieldType::Boolean => value.is_boolean(),
        ExternalFieldType::Decimal => value.is_number(),
        ExternalFieldType::Date => value.as_str().is_some_and(|raw| {
            chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d")
                .is_ok_and(|date| date.to_string() == raw)
        }),
        ExternalFieldType::Uuid => value.as_str().is_some_and(|raw| {
            uuid::Uuid::parse_str(raw).is_ok_and(|id| id.hyphenated().to_string() == raw)
        }),
    }
}

fn fingerprint(value: &Value) -> Result<String, ExternalSourceError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_uri(&bytes))
        .map_err(|_| ExternalSourceError::Configuration)
}

fn load_pack(
    path: &Path,
    expected: &Digest,
) -> Result<(AdapterPack, PackArtifactBytes), ExternalSourceError> {
    let parent = path.parent().ok_or(ExternalSourceError::Artifact)?;
    let file_name = path.file_name().ok_or(ExternalSourceError::Artifact)?;
    let root = open_directory(parent)?;
    let bytes = read_relative(&root, Path::new(file_name), MAXIMUM_PACK_BYTES)?;
    if sha256_uri(&bytes) != expected.as_str() {
        return Err(ExternalSourceError::Artifact);
    }
    let format = FormatSpec {
        kind: ADAPTER_PACK_KIND,
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    let pack: AdapterPack = Reader::new("pack.yaml")
        .decode(&bytes, &Expect::one(&format))
        .map_err(|_| ExternalSourceError::Artifact)?
        .value;
    if !registry_adapter_core::check_pack(&pack).is_empty() {
        return Err(ExternalSourceError::Contract);
    }
    let files = pack.pinned_files();
    if files.len() > MAXIMUM_CLOSURE_FILES {
        return Err(ExternalSourceError::Artifact);
    }
    let mut retained = BTreeMap::<String, (String, Vec<u8>)>::new();
    let mut total = 0;
    for file in files {
        if !valid_relative_file(&file.path) {
            return Err(ExternalSourceError::Artifact);
        }
        if let Some((previous, _)) = retained.get(file.path.as_str()) {
            if previous != file.digest.as_str() {
                return Err(ExternalSourceError::Artifact);
            }
            continue;
        }
        let data = read_relative(&root, Path::new(&file.path), MAXIMUM_CLOSURE_FILE_BYTES)?;
        let digest = sha256_uri(&data);
        total += data.len();
        if digest != file.digest.as_str() || total > MAXIMUM_CLOSURE_BYTES {
            return Err(ExternalSourceError::Artifact);
        }
        retained.insert(file.path.to_string(), (digest, data));
    }
    let artifacts =
        PackArtifactBytes::new(retained.into_iter().map(|(path, (_, data))| (path, data)));
    Ok((pack, artifacts))
}

fn capture_ca_bundles(
    connection: &AdapterEndpointBindings,
) -> Result<BTreeMap<String, Vec<u8>>, ExternalSourceError> {
    let mut bundles = BTreeMap::new();
    if let Some(tls) = &connection.outbound_tls {
        if tls.trust_profiles.len() > 32 {
            return Err(ExternalSourceError::Configuration);
        }
        for (id, profile) in &tls.trust_profiles {
            if !valid_absolute_file(&profile.ca_bundle_file) {
                return Err(ExternalSourceError::Configuration);
            }
            let path = Path::new(&profile.ca_bundle_file);
            let parent = path.parent().ok_or(ExternalSourceError::Artifact)?;
            let name = path.file_name().ok_or(ExternalSourceError::Artifact)?;
            let root = open_directory(parent)?;
            bundles.insert(
                id.clone(),
                read_relative(&root, Path::new(name), MAXIMUM_CA_BYTES)?,
            );
        }
    }
    Ok(bundles)
}

fn valid_absolute_file(value: &str) -> bool {
    value.strip_prefix('/').is_some_and(valid_relative_file)
}

fn valid_relative_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File, ExternalSourceError> {
    use rustix::fs::{open, Mode, OFlags};

    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| ExternalSourceError::Artifact)
}

#[cfg(not(unix))]
fn open_directory(_: &Path) -> Result<File, ExternalSourceError> {
    Err(ExternalSourceError::Artifact)
}

#[cfg(unix)]
fn read_relative(root: &File, path: &Path, maximum: usize) -> Result<Vec<u8>, ExternalSourceError> {
    use rustix::fs::{openat, Mode, OFlags};

    let mut dir = root
        .try_clone()
        .map_err(|_| ExternalSourceError::Artifact)?;
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(ExternalSourceError::Artifact);
        };
        let leaf = parts.peek().is_none();
        let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        if !leaf {
            flags |= OFlags::DIRECTORY;
        }
        let opened = openat(&dir, name, flags, Mode::empty())
            .map(File::from)
            .map_err(|_| ExternalSourceError::Artifact)?;
        if !leaf {
            dir = opened;
            continue;
        }
        let metadata = opened
            .metadata()
            .map_err(|_| ExternalSourceError::Artifact)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
            return Err(ExternalSourceError::Artifact);
        }
        let mut data = Vec::with_capacity(metadata.len() as usize);
        opened
            .take(maximum as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|_| ExternalSourceError::Artifact)?;
        if data.len() as u64 != metadata.len() || data.len() > maximum {
            return Err(ExternalSourceError::Artifact);
        }
        return Ok(data);
    }
    Err(ExternalSourceError::Artifact)
}

#[cfg(not(unix))]
fn read_relative(_: &File, _: &Path, _: usize) -> Result<Vec<u8>, ExternalSourceError> {
    Err(ExternalSourceError::Artifact)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use registry_adapter_core::ProjectionRow;
    use registry_adapter_engine::evidence::{EvidenceAcquisitionIntent, EvidenceHookFuture};
    use registry_platform_yaml::ExternalId;

    /// Indexed bindings over the example pack for store and startup tests,
    /// as (projection, binding fingerprint, grant fingerprint, cache
    /// lifetime). The replay transcript is empty, so no source call succeeds.
    #[cfg(feature = "postgres-test")]
    pub(crate) fn indexed_service(bindings: &[(&str, &str, &str, u32)]) -> ExternalSourceService {
        let (pack, artifacts) = example();
        let mut service = ExternalSourceService::default();
        for (id, binding, grant, ttl) in bindings {
            let transcript = Arc::new(
                registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                    serde_json::from_value(
                        json!([{"type":"endpoint","endpoint":"synthetic-registry"}]),
                    )
                    .unwrap(),
                    serde_json::from_value(json!([])).unwrap(),
                ),
            );
            let program = compile_projection_pack(
                &pack,
                "person-batch",
                &artifacts,
                EvidenceLimits::default(),
            )
            .unwrap()
            .bind_replay(transcript)
            .unwrap();
            service.bindings.insert(
                (*id).to_owned(),
                BoundExternalSource {
                    program,
                    fields: BTreeSet::from(["label".to_owned()]),
                    mode: ExternalProjectionMode::Indexed,
                    grant_valid_until: Utc::now() + chrono::Duration::days(1),
                    binding_fingerprint: (*binding).to_owned(),
                    grant_fingerprint: (*grant).to_owned(),
                    cache_ttl_seconds: Some(*ttl),
                    field_types: BTreeMap::new(),
                },
            );
        }
        service
    }

    /// Add a live binding over the example pack's exact route, which retains
    /// nothing. Each source call must match the next `transcript` exchange.
    #[cfg(feature = "postgres-test")]
    pub(crate) fn add_live_binding(
        service: &mut ExternalSourceService,
        projection: &str,
        field: &str,
        transcript: Arc<registry_adapter_engine::replay::ReplayTranscript>,
    ) {
        let (pack, artifacts) = example();
        let program =
            compile_projection_pack(&pack, "person-exact", &artifacts, EvidenceLimits::default())
                .unwrap()
                .bind_replay(transcript)
                .unwrap();
        service.bindings.insert(
            projection.to_owned(),
            BoundExternalSource {
                program,
                fields: BTreeSet::from([field.to_owned()]),
                mode: ExternalProjectionMode::Live,
                grant_valid_until: Utc::now() + chrono::Duration::days(1),
                binding_fingerprint: "live-binding".to_owned(),
                grant_fingerprint: "live-grant".to_owned(),
                cache_ttl_seconds: None,
                field_types: BTreeMap::from([(
                    field.to_owned(),
                    (ExternalFieldType::String, false),
                )]),
            },
        );
    }

    /// Add an indexed binding over the example pack's batch route with a
    /// sixty-second cache lifetime. Each source call must match the next
    /// `transcript` exchange.
    #[cfg(feature = "postgres-test")]
    pub(crate) fn add_indexed_binding(
        service: &mut ExternalSourceService,
        projection: &str,
        field: &str,
        transcript: Arc<registry_adapter_engine::replay::ReplayTranscript>,
    ) {
        let (pack, artifacts) = example();
        let program =
            compile_projection_pack(&pack, "person-batch", &artifacts, EvidenceLimits::default())
                .unwrap()
                .bind_replay(transcript)
                .unwrap();
        service.bindings.insert(
            projection.to_owned(),
            BoundExternalSource {
                program,
                fields: BTreeSet::from([field.to_owned()]),
                mode: ExternalProjectionMode::Indexed,
                grant_valid_until: Utc::now() + chrono::Duration::days(1),
                binding_fingerprint: "indexed-binding".to_owned(),
                grant_fingerprint: "indexed-grant".to_owned(),
                cache_ttl_seconds: Some(60),
                field_types: BTreeMap::from([(
                    field.to_owned(),
                    (ExternalFieldType::String, false),
                )]),
            },
        );
    }

    struct Hooks;
    impl EvidenceHostHooks for Hooks {
        fn before_acquisition<'a>(
            &'a self,
            _: EvidenceAcquisitionIntent,
        ) -> EvidenceHookFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    fn project_contracts() -> (ExternalProjectionSource, ExternalRecordTypeSource) {
        let projection = serde_json::from_value(json!({
            "id":"holder","recordType":"person","operation":"person-exact","operationVersion":"1",
            "purpose":"licensing","scope":"licensing-holders","selectorScheme":"urn:example:person-number",
            "mode":"live","cardinality":"one","fields":["family-name"]
        })).unwrap();
        let record = serde_json::from_value(json!({
            "id":"person","authority":"urn:example:population-register","identifierScheme":"urn:example:person-number",
            "fields":[{"id":"family-name","type":"string","classification":"public"}]
        })).unwrap();
        (projection, record)
    }

    fn example() -> (AdapterPack, PackArtifactBytes) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/external-projections");
        let bytes = std::fs::read(root.join("pack.yaml")).unwrap();
        let digest = Digest::new(sha256_uri(&bytes)).unwrap();
        load_pack(&root.join("pack.yaml"), &digest).unwrap()
    }

    #[test]
    fn project_operation_cannot_change_source_scope_scheme_type_or_retention() {
        let (pack, artifacts) = example();
        let program =
            compile_projection_pack(&pack, "person-exact", &artifacts, EvidenceLimits::default())
                .unwrap();
        let (projection, record) = project_contracts();
        assert!(check_pack_contract(&projection, &record, &program).is_ok());

        let mut restricted_pack = serde_json::to_value(&pack).unwrap();
        restricted_pack["sourceRoutes"][0]["projection"]["localDisclosure"] =
            json!("acquisition-only");
        let restricted = compile_projection_pack(
            &serde_json::from_value(restricted_pack).unwrap(),
            "person-exact",
            &artifacts,
            EvidenceLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            check_pack_contract(&projection, &record, &restricted),
            Err(ExternalSourceError::Contract)
        ));

        let mut wrong_scope = projection.clone();
        wrong_scope.scope = ExternalId::new("different-scope").unwrap();
        assert!(matches!(
            check_pack_contract(&wrong_scope, &record, &program),
            Err(ExternalSourceError::Contract)
        ));

        let mut wrong_scheme = record.clone();
        wrong_scheme.identifier_scheme = ExternalId::new("urn:example:unrelated").unwrap();
        assert!(matches!(
            check_pack_contract(&projection, &wrong_scheme, &program),
            Err(ExternalSourceError::Contract)
        ));

        let mut wrong_type = record.clone();
        wrong_type.fields[0].value_type = ExternalFieldType::Integer;
        assert!(matches!(
            check_pack_contract(&projection, &wrong_type, &program),
            Err(ExternalSourceError::Contract)
        ));

        let mut indexed = projection;
        indexed.mode = ExternalProjectionMode::Indexed;
        assert!(matches!(
            check_pack_contract(&indexed, &record, &program),
            Err(ExternalSourceError::Contract)
        ));
    }

    #[test]
    fn exact_pack_pin_and_every_referenced_file_are_checked() {
        let root = tempfile::tempdir().unwrap();
        let pack = root.path().join("pack.yaml");
        std::fs::write(&pack, b"synthetic mismatch").unwrap();
        assert!(matches!(
            load_pack(&pack, &Digest::new(sha256_uri(b"expected bytes")).unwrap()),
            Err(ExternalSourceError::Artifact)
        ));

        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/external-projections/pack.yaml");
        let bytes = std::fs::read(source).unwrap();
        std::fs::write(&pack, &bytes).unwrap();
        assert!(matches!(
            load_pack(&pack, &Digest::new(sha256_uri(&bytes)).unwrap()),
            Err(ExternalSourceError::Artifact)
        ));
    }

    #[tokio::test]
    async fn a_result_finished_at_grant_cutoff_is_not_accepted() {
        let (pack, artifacts) = example();
        let transcript = Arc::new(registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
            serde_json::from_value(json!([{"type":"endpoint","endpoint":"synthetic-registry"}])).unwrap(),
            serde_json::from_value(json!([{
                "request":{"endpoint":"synthetic-registry","method":"POST","path":"/people/exact","body":{
                    "type":"exact","key":"person-7","fields":["family-name"]
                }},
                "response":{"status":200,"body":{"subject":"person-7","state":"found","properties":{"family-name":"Lee"}}}
            }])).unwrap(),
        ));
        let program =
            compile_projection_pack(&pack, "person-exact", &artifacts, EvidenceLimits::default())
                .unwrap()
                .bind_replay(Arc::clone(&transcript))
                .unwrap();
        let cutoff = DateTime::parse_from_rfc3339("2030-01-02T00:00:00Z")
            .unwrap()
            .to_utc();
        let fields = BTreeSet::from(["family-name".to_owned()]);
        let service = ExternalSourceService {
            bindings: BTreeMap::from([(
                "holder".to_owned(),
                BoundExternalSource {
                    program,
                    fields: fields.clone(),
                    mode: ExternalProjectionMode::Live,
                    grant_valid_until: cutoff,
                    binding_fingerprint: "binding".to_owned(),
                    grant_fingerprint: "grant".to_owned(),
                    cache_ttl_seconds: None,
                    field_types: BTreeMap::from([(
                        "family-name".to_owned(),
                        (ExternalFieldType::String, false),
                    )]),
                },
            )]),
            unavailable: BTreeMap::new(),
        };
        let samples = std::sync::atomic::AtomicUsize::new(0);
        let result = service
            .acquire(
                "holder",
                Arc::new(Hooks),
                ProjectionRequest::Exact {
                    key: "person-7".to_owned(),
                },
                &fields,
                || {
                    if samples.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        cutoff - chrono::Duration::seconds(1)
                    } else {
                        cutoff
                    }
                },
            )
            .await;
        assert!(matches!(result, Err(ExternalSourceError::Grant)));
        transcript.finish().unwrap();
    }

    #[tokio::test]
    async fn a_no_store_source_response_is_refused_for_the_indexed_store() {
        async fn indexed_batch(
            no_store: bool,
        ) -> (
            Result<ProjectionResult, ExternalSourceError>,
            Arc<registry_adapter_engine::replay::ReplayTranscript>,
        ) {
            let (pack, artifacts) = example();
            let mut response = json!({"status":200,"body":{"records":[
                {"subject":"person-7","state":"found","properties":{"family-name":"Lee"}}
            ]}});
            if no_store {
                response["headers"] = json!({"Cache-Control":"private, no-store"});
            }
            let transcript = Arc::new(
                registry_adapter_engine::replay::ReplayTranscript::from_exchanges(
                    serde_json::from_value(
                        json!([{"type":"endpoint","endpoint":"synthetic-registry"}]),
                    )
                    .unwrap(),
                    serde_json::from_value(json!([{
                        "request":{"endpoint":"synthetic-registry","method":"POST","path":"/people/batch","body":{
                            "type":"batch","keys":["person-7"],"fields":["family-name"]
                        }},
                        "response":response
                    }]))
                    .unwrap(),
                ),
            );
            let program = compile_projection_pack(
                &pack,
                "person-batch",
                &artifacts,
                EvidenceLimits::default(),
            )
            .unwrap()
            .bind_replay(Arc::clone(&transcript))
            .unwrap();
            let fields = BTreeSet::from(["family-name".to_owned()]);
            let service = ExternalSourceService {
                bindings: BTreeMap::from([(
                    "holder".to_owned(),
                    BoundExternalSource {
                        program,
                        fields: fields.clone(),
                        mode: ExternalProjectionMode::Indexed,
                        grant_valid_until: Utc::now() + chrono::Duration::days(1),
                        binding_fingerprint: "binding".to_owned(),
                        grant_fingerprint: "grant".to_owned(),
                        cache_ttl_seconds: Some(60),
                        field_types: BTreeMap::from([(
                            "family-name".to_owned(),
                            (ExternalFieldType::String, false),
                        )]),
                    },
                )]),
                unavailable: BTreeMap::new(),
            };
            let result = service
                .acquire(
                    "holder",
                    Arc::new(Hooks),
                    ProjectionRequest::Batch {
                        keys: vec!["person-7".to_owned()],
                    },
                    &fields,
                    Utc::now,
                )
                .await;
            (result, transcript)
        }

        let (stored, transcript) = indexed_batch(false).await;
        assert!(stored.is_ok());
        transcript.finish().unwrap();
        let (refused, transcript) = indexed_batch(true).await;
        assert!(matches!(
            refused,
            Err(ExternalSourceError::Acquisition(ProjectionError::NoStore))
        ));
        transcript.finish().unwrap();
    }

    #[test]
    fn a_deployment_cache_lifetime_only_shortens_the_authored_one() {
        let (live, _) = project_contracts();
        assert!(matches!(effective_ttl(&live, None), Ok(None)));
        assert!(matches!(
            effective_ttl(&live, Some(60)),
            Err(ExternalSourceError::Configuration)
        ));
        let mut indexed = live;
        indexed.mode = ExternalProjectionMode::Indexed;
        indexed.cache_ttl_seconds = Some(registry_platform_yaml::BoundedU32::new(300).unwrap());
        assert!(matches!(effective_ttl(&indexed, None), Ok(Some(300))));
        assert!(matches!(effective_ttl(&indexed, Some(60)), Ok(Some(60))));
        assert!(matches!(effective_ttl(&indexed, Some(900)), Ok(Some(300))));
    }

    fn decimal_fields(value: Value) -> Map<String, Value> {
        let Value::Object(fields) = json!({"balance": value, "label": "x"}) else {
            unreachable!()
        };
        fields
    }

    fn decimal_types() -> FieldTypes {
        BTreeMap::from([
            ("balance".to_owned(), (ExternalFieldType::Decimal, true)),
            ("label".to_owned(), (ExternalFieldType::String, false)),
        ])
    }

    fn present(key: &str, value: Value) -> ProjectionRecord {
        ProjectionRecord::Present {
            key: key.to_owned(),
            fields: decimal_fields(value),
            source_revision: None,
        }
    }

    fn balance_of(record: &ProjectionRecord) -> Value {
        match record {
            ProjectionRecord::Present { fields, .. } => fields["balance"].clone(),
            _ => panic!("not present"),
        }
    }

    /// Every result shape, the exact (live) and batch and by-parent (indexed)
    /// ones, serves a decimal as a string the generated schema accepts.
    #[test]
    fn decimals_are_served_as_strings_the_generated_schema_accepts() {
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&crate::external_view_artifacts::decimal_schema())
            .unwrap();
        let types = decimal_types();
        let spelled: [(Value, &str); 4] = [
            (json!(12.5), "12.5"),
            (json!(-3), "-3"),
            (json!(0.1), "0.1"),
            (json!(100), "100"),
        ];
        for (number, text) in spelled {
            let mut exact = ProjectionResult::Exact {
                record: present("a", number.clone()),
            };
            decimals_to_wire(&mut exact, &types).unwrap();
            let ProjectionResult::Exact { record } = &exact else {
                unreachable!()
            };
            assert_eq!(balance_of(record), json!(text));
            assert!(validator.is_valid(&balance_of(record)));

            let mut batch = ProjectionResult::Batch {
                records: vec![present("a", number.clone()), present("b", Value::Null)],
            };
            decimals_to_wire(&mut batch, &types).unwrap();
            let ProjectionResult::Batch { records } = &batch else {
                unreachable!()
            };
            assert_eq!(balance_of(&records[0]), json!(text));
            assert_eq!(balance_of(&records[1]), Value::Null);

            let Value::Object(fields) = json!({"balance": number}) else {
                unreachable!()
            };
            let mut by_parent = ProjectionResult::ByParent {
                parent_key: "p".to_owned(),
                snapshot: "s".to_owned(),
                rows: vec![ProjectionRow {
                    key: "r".to_owned(),
                    parent_key: "p".to_owned(),
                    fields,
                    source_revision: None,
                }],
            };
            decimals_to_wire(&mut by_parent, &types).unwrap();
            let ProjectionResult::ByParent { rows, .. } = &by_parent else {
                unreachable!()
            };
            assert_eq!(rows[0].fields["balance"], json!(text));
        }
        assert!(!validator.is_valid(&json!(12.5)));
    }

    /// A source number whose shortest spelling is an exponent form (below 1e-5
    /// or from 1e16) is still served as a plain decimal string, and one such
    /// value does not fail the batch that carries it.
    #[test]
    fn exponent_range_decimals_are_served_as_plain_strings() {
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&crate::external_view_artifacts::decimal_schema())
            .unwrap();
        let types = decimal_types();
        let spelled: [(Value, &str); 5] = [
            (json!(0.000001), "0.000001"),
            (json!(1e16), "10000000000000000"),
            (json!(-1e-7), "-0.0000001"),
            (json!(1.5e-9), "0.0000000015"),
            (json!(12.5), "12.5"),
        ];
        let mut batch = ProjectionResult::Batch {
            records: spelled
                .iter()
                .map(|(number, _)| present("a", number.clone()))
                .collect(),
        };
        decimals_to_wire(&mut batch, &types).expect("one extreme value does not fail the batch");
        let ProjectionResult::Batch { records } = &batch else {
            unreachable!()
        };
        for (record, (_, text)) in records.iter().zip(spelled) {
            assert_eq!(balance_of(record), json!(text));
            assert!(validator.is_valid(&balance_of(record)), "{text}");
        }
    }

    #[test]
    fn plain_decimal_accepts_only_the_served_pattern() {
        for good in ["0", "-1", "12.50", "007"] {
            assert!(plain_decimal(good), "{good}");
        }
        for bad in ["", "-", "1.", ".5", "1e5", "1.2.3", "+1", "--1", "1 "] {
            assert!(!plain_decimal(bad), "{bad}");
        }
    }

    fn example_registry() -> CompiledRegistry {
        let source = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/breg/examples/external-views/registry.yaml"),
        )
        .unwrap();
        let project = crate::contract::parse_project_yaml(&source).unwrap();
        crate::compiler::compile_project(&project, &[], crate::compiler::CompileProfile::Authoring)
            .unwrap()
    }

    fn example_binding(id: &str, fields: &[&str], ca_file: &Path) -> Value {
        let pack = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/external-projections/pack.yaml")
            .canonicalize()
            .unwrap();
        let digest = sha256_uri(&std::fs::read(&pack).unwrap());
        json!({
            "id":id,"packFile":pack.to_str().unwrap(),"packDigest":digest,
            "connection":{"id":"synthetic-licensing","endpoints":[{"endpoint":"synthetic-registry",
                "baseUrl":"https://source.example.test","tlsTrustProfile":"source-ca",
                "credential":{"type":"static-api-key","valueRef":"secret:file/source-key"}}],
                "outboundTls":{"trustProfiles":{"source-ca":{"caBundleFile":ca_file.to_str().unwrap()}}}},
            "endpointPolicies":[{"endpoint":"synthetic-registry","baseUrl":"https://source.example.test",
                "tlsTrustProfile":"source-ca","clientIdentity":"forbidden",
                "authentication":{"type":"static-api-key"}}],
            "allowedFields":fields,"grantValidUntil":"2030-01-01T00:00:00Z",
            "acquisition":{"maximumDataOperations":8,"attemptTimeoutMilliseconds":8000,"maximumResponseBytes":262144}
        })
    }

    /// Copy the example pack into `dir` with an edited pack.yaml and point
    /// the binding at the copy.
    fn use_pack_copy(binding: &mut Value, dir: &Path, edit: impl Fn(&str) -> String) {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/adapter/examples/external-projections");
        let target = dir.canonicalize().unwrap();
        for folder in ["scripts", "schemas"] {
            std::fs::create_dir_all(target.join(folder)).unwrap();
            for entry in std::fs::read_dir(source.join(folder)).unwrap() {
                let entry = entry.unwrap();
                std::fs::copy(entry.path(), target.join(folder).join(entry.file_name())).unwrap();
            }
        }
        let pack = edit(&std::fs::read_to_string(source.join("pack.yaml")).unwrap());
        let pack_file = target.join("pack.yaml");
        std::fs::write(&pack_file, &pack).unwrap();
        binding["packFile"] = json!(pack_file.to_str().unwrap());
        binding["packDigest"] = json!(sha256_uri(pack.as_bytes()));
    }

    fn load_values(registry: &CompiledRegistry, bindings: &[Value]) -> ExternalSourceService {
        let bindings = bindings
            .iter()
            .map(|binding| serde_json::from_value(binding.clone()).unwrap())
            .collect::<Vec<ExternalSourceBinding>>();
        ExternalSourceService::load(registry, &bindings, Arc::new(SecretResolver::disabled()))
            .unwrap()
    }

    fn fingerprints(service: &ExternalSourceService, id: &str) -> (String, String) {
        let bound = service.binding(id).unwrap_or_else(|| {
            panic!(
                "{id} is unavailable: {:?}",
                service.unavailable_projections().get(id)
            )
        });
        (
            bound.binding_fingerprint().to_owned(),
            bound.grant_fingerprint().to_owned(),
        )
    }

    #[test]
    fn only_the_pack_contract_operation_and_fields_enter_the_authority_fingerprints() {
        let registry = example_registry();
        let trust = tempfile::tempdir().unwrap();
        let ca_file = trust.path().canonicalize().unwrap().join("source-ca.pem");
        std::fs::write(&ca_file, b"synthetic certificate authority one").unwrap();
        let original = example_binding("person-indexed", &["family-name", "given-name"], &ca_file);
        let first = fingerprints(
            &load_values(&registry, std::slice::from_ref(&original)),
            "person-indexed",
        );

        // A renewed grant, a replaced CA bundle, a moved endpoint and new
        // acquisition limits grant no new authority.
        std::fs::write(&ca_file, b"synthetic certificate authority two").unwrap();
        let mut renewed = original.clone();
        renewed["grantValidUntil"] = json!("2031-06-01T00:00:00Z");
        renewed["connection"]["endpoints"][0]["baseUrl"] = json!("https://renewed.example.test");
        renewed["endpointPolicies"][0]["baseUrl"] = json!("https://renewed.example.test");
        renewed["acquisition"] = json!({"maximumDataOperations":2,"attemptTimeoutMilliseconds":3000,"maximumResponseBytes":65536});
        renewed["cacheTtlSeconds"] = json!(120);
        assert_eq!(
            fingerprints(&load_values(&registry, &[renewed]), "person-indexed"),
            first
        );

        // A rebuilt pack with the same reviewed contract keeps the authority,
        // and fields approved beyond the projection's own grant nothing.
        let packs = tempfile::tempdir().unwrap();
        let mut rebuilt = original.clone();
        use_pack_copy(&mut rebuilt, packs.path(), |pack| {
            format!("{pack}# rebuilt without a contract change\n")
        });
        rebuilt["allowedFields"] = json!(["family-name", "given-name", "unprojected"]);
        assert_eq!(
            fingerprints(&load_values(&registry, &[rebuilt]), "person-indexed"),
            first
        );

        // A changed source contract is a different authority.
        let changed = tempfile::tempdir().unwrap();
        let mut recontracted = original.clone();
        use_pack_copy(&mut recontracted, changed.path(), |pack| {
            pack.replacen("maximumBatchKeys: 64", "maximumBatchKeys: 32", 1)
        });
        let (binding, grant) =
            fingerprints(&load_values(&registry, &[recontracted]), "person-indexed");
        assert_ne!(binding, first.0);
        assert_ne!(grant, first.1);

        // Fields approved below the projection's own leave it unbound.
        let mut narrowed = original;
        narrowed["allowedFields"] = json!(["family-name"]);
        let service = load_values(&registry, &[narrowed]);
        assert_eq!(
            service.unavailable_projections().get("person-indexed"),
            Some(&ExternalSourceError::Grant.to_string())
        );
    }

    #[test]
    fn a_refused_binding_leaves_the_other_projections_bound() {
        let registry = example_registry();
        let trust = tempfile::tempdir().unwrap();
        let ca_file = trust.path().canonicalize().unwrap().join("source-ca.pem");
        std::fs::write(&ca_file, b"synthetic certificate authority").unwrap();
        let good = example_binding("person-indexed", &["family-name", "given-name"], &ca_file);
        let mut pinned_elsewhere = example_binding("person-live", &["family-name"], &ca_file);
        pinned_elsewhere["packDigest"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        let retired = example_binding("retired-projection", &["family-name"], &ca_file);
        let service = load_values(&registry, &[good, pinned_elsewhere, retired]);

        assert!(service.binding("person-indexed").is_some());
        assert!(service.binding("person-live").is_none());
        let unavailable = service.unavailable_projections();
        assert_eq!(
            unavailable.get("person-live").map(String::as_str),
            Some(ExternalSourceError::Artifact.to_string().as_str())
        );
        assert_eq!(
            unavailable.get("retired-projection").map(String::as_str),
            Some(ExternalSourceError::UnknownProjection.to_string().as_str())
        );
        for unbound in ["holdings-live", "holdings-indexed"] {
            assert_eq!(
                unavailable.get(unbound).map(String::as_str),
                Some(ExternalSourceError::Unbound.to_string().as_str())
            );
        }
        assert!(!unavailable.contains_key("person-indexed"));
    }

    #[test]
    fn retired_retention_and_selector_members_are_refused() {
        let binding = json!({
            "id":"holder","packFile":"/packs/pack.yaml",
            "packDigest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "connection":{"id":"source","endpoints":[{"endpoint":"synthetic-registry",
                "baseUrl":"https://source.example.test",
                "credential":{"type":"static-api-key","valueRef":"secret:file/source-key"}}]},
            "endpointPolicies":[{"endpoint":"synthetic-registry","baseUrl":"https://source.example.test",
                "clientIdentity":"forbidden","authentication":{"type":"static-api-key"}}],
            "allowedFields":["family-name"],"grantValidUntil":"2030-01-01T00:00:00Z",
            "cacheTtlSeconds":60,
            "acquisition":{"maximumDataOperations":8,"attemptTimeoutMilliseconds":8000,"maximumResponseBytes":262144}
        });
        let parsed: ExternalSourceBinding = serde_json::from_value(binding.clone()).unwrap();
        assert_eq!(parsed.cache_ttl_seconds.map(|ttl| ttl.get()), Some(60));
        for (member, value) in [
            ("allowedSelectors", json!(["person-7"])),
            (
                "retention",
                json!({"maximumRetentionSeconds":300,"refreshIntervalSeconds":60}),
            ),
        ] {
            let mut retired = binding.clone();
            retired[member] = value;
            assert!(serde_json::from_value::<ExternalSourceBinding>(retired).is_err());
        }
    }

    #[test]
    fn the_acquisition_timeout_is_spelled_as_an_attempt_timeout() {
        let acquisition = json!({
            "maximumDataOperations":8,"attemptTimeoutMilliseconds":8000,"maximumResponseBytes":262144
        });
        let parsed: ExternalSourceAcquisition = serde_json::from_value(acquisition).unwrap();
        assert_eq!(parsed.attempt_timeout_milliseconds.get(), 8000);
        let refused = json!({
            "maximumDataOperations":8,"timeoutMilliseconds":8000,"maximumResponseBytes":262144
        });
        assert!(serde_json::from_value::<ExternalSourceAcquisition>(refused).is_err());
    }
}
